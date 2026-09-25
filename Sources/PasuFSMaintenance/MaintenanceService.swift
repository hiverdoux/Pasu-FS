import Foundation
import PasuFSHostCore
import PasuFSIPC
import PasuFSMaintenanceCore
import Security

enum UninstallAuthorization {
  static func validate(_ data: Data) throws {
    guard data.count == MemoryLayout<AuthorizationExternalForm>.size else {
      throw MaintenanceError(.authorizationMalformed)
    }
    var external = AuthorizationExternalForm()
    _ = withUnsafeMutableBytes(of: &external) { data.copyBytes(to: $0) }
    var reference: AuthorizationRef?
    let importStatus = AuthorizationCreateFromExternalForm(&external, &reference)
    guard importStatus == errAuthorizationSuccess,
      let reference
    else { throw MaintenanceError(.authorizationInvalid, detail: String(importStatus)) }
    defer { AuthorizationFree(reference, []) }
    var definition: CFDictionary?
    let lookup = AdministrativeAuthorizationOperation.uninstall.rightName.withCString {
      AuthorizationRightGet($0, &definition)
    }
    guard lookup == errAuthorizationSuccess, let definition,
      AdministrativeAuthorizationRule.isSecure(definition)
    else {
      throw MaintenanceError(.authorizationRuleUnexpected)
    }
    let status = AdministrativeAuthorizationOperation.uninstall.rightName.withCString { name in
      var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
      return withUnsafeMutablePointer(to: &item) { itemPointer in
        var rights = AuthorizationRights(count: 1, items: itemPointer)
        // Authenticate and check exactly once in the GUI-created authorization session.
        // timeout=0 remains in force: a previous GUI-side authentication would already be expired.
        return AuthorizationCopyRights(
          reference, &rights, nil, [.extendRights, .interactionAllowed], nil)
      }
    }
    if status == errAuthorizationCanceled {
      throw MaintenanceError(.authorizationCanceled)
    }
    guard status == errAuthorizationSuccess else {
      throw MaintenanceError(.authorizationDenied, detail: String(status))
    }
  }
}

final class MaintenanceService: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
  private let listener = NSXPCListener(machServiceName: MaintenanceContract.service)
  private let queue = DispatchQueue(label: "com.example.pasu.fs.maintenance.operations")
  private let stateStore: UninstallStateStore
  private var session: UninstallSession?
  private var removing = false
  private var lastActivity = Date()
  private var connections: [UUID: NSXPCConnection] = [:]

  override init() {
    do { stateStore = try UninstallStateStore() } catch {
      fatalError("Cannot locate product storage: \(error)")
    }
    super.init()
  }

  func run() throws {
    try SystemOperations.validateInstallation()
    let requirement = try CodeSigningRequirementResolver.designatedRequirement(
      forCodeAt: URL(fileURLWithPath: MaintenanceContract.appPath), requireRootOwnedBundle: true)
    listener.delegate = self
    listener.setConnectionCodeSigningRequirement(requirement)
    listener.activate()
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + 30, repeating: 30)
    timer.setEventHandler { [self] in
      if !removing, Date().timeIntervalSince(lastActivity) > 60,
        session == nil || Date() >= session!.expires
      {
        exit(EXIT_SUCCESS)
      }
    }
    timer.resume()
    withExtendedLifetime(timer) { RunLoop.current.run() }
  }

  func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection)
    -> Bool
  {
    let identifier = UUID()
    let handler = ConnectionHandler(
      service: self, identifier: identifier, processID: connection.processIdentifier)
    connection.exportedInterface = NSXPCInterface(with: PasuFSMaintenanceXPCProtocol.self)
    connection.exportedObject = handler
    connection.invalidationHandler = { [weak self] in
      guard let self else { return }
      self.queue.async {
        self.connections.removeValue(forKey: identifier)
        if !self.removing, self.session?.connection == identifier { self.session = nil }
      }
    }
    queue.sync { connections[identifier] = connection }
    connection.activate()
    return true
  }

  func status(nonce: Data, reply: @escaping @Sendable (Data?, NSError?) -> Void) {
    queue.async { [self] in
      lastActivity = Date()
      respond(reply) {
        guard nonce.count == 32 else { throw MaintenanceError(.invalidHandshake) }
        return try MaintenanceContract.encode(
          MaintenanceStatus(nonce: nonce, state: stateStore.read()))
      }
    }
  }

  func prepare(
    data: Data, connection: UUID, processID: Int32,
    reply: @escaping @Sendable (Data?, NSError?) -> Void
  ) {
    queue.async { [self] in
      lastActivity = Date()
      respond(reply) {
        guard !removing, session == nil || session!.expires <= Date() else {
          throw MaintenanceError(.requestInProgress)
        }
        let request = try MaintenanceContract.decode(UninstallPreparation.self, from: data)
        try UninstallAuthorization.validate(request.authorization)
        try SystemOperations.validateRemoval(excluding: processID)
        let authorized = try UninstallSession(
          connection: connection, processID: processID, removeData: request.removeData,
          previousState: stateStore.read())
        try stateStore.write(UninstallState(phase: .prepared, removeData: request.removeData))
        session = authorized
        return try MaintenanceContract.encode(UninstallTicket(identifier: authorized.ticket))
      }
    }
  }

  func commit(data: Data, connection: UUID, reply: @escaping @Sendable (Data?, NSError?) -> Void) {
    queue.async { [self] in
      lastActivity = Date()
      do {
        let request = try MaintenanceContract.decode(UninstallCommit.self, from: data)
        guard !removing, let authorized = session else {
          throw MaintenanceError(.noCurrentApproval)
        }
        try authorized.validate(ticket: request.ticket, connection: connection)
        switch request.action {
        case .cancel:
          if let previous = authorized.previousState {
            try stateStore.write(previous)
          } else {
            try stateStore.clear()
          }
        case .awaitRestart:
          try stateStore.write(
            UninstallState(phase: .awaitingRestart, removeData: authorized.removeData))
        case .removeFiles:
          try SystemOperations.validateRemoval(excluding: authorized.processID)
          try stateStore.write(UninstallState(phase: .removing, removeData: authorized.removeData))
          removing = true
        }
        session = nil  // The ticket is consumed exactly once, including deferral until reboot.
        reply(try MaintenanceContract.encode(MaintenanceAcknowledgement()), nil)
        if removing {
          queue.async { [self] in
            do {
              try SystemOperations.finishRemoval(session: authorized, stateStore: stateStore)
            } catch {
              try? stateStore.write(
                UninstallState(
                  phase: .failed, removeData: authorized.removeData,
                  failure: error as? MaintenanceError
                    ?? MaintenanceError(.internalFailure, detail: String(describing: error))))
              NSLog("Pasu FS uninstall failed: %@", String(describing: error))
              removing = false
              lastActivity = Date()
            }
          }
        }
      } catch {
        NSLog("Pasu FS maintenance commit failed: %@", String(describing: error))
        reply(nil, MaintenanceContract.remoteError(error))
      }
    }
  }

  private func respond(
    _ reply: @escaping @Sendable (Data?, NSError?) -> Void, body: () throws -> Data
  ) {
    do { reply(try body(), nil) } catch {
      NSLog("Pasu FS maintenance request failed: %@", String(describing: error))
      reply(nil, MaintenanceContract.remoteError(error))
    }
  }
}

private final class ConnectionHandler: NSObject, PasuFSMaintenanceXPCProtocol, @unchecked Sendable {
  let service: MaintenanceService
  let identifier: UUID
  let processID: Int32
  init(service: MaintenanceService, identifier: UUID, processID: Int32) {
    self.service = service
    self.identifier = identifier
    self.processID = processID
  }
  func status(_ nonce: Data, withReply reply: @escaping @Sendable (Data?, NSError?) -> Void) {
    service.status(nonce: nonce, reply: reply)
  }
  func prepare(_ request: Data, withReply reply: @escaping @Sendable (Data?, NSError?) -> Void) {
    service.prepare(data: request, connection: identifier, processID: processID, reply: reply)
  }
  func commit(_ request: Data, withReply reply: @escaping @Sendable (Data?, NSError?) -> Void) {
    service.commit(data: request, connection: identifier, reply: reply)
  }
}
