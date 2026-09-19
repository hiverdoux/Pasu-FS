import Foundation
import PasuFSIPC
import PasuFSMaintenanceCore

public protocol MaintenanceControlling: Sendable {
  func status() async throws -> UninstallState?
  func prepare(authorization: Data, removeData: Bool) async throws -> UninstallTicket
  func commit(ticket: UninstallTicket, action: UninstallCommitAction) async throws
  func invalidate() async
}

@MainActor
public protocol UninstallAuthorizing {
  func prepare(using client: any MaintenanceControlling, removeData: Bool) async throws
    -> UninstallTicket
}

public struct SystemUninstallAuthorizer: UninstallAuthorizing {
  public init() {}
  public func prepare(using client: any MaintenanceControlling, removeData: Bool) async throws
    -> UninstallTicket
  {
    try await OneShotAdministrativeAuthorizer().withExternalAuthorization(.uninstall) { data in
      try await client.prepare(authorization: data, removeData: removeData)
    }
  }
}

public actor MaintenanceClient: MaintenanceControlling {
  private let bundleURL: URL
  private var connection: NSXPCConnection?
  private var authenticated = false

  public init(hostBundleURL: URL = Bundle.main.bundleURL) { bundleURL = hostBundleURL }

  public func status() async throws -> UninstallState? {
    let proxy = try makeProxy()
    let nonce = Data((0..<32).map { _ in UInt8.random(in: .min ... .max) })
    do {
      let data = try await receive { reply in proxy.status(nonce, withReply: reply) }
      let status = try MaintenanceContract.decode(MaintenanceStatus.self, from: data)
      guard status.nonce == nonce, status.version == MaintenanceContract.protocolVersion else {
        throw MaintenanceError("The maintenance service handshake did not match this app.")
      }
      authenticated = true
      return status.state
    } catch {
      invalidate()
      throw error
    }
  }

  public func prepare(authorization: Data, removeData: Bool) async throws -> UninstallTicket {
    // Verify a signed response before sending the transferable authorization reference.
    if !authenticated { _ = try await status() }
    let proxy = try makeProxy()
    let request = try MaintenanceContract.encode(
      UninstallPreparation(authorization: authorization, removeData: removeData))
    // prepare owns the native authentication dialog; allow time for the user's response.
    let data = try await receive(timeout: 600) { reply in proxy.prepare(request, withReply: reply) }
    return try MaintenanceContract.decode(UninstallTicket.self, from: data)
  }

  public func commit(ticket: UninstallTicket, action: UninstallCommitAction) async throws {
    guard authenticated else {
      throw MaintenanceError("The uninstall connection was lost. Please try again.")
    }
    let proxy = try makeProxy()
    let request = try MaintenanceContract.encode(
      UninstallCommit(ticket: ticket.identifier, action: action))
    let data = try await receive { reply in proxy.commit(request, withReply: reply) }
    let acknowledgement = try MaintenanceContract.decode(
      MaintenanceAcknowledgement.self, from: data)
    guard acknowledgement.accepted else {
      throw MaintenanceError("The uninstall request was not accepted.")
    }
  }

  public func invalidate() {
    connection?.invalidate()
    connection = nil
    authenticated = false
  }

  private func makeProxy() throws -> PasuFSMaintenanceXPCProtocol {
    if connection == nil {
      let helper = bundleURL.appendingPathComponent(MaintenanceContract.embeddedHelperPath)
      let requirement = try CodeSigningRequirementResolver.designatedRequirement(forCodeAt: helper)
      let created = NSXPCConnection(
        machServiceName: MaintenanceContract.service, options: .privileged)
      created.remoteObjectInterface = NSXPCInterface(with: PasuFSMaintenanceXPCProtocol.self)
      created.setCodeSigningRequirement(requirement)
      created.invalidationHandler = { [weak self] in
        guard let self else { return }
        Task { await self.invalidate() }
      }
      created.interruptionHandler = created.invalidationHandler
      created.activate()
      connection = created
    }
    guard
      let proxy = connection?.remoteObjectProxyWithErrorHandler({ _ in })
        as? PasuFSMaintenanceXPCProtocol
    else {
      throw MaintenanceError(
        "The maintenance service is unavailable. Reinstall the Pasu FS package.")
    }
    return proxy
  }

  private func receive(
    timeout: TimeInterval = 15,
    _ invocation: (@escaping @Sendable (Data?, NSError?) -> Void) -> Void
  ) async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
      let gate = XPCReplyGate(continuation)
      DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
        gate.resume(
          throwing: MaintenanceError(
            "The maintenance service did not reply. Check its background-item permission or reinstall the package."
          ))
      }
      invocation { data, error in
        if let error {
          gate.resume(throwing: error)
        } else if let data {
          gate.resume(returning: data)
        } else {
          gate.resume(throwing: MaintenanceError("Invalid maintenance reply."))
        }
      }
    }
  }
}
