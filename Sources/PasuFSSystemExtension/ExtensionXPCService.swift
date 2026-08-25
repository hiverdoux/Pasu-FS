import Foundation
import PasuFSIPC

final class ExtensionXPCService: NSObject, NSXPCListenerDelegate, @unchecked Sendable {
  private let listener: NSXPCListener
  private let handler: ExtensionXPCHandler
  private let connectionLock = NSLock()
  private var connections: [ObjectIdentifier: NSXPCConnection] = [:]

  init(runtime: ExtensionRuntime, expectedHostRequirement: String) {
    self.listener = NSXPCListener(machServiceName: PasuFSXPC.machServiceName)
    self.handler = ExtensionXPCHandler(runtime: runtime)
    super.init()
    listener.delegate = self
    listener.setConnectionCodeSigningRequirement(expectedHostRequirement)
  }

  func activate() {
    listener.activate()
  }

  func invalidate() {
    listener.invalidate()
    connectionLock.lock()
    let currentConnections = Array(connections.values)
    connections.removeAll()
    connectionLock.unlock()
    for connection in currentConnections {
      connection.invalidate()
    }
  }

  func listener(
    _ listener: NSXPCListener,
    shouldAcceptNewConnection newConnection: NSXPCConnection
  ) -> Bool {
    newConnection.exportedInterface = NSXPCInterface(with: PasuFSExtensionXPCProtocol.self)
    newConnection.exportedObject = handler
    let identifier = ObjectIdentifier(newConnection)
    newConnection.invalidationHandler = { [weak self, weak newConnection] in
      guard let self, let newConnection else { return }
      self.connectionLock.lock()
      self.connections.removeValue(forKey: ObjectIdentifier(newConnection))
      self.connectionLock.unlock()
    }
    connectionLock.lock()
    connections[identifier] = newConnection
    connectionLock.unlock()
    newConnection.activate()
    return true
  }
}

private final class ExtensionXPCHandler: NSObject, PasuFSExtensionXPCProtocol, @unchecked Sendable {
  private unowned let runtime: ExtensionRuntime

  init(runtime: ExtensionRuntime) {
    self.runtime = runtime
  }

  func handshake(_ requestData: Data, withReply reply: @escaping (Data?, NSError?) -> Void) {
    runtime.handshake(requestData, reply: reply)
  }

  func applyPolicy(_ policyData: Data, withReply reply: @escaping (Data?, NSError?) -> Void) {
    runtime.applyPolicy(policyData, reply: reply)
  }

  func queryPolicy(withReply reply: @escaping (Data?, NSError?) -> Void) {
    runtime.queryPolicy(reply: reply)
  }

  func queryStatus(withReply reply: @escaping (Data?, NSError?) -> Void) {
    runtime.queryStatus(reply: reply)
  }

  func readAuditLog(
    _ maximumLineCount: NSNumber,
    withReply reply: @escaping (Data?, NSError?) -> Void
  ) {
    runtime.readAuditLog(maximumLineCount.intValue, reply: reply)
  }
}
