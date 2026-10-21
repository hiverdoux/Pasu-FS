import Foundation
import PasuFSConfiguration
import PasuFSIPC

public enum ExtensionControlClientError: Error, CustomStringConvertible, Sendable {
  case interfaceUnavailable
  case invalidReply
  case handshakeMismatch
  case configurationProtocolMismatch(expected: Int, actual: Int)
  case requestTimedOut
  case connectionInterrupted
  case policyAuditLogUnsupported

  public var description: String {
    switch self {
    case .interfaceUnavailable:
      "The Endpoint Security extension XPC interface is unavailable."
    case .invalidReply:
      "The Endpoint Security extension returned an invalid reply."
    case .handshakeMismatch:
      "The authenticated XPC handshake returned the wrong nonce."
    case .configurationProtocolMismatch(let expected, let actual):
      "The host requires configuration protocol \(expected), but the extension reported \(actual)."
    case .requestTimedOut:
      "The Endpoint Security extension did not reply before the timeout."
    case .connectionInterrupted:
      "The connection to the Endpoint Security extension was interrupted before it replied."
    case .policyAuditLogUnsupported:
      "The running protection extension does not support policy logs. Update the extension to view this tab."
    }
  }
}

public protocol ExtensionRuntimeControlling: Sendable {
  /// Stores a policy set. `authorization` is the external form of a fresh administrator
  /// authorization session; the extension requires one for a change that reduces
  /// protection and shows the macOS password dialog while it verifies it.
  /// `savedPolicyIdentifier` names the policy the user saved, whose retired folder paths the
  /// extension releases once the set is stored.
  func applyPolicySet(
    _ document: PolicySetDocument, authorization: Data?, savedPolicyIdentifier: UUID?
  ) async throws -> PolicyApplyReceipt
  func queryStatus() async throws -> ExtensionStatusSnapshot
  func queryPolicySet() async throws -> PolicySetDocument
  func readAuditLog(maximumLineCount: Int) async throws -> AuditLogBatch
  func readPolicyAuditLog(
    setIdentifier: UUID, policyIdentifier: UUID, maximumLineCount: Int
  ) async throws -> AuditLogBatch
  func invalidate() async
}

extension ExtensionRuntimeControlling {
  public func readPolicyAuditLog(
    setIdentifier: UUID, policyIdentifier: UUID, maximumLineCount: Int
  ) async throws -> AuditLogBatch {
    throw ExtensionControlClientError.policyAuditLogUnsupported
  }
}

public actor ExtensionControlClient: ExtensionRuntimeControlling {
  /// How long a save that carries an administrator authorization may wait for the dialog.
  public static let authorizationTimeout: TimeInterval = 600

  private let hostBundleURL: URL
  private let requestTimeout: TimeInterval
  private var connection: NSXPCConnection?
  private var isAuthenticated = false
  private var supportsPolicyAuditLog = false
  /// Requests waiting for a reply; a lost connection fails them at once instead of leaving
  /// them to their timeout.
  private var pendingReplies: [ObjectIdentifier: XPCReplyGate] = [:]

  public init(
    hostBundleURL: URL = Bundle.main.bundleURL,
    requestTimeout: TimeInterval = 5
  ) {
    self.hostBundleURL = hostBundleURL.standardizedFileURL
    self.requestTimeout = requestTimeout
  }

  public func applyPolicySet(
    _ document: PolicySetDocument, authorization: Data? = nil, savedPolicyIdentifier: UUID? = nil
  ) async throws -> PolicyApplyReceipt {
    let data = try XPCJSONCodec.encode(
      PolicyApplyRequest(
        policySetData: try PolicySetDocumentCodec.encode(document),
        authorization: authorization,
        savedPolicyIdentifier: savedPolicyIdentifier
      )
    )
    // With an authorization, the extension waits for the user's answer to the password dialog.
    let timeout = authorization == nil ? requestTimeout : Self.authorizationTimeout
    return try await request(PolicyApplyReceipt.self, timeout: timeout) { proxy, reply in
      proxy.applyPolicy(data, withReply: reply)
    }
  }

  public func queryStatus() async throws -> ExtensionStatusSnapshot {
    try await request(ExtensionStatusSnapshot.self) { proxy, reply in
      proxy.queryStatus(withReply: reply)
    }
  }

  public func queryPolicySet() async throws -> PolicySetDocument {
    let proxy = try await authenticatedProxy()
    let data = try await requestData { reply in
      proxy.queryPolicy(withReply: reply)
    }
    return try PolicySetDocumentCodec.decode(data)
  }

  public func readAuditLog(maximumLineCount: Int = 500) async throws -> AuditLogBatch {
    try await request(AuditLogBatch.self) { proxy, reply in
      proxy.readAuditLog(NSNumber(value: maximumLineCount), withReply: reply)
    }
  }

  public func invalidate() {
    connection?.invalidate()
    connection = nil
    isAuthenticated = false
    supportsPolicyAuditLog = false
    let interrupted = pendingReplies.values
    pendingReplies = [:]
    for gate in interrupted {
      gate.resume(throwing: ExtensionControlClientError.connectionInterrupted)
    }
  }

  public func readPolicyAuditLog(
    setIdentifier: UUID, policyIdentifier: UUID, maximumLineCount: Int = 500
  ) async throws -> AuditLogBatch {
    let proxy = try await authenticatedProxy()
    guard supportsPolicyAuditLog else {
      throw ExtensionControlClientError.policyAuditLogUnsupported
    }
    let data = try XPCJSONCodec.encode(
      PolicyAuditLogRequest(
        key: PolicyAuditLogKey(setIdentifier: setIdentifier, policyIdentifier: policyIdentifier),
        maximumLineCount: maximumLineCount
      )
    )
    do {
      let response = try await requestData { reply in
        proxy.readPolicyAuditLog(data, withReply: reply)
      }
      return try XPCJSONCodec.decode(AuditLogBatch.self, from: response)
    } catch {
      invalidate()
      throw error
    }
  }

  private func request<T: Decodable>(
    _ type: T.Type,
    timeout: TimeInterval? = nil,
    invocation: (PasuFSExtensionXPCProtocol, @escaping (Data?, NSError?) -> Void) -> Void
  ) async throws -> T {
    let proxy = try await authenticatedProxy()
    do {
      let data = try await requestData(timeout: timeout) { reply in
        invocation(proxy, reply)
      }
      return try XPCJSONCodec.decode(type, from: data)
    } catch {
      invalidate()
      throw error
    }
  }

  private func authenticatedProxy() async throws -> PasuFSExtensionXPCProtocol {
    let proxy = try makeProxy()
    guard !isAuthenticated else { return proxy }

    var generator = SystemRandomNumberGenerator()
    let nonce = Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    let handshakeRequest = try XPCJSONCodec.encode(
      XPCHandshakeRequest(
        nonce: nonce
      )
    )
    let data = try await requestData { reply in
      proxy.handshake(handshakeRequest, withReply: reply)
    }
    let response = try XPCJSONCodec.decode(XPCHandshakeResponse.self, from: data)
    let expectedProtocol = XPCHandshakeResponse.currentConfigurationProtocolVersion
    guard response.configurationProtocolVersion == expectedProtocol else {
      throw ExtensionControlClientError.configurationProtocolMismatch(
        expected: expectedProtocol,
        actual: response.configurationProtocolVersion
      )
    }
    guard response.nonce == nonce else {
      throw ExtensionControlClientError.handshakeMismatch
    }
    isAuthenticated = true
    supportsPolicyAuditLog = response.supportsPolicyAuditLog
    return proxy
  }

  private func makeProxy() throws -> PasuFSExtensionXPCProtocol {
    if connection == nil {
      let extensionURL = CodeSigningRequirementResolver.embeddedExtensionURL(
        in: hostBundleURL
      )
      let requirement = try CodeSigningRequirementResolver.designatedRequirement(
        forCodeAt: extensionURL
      )
      let newConnection = NSXPCConnection(
        machServiceName: PasuFSXPC.machServiceName,
        options: .privileged
      )
      newConnection.remoteObjectInterface = NSXPCInterface(
        with: PasuFSExtensionXPCProtocol.self
      )
      newConnection.setCodeSigningRequirement(requirement)
      newConnection.invalidationHandler = { [weak self] in
        guard let client = self else { return }
        Task { await client.invalidate() }
      }
      newConnection.interruptionHandler = { [weak self] in
        guard let client = self else { return }
        Task { await client.invalidate() }
      }
      newConnection.activate()
      connection = newConnection
    }
    guard
      let proxy = connection?.remoteObjectProxyWithErrorHandler({ _ in })
        as? PasuFSExtensionXPCProtocol
    else {
      throw ExtensionControlClientError.interfaceUnavailable
    }
    return proxy
  }

  private func requestData(
    timeout: TimeInterval? = nil,
    invocation: (@escaping (Data?, NSError?) -> Void) -> Void
  ) async throws -> Data {
    let gate = XPCReplyGate()
    pendingReplies[ObjectIdentifier(gate)] = gate
    defer { pendingReplies.removeValue(forKey: ObjectIdentifier(gate)) }
    return try await withCheckedThrowingContinuation { continuation in
      gate.start(continuation)
      DispatchQueue.global().asyncAfter(deadline: .now() + (timeout ?? requestTimeout)) {
        gate.resume(throwing: ExtensionControlClientError.requestTimedOut)
      }
      invocation { data, error in
        if let error {
          gate.resume(throwing: error)
        } else if let data {
          gate.resume(returning: data)
        } else {
          gate.resume(throwing: ExtensionControlClientError.invalidReply)
        }
      }
    }
  }
}

final class XPCReplyGate: @unchecked Sendable {
  private let lock = NSLock()
  private var continuation: CheckedContinuation<Data, any Error>?

  init() {}

  convenience init(_ continuation: CheckedContinuation<Data, any Error>) {
    self.init()
    start(continuation)
  }

  /// The gate forwards the first result it receives after this call and drops the others.
  func start(_ continuation: CheckedContinuation<Data, any Error>) {
    lock.lock()
    defer { lock.unlock() }
    self.continuation = continuation
  }

  func resume(returning value: sending Data) {
    takeContinuation()?.resume(returning: value)
  }

  func resume(throwing error: any Error) {
    takeContinuation()?.resume(throwing: error)
  }

  private func takeContinuation() -> CheckedContinuation<Data, any Error>? {
    lock.lock()
    defer { lock.unlock() }
    let continuation = continuation
    self.continuation = nil
    return continuation
  }
}
