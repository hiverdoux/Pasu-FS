import Foundation
import PasuFSConfiguration
import PasuFSIPC

public enum ExtensionControlClientError: Error, CustomStringConvertible, Sendable {
  case interfaceUnavailable
  case invalidReply
  case handshakeMismatch
  case configurationProtocolMismatch(expected: Int, actual: Int)
  case requestTimedOut
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
    case .policyAuditLogUnsupported:
      "The running protection extension does not support policy logs. Update the extension to view this tab."
    }
  }
}

public protocol ExtensionRuntimeControlling: Sendable {
  func applyPolicySet(_ document: PolicySetDocument) async throws -> PolicyApplyReceipt
  func queryStatus() async throws -> ExtensionStatusSnapshot
  func queryPolicySet() async throws -> PolicySetDocument
  func applySystemCompatibilitySettings(
    _ document: SystemCompatibilitySettingsDocument
  ) async throws -> SystemCompatibilitySettingsApplyReceipt
  func querySystemCompatibilityState() async throws -> SystemCompatibilityStateSnapshot
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
  private let hostBundleURL: URL
  private let requestTimeout: TimeInterval
  private let systemCompatibilityCatalogDigest: String
  private var connection: NSXPCConnection?
  private var isAuthenticated = false
  private var supportsPolicyAuditLog = false

  public init(
    hostBundleURL: URL = Bundle.main.bundleURL,
    requestTimeout: TimeInterval = 5,
    systemCompatibilityCatalog: SystemCompatibilityCatalog =
      BuiltInSystemCompatibilityCatalog.catalog
  ) {
    self.hostBundleURL = hostBundleURL.standardizedFileURL
    self.requestTimeout = requestTimeout
    self.systemCompatibilityCatalogDigest =
      (try? systemCompatibilityCatalog.catalogDigest()) ?? ""
  }

  public func applyPolicySet(_ document: PolicySetDocument) async throws -> PolicyApplyReceipt {
    let data = try PolicySetDocumentCodec.encode(document)
    return try await request(PolicyApplyReceipt.self) { proxy, reply in
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

  public func applySystemCompatibilitySettings(
    _ document: SystemCompatibilitySettingsDocument
  ) async throws -> SystemCompatibilitySettingsApplyReceipt {
    let settingsData = try SystemCompatibilitySettingsCodec.encode(document)
    let data = try XPCJSONCodec.encode(
      SystemCompatibilitySettingsApplyRequest(
        catalogDigest: systemCompatibilityCatalogDigest,
        settingsData: settingsData
      )
    )
    return try await request(SystemCompatibilitySettingsApplyReceipt.self) { proxy, reply in
      proxy.applySystemCompatibilitySettings(data, withReply: reply)
    }
  }

  public func querySystemCompatibilityState() async throws
    -> SystemCompatibilityStateSnapshot
  {
    try await request(SystemCompatibilityStateSnapshot.self) { proxy, reply in
      proxy.querySystemCompatibilityState(withReply: reply)
    }
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
    invocation: (PasuFSExtensionXPCProtocol, @escaping (Data?, NSError?) -> Void) -> Void
  ) async throws -> T {
    let proxy = try await authenticatedProxy()
    do {
      let data = try await requestData { reply in
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
    invocation: (@escaping (Data?, NSError?) -> Void) -> Void
  ) async throws -> Data {
    try await withCheckedThrowingContinuation { continuation in
      let gate = XPCReplyGate(continuation)
      DispatchQueue.global().asyncAfter(deadline: .now() + requestTimeout) {
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

  init(_ continuation: CheckedContinuation<Data, any Error>) {
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
