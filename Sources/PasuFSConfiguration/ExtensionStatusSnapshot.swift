import Foundation

public enum ExtensionRuntimePhase: String, Codable, Sendable {
  case starting
  case waitingForFullDiskAccess
  case idle
  case enforcing
  case monitoring
  case degraded
  case stopped
}

public struct ExtensionStatusSnapshot: Codable, Equatable, Sendable {
  public static let currentSchemaVersion = 2

  public var schemaVersion: Int
  public var runtimeInstanceIdentifier: UUID
  public var phase: ExtensionRuntimePhase
  public var activePolicySetIdentifier: UUID?
  public var activePolicyRevision: UInt64?
  public var activePolicyDigest: String?
  public var protectionPolicyCount: Int
  public var auditPolicyCount: Int
  public var policyWarning: String?
  public var detail: String?
  public var timestamp: Date
  public var coveredAuthorizationEvents: [String]
  public var droppedAuditEventCount: UInt64

  public init(
    schemaVersion: Int = Self.currentSchemaVersion,
    runtimeInstanceIdentifier: UUID,
    phase: ExtensionRuntimePhase,
    activePolicySetIdentifier: UUID? = nil,
    activePolicyRevision: UInt64? = nil,
    activePolicyDigest: String? = nil,
    protectionPolicyCount: Int = 0,
    auditPolicyCount: Int = 0,
    policyWarning: String? = nil,
    detail: String? = nil,
    timestamp: Date = Date(),
    coveredAuthorizationEvents: [String] = ["AUTH_OPEN"],
    droppedAuditEventCount: UInt64 = 0
  ) {
    self.schemaVersion = schemaVersion
    self.runtimeInstanceIdentifier = runtimeInstanceIdentifier
    self.phase = phase
    self.activePolicySetIdentifier = activePolicySetIdentifier
    self.activePolicyRevision = activePolicyRevision
    self.activePolicyDigest = activePolicyDigest
    self.protectionPolicyCount = protectionPolicyCount
    self.auditPolicyCount = auditPolicyCount
    self.policyWarning = policyWarning
    self.detail = detail
    self.timestamp = timestamp
    self.coveredAuthorizationEvents = coveredAuthorizationEvents
    self.droppedAuditEventCount = droppedAuditEventCount
  }
}

public enum PolicyApplyResult: String, Codable, Sendable {
  case accepted
  case unchanged
}

public struct PolicyApplyReceipt: Codable, Equatable, Sendable {
  public var result: PolicyApplyResult
  public var acceptedSetIdentifier: UUID
  public var acceptedRevision: UInt64
  public var acceptedDigest: String
  public var acceptedAt: Date

  public init(
    result: PolicyApplyResult,
    acceptedSetIdentifier: UUID,
    acceptedRevision: UInt64,
    acceptedDigest: String,
    acceptedAt: Date = Date()
  ) {
    self.result = result
    self.acceptedSetIdentifier = acceptedSetIdentifier
    self.acceptedRevision = acceptedRevision
    self.acceptedDigest = acceptedDigest
    self.acceptedAt = acceptedAt
  }
}

public struct XPCHandshakeRequest: Codable, Equatable, Sendable {
  public static let currentConfigurationProtocolVersion = 2

  public var nonce: Data
  public var configurationProtocolVersion: Int

  public init(
    nonce: Data,
    configurationProtocolVersion: Int = Self.currentConfigurationProtocolVersion
  ) {
    self.nonce = nonce
    self.configurationProtocolVersion = configurationProtocolVersion
  }
}

public struct XPCHandshakeResponse: Codable, Equatable, Sendable {
  public static let currentConfigurationProtocolVersion =
    XPCHandshakeRequest.currentConfigurationProtocolVersion

  public var nonce: Data
  public var runtimeInstanceIdentifier: UUID
  public var configurationProtocolVersion: Int
  public var timestamp: Date

  public init(
    nonce: Data,
    runtimeInstanceIdentifier: UUID,
    configurationProtocolVersion: Int = Self.currentConfigurationProtocolVersion,
    timestamp: Date = Date()
  ) {
    self.nonce = nonce
    self.runtimeInstanceIdentifier = runtimeInstanceIdentifier
    self.configurationProtocolVersion = configurationProtocolVersion
    self.timestamp = timestamp
  }

  private enum CodingKeys: String, CodingKey {
    case nonce
    case runtimeInstanceIdentifier
    case configurationProtocolVersion
    case timestamp
  }

  public init(from decoder: any Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    nonce = try container.decode(Data.self, forKey: .nonce)
    runtimeInstanceIdentifier = try container.decode(UUID.self, forKey: .runtimeInstanceIdentifier)
    configurationProtocolVersion =
      try container.decodeIfPresent(
        Int.self,
        forKey: .configurationProtocolVersion
      ) ?? 1
    timestamp = try container.decode(Date.self, forKey: .timestamp)
  }

  public func encode(to encoder: any Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(nonce, forKey: .nonce)
    try container.encode(runtimeInstanceIdentifier, forKey: .runtimeInstanceIdentifier)
    try container.encode(configurationProtocolVersion, forKey: .configurationProtocolVersion)
    try container.encode(timestamp, forKey: .timestamp)
  }
}
