import Foundation
import PasuFSPolicy

public enum ExtensionRuntimePhase: String, Codable, Sendable {
  case starting
  case waitingForFullDiskAccess
  case idle
  case enforcing
  case monitoring
  case degraded
  case stopped
}

/// The retired folder paths of one stored policy.
public struct PolicyRetiredFolderPaths: Codable, Equatable, Sendable {
  public var policyIdentifier: UUID
  /// Oldest first.
  public var paths: [String]

  public init(policyIdentifier: UUID, paths: [String]) {
    self.policyIdentifier = policyIdentifier
    self.paths = paths
  }
}

/// Which requests Endpoint Security delivers to the extension. With target path muting
/// inverted, the kernel delivers only requests whose target path matches a registered prefix
/// or literal path; mounts, forks and exits name no target path and are always delivered.
public struct TargetPathMutingStatus: Codable, Equatable, Sendable {
  /// Whether target path muting is inverted, so that registered paths select the requests.
  public var isInverted: Bool
  /// Whether every request is delivered: muting is not inverted, or a path could not be
  /// registered and `/` is registered for every request instead.
  public var deliversAllRequests: Bool
  /// Registered prefixes and literal paths, counted by path.
  public var prefixCount: Int
  public var literalCount: Int
  /// The latest error from inverting muting or from registering or removing a path.
  public var lastError: String?
  public var lastErrorAt: Date?

  public init(
    isInverted: Bool, deliversAllRequests: Bool, prefixCount: Int, literalCount: Int,
    lastError: String? = nil, lastErrorAt: Date? = nil
  ) {
    self.isInverted = isInverted
    self.deliversAllRequests = deliversAllRequests
    self.prefixCount = prefixCount
    self.literalCount = literalCount
    self.lastError = lastError
    self.lastErrorAt = lastErrorAt
  }
}

/// What Endpoint Security does with an authorization request the extension doesn't answer: one
/// whose deadline passes, or one it drops because the extension's queue is full.
public struct DeadlineMissModeStatus: Codable, Equatable, Sendable {
  public enum Setting: String, Codable, Sendable {
    /// Set and confirmed (macOS 27 and later): macOS denies such a request and keeps the extension
    /// running.
    case failClosed
    /// The system has no setting (before macOS 27), so the default applies: macOS stops the
    /// extension when a deadline passes and allows a dropped request.
    case killUnavailable
    /// Setting or confirming the fail-closed mode failed, and the extension asked for the default
    /// again. `error` says what failed.
    case killAfterFailure
  }

  public var setting: Setting
  public var error: String?
  /// The longest macOS waits for the extension's answer to each authorization request, when the
  /// extension shortened macOS's default deadline and confirmed the value for every event it
  /// answers. Only with `failClosed`; absent while the default deadlines apply, and from
  /// extensions that predate the setting.
  public var maximumDeadlineMilliseconds: UInt32?
  /// What failed while shortening the deadline. The default deadlines then apply, and the
  /// fail-closed mode stays.
  public var maximumDeadlineError: String?

  public init(
    setting: Setting, error: String? = nil, maximumDeadlineMilliseconds: UInt32? = nil,
    maximumDeadlineError: String? = nil
  ) {
    self.setting = setting
    self.error = error
    self.maximumDeadlineMilliseconds = maximumDeadlineMilliseconds
    self.maximumDeadlineError = maximumDeadlineError
  }

  /// Whether macOS denies the requests the extension doesn't answer instead of allowing them.
  public var deniesUnansweredRequests: Bool { setting == .failClosed }
}

/// When the extension connected to Endpoint Security during this run. With
/// `NSEndpointSecurityEarlyBoot`, macOS holds mounts and the start of programs other than Apple
/// platform binaries from early in startup until the extension's first subscription, or until
/// a timeout of its own, so these times tell how long that hold could last.
public struct EndpointConnectionStatus: Codable, Equatable, Sendable {
  /// Whether the running extension's Info.plist sets `NSEndpointSecurityEarlyBoot`.
  public var requestsEarlyBoot: Bool
  /// When the current client was created, and how many seconds after the Mac started.
  public var clientCreatedAt: Date?
  public var clientCreatedSecondsAfterStartup: Double?
  /// When the current client first subscribed, how many seconds after the Mac started, and how
  /// many event types that subscription named.
  public var firstSubscriptionAt: Date?
  public var firstSubscriptionSecondsAfterStartup: Double?
  public var firstSubscriptionEventCount: Int?
  /// Whether the first subscription included the authorization events of the policies in
  /// effect, rather than the process events alone.
  public var firstSubscriptionIncludesPolicyEvents: Bool?
  /// The latest failure to create a client or to subscribe during this run, and when it
  /// happened. Kept after a later attempt succeeds.
  public var lastFailure: String?
  public var lastFailureAt: Date?

  public init(
    requestsEarlyBoot: Bool, clientCreatedAt: Date? = nil,
    clientCreatedSecondsAfterStartup: Double? = nil, firstSubscriptionAt: Date? = nil,
    firstSubscriptionSecondsAfterStartup: Double? = nil, firstSubscriptionEventCount: Int? = nil,
    firstSubscriptionIncludesPolicyEvents: Bool? = nil, lastFailure: String? = nil,
    lastFailureAt: Date? = nil
  ) {
    self.requestsEarlyBoot = requestsEarlyBoot
    self.clientCreatedAt = clientCreatedAt
    self.clientCreatedSecondsAfterStartup = clientCreatedSecondsAfterStartup
    self.firstSubscriptionAt = firstSubscriptionAt
    self.firstSubscriptionSecondsAfterStartup = firstSubscriptionSecondsAfterStartup
    self.firstSubscriptionEventCount = firstSubscriptionEventCount
    self.firstSubscriptionIncludesPolicyEvents = firstSubscriptionIncludesPolicyEvents
    self.lastFailure = lastFailure
    self.lastFailureAt = lastFailureAt
  }
}

public struct ExtensionStatusSnapshot: Codable, Equatable, Sendable {
  /// Schema 7 adds when the extension connected to Endpoint Security and, in the execution
  /// history status, when tracking began and how many histories began with a launchd start
  /// that the kernel reported. Schema 6 added the version and build of the extension that
  /// reports the status. Schema 5 added the confirmed maximum deadline and the error from
  /// shortening it to the missed-deadline setting. Schema 4 added retired folder paths, request
  /// delivery, the missed-deadline setting and the unchecked-request count. All of them are
  /// optional, and a reader accepts earlier schemas without them.
  public static let currentSchemaVersion = 7

  public var schemaVersion: Int
  public var runtimeInstanceIdentifier: UUID
  public var phase: ExtensionRuntimePhase
  public var activePolicySetIdentifier: UUID?
  public var activePolicyRevision: UInt64?
  public var activePolicyDigest: String?
  public var systemCompatibilityCatalogDigest: String?
  /// The compatibility profiles turned on in the policies in effect that are active here.
  public var activeSystemCompatibilityProfileCount: Int?
  public var systemCompatibilityWarning: String?
  public var protectionPolicyCount: Int
  public var auditPolicyCount: Int
  public var policyWarning: String?
  public var detail: String?
  public var timestamp: Date
  public var coveredAuthorizationEvents: [String]
  public var processLineageStatus: ProcessLineageStatus?
  public var droppedAuditEventCount: UInt64
  public var auditDelivery: AuditDeliveryMetrics?
  public var authorization: AuthorizationMetrics?
  /// Absent from extensions that predate the count of unchecked requests.
  public var uncheckedRequests: UncheckedRequestMetrics?
  public var executionOriginStatus: ExecutionOriginStatus?
  public var policyStorageState: PolicyStorageState?
  public var executionOriginCapabilities: ExecutionOriginCapabilities?
  /// The stored policies that keep retired folder paths, each with its paths. Empty when none
  /// does; absent from extensions that predate retired folder paths.
  public var retiredFolderPaths: [PolicyRetiredFolderPaths]?
  /// Absent from extensions that predate target path selection, which receive every request.
  public var targetPathMuting: TargetPathMutingStatus?
  /// Absent while there is no Endpoint Security client, and from extensions that predate the
  /// setting, which run in the default kill mode.
  public var deadlineMissMode: DeadlineMissModeStatus?
  /// The `CFBundleShortVersionString` and `CFBundleVersion` of the running extension. While an
  /// update waits for a restart, macOS reports no version as enabled, and only these tell which
  /// version runs. Absent from extensions that predate schema 6.
  public var extensionVersion: String?
  public var extensionBuildVersion: String?
  /// Absent from extensions that predate schema 7.
  public var endpointConnection: EndpointConnectionStatus?

  public init(
    schemaVersion: Int = Self.currentSchemaVersion,
    runtimeInstanceIdentifier: UUID,
    phase: ExtensionRuntimePhase,
    activePolicySetIdentifier: UUID? = nil,
    activePolicyRevision: UInt64? = nil,
    activePolicyDigest: String? = nil,
    systemCompatibilityCatalogDigest: String? = nil,
    activeSystemCompatibilityProfileCount: Int? = nil,
    systemCompatibilityWarning: String? = nil,
    protectionPolicyCount: Int = 0,
    auditPolicyCount: Int = 0,
    policyWarning: String? = nil,
    detail: String? = nil,
    timestamp: Date = Date(),
    coveredAuthorizationEvents: [String] = AuthorizationEventCatalog.supportedEventNames,
    processLineageStatus: ProcessLineageStatus? = nil,
    droppedAuditEventCount: UInt64 = 0,
    auditDelivery: AuditDeliveryMetrics? = nil, authorization: AuthorizationMetrics? = nil,
    uncheckedRequests: UncheckedRequestMetrics? = nil,
    executionOriginStatus: ExecutionOriginStatus? = nil,
    policyStorageState: PolicyStorageState? = nil,
    executionOriginCapabilities: ExecutionOriginCapabilities? = nil,
    retiredFolderPaths: [PolicyRetiredFolderPaths]? = nil,
    targetPathMuting: TargetPathMutingStatus? = nil,
    deadlineMissMode: DeadlineMissModeStatus? = nil,
    extensionVersion: String? = nil,
    extensionBuildVersion: String? = nil,
    endpointConnection: EndpointConnectionStatus? = nil
  ) {
    self.schemaVersion = schemaVersion
    self.runtimeInstanceIdentifier = runtimeInstanceIdentifier
    self.phase = phase
    self.activePolicySetIdentifier = activePolicySetIdentifier
    self.activePolicyRevision = activePolicyRevision
    self.activePolicyDigest = activePolicyDigest
    self.systemCompatibilityCatalogDigest = systemCompatibilityCatalogDigest
    self.activeSystemCompatibilityProfileCount = activeSystemCompatibilityProfileCount
    self.systemCompatibilityWarning = systemCompatibilityWarning
    self.protectionPolicyCount = protectionPolicyCount
    self.auditPolicyCount = auditPolicyCount
    self.policyWarning = policyWarning
    self.detail = detail
    self.timestamp = timestamp
    self.coveredAuthorizationEvents = coveredAuthorizationEvents
    self.processLineageStatus = processLineageStatus
    self.droppedAuditEventCount = droppedAuditEventCount
    self.auditDelivery = auditDelivery
    self.authorization = authorization
    self.uncheckedRequests = uncheckedRequests
    self.executionOriginStatus = executionOriginStatus
    self.policyStorageState = policyStorageState
    self.executionOriginCapabilities = executionOriginCapabilities
    self.retiredFolderPaths = retiredFolderPaths
    self.targetPathMuting = targetPathMuting
    self.deadlineMissMode = deadlineMissMode
    self.extensionVersion = extensionVersion
    self.extensionBuildVersion = extensionBuildVersion
    self.endpointConnection = endpointConnection
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

public enum PolicyApplyRequestError: Error, Equatable, CustomStringConvertible, Sendable {
  case requestTooLarge(Int)
  case unversionedRequest(expected: Int)
  case protocolMismatch(expected: Int, received: Int)
  case malformedRequest(String)

  public var description: String {
    switch self {
    case .requestTooLarge(let size):
      "Policy request exceeds the \(PolicyApplyRequest.maximumEncodedSize) byte limit: \(size) bytes."
    case .unversionedRequest(let expected):
      "The policy request does not state a configuration protocol version; this extension requires protocol \(expected). Update the Pasu FS app."
    case .protocolMismatch(let expected, let received):
      "Configuration protocol mismatch: expected \(expected), received \(received). Update the Pasu FS app."
    case .malformedRequest(let detail):
      "The policy request is malformed: \(detail)"
    }
  }
}

/// One policy-set save sent to the extension.
///
/// `authorization` is the external form of a fresh administrator authorization session
/// created by the app. The extension requires it only for a change that weakens
/// protection (see `PolicyWeakeningAnalyzer`) and verifies it as root; a change that only
/// strengthens protection is sent without one.
///
/// `savedPolicyIdentifier` names the policy whose Save the user chose. Once the set is stored,
/// the extension releases that policy's retired folder paths; a set sent for another reason,
/// such as deleting a policy, leaves every retired path in place.
public struct PolicyApplyRequest: Codable, Equatable, Sendable {
  public static let currentConfigurationProtocolVersion =
    XPCHandshakeRequest.currentConfigurationProtocolVersion
  /// The encoded policy set is at most 1 MiB; base64 and the authorization add less than
  /// half of that.
  public static let maximumEncodedSize = 2 * PolicySetDocumentCodec.maximumDocumentSize

  public var configurationProtocolVersion: Int
  public var policySetData: Data
  public var authorization: Data?
  public var savedPolicyIdentifier: UUID?

  public init(
    policySetData: Data,
    authorization: Data? = nil,
    savedPolicyIdentifier: UUID? = nil,
    configurationProtocolVersion: Int = Self.currentConfigurationProtocolVersion
  ) {
    self.configurationProtocolVersion = configurationProtocolVersion
    self.policySetData = policySetData
    self.authorization = authorization
    self.savedPolicyIdentifier = savedPolicyIdentifier
  }

  /// Decodes a request, naming the reason when an app that predates the request format
  /// or speaks another protocol version sent a bare policy set.
  public static func decode(_ data: Data) throws -> PolicyApplyRequest {
    guard data.count <= maximumEncodedSize else {
      throw PolicyApplyRequestError.requestTooLarge(data.count)
    }
    let object: [String: Any]
    do {
      guard let decoded = try JSONSerialization.jsonObject(with: data) as? [String: Any] else {
        throw PolicyApplyRequestError.malformedRequest("the top level is not an object.")
      }
      object = decoded
    } catch let error as PolicyApplyRequestError {
      throw error
    } catch {
      throw PolicyApplyRequestError.malformedRequest(String(describing: error))
    }
    guard let version = object["configurationProtocolVersion"] as? Int else {
      throw PolicyApplyRequestError.unversionedRequest(
        expected: currentConfigurationProtocolVersion)
    }
    guard version == currentConfigurationProtocolVersion else {
      throw PolicyApplyRequestError.protocolMismatch(
        expected: currentConfigurationProtocolVersion, received: version)
    }
    do {
      return try JSONDecoder().decode(PolicyApplyRequest.self, from: data)
    } catch {
      throw PolicyApplyRequestError.malformedRequest(String(describing: error))
    }
  }
}

public struct XPCHandshakeRequest: Codable, Equatable, Sendable {
  /// The app and extension accept only their own protocol version. Protocol 8 carries policy
  /// schema 5 and the policy whose Save released its retired folder paths.
  public static let currentConfigurationProtocolVersion = 8

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
  public var systemCompatibilityCatalogDigest: String
  public var supportsPolicyAuditLog: Bool
  public var timestamp: Date

  public init(
    nonce: Data,
    runtimeInstanceIdentifier: UUID,
    configurationProtocolVersion: Int = Self.currentConfigurationProtocolVersion,
    systemCompatibilityCatalogDigest: String = "",
    supportsPolicyAuditLog: Bool = false,
    timestamp: Date = Date()
  ) {
    self.nonce = nonce
    self.runtimeInstanceIdentifier = runtimeInstanceIdentifier
    self.configurationProtocolVersion = configurationProtocolVersion
    self.systemCompatibilityCatalogDigest = systemCompatibilityCatalogDigest
    self.supportsPolicyAuditLog = supportsPolicyAuditLog
    self.timestamp = timestamp
  }

  private enum CodingKeys: String, CodingKey {
    case nonce
    case runtimeInstanceIdentifier
    case configurationProtocolVersion
    case systemCompatibilityCatalogDigest
    case supportsPolicyAuditLog
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
    systemCompatibilityCatalogDigest =
      try container.decodeIfPresent(
        String.self,
        forKey: .systemCompatibilityCatalogDigest
      ) ?? ""
    supportsPolicyAuditLog =
      try container.decodeIfPresent(Bool.self, forKey: .supportsPolicyAuditLog) ?? false
    timestamp = try container.decode(Date.self, forKey: .timestamp)
  }

  public func encode(to encoder: any Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(nonce, forKey: .nonce)
    try container.encode(runtimeInstanceIdentifier, forKey: .runtimeInstanceIdentifier)
    try container.encode(configurationProtocolVersion, forKey: .configurationProtocolVersion)
    try container.encode(
      systemCompatibilityCatalogDigest,
      forKey: .systemCompatibilityCatalogDigest
    )
    try container.encode(supportsPolicyAuditLog, forKey: .supportsPolicyAuditLog)
    try container.encode(timestamp, forKey: .timestamp)
  }
}
