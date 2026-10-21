import Foundation
import PasuFSPolicy

public enum PolicyRuleMatchKind: String, Codable, Equatable, Sendable {
  case direct
  case inherited
  case systemCompatibilityProfile
  case none
  case decodeError
  case truncatedPath
  /// A mount request whose mount point is a policy folder, lies inside it or contains it.
  /// The decision depends on the mount point alone, not on a program list.
  case mountPoint
  /// The request acts on a folder that contains the policy folder, such as renaming, deleting
  /// or copying a parent folder, and touches no path inside the policy folder. A rename of such
  /// a folder is allowed for every program and the policy follows its folder; other requests
  /// are decided by the program lists, whose evidence the record keeps.
  case enclosingFolder
}

public enum PolicyEvaluationDecision: String, Codable, Equatable, Sendable {
  case allow
  case deny
  case wouldAllow
  case wouldDeny
}

public struct PolicyEvaluationRecord: Codable, Equatable, Identifiable, Sendable {
  public var policyIdentifier: UUID
  public var policyName: String
  public var mode: PolicyMode
  public var policyType: PolicyType
  public var match: PolicyRuleMatchKind
  public var ruleIdentifier: String?
  public var systemCompatibilityProfileIdentifier: String?
  public var systemCompatibilityAuthorizationDigest: String?
  public var decision: PolicyEvaluationDecision
  public var detail: String?
  public var executionOrigin: ExecutionOriginDecision?
  /// The retired folder path of this policy that the request touched, when it touched one. The
  /// request was decided as if it were inside the policy's folder; an allowed request is
  /// recorded with this path as a warning that a program still uses the folder's former path.
  public var retiredFolderPath: String?

  public var id: String {
    "\(policyIdentifier.uuidString):\(ruleIdentifier ?? systemCompatibilityProfileIdentifier ?? "none"):"
      + "\(match.rawValue):\(decision.rawValue)"
  }

  public init(
    policyIdentifier: UUID,
    policyName: String,
    mode: PolicyMode,
    policyType: PolicyType,
    match: PolicyRuleMatchKind,
    ruleIdentifier: String? = nil,
    systemCompatibilityProfileIdentifier: String? = nil,
    systemCompatibilityAuthorizationDigest: String? = nil,
    decision: PolicyEvaluationDecision,
    detail: String? = nil,
    executionOrigin: ExecutionOriginDecision? = nil,
    retiredFolderPath: String? = nil
  ) {
    self.policyIdentifier = policyIdentifier
    self.policyName = policyName
    self.mode = mode
    self.policyType = policyType
    self.match = match
    self.ruleIdentifier = ruleIdentifier
    self.systemCompatibilityProfileIdentifier = systemCompatibilityProfileIdentifier
    self.systemCompatibilityAuthorizationDigest = systemCompatibilityAuthorizationDigest
    self.decision = decision
    self.detail = detail
    self.executionOrigin = executionOrigin
    self.retiredFolderPath = retiredFolderPath
  }
}

public struct AuditEventRecord: Codable, Equatable, Identifiable, Sendable {
  /// Schema 9 records tell how the beginning of a complete execution history was established
  /// (`historyEvidence`) and carry each program's current parent and start time. Schema 8
  /// records could name a mount point, an enclosing folder or a retired folder path, combine
  /// repeated requests and report messages macOS dropped. Readers accept every earlier schema,
  /// whose records lack those fields.
  public static let currentSchemaVersion = 9

  public var schemaVersion: Int?
  public var eventIdentifier: UUID?
  public var processLineage: ProcessLineageSnapshot?
  public var timestamp: Date
  public var policySetIdentifier: UUID?
  public var policyRevision: UInt64?
  public var eventSequence: UInt64?
  public var eventType: String
  public var processID: Int32?
  public var executablePath: String?
  public var teamIdentifier: String?
  public var signingIdentifier: String?
  public var isPlatformBinary: Bool?
  public var codeSigningFlags: UInt32?
  public var operatingSystemBuild: String?
  public var targetPath: String?
  /// The second path of a request that names two locations, such as the new name of a rename.
  public var destinationPath: String?
  public var pathWasTruncated: Bool?
  public var requestedFlags: Int32?
  public var policyDecision: String
  public var kernelResponse: String
  public var policyEvaluations: [PolicyEvaluationRecord]?
  public var detail: String?
  /// The number of requests this record stands for, present only when it is more than one. The
  /// other fields describe the first of them; see `combinesAnyTarget`.
  public var requestCount: UInt64?
  /// The time of the last request this record stands for, present with `requestCount`. A record
  /// of messages macOS dropped (`DELIVERY_GAP`) uses it alone, for the last gap it combines.
  public var lastTimestamp: Date?

  public var id: String {
    if let eventIdentifier { return eventIdentifier.uuidString }
    return
      "\(runtimeIDComponent)-\(eventType)-\(processID ?? 0)-\(eventSequence ?? 0)-\(timestamp.timeIntervalSinceReferenceDate)"
  }

  private var runtimeIDComponent: String {
    policyRevision.map(String.init) ?? "none"
  }

  public init(
    schemaVersion: Int? = Self.currentSchemaVersion,
    eventIdentifier: UUID? = UUID(),
    processLineage: ProcessLineageSnapshot? = nil,
    timestamp: Date = Date(),
    policySetIdentifier: UUID? = nil,
    policyRevision: UInt64? = nil,
    eventSequence: UInt64? = nil,
    eventType: String,
    processID: Int32? = nil,
    executablePath: String? = nil,
    teamIdentifier: String? = nil,
    signingIdentifier: String? = nil,
    isPlatformBinary: Bool? = nil,
    codeSigningFlags: UInt32? = nil,
    operatingSystemBuild: String? = nil,
    targetPath: String? = nil,
    destinationPath: String? = nil,
    pathWasTruncated: Bool? = nil,
    requestedFlags: Int32? = nil,
    policyDecision: String,
    kernelResponse: String,
    policyEvaluations: [PolicyEvaluationRecord]? = nil,
    detail: String? = nil,
    requestCount: UInt64? = nil,
    lastTimestamp: Date? = nil
  ) {
    self.schemaVersion = schemaVersion
    self.eventIdentifier = eventIdentifier
    self.processLineage = processLineage
    self.timestamp = timestamp
    self.policySetIdentifier = policySetIdentifier
    self.policyRevision = policyRevision
    self.eventSequence = eventSequence
    self.eventType = eventType
    self.processID = processID
    self.executablePath = executablePath
    self.teamIdentifier = teamIdentifier
    self.signingIdentifier = signingIdentifier
    self.isPlatformBinary = isPlatformBinary
    self.codeSigningFlags = codeSigningFlags
    self.operatingSystemBuild = operatingSystemBuild
    self.targetPath = targetPath
    self.destinationPath = destinationPath
    self.pathWasTruncated = pathWasTruncated
    self.requestedFlags = requestedFlags
    self.policyDecision = policyDecision
    self.kernelResponse = kernelResponse
    self.policyEvaluations = policyEvaluations
    self.detail = detail
    self.requestCount = requestCount
    self.lastTimestamp = lastTimestamp
  }

  /// The number of requests this record stands for: one unless later requests were added to it.
  public var representedRequestCount: UInt64 { max(requestCount ?? 1, 1) }

  /// The time of the last request this record stands for.
  public var lastRequestTimestamp: Date { lastTimestamp ?? timestamp }

  /// Whether later requests can be added to this record whatever their target: an allowed
  /// request that every policy taking part allowed or would allow, and none of them at a
  /// retired folder path. Any other request is combined only with identical repeats, so its
  /// target and destination hold for every request.
  public var combinesAnyTarget: Bool {
    guard kernelResponse == "allow", let evaluations = policyEvaluations, !evaluations.isEmpty
    else { return false }
    return evaluations.allSatisfy {
      ($0.decision == .allow || $0.decision == .wouldAllow) && $0.retiredFolderPath == nil
    }
  }

  /// Whether a policy decided this request at one of its retired folder paths.
  public var touchesRetiredFolderPath: Bool {
    policyEvaluations?.contains { $0.retiredFolderPath != nil } ?? false
  }
}

public struct AuditLogBatch: Codable, Equatable, Sendable {
  public var records: [AuditEventRecord]
  public var skippedLineCount: Int
  public var droppedEventCount: UInt64
  public var isTruncated: Bool
  public var warning: String?

  public init(
    records: [AuditEventRecord],
    skippedLineCount: Int = 0,
    droppedEventCount: UInt64 = 0,
    isTruncated: Bool = false,
    warning: String? = nil
  ) {
    self.records = records
    self.skippedLineCount = skippedLineCount
    self.droppedEventCount = droppedEventCount
    self.isTruncated = isTruncated
    self.warning = warning
  }
}
