import Foundation

public enum PolicyRuleMatchKind: String, Codable, Equatable, Sendable {
  case direct
  case inherited
  case systemCompatibilityProfile
  case none
  case decodeError
  case truncatedPath
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
    detail: String? = nil
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
  }
}

public struct AuditEventRecord: Codable, Equatable, Identifiable, Sendable {
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
  public var pathWasTruncated: Bool?
  public var requestedFlags: Int32?
  public var policyDecision: String
  public var kernelResponse: String
  public var policyEvaluations: [PolicyEvaluationRecord]?
  public var detail: String?

  public var id: String {
    if let eventIdentifier { return eventIdentifier.uuidString }
    return
      "\(runtimeIDComponent)-\(eventType)-\(processID ?? 0)-\(eventSequence ?? 0)-\(timestamp.timeIntervalSinceReferenceDate)"
  }

  private var runtimeIDComponent: String {
    policyRevision.map(String.init) ?? "none"
  }

  public init(
    schemaVersion: Int? = 5,
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
    pathWasTruncated: Bool? = nil,
    requestedFlags: Int32? = nil,
    policyDecision: String,
    kernelResponse: String,
    policyEvaluations: [PolicyEvaluationRecord]? = nil,
    detail: String? = nil
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
    self.pathWasTruncated = pathWasTruncated
    self.requestedFlags = requestedFlags
    self.policyDecision = policyDecision
    self.kernelResponse = kernelResponse
    self.policyEvaluations = policyEvaluations
    self.detail = detail
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
