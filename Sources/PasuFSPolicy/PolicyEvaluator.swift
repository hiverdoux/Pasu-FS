/// A stable, hashable representation of the eight 32-bit words in a macOS
/// `audit_token_t`. The Endpoint Security adapter will be responsible for
/// converting the kernel token into this value.
public struct AuditTokenKey: Hashable, Sendable {
  public static let wordCount = 8

  public let words: [UInt32]

  public init(words: [UInt32]) throws {
    guard words.count == Self.wordCount else {
      throw AuditTokenKeyError.invalidWordCount(words.count)
    }
    self.words = words
  }
}

public enum AuditTokenKeyError: Error, Equatable {
  case invalidWordCount(Int)
}

/// Identifies one operating-system process instance without depending on
/// mutable credential fields in its audit token. The Endpoint Security adapter
/// obtains both values through the supported libbsm extraction functions.
public struct ProcessInstanceKey: Hashable, Sendable {
  public let processID: Int32
  public let processVersion: Int32

  public init(processID: Int32, processVersion: Int32) {
    self.processID = processID
    self.processVersion = processVersion
  }
}

/// Process facts used by the policy prototype. A PID is never used alone as an
/// authorization key; `processInstance` pairs it with the kernel PID version.
public struct ProcessFacts: Equatable, Sendable {
  public let auditToken: AuditTokenKey
  public let processInstance: ProcessInstanceKey
  public let teamIdentifier: String?
  public let signingIdentifier: String?

  public init(
    auditToken: AuditTokenKey,
    processInstance: ProcessInstanceKey,
    teamIdentifier: String?,
    signingIdentifier: String?
  ) {
    self.auditToken = auditToken
    self.processInstance = processInstance
    self.teamIdentifier = teamIdentifier
    self.signingIdentifier = signingIdentifier
  }
}

/// The first prototype supports an exact Team ID and Signing ID pair. Future
/// prototypes may add explicit unsigned-program and version-pinning policies.
public struct SignedProgramIdentity: Hashable, Sendable {
  public let teamIdentifier: String
  public let signingIdentifier: String

  public init(teamIdentifier: String, signingIdentifier: String) {
    self.teamIdentifier = teamIdentifier
    self.signingIdentifier = signingIdentifier
  }

  fileprivate func matches(_ process: ProcessFacts) -> Bool {
    process.teamIdentifier == teamIdentifier
      && process.signingIdentifier == signingIdentifier
  }
}

public struct AllowRule: Hashable, Sendable {
  public let id: String
  public let program: SignedProgramIdentity
  public let allowsDescendants: Bool

  public init(
    id: String,
    program: SignedProgramIdentity,
    allowsDescendants: Bool
  ) {
    self.id = id
    self.program = program
    self.allowsDescendants = allowsDescendants
  }
}

public struct PolicySnapshot: Equatable, Sendable {
  public let rules: [AllowRule]

  public init(rules: [AllowRule]) {
    self.rules = rules
  }

  fileprivate func directRule(for process: ProcessFacts) -> AllowRule? {
    rules.first { $0.program.matches(process) }
  }

  fileprivate func rule(id: String) -> AllowRule? {
    rules.first { $0.id == id }
  }
}

public enum AuthorizationDecision: Equatable, Sendable {
  case allowedDirect(ruleID: String)
  case allowedInherited(ruleID: String)
  case denied
}

/// A synchronous, in-memory prototype for direct allow rules and descendant
/// inheritance. It has no filesystem access and contains no Endpoint Security
/// callbacks; those boundaries are intentional at this stage.
public struct PolicyEvaluator: Sendable {
  private var policy: PolicySnapshot
  private var inheritedRuleByProcess: [ProcessInstanceKey: String] = [:]

  public init(policy: PolicySnapshot) {
    self.policy = policy
  }

  /// Replaces the policy atomically from the evaluator's perspective and
  /// discards runtime lineage whose originating rule no longer permits it.
  public mutating func replacePolicy(with newPolicy: PolicySnapshot) {
    policy = newPolicy

    let inheritableRuleIDs = Set(
      newPolicy.rules.lazy
        .filter(\.allowsDescendants)
        .map(\.id)
    )

    inheritedRuleByProcess = inheritedRuleByProcess.filter {
      inheritableRuleIDs.contains($0.value)
    }
  }

  /// Records a process execution. A process matching an inheritable direct
  /// rule becomes an allow root. Existing inherited trust is preserved across
  /// an exec into a different program image when its prior process instance is
  /// supplied.
  public mutating func observeExec(_ process: ProcessFacts) {
    observeExec(from: nil, to: process)
  }

  /// Transfers inherited trust from the process that invoked `exec` to the
  /// newly executing process. macOS may change the audit-token process version
  /// across exec even though the PID remains the same.
  public mutating func observeExec(
    from source: ProcessInstanceKey,
    to process: ProcessFacts
  ) {
    observeExec(from: Optional(source), to: process)
  }

  private mutating func observeExec(
    from source: ProcessInstanceKey?,
    to process: ProcessFacts
  ) {
    let inheritedRuleID = source.flatMap { inheritedRuleByProcess[$0] }
    if let source, source != process.processInstance {
      inheritedRuleByProcess.removeValue(forKey: source)
    }

    if let directRule = policy.directRule(for: process),
      directRule.allowsDescendants
    {
      inheritedRuleByProcess[process.processInstance] = directRule.id
      return
    }

    guard let inheritedRuleID,
      policy.rule(id: inheritedRuleID)?.allowsDescendants == true
    else {
      return
    }

    inheritedRuleByProcess[process.processInstance] = inheritedRuleID
  }

  /// Propagates trust only through an observed fork from a currently trusted
  /// lineage. Executable names and PIDs do not participate in this decision.
  public mutating func observeFork(
    parent: ProcessInstanceKey,
    child: ProcessInstanceKey
  ) {
    guard let ruleID = inheritedRuleByProcess[parent],
      policy.rule(id: ruleID)?.allowsDescendants == true
    else {
      return
    }

    inheritedRuleByProcess[child] = ruleID
  }

  public mutating func observeExit(_ process: ProcessInstanceKey) {
    inheritedRuleByProcess.removeValue(forKey: process)
  }

  public func decision(for process: ProcessFacts) -> AuthorizationDecision {
    if let directRule = policy.directRule(for: process) {
      return .allowedDirect(ruleID: directRule.id)
    }

    guard let inheritedRuleID = inheritedRuleByProcess[process.processInstance],
      policy.rule(id: inheritedRuleID)?.allowsDescendants == true
    else {
      return .denied
    }

    return .allowedInherited(ruleID: inheritedRuleID)
  }
}
