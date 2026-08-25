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
  public let isPlatformBinary: Bool

  public init(
    auditToken: AuditTokenKey,
    processInstance: ProcessInstanceKey,
    teamIdentifier: String?,
    signingIdentifier: String?,
    isPlatformBinary: Bool = false
  ) {
    self.auditToken = auditToken
    self.processInstance = processInstance
    self.teamIdentifier = teamIdentifier
    self.signingIdentifier = signingIdentifier
    self.isPlatformBinary = isPlatformBinary
  }
}

/// Identifies a non-platform program by its exact Team ID and Signing ID pair.
public struct SignedProgramIdentity: Hashable, Sendable {
  public let teamIdentifier: String
  public let signingIdentifier: String

  public init(teamIdentifier: String, signingIdentifier: String) {
    self.teamIdentifier = teamIdentifier
    self.signingIdentifier = signingIdentifier
  }

  fileprivate func matches(_ process: ProcessFacts) -> Bool {
    !process.isPlatformBinary
      && process.teamIdentifier == teamIdentifier
      && process.signingIdentifier == signingIdentifier
  }
}

/// The kernel-supplied code-signing identity used by one direct allow rule.
/// Platform binaries are deliberately distinct from Team ID-signed programs;
/// a copied binary cannot match merely by reusing a signing identifier string.
public enum ProgramIdentity: Hashable, Sendable {
  case teamSigned(SignedProgramIdentity)
  case platformBinary(signingIdentifier: String)

  fileprivate func matches(_ process: ProcessFacts) -> Bool {
    switch self {
    case .teamSigned(let identity):
      identity.matches(process)
    case .platformBinary(let signingIdentifier):
      process.isPlatformBinary
        && process.signingIdentifier == signingIdentifier
    }
  }
}

public struct AllowRule: Hashable, Sendable {
  public let id: String
  public let identity: ProgramIdentity
  public let allowsDescendants: Bool

  public init(
    id: String,
    program: SignedProgramIdentity,
    allowsDescendants: Bool
  ) {
    self.init(
      id: id,
      identity: .teamSigned(program),
      allowsDescendants: allowsDescendants
    )
  }

  public init(
    id: String,
    identity: ProgramIdentity,
    allowsDescendants: Bool
  ) {
    self.id = id
    self.identity = identity
    self.allowsDescendants = allowsDescendants
  }
}

public struct PolicySnapshot: Equatable, Sendable {
  public let rules: [AllowRule]

  public init(rules: [AllowRule]) {
    self.rules = rules
  }

  fileprivate func directRule(for process: ProcessFacts) -> AllowRule? {
    rules.first { $0.identity.matches(process) }
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

/// Describes whether a process matched a configured program identity. The
/// caller decides whether a match means allow (whitelist) or deny (blacklist).
public enum RuleMatch: Equatable, Sendable {
  case direct(ruleID: String)
  case inherited(ruleID: String)
  case none
}

/// A synchronous, in-memory matcher for direct program identities and observed
/// descendant inheritance. It has no filesystem access and does not assign an
/// allow/deny meaning to a match; policy type interpretation stays with the
/// caller. `decision(for:)` remains as the single-whitelist compatibility API
/// used by the development harness.
public struct PolicyEvaluator: Sendable {
  private var policy: PolicySnapshot
  private var inheritedRuleByProcess: [ProcessInstanceKey: String] = [:]

  public init(policy: PolicySnapshot) {
    self.policy = policy
  }

  /// Replaces the policy atomically from the evaluator's perspective and
  /// discards runtime lineage whose originating rule no longer permits it.
  public mutating func replacePolicy(with newPolicy: PolicySnapshot) {
    let previousPolicy = policy
    policy = newPolicy

    let inheritableRuleIDs = Set(
      newPolicy.rules.lazy
        .filter { rule in
          rule.allowsDescendants && previousPolicy.rule(id: rule.id) == rule
        }
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

  public func match(for process: ProcessFacts) -> RuleMatch {
    if let directRule = policy.directRule(for: process) {
      return .direct(ruleID: directRule.id)
    }

    guard let inheritedRuleID = inheritedRuleByProcess[process.processInstance],
      policy.rule(id: inheritedRuleID)?.allowsDescendants == true
    else {
      return .none
    }

    return .inherited(ruleID: inheritedRuleID)
  }

  public func decision(for process: ProcessFacts) -> AuthorizationDecision {
    switch match(for: process) {
    case .direct(let ruleID):
      .allowedDirect(ruleID: ruleID)
    case .inherited(let ruleID):
      .allowedInherited(ruleID: ruleID)
    case .none:
      .denied
    }
  }
}
