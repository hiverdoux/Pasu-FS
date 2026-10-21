import Foundation

/// A stable, hashable representation of the eight 32-bit words in a macOS
/// `audit_token_t`. The Endpoint Security decoder
/// (`EndpointDecoder.auditTokenKey`) converts the kernel token into this value.
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
/// mutable credential fields in its audit token. The Endpoint Security decoder
/// obtains both values through the supported libbsm extraction functions.
public struct ProcessInstanceKey: Codable, Hashable, Sendable {
  public let processID: Int32
  public let processVersion: Int32

  public init(processID: Int32, processVersion: Int32) {
    self.processID = processID
    self.processVersion = processVersion
  }
}

/// Process facts used by the policy evaluator. A PID is never used alone as an
/// authorization key; `processInstance` pairs it with the kernel PID version.
public struct ProcessFacts: Equatable, Sendable {
  public let auditToken: AuditTokenKey
  public let processInstance: ProcessInstanceKey
  public let teamIdentifier: String?
  public let signingIdentifier: String?
  public let isPlatformBinary: Bool
  public let codeSigningFlags: UInt32
  /// The effective user ID in the audit token, or nil when it was not read.
  public let effectiveUserID: UInt32?
  /// The PID of the process that forked this one, as the kernel recorded it at the fork. Unlike
  /// the current parent, it does not change when the parent exits. Nil when it was not read.
  public let originalParentProcessID: Int32?
  /// The current parent process from the audit token Endpoint Security reports for it, and
  /// that parent's effective user ID; nil when not reported.
  public let parentProcessInstance: ProcessInstanceKey?
  public let parentEffectiveUserID: UInt32?
  /// When the fork that created the process happened, as the kernel recorded it. Replacing the
  /// executable keeps it. Nil when not reported.
  public let startTime: Date?

  public init(
    auditToken: AuditTokenKey,
    processInstance: ProcessInstanceKey,
    teamIdentifier: String?,
    signingIdentifier: String?,
    isPlatformBinary: Bool = false,
    codeSigningFlags: UInt32 = 0,
    effectiveUserID: UInt32? = nil,
    originalParentProcessID: Int32? = nil,
    parentProcessInstance: ProcessInstanceKey? = nil,
    parentEffectiveUserID: UInt32? = nil,
    startTime: Date? = nil
  ) {
    self.auditToken = auditToken
    self.processInstance = processInstance
    self.teamIdentifier = teamIdentifier
    self.signingIdentifier = signingIdentifier
    self.isPlatformBinary = isPlatformBinary
    self.codeSigningFlags = codeSigningFlags
    self.effectiveUserID = effectiveUserID
    self.originalParentProcessID = originalParentProcessID
    self.parentProcessInstance = parentProcessInstance
    self.parentEffectiveUserID = parentEffectiveUserID
    self.startTime = startTime
  }
}

/// Identifies a non-platform program by its exact Team ID and Signing ID pair.
public struct SignedProgramIdentity: Codable, Hashable, Sendable {
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
public enum ProgramIdentity: Codable, Hashable, Sendable {
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
/// caller. `decision(for:)` reads a match with the meaning of a single allow
/// list: a direct or inherited match allows, and no match denies.
///
/// The system extension does not use this type. It records process histories
/// with `ExecutionOriginTracker`, whose decision also covers the first program
/// of a history, block rules and the system intermediaries, and
/// `EndpointEventCoordinator` evaluates those histories against each policy and
/// records the outcome for the policy's mode. This type is a reference
/// implementation of the descendant inheritance rules, covered by unit tests
/// only.
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

  /// Like `observeExec(from:to:)`, but also treats the invoking process as an
  /// allow root when its own code-signing identity matches an inheritable
  /// rule. This covers programs whose exec happened before this evaluator
  /// started observing, such as an app launched before the extension started
  /// or before its rule was added.
  public mutating func observeExec(
    from source: ProcessFacts,
    to process: ProcessFacts
  ) {
    adoptDirectRoot(source)
    observeExec(from: Optional(source.processInstance), to: process)
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

  /// Like `observeFork(parent:child:)`, but also treats the parent as an allow
  /// root when its own code-signing identity matches an inheritable rule, even
  /// if its exec was never observed.
  public mutating func observeFork(
    parent: ProcessFacts,
    child: ProcessInstanceKey
  ) {
    adoptDirectRoot(parent)
    observeFork(parent: parent.processInstance, child: child)
  }

  /// Records a directly matching process as an allow root. The identity comes
  /// from the kernel-supplied code-signing facts of the current event, so this
  /// grants nothing beyond what an observed exec of the same program would.
  private mutating func adoptDirectRoot(_ process: ProcessFacts) {
    guard let directRule = policy.directRule(for: process),
      directRule.allowsDescendants
    else {
      return
    }
    inheritedRuleByProcess[process.processInstance] = directRule.id
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
