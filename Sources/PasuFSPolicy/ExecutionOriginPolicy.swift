import Foundation

/// Facts about one observed executable image. Paths refine the role of an
/// already authenticated platform binary; a path alone never authenticates it.
public struct ExecutionProgram: Codable, Equatable, Sendable {
  public var instance: ProcessInstanceKey
  public var executablePath: String
  public var teamIdentifier: String?
  public var signingIdentifier: String?
  public var isPlatformBinary: Bool
  public var codeSigningFlags: UInt32
  public var pathWasTruncated: Bool
  /// The PID of the process that forked this one, as the kernel recorded it; nil when unknown.
  /// It describes the process, not the image, and is not part of the program's identity.
  public var originalParentProcessID: Int32?
  /// The PID of the process's current parent when the event was reported, from the parent's
  /// audit token; nil when not reported. It describes the process, like the original parent.
  public var parentProcessID: Int32?
  /// When the fork that created the process happened, as the kernel recorded it; nil when not
  /// reported. It describes the process: an executable replacement keeps it.
  public var startTime: Date?

  public init(facts: ProcessFacts, executablePath: String, pathWasTruncated: Bool = false) {
    instance = facts.processInstance
    self.executablePath = executablePath
    teamIdentifier = facts.teamIdentifier
    signingIdentifier = facts.signingIdentifier
    isPlatformBinary = facts.isPlatformBinary
    codeSigningFlags = facts.codeSigningFlags
    self.pathWasTruncated = pathWasTruncated
    originalParentProcessID = facts.originalParentProcessID
    parentProcessID = facts.parentProcessInstance?.processID
    startTime = facts.startTime
  }

  public var identity: ProgramIdentity? {
    // Both flags are supplied by Endpoint Security, not read from the executable. An ad hoc
    // signature carries no Team ID, so any program could present the same signing identifier:
    // such a program gets no identity and matches no rule.
    guard codeSigningFlags & CodeSigningFlag.valid != 0,
      codeSigningFlags & CodeSigningFlag.adhoc == 0,
      let signingIdentifier,
      !signingIdentifier.isEmpty
    else { return nil }
    if isPlatformBinary { return .platformBinary(signingIdentifier: signingIdentifier) }
    guard let teamIdentifier, !teamIdentifier.isEmpty else { return nil }
    return .teamSigned(
      SignedProgramIdentity(teamIdentifier: teamIdentifier, signingIdentifier: signingIdentifier))
  }

  public var intermediaryRole: SystemIntermediaryRole? {
    guard !pathWasTruncated, let identity else { return nil }
    switch (identity, executablePath) {
    case (.platformBinary("com.apple.xpc.launchd"), "/sbin/launchd"):
      return .launchd
    case (.platformBinary("com.apple.xpc.proxy"), "/usr/libexec/xpcproxy"):
      return .xpcproxy
    default:
      return nil
    }
  }

  var isBootAnchor: Bool { instance.processID == 1 && intermediaryRole == .launchd }

  var estimatedBytes: Int {
    256 + executablePath.utf8.count + (teamIdentifier?.utf8.count ?? 0)
      + (signingIdentifier?.utf8.count ?? 0)
  }

  func hasSameImage(as other: Self) -> Bool {
    executablePath == other.executablePath && teamIdentifier == other.teamIdentifier
      && signingIdentifier == other.signingIdentifier && isPlatformBinary == other.isPlatformBinary
      && identity == other.identity && pathWasTruncated == other.pathWasTruncated
  }
}

/// The code-signing flags that `ExecutionProgram.identity` reads, with the values Endpoint
/// Security reports for them (`cs_blobs.h`).
private enum CodeSigningFlag {
  /// `CS_VALID`: the kernel found the signature valid.
  static let valid: UInt32 = 0x0000_0001
  /// `CS_ADHOC`: the signature has no certificate chain and therefore no Team ID.
  static let adhoc: UInt32 = 0x0000_0002
}

public enum SystemIntermediaryRole: String, Codable, Sendable {
  case launchd
  case xpcproxy
}

public enum ExecutionOriginUncertainty: String, Codable, Sendable {
  case beforeObservation
  case eventLoss
  case stateLimit
  case policyChanged
  case identityChanged
  case decodeFailure
  case unavailableEventVersion
}

/// How the beginning of a complete execution history was established.
public enum ExecutionHistoryEvidence: String, Codable, Sendable {
  /// The extension observed the history from a fork by launchd onward.
  case observed
  /// The history begins with a process that launchd forked before observation began. The
  /// kernel reported it as an Apple platform binary whose original and current parent is
  /// launchd (PID 1) and whose fork came before the observation start, so its history begins
  /// as if that launch had been observed. Programs that process ran before then are unknown.
  case kernelLaunchdStart
}

public enum ExecutionOriginDecisionReason: String, Codable, Sendable {
  case allowed
  case allowedInherited
  case blacklistAllowed
  case emptyAllowList
  case originNotAllowed
  case actorNotAllowed
  case deniedInHistory
  case incompleteHistory
  case noFirstProgram
}

/// Stable, structured authorization evidence for authenticated clients and logs.
public struct ExecutionOriginDecision: Codable, Equatable, Sendable {
  public var bootIdentifier: String
  public var isAllowed: Bool
  public var reason: ExecutionOriginDecisionReason
  public var isBlacklistEnabled: Bool
  public var origin: ExecutionProgram?
  public var actor: ExecutionProgram
  public var originRuleIdentifier: String?
  public var actorRuleIdentifier: String?
  public var inheritedRuleIdentifier: String?
  public var inheritedFrom: ExecutionProgram?
  public var deniedProgram: ExecutionProgram?
  public var denyRuleIdentifier: String?
  public var actorIntermediaryRole: SystemIntermediaryRole?
  public var uncertainty: ExecutionOriginUncertainty?
  /// How the beginning of the history was established; nil when the history is incomplete,
  /// and in records made before log schema 9.
  public var historyEvidence: ExecutionHistoryEvidence?
}

public struct ExecutionOriginPolicySnapshot: Equatable, Sendable {
  public let isBlacklistEnabled: Bool
  public let allowRules: [AllowRule]
  public let denyRules: [AllowRule]

  public init(isBlacklistEnabled: Bool = false, allowRules: [AllowRule], denyRules: [AllowRule]) {
    self.isBlacklistEnabled = isBlacklistEnabled
    self.allowRules = allowRules
    self.denyRules = denyRules
  }

}

public struct ExecutionOriginStatus: Codable, Equatable, Sendable {
  public var bootIdentifier: String
  public var observedProcessCount: Int
  public var estimatedDataBytes: Int
  public var maximumEstimatedDataBytes: Int
  public var maximumProcessCount: Int
  public var coverageEpoch: UInt64
  public var invalidationCount: UInt64
  public var discardedProcessCount: UInt64
  public var lastInvalidation: ExecutionOriginUncertainty?
  /// When observation of process events began; absent while unknown and from extensions that
  /// predate status schema 7.
  public var observationStartedAt: Date?
  /// How many histories began with a launchd start that the kernel reported for a process older
  /// than the observation (`ExecutionHistoryEvidence.kernelLaunchdStart`); absent from
  /// extensions that predate status schema 7.
  public var kernelLaunchdStartHistoryCount: UInt64?
}

/// Synchronous authorization state, independent of the asynchronous history
/// graph. A fork shares its origin, denial and ancestor-identity facts using
/// copy-on-write. At most one image per ancestor identity is retained, within
/// the shared data budget, rather than a chain of exited processes.
/// The owner must serialize delivery, policy changes and authorization checks.
public struct ExecutionOriginTracker: Sendable {
  public struct Summary: Sendable {
    fileprivate var program: ExecutionProgram
    fileprivate var origin: ExecutionProgram?
    fileprivate var denied: [ProgramIdentity: ExecutionProgram] = [:]
    fileprivate var observedAncestors: [ProgramIdentity: ExecutionProgram] = [:]
    fileprivate var epoch: UInt64
    fileprivate var uncertainty: ExecutionOriginUncertainty?
    fileprivate var evidence: ExecutionHistoryEvidence = .observed

    fileprivate var estimatedBytes: Int {
      256 + program.estimatedBytes + (origin?.estimatedBytes ?? 0)
        + denied.values.reduce(0) { $0 + $1.estimatedBytes + 128 }
        + observedAncestors.values.reduce(0) { $0 + $1.estimatedBytes + 128 }
    }
  }

  private var processes: [ProcessInstanceKey: Summary] = [:]
  private var trackedDenyIdentities: Set<ProgramIdentity> = []
  private var metrics: ExecutionOriginStatus
  /// No fork of a process created before this moment was observed. Nil when unknown, and then
  /// no history begins before observation.
  private let observationStart: Date?

  /// - Parameter observationStart: When observation of process events began, taken before the
  ///   subscription so that a process forked while it takes effect counts as unobserved.
  public init(
    bootIdentifier: String, observationStart: Date? = nil,
    maximumEstimatedDataBytes: Int = 16 * 1_024 * 1_024, maximumProcessCount: Int = 16_384
  ) {
    self.observationStart = observationStart
    metrics = ExecutionOriginStatus(
      bootIdentifier: bootIdentifier, observedProcessCount: 0, estimatedDataBytes: 0,
      maximumEstimatedDataBytes: max(1_024, maximumEstimatedDataBytes),
      maximumProcessCount: max(1, maximumProcessCount), coverageEpoch: 1,
      invalidationCount: 0, discardedProcessCount: 0, lastInvalidation: nil,
      observationStartedAt: observationStart,
      kernelLaunchdStartHistoryCount: observationStart == nil ? nil : 0)
  }

  public var status: ExecutionOriginStatus { metrics }

  /// The latest program recorded for a process instance, whether or not its history is
  /// complete.
  public func program(for instance: ProcessInstanceKey) -> ExecutionProgram? {
    processes[instance]?.program
  }

  /// A newly tracked denial could have occurred before it was configured.
  /// Such histories remain incomplete until a newly observed launch from the
  /// boot anchor. Allow-list edits and mode changes can reuse recorded facts.
  public mutating func configure(policies: [ExecutionOriginPolicySnapshot]) {
    let updated = Set(policies.flatMap { $0.denyRules.map(\.identity) })
    if !updated.isSubset(of: trackedDenyIdentities), !processes.isEmpty {
      invalidate(.policyChanged)
    }
    trackedDenyIdentities = updated
  }

  /// Makes every recorded history incomplete. Only process starts, forks and exits build the
  /// histories, so of the messages macOS drops only those call for this (`.eventLoss`).
  public mutating func invalidate(_ reason: ExecutionOriginUncertainty) {
    metrics.coverageEpoch &+= 1
    metrics.invalidationCount &+= 1
    metrics.lastInvalidation = reason
  }

  public mutating func observeFork(parent: ExecutionProgram, child: ExecutionProgram) {
    let source = summary(for: parent)
    save(appending(child, to: source))
  }

  public mutating func observeExec(from source: ExecutionProgram, to target: ExecutionProgram) {
    let next = appending(target, to: summary(for: source))
    if source.instance != target.instance { observeExit(source.instance) }
    save(next)
  }

  public mutating func observeExit(_ instance: ProcessInstanceKey) {
    if let removed = processes.removeValue(forKey: instance) {
      metrics.estimatedDataBytes -= removed.estimatedBytes
      metrics.observedProcessCount = processes.count
    }
  }

  /// The history of the process running `program`, with `program` recorded as its current
  /// image. A process without a recorded history gets one here: complete when the program is
  /// the authenticated PID 1 launchd or when the kernel reports that launchd forked the process
  /// before observation began (`ExecutionHistoryEvidence.kernelLaunchdStart`, decided by
  /// `launchdStartedBeforeObservation(_:)`), and otherwise incomplete (`.beforeObservation`).
  public mutating func summary(for program: ExecutionProgram) -> Summary {
    if var existing = processes[program.instance] {
      if !existing.program.hasSameImage(as: program) {
        existing.uncertainty = .identityChanged
      }
      // Only the authenticated PID 1 launchd is a bootstrap anchor. A later
      // intermediary in an ordinary lineage can never repair its history.
      if program.isBootAnchor {
        existing = Summary(program: program, epoch: metrics.coverageEpoch)
      }
      existing.program = program
      includeDenial(program, in: &existing)
      save(existing)
      return currentCoverage(existing)
    }
    var initial: Summary
    if program.isBootAnchor {
      initial = Summary(program: program, epoch: metrics.coverageEpoch)
    } else if launchdStartedBeforeObservation(program) {
      // The history launchd's observed fork and executable replacement would have produced:
      // the program is the first one unless it is an intermediary, nothing precedes it, and a
      // blocked program still denies.
      initial = Summary(
        program: program, origin: program.intermediaryRole == nil ? program : nil,
        epoch: metrics.coverageEpoch, evidence: .kernelLaunchdStart)
      metrics.kernelLaunchdStartHistoryCount = (metrics.kernelLaunchdStartHistoryCount ?? 0) &+ 1
    } else {
      initial = Summary(
        program: program, epoch: metrics.coverageEpoch, uncertainty: .beforeObservation)
    }
    includeDenial(program, in: &initial)
    save(initial)
    return currentCoverage(initial)
  }

  /// Whether the kernel reports that launchd started this process, which the tracker has not
  /// seen, before observation began: an Apple platform binary with a valid signature, whose
  /// original parent (`original_ppid`) and current parent are both launchd (PID 1), created by
  /// a fork that came before the observation start. No later fork is accepted, so a process
  /// whose launch macOS failed to deliver stays incomplete. A process reparented to launchd has
  /// another original parent, and one traced by a debugger another current parent. Programs
  /// the process ran before observation began, if any, are unknown: the current one counts as
  /// the first, and block rules for earlier ones can't apply.
  private func launchdStartedBeforeObservation(_ program: ExecutionProgram) -> Bool {
    guard let observationStart, let started = program.startTime, started < observationStart,
      program.originalParentProcessID == 1, program.parentProcessID == 1,
      case .platformBinary = program.identity
    else { return false }
    return true
  }

  public func evaluate(
    _ summary: Summary, policy: ExecutionOriginPolicySnapshot
  ) -> ExecutionOriginDecision {
    let summary = currentCoverage(summary)
    let actor = summary.program
    let originRule = summary.origin?.identity.flatMap { identity in
      policy.allowRules.first { $0.identity == identity }
    }
    let actorRule = actor.identity.flatMap { identity in
      policy.allowRules.first { $0.identity == identity }
    }
    let inheritedRule = policy.allowRules.first {
      $0.allowsDescendants && summary.observedAncestors[$0.identity] != nil
    }
    let denied = policy.denyRules.first { summary.denied[$0.identity] != nil }
    var reason: ExecutionOriginDecisionReason
    if denied != nil {
      reason = .deniedInHistory
    } else if !policy.isBlacklistEnabled && policy.allowRules.isEmpty {
      reason = .emptyAllowList
    } else if summary.uncertainty != nil {
      reason = .incompleteHistory
    } else if summary.origin == nil {
      reason = .noFirstProgram
    } else if policy.isBlacklistEnabled {
      reason = .blacklistAllowed
    } else if originRule == nil {
      reason = .originNotAllowed
    } else if actor.intermediaryRole == nil && actorRule == nil {
      reason = inheritedRule == nil ? .actorNotAllowed : .allowedInherited
    } else {
      reason = .allowed
    }
    return ExecutionOriginDecision(
      bootIdentifier: metrics.bootIdentifier,
      isAllowed: reason == .allowed || reason == .allowedInherited || reason == .blacklistAllowed,
      reason: reason, isBlacklistEnabled: policy.isBlacklistEnabled,
      origin: summary.origin, actor: actor,
      originRuleIdentifier: policy.isBlacklistEnabled ? nil : originRule?.id,
      actorRuleIdentifier: policy.isBlacklistEnabled ? nil : actorRule?.id,
      inheritedRuleIdentifier: reason == .allowedInherited ? inheritedRule?.id : nil,
      inheritedFrom: reason == .allowedInherited
        ? inheritedRule.flatMap { summary.observedAncestors[$0.identity] } : nil,
      deniedProgram: denied.flatMap { summary.denied[$0.identity] },
      denyRuleIdentifier: denied?.id, actorIntermediaryRole: actor.intermediaryRole,
      uncertainty: summary.uncertainty,
      historyEvidence: summary.uncertainty == nil ? summary.evidence : nil)
  }

  private func currentCoverage(_ summary: Summary) -> Summary {
    var result = summary
    if result.epoch != metrics.coverageEpoch && result.uncertainty == nil {
      result.uncertainty = metrics.lastInvalidation ?? .eventLoss
    }
    return result
  }

  private func appending(_ program: ExecutionProgram, to source: Summary) -> Summary {
    var next = currentCoverage(source)
    // Only an observed fork or executable replacement establishes ancestry.
    // Re-reading an actor, its PID or its responsible-process value does not.
    // Retain facts independently of policy so current rules also apply to
    // existing descendants. Later exit or exec cannot rewrite a child's facts.
    if next.uncertainty == nil, source.program.intermediaryRole == nil,
      let identity = source.program.identity
    {
      next.observedAncestors[identity] = source.program
    }
    next.program = program
    if next.origin == nil && next.uncertainty == nil && program.intermediaryRole == nil {
      next.origin = program
    }
    includeDenial(program, in: &next)
    return next
  }

  private func includeDenial(_ program: ExecutionProgram, in summary: inout Summary) {
    guard program.intermediaryRole == nil, let identity = program.identity,
      trackedDenyIdentities.contains(identity), summary.denied[identity] == nil
    else { return }
    summary.denied[identity] = program
  }

  private mutating func save(_ summary: Summary) {
    let previousBytes = processes[summary.program.instance]?.estimatedBytes ?? 0
    if metrics.estimatedDataBytes - previousBytes + summary.estimatedBytes
      > metrics.maximumEstimatedDataBytes
      || (processes[summary.program.instance] == nil
        && processes.count >= metrics.maximumProcessCount)
    {
      metrics.discardedProcessCount &+= UInt64(processes.count)
      processes.removeAll(keepingCapacity: false)
      metrics.estimatedDataBytes = 0
      metrics.observedProcessCount = 0
      invalidate(.stateLimit)
      // Returning the old-epoch summary also fails closed for the current call.
      return
    }
    processes[summary.program.instance] = summary
    metrics.estimatedDataBytes += summary.estimatedBytes - previousBytes
    metrics.observedProcessCount = processes.count
  }
}
