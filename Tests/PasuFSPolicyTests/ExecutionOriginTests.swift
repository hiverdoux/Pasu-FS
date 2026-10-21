import Foundation
import XCTest

@testable import PasuFSPolicy

final class ExecutionOriginTests: XCTestCase {
  func testBothEndsRequireDirectMatchesInTheSameAllowList() throws {
    let a = try program(10, "a")
    let c = try program(20, "c")
    for allowOrigin in [false, true] {
      for allowActor in [false, true] {
        let policy = policy(allows: (allowOrigin ? [a] : []) + (allowActor ? [c] : []))
        var tracker = tracker(policy)
        try launch(a, tracker: &tracker)
        tracker.observeFork(parent: a, child: c)
        let result = decision(c, policy, &tracker)
        XCTAssertEqual(result.isAllowed, allowOrigin && allowActor)
        XCTAssertEqual(result.origin?.instance, a.instance)
      }
    }
  }

  func testUnlistedIntermediateCanLeadToListedActorButCannotAccessItself() throws {
    let a = try program(10, "a")
    let b = try program(20, "b")
    let c = try program(30, "c")
    let policy = policy(allows: [a, c])
    var tracker = tracker(policy)
    try launch(a, tracker: &tracker)
    tracker.observeFork(parent: a, child: b)
    tracker.observeFork(parent: b, child: c)
    XCTAssertEqual(decision(b, policy, &tracker).reason, .actorNotAllowed)
    XCTAssertTrue(decision(c, policy, &tracker).isAllowed)
  }

  func testDenialAnywhereSurvivesExecExitAndLaterDirectAllowInBothModes() throws {
    let a = try program(10, "a")
    let b = try program(20, "b")
    let c = try program(30, "c")
    for blacklist in [false, true] {
      for denied in [a, b, c] {
        let policy = policy(blacklist: blacklist, allows: [a, b, c], denies: [denied])
        var tracker = tracker(policy)
        try launch(a, tracker: &tracker)
        tracker.observeFork(parent: a, child: b)
        tracker.observeExit(a.instance)
        tracker.observeFork(parent: b, child: c)
        var replacement = c
        replacement.instance = ProcessInstanceKey(
          processID: c.instance.processID, processVersion: 2)
        replacement.signingIdentifier = "com.example.replacement"
        tracker.observeExec(from: c, to: replacement)
        tracker.observeExit(b.instance)
        let result = decision(replacement, policy, &tracker)
        XCTAssertEqual(result.reason, .deniedInHistory)
        XCTAssertEqual(result.deniedProgram?.signingIdentifier, denied.signingIdentifier)
      }
    }
  }

  func testIntermediariesAreNodeLocalSkipsAndNeverReselectTheOrigin() throws {
    let a = try program(10, "a")
    let c = try program(30, "c")
    let system = try xpcproxy(20)
    for blacklist in [false, true] {
      for denyOrigin in [false, true] {
        let policy = policy(
          blacklist: blacklist, allows: [a, c], denies: [system] + (denyOrigin ? [a] : []))
        var tracker = tracker(policy)
        let leader = try xpcproxy(5)
        try launch(leader, tracker: &tracker)
        tracker.observeExec(from: leader, to: a)
        tracker.observeFork(parent: a, child: system)
        let end = decision(system, policy, &tracker)
        XCTAssertEqual(end.origin?.instance, a.instance)
        XCTAssertEqual(end.actorIntermediaryRole, .xpcproxy)
        XCTAssertEqual(end.isAllowed, !denyOrigin)
        tracker.observeFork(parent: system, child: c)
        let later = decision(c, policy, &tracker)
        XCTAssertEqual(later.origin?.instance, a.instance)
        XCTAssertEqual(later.isAllowed, !denyOrigin)
      }
    }
  }

  func testIntermediaryDoesNotFixUnallowedOriginUnknownHistoryOrEmptyAllowList() throws {
    let a = try program(10, "a")
    let system = try xpcproxy(20)
    let other = try program(30, "other")
    for allows in [[], [other]] {
      let policy = policy(allows: allows)
      var tracker = tracker(policy)
      try launch(a, tracker: &tracker)
      tracker.observeFork(parent: a, child: system)
      XCTAssertFalse(decision(system, policy, &tracker).isAllowed)
    }
    // An unobserved third-party parent stays unknown, even when launchd started it before
    // observation began: only Apple platform binaries begin a history that way.
    let policy = policy(blacklist: true)
    var tracker = tracker(policy, observationStart: observationStart)
    tracker.observeFork(parent: startedByLaunchd(a), child: system)
    XCTAssertEqual(decision(system, policy, &tracker).uncertainty, .beforeObservation)
    XCTAssertNil(decision(system, policy, &tracker).historyEvidence)
  }

  func testAllIntermediariesHaveNoFirstProgramEvenInBlacklistMode() throws {
    let system = try xpcproxy(10)
    for blacklist in [false, true] {
      let policy = policy(blacklist: blacklist, allows: [system])
      var tracker = tracker(policy)
      try launch(system, tracker: &tracker)
      XCTAssertEqual(decision(system, policy, &tracker).reason, .noFirstProgram)
    }
  }

  func testPlatformStatusAloneAndCopiedSigningNamesAreNotIntermediaries() throws {
    var apple = try program(10, "apple", platform: true)
    apple.signingIdentifier = "com.apple.TextEdit"
    apple.executablePath = "/System/Applications/TextEdit.app/Contents/MacOS/TextEdit"
    var fake = try xpcproxy(20)
    fake.isPlatformBinary = false
    fake.teamIdentifier = "TEAM123456"
    var invalid = try xpcproxy(30)
    invalid.codeSigningFlags = 0
    var adHoc = fake
    adHoc.codeSigningFlags = 3
    XCTAssertNil(adHoc.identity)
    for candidate in [apple, fake, invalid, adHoc] {
      XCTAssertNil(candidate.intermediaryRole)
      let policy = policy(blacklist: true)
      var tracker = tracker(policy)
      try launch(candidate, tracker: &tracker)
      XCTAssertEqual(decision(candidate, policy, &tracker).origin?.instance, candidate.instance)
    }
  }

  func testFirstEqualsActorAndParentExecCannotChangeChildOrigin() throws {
    let a = try program(10, "a")
    var child = a
    child.instance = ProcessInstanceKey(processID: 20, processVersion: 1)
    var replacement = try program(10, "replacement")
    replacement.instance = ProcessInstanceKey(processID: 10, processVersion: 2)
    let policy = policy(allows: [a, replacement])
    var tracker = tracker(policy)
    try launch(a, tracker: &tracker)
    XCTAssertTrue(decision(a, policy, &tracker).isAllowed)
    tracker.observeFork(parent: a, child: child)
    tracker.observeExec(from: a, to: replacement)
    tracker.observeExit(replacement.instance)
    let result = decision(child, policy, &tracker)
    XCTAssertTrue(result.isAllowed)
    XCTAssertEqual(result.origin, a)
    XCTAssertEqual(tracker.status.observedProcessCount, 2)  // PID 1 and the child.
  }

  func testPIDReuseAndAnotherBootCannotAcquireTheOldOrigin() throws {
    let a = try program(10, "a")
    let policy = policy(allows: [a])
    var first = tracker(policy)
    try launch(a, tracker: &first)
    first.observeExit(a.instance)
    var reused = a
    reused.instance = ProcessInstanceKey(processID: 10, processVersion: 2)
    XCTAssertEqual(decision(reused, policy, &first).reason, .incompleteHistory)
    // In another boot session the third-party program started before observation, as far as
    // the new tracker knows, and its history stays unknown.
    var second = ExecutionOriginTracker(
      bootIdentifier: "another-boot", observationStart: observationStart)
    second.configure(policies: [policy])
    XCTAssertEqual(decision(startedByLaunchd(a), policy, &second).uncertainty, .beforeObservation)
  }

  // MARK: - Processes that launchd started before observation began

  func testPlatformServiceThatLaunchdStartedBeforeObservationHasACompleteHistory() throws {
    let daemon = startedByLaunchd(try program(40, "daemon", platform: true))
    for blacklist in [false, true] {
      let unlisted = policy(blacklist: blacklist, allows: [try program(41, "other")])
      var tracker = tracker(unlisted, observationStart: observationStart)
      let result = decision(daemon, unlisted, &tracker)
      XCTAssertNil(result.uncertainty)
      XCTAssertEqual(result.historyEvidence, .kernelLaunchdStart)
      XCTAssertEqual(result.origin, daemon)
      // The lists still decide: the history is restored, not allowed.
      XCTAssertEqual(result.reason, blacklist ? .blacklistAllowed : .originNotAllowed)
      XCTAssertEqual(tracker.status.kernelLaunchdStartHistoryCount, 1)
      XCTAssertEqual(tracker.status.observationStartedAt, observationStart)
    }
    let listed = policy(allows: [daemon])
    var tracker = tracker(listed, observationStart: observationStart)
    let allowed = decision(daemon, listed, &tracker)
    XCTAssertEqual(allowed.reason, .allowed)
    XCTAssertEqual(allowed.historyEvidence, .kernelLaunchdStart)
    // Seen again, the process keeps the history it was given; the count is per history.
    XCTAssertEqual(decision(daemon, listed, &tracker).reason, .allowed)
    XCTAssertEqual(tracker.status.kernelLaunchdStartHistoryCount, 1)
  }

  func testOnlyPlatformBinariesForkedByLaunchdBeforeObservationQualify() throws {
    let platform = try program(50, "daemon", platform: true)
    var invalid = platform
    invalid.codeSigningFlags = 0
    var adHoc = platform
    adHoc.codeSigningFlags = 3
    let cases: [(String, ExecutionProgram)] = [
      ("third-party program", startedByLaunchd(try program(51, "agent"))),
      ("invalid signature", startedByLaunchd(invalid)),
      ("ad hoc signature", startedByLaunchd(adHoc)),
      (
        "started at the observation start",
        startedByLaunchd(platform, at: observationStart)
      ),
      (
        "started after the observation start",
        startedByLaunchd(platform, at: observationStart.addingTimeInterval(1))
      ),
      ("start time not reported", startedByLaunchd(platform, reportsStart: false)),
      ("another original parent", startedByLaunchd(platform, originalParent: 900)),
      ("original parent not reported", startedByLaunchd(platform, originalParent: nil)),
      // A traced process has the debugger as its current parent.
      ("another current parent", startedByLaunchd(platform, parent: 900)),
      ("current parent not reported", startedByLaunchd(platform, parent: nil)),
    ]
    for (label, candidate) in cases {
      let policy = policy(blacklist: true)
      var tracker = tracker(policy, observationStart: observationStart)
      let result = decision(candidate, policy, &tracker)
      XCTAssertEqual(result.uncertainty, .beforeObservation, label)
      XCTAssertEqual(result.reason, .incompleteHistory, label)
      XCTAssertNil(result.historyEvidence, label)
      XCTAssertEqual(tracker.status.kernelLaunchdStartHistoryCount, 0, label)
    }
    // Without a known observation start no history begins before observation.
    let policy = policy(blacklist: true)
    var unknownStart = tracker(policy)
    XCTAssertEqual(
      decision(startedByLaunchd(platform), policy, &unknownStart).uncertainty, .beforeObservation)
    XCTAssertNil(unknownStart.status.kernelLaunchdStartHistoryCount)
  }

  func testBlockedPlatformServiceStartedBeforeObservationIsDeniedInBothModes() throws {
    let daemon = startedByLaunchd(try program(60, "daemon", platform: true))
    for blacklist in [false, true] {
      let policy = policy(blacklist: blacklist, allows: [daemon], denies: [daemon])
      var tracker = tracker(policy, observationStart: observationStart)
      let result = decision(daemon, policy, &tracker)
      XCTAssertEqual(result.reason, .deniedInHistory)
      XCTAssertEqual(result.deniedProgram, daemon)
      XCTAssertEqual(result.historyEvidence, .kernelLaunchdStart)
    }
  }

  func testObservedLaunchRecordsObservedEvidence() throws {
    let a = try program(70, "a")
    let policy = policy(allows: [a])
    var tracker = tracker(policy, observationStart: observationStart)
    try launch(a, tracker: &tracker)
    let result = decision(a, policy, &tracker)
    XCTAssertTrue(result.isAllowed)
    XCTAssertEqual(result.historyEvidence, .observed)
    XCTAssertEqual(tracker.status.kernelLaunchdStartHistoryCount, 0)
  }

  /// With NSEndpointSecurityEarlyBoot, a launch daemon that is not a platform binary waits at
  /// its exec until the extension subscribes; xpcproxy, forked by launchd, already runs.
  func testProgramStartedByAnIntermediaryThatPredatesObservationIsItsOwnFirstProgram() throws {
    let proxy = startedByLaunchd(try xpcproxy(80))
    var daemon = try program(80, "daemon")
    daemon.instance = ProcessInstanceKey(processID: 80, processVersion: 2)
    for allowed in [false, true] {
      let policy = policy(allows: allowed ? [daemon] : [try program(81, "other")])
      var tracker = tracker(policy, observationStart: observationStart)
      tracker.observeExec(from: proxy, to: daemon)
      let result = decision(daemon, policy, &tracker)
      XCTAssertNil(result.uncertainty)
      XCTAssertEqual(result.origin, daemon)
      XCTAssertEqual(result.historyEvidence, .kernelLaunchdStart)
      XCTAssertEqual(result.reason, allowed ? .allowed : .originNotAllowed)
    }
    // The intermediary itself has no first program, as after an observed launch.
    let policy = policy(blacklist: true)
    var tracker = tracker(policy, observationStart: observationStart)
    XCTAssertEqual(decision(proxy, policy, &tracker).reason, .noFirstProgram)
  }

  func testChildOfAServiceThatPredatesObservationKeepsTheServiceAsFirstProgram() throws {
    let service = startedByLaunchd(try program(90, "service", platform: true))
    let child = try program(91, "child")
    var forked = service
    forked.instance = ProcessInstanceKey(processID: 91, processVersion: 0)
    forked.startTime = observationStart.addingTimeInterval(5)
    forked.originalParentProcessID = 90
    forked.parentProcessID = 90
    var delegating = policy(allows: [service, child])
    delegating = ExecutionOriginPolicySnapshot(
      allowRules: delegating.allowRules.map {
        AllowRule(
          id: $0.id, identity: $0.identity, allowsDescendants: $0.id == "com.example.service")
      }, denyRules: [])
    var tracker = tracker(delegating, observationStart: observationStart)
    tracker.observeFork(parent: service, child: forked)
    var unlistedChild = try program(91, "unlisted")
    unlistedChild.instance = ProcessInstanceKey(processID: 91, processVersion: 1)
    tracker.observeExec(from: forked, to: unlistedChild)
    let result = decision(unlistedChild, delegating, &tracker)
    XCTAssertEqual(result.origin, service)
    XCTAssertEqual(result.reason, .allowedInherited)
    XCTAssertEqual(result.inheritedFrom?.identity, service.identity)
    XCTAssertEqual(result.historyEvidence, .kernelLaunchdStart)
    // A blocked program found later in the observed part of the history still denies.
    let blocking = policy(blacklist: true, denies: [unlistedChild])
    tracker.configure(policies: [blocking])
    let replaced = startedByLaunchd(try program(92, "service", platform: true))
    var second = replaced
    second.instance = ProcessInstanceKey(processID: 92, processVersion: 2)
    second.signingIdentifier = "com.example.unlisted"
    second.isPlatformBinary = false
    second.teamIdentifier = "TEAM123456"
    tracker.observeExec(from: replaced, to: second)
    XCTAssertEqual(decision(second, blocking, &tracker).reason, .deniedInHistory)
  }

  func testRestoredHistoryIsLostLikeAnObservedOneAfterEventLoss() throws {
    let daemon = startedByLaunchd(try program(100, "daemon", platform: true))
    let policy = policy(blacklist: true)
    var tracker = tracker(policy, observationStart: observationStart)
    XCTAssertEqual(decision(daemon, policy, &tracker).reason, .blacklistAllowed)
    tracker.invalidate(.eventLoss)
    let result = decision(daemon, policy, &tracker)
    XCTAssertEqual(result.uncertainty, .eventLoss)
    XCTAssertNil(result.historyEvidence)
  }

  func testDecisionWithEvidenceSurvivesEncodingAndOldRecordsDecodeWithoutIt() throws {
    let daemon = startedByLaunchd(try program(110, "daemon", platform: true))
    let policy = policy(blacklist: true)
    var tracker = tracker(policy, observationStart: observationStart)
    let result = decision(daemon, policy, &tracker)
    let data = try JSONEncoder().encode(result)
    let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    XCTAssertEqual(object["historyEvidence"] as? String, "kernelLaunchdStart")
    let actor = try XCTUnwrap(object["actor"] as? [String: Any])
    XCTAssertEqual(actor["parentProcessID"] as? Int, 1)
    XCTAssertNotNil(actor["startTime"])
    XCTAssertEqual(try JSONDecoder().decode(ExecutionOriginDecision.self, from: data), result)
    // A record written before the evidence existed has neither field.
    var older = object
    older["historyEvidence"] = nil
    var olderActor = actor
    olderActor["parentProcessID"] = nil
    olderActor["startTime"] = nil
    older["actor"] = olderActor
    let decoded = try JSONDecoder().decode(
      ExecutionOriginDecision.self, from: JSONSerialization.data(withJSONObject: older))
    XCTAssertNil(decoded.historyEvidence)
    XCTAssertNil(decoded.actor.startTime)
    XCTAssertNil(decoded.actor.parentProcessID)
  }

  func testModeAndAllowListChangesReevaluateFactsWithoutGrantingUnlistedActors() throws {
    let a = try program(10, "a")
    let b = try program(20, "b")
    var policy = policy(allows: [a])
    var tracker = tracker(policy)
    try launch(a, tracker: &tracker)
    tracker.observeFork(parent: a, child: b)
    XCTAssertEqual(decision(b, policy, &tracker).reason, .actorNotAllowed)
    policy = self.policy(blacklist: true, allows: [a])
    tracker.configure(policies: [policy])
    XCTAssertTrue(decision(b, policy, &tracker).isAllowed)
    policy = self.policy(allows: [a])
    tracker.configure(policies: [policy])
    XCTAssertEqual(decision(b, policy, &tracker).reason, .actorNotAllowed)
    policy = self.policy()
    tracker.configure(policies: [policy])
    XCTAssertEqual(decision(a, policy, &tracker).reason, .emptyAllowList)
  }

  func testNewDenialCannotAssumeAnOldIntermediateWasClean() throws {
    let a = try program(10, "a")
    let b = try program(20, "b")
    let c = try program(30, "c")
    var policy = policy(allows: [a, c])
    var tracker = tracker(policy)
    try launch(a, tracker: &tracker)
    tracker.observeFork(parent: a, child: b)
    tracker.observeFork(parent: b, child: c)
    tracker.observeExit(b.instance)
    policy = self.policy(allows: [a, c], denies: [b])
    tracker.configure(policies: [policy])
    XCTAssertEqual(decision(c, policy, &tracker).uncertainty, .policyChanged)
    try launch(a, tracker: &tracker)
    tracker.observeFork(parent: a, child: c)
    XCTAssertTrue(decision(c, policy, &tracker).isAllowed)
  }

  func testUnobservedAllowedProcessIsNotAdoptedAsTrustedRoot() throws {
    let a = try program(10, "a")
    let b = try program(20, "b")
    let policy = policy(blacklist: true, allows: [a, b])
    var tracker = tracker(policy)
    tracker.observeExec(from: a, to: b)
    XCTAssertEqual(decision(b, policy, &tracker).uncertainty, .beforeObservation)
  }

  func testEventLossInvalidatesOldPathsButNewObservedLaunchCanRecover() throws {
    let a = try program(10, "a")
    let policy = policy(allows: [a])
    var tracker = tracker(policy)
    try launch(a, tracker: &tracker)
    XCTAssertTrue(decision(a, policy, &tracker).isAllowed)
    tracker.invalidate(.eventLoss)
    XCTAssertEqual(decision(a, policy, &tracker).uncertainty, .eventLoss)
    XCTAssertEqual(tracker.status.invalidationCount, 1)
    XCTAssertEqual(tracker.status.lastInvalidation, .eventLoss)
    try launch(a, tracker: &tracker)
    XCTAssertTrue(decision(a, policy, &tracker).isAllowed)
    tracker.invalidate(.unavailableEventVersion)
    XCTAssertEqual(decision(a, policy, &tracker).uncertainty, .unavailableEventVersion)
  }

  func testStatePressureBoundsStorageAndNeverRestoresUnknownAuthority() throws {
    let a = try program(10, "a")
    let policy = policy(allows: [a])
    var tracker = ExecutionOriginTracker(bootIdentifier: "test", maximumProcessCount: 2)
    tracker.configure(policies: [policy])
    try launch(a, tracker: &tracker)
    tracker.observeFork(parent: a, child: try program(20, "a"))
    XCTAssertLessThanOrEqual(tracker.status.observedProcessCount, 2)
    XCTAssertGreaterThan(tracker.status.discardedProcessCount, 0)
    XCTAssertFalse(decision(a, policy, &tracker).isAllowed)
    XCTAssertLessThanOrEqual(
      tracker.status.estimatedDataBytes, tracker.status.maximumEstimatedDataBytes)
  }

  func testLongExecChainDoesNotRetainAllPastImages() throws {
    var actor = try program(10, "a")
    let policy = policy(allows: [actor])
    var tracker = tracker(policy)
    try launch(actor, tracker: &tracker)
    for version in 2...10_000 {
      var next = actor
      next.instance = ProcessInstanceKey(processID: 10, processVersion: Int32(version))
      tracker.observeExec(from: actor, to: next)
      actor = next
    }
    XCTAssertEqual(tracker.status.observedProcessCount, 2)
    XCTAssertLessThan(tracker.status.estimatedDataBytes, 4_096)
    XCTAssertTrue(decision(actor, policy, &tracker).isAllowed)
  }

  private let observationStart = Date(timeIntervalSince1970: 1_800_000_000)

  private func tracker(_ policy: ExecutionOriginPolicySnapshot, observationStart: Date? = nil)
    -> ExecutionOriginTracker
  {
    var result = ExecutionOriginTracker(
      bootIdentifier: "test-boot", observationStart: observationStart)
    result.configure(policies: [policy])
    return result
  }

  /// `program` as the kernel reports a process that launchd forked, at `start` or by default
  /// 30 seconds before the observation start, and that is still launchd's child.
  /// `reportsStart` false leaves the start time unreported.
  private func startedByLaunchd(
    _ program: ExecutionProgram, at start: Date? = nil, reportsStart: Bool = true,
    originalParent: Int32? = 1, parent: Int32? = 1
  ) -> ExecutionProgram {
    var result = program
    result.startTime = reportsStart ? start ?? observationStart.addingTimeInterval(-30) : nil
    result.originalParentProcessID = originalParent
    result.parentProcessID = parent
    return result
  }

  private func decision(
    _ actor: ExecutionProgram, _ policy: ExecutionOriginPolicySnapshot,
    _ tracker: inout ExecutionOriginTracker
  ) -> ExecutionOriginDecision {
    let summary = tracker.summary(for: actor)
    return tracker.evaluate(summary, policy: policy)
  }

  private func policy(
    blacklist: Bool = false, allows: [ExecutionProgram] = [], denies: [ExecutionProgram] = []
  ) -> ExecutionOriginPolicySnapshot {
    func rule(_ program: ExecutionProgram) -> AllowRule {
      AllowRule(
        id: program.signingIdentifier!, identity: program.identity!, allowsDescendants: false)
    }
    return ExecutionOriginPolicySnapshot(
      isBlacklistEnabled: blacklist, allowRules: allows.map(rule), denyRules: denies.map(rule))
  }

  private func launch(_ target: ExecutionProgram, tracker: inout ExecutionOriginTracker) throws {
    var launchd = try program(1, "launchd", platform: true)
    launchd.signingIdentifier = "com.apple.xpc.launchd"
    launchd.executablePath = "/sbin/launchd"
    var child = launchd
    child.instance = ProcessInstanceKey(processID: target.instance.processID, processVersion: 0)
    tracker.observeFork(parent: launchd, child: child)
    tracker.observeExec(from: child, to: target)
  }

  private func xpcproxy(_ pid: Int32) throws -> ExecutionProgram {
    var result = try program(pid, "xpcproxy", platform: true)
    result.signingIdentifier = "com.apple.xpc.proxy"
    result.executablePath = "/usr/libexec/xpcproxy"
    return result
  }

  private func program(_ pid: Int32, _ name: String, platform: Bool = false) throws
    -> ExecutionProgram
  {
    ExecutionProgram(
      facts: ProcessFacts(
        auditToken: try AuditTokenKey(words: Array(repeating: UInt32(pid), count: 8)),
        processInstance: ProcessInstanceKey(processID: pid, processVersion: 1),
        teamIdentifier: platform ? nil : "TEAM123456", signingIdentifier: "com.example.\(name)",
        isPlatformBinary: platform, codeSigningFlags: 1),
      executablePath: "/example/\(name)")
  }
}
