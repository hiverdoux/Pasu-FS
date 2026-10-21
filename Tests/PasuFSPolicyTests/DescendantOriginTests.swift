import Foundation
import XCTest

@testable import PasuFSPolicy

final class DescendantOriginTests: XCTestCase {
  func testOptInAllowsUnlistedChildrenAndLaterGenerationsAcrossExecAndExit() throws {
    let root = try program(10, "agent")
    let shell = try program(20, "shell")
    var tool = try program(30, "tool")
    // A delegated tool need not have its own representable signing identity.
    tool.teamIdentifier = nil
    tool.signingIdentifier = nil
    tool.codeSigningFlags = 0
    let policy = policy(allows: [root], descendants: [root])
    var tracker = tracker(policy)
    try launch(root, in: &tracker)
    tracker.observeFork(parent: root, child: shell)
    tracker.observeExit(root.instance)
    tracker.observeFork(parent: shell, child: tool)
    var replaced = tool
    replaced.instance = ProcessInstanceKey(processID: 30, processVersion: 2)
    replaced.executablePath = "/example/replacement"
    tracker.observeExec(from: tool, to: replaced)
    let result = decision(replaced, policy, &tracker)
    XCTAssertEqual(result.reason, .allowedInherited)
    XCTAssertTrue(result.isAllowed)
    XCTAssertNil(result.actorRuleIdentifier)
    XCTAssertEqual(result.inheritedRuleIdentifier, root.signingIdentifier)
    XCTAssertEqual(result.inheritedFrom, root)
    XCTAssertEqual(result.origin, root)
    XCTAssertEqual(
      try JSONDecoder().decode(
        ExecutionOriginDecision.self,
        from: JSONEncoder().encode(result)), result)
  }

  func testDelegationAtAnIntermediateProgramKeepsTheOriginalOrigin() throws {
    let terminal = try program(10, "terminal")
    let agent = try program(20, "agent")
    let tool = try program(30, "tool")
    for allowOrigin in [false, true] {
      let policy = policy(allows: (allowOrigin ? [terminal] : []) + [agent], descendants: [agent])
      var tracker = tracker(policy)
      try launch(terminal, in: &tracker)
      tracker.observeFork(parent: terminal, child: agent)
      tracker.observeFork(parent: agent, child: tool)
      let result = decision(tool, policy, &tracker)
      XCTAssertEqual(result.origin, terminal)
      XCTAssertEqual(result.reason, allowOrigin ? .allowedInherited : .originNotAllowed)
      XCTAssertEqual(result.inheritedFrom, allowOrigin ? agent : nil)
    }
  }

  func testDenialAtEveryPositionSurvivesExecExitAndDelegation() throws {
    let root = try program(10, "agent")
    let middle = try program(20, "middle")
    let tool = try program(30, "tool")
    for denied in [root, middle, tool] {
      let policy = policy(allows: [root, tool], descendants: [root], denies: [denied])
      var tracker = tracker(policy)
      try launch(root, in: &tracker)
      tracker.observeFork(parent: root, child: middle)
      tracker.observeFork(parent: middle, child: tool)
      tracker.observeExit(root.instance)
      tracker.observeExit(middle.instance)
      var replaced = tool
      replaced.instance = ProcessInstanceKey(processID: 30, processVersion: 2)
      replaced.signingIdentifier = "com.example.replacement"
      tracker.observeExec(from: tool, to: replaced)
      let result = decision(replaced, policy, &tracker)
      XCTAssertEqual(result.reason, .deniedInHistory)
      XCTAssertFalse(result.isAllowed)
      XCTAssertNil(result.inheritedRuleIdentifier)
      XCTAssertEqual(result.deniedProgram, denied)
    }
  }

  func testTurningOffOrRemovingTheGrantRevokesExistingDescendants() throws {
    let root = try program(10, "origin")
    let agent = try program(20, "agent")
    let tool = try program(30, "tool")
    let enabled = policy(allows: [root, agent], descendants: [agent])
    var tracker = tracker(enabled)
    try launch(root, in: &tracker)
    tracker.observeFork(parent: root, child: agent)
    tracker.observeFork(parent: agent, child: tool)
    XCTAssertTrue(decision(tool, enabled, &tracker).isAllowed)
    for current in [policy(allows: [root, agent]), policy(allows: [root])] {
      tracker.configure(policies: [current])
      XCTAssertEqual(decision(tool, current, &tracker).reason, .actorNotAllowed)
    }
    tracker.configure(policies: [enabled])
    XCTAssertEqual(decision(tool, enabled, &tracker).inheritedFrom, agent)
  }

  func testEnablingDelegationAppliesToAlreadyObservedDescendants() throws {
    let root = try program(10, "agent")
    let existing = try program(20, "old-child")
    let fresh = try program(30, "new-child")
    let original = policy(allows: [root])
    var tracker = tracker(original)
    try launch(root, in: &tracker)
    tracker.observeFork(parent: root, child: existing)
    XCTAssertEqual(decision(existing, original, &tracker).reason, .actorNotAllowed)
    let enabled = policy(allows: [root], descendants: [root])
    tracker.configure(policies: [enabled])
    let result = decision(existing, enabled, &tracker)
    XCTAssertEqual(result.reason, .allowedInherited)
    XCTAssertEqual(result.inheritedFrom, root)
    tracker.observeFork(parent: root, child: fresh)
    XCTAssertEqual(decision(fresh, enabled, &tracker).reason, .allowedInherited)
    tracker.configure(policies: [original])
    XCTAssertEqual(decision(existing, original, &tracker).reason, .actorNotAllowed)
  }

  func testNewRuleUsesAnObservedIntermediateAfterExecAndExitWithoutGrantingItsSibling() throws {
    let root = try program(10, "origin")
    let middle = try program(20, "middle")
    let child = try program(30, "tool")
    let sibling = try program(40, "sibling")
    let original = policy(allows: [root])
    var tracker = tracker(original)
    try launch(root, in: &tracker)
    tracker.observeFork(parent: root, child: middle)
    tracker.observeFork(parent: root, child: sibling)
    tracker.observeExec(from: middle, to: child)
    tracker.observeExit(root.instance)
    XCTAssertEqual(decision(child, original, &tracker).reason, .actorNotAllowed)
    for allowOrigin in [false, true] {
      let updated = policy(
        allows: (allowOrigin ? [root] : []) + [middle], descendants: [middle])
      tracker.configure(policies: [updated])
      let result = decision(child, updated, &tracker)
      XCTAssertEqual(result.origin, root)
      XCTAssertEqual(result.reason, allowOrigin ? .allowedInherited : .originNotAllowed)
      XCTAssertEqual(result.inheritedFrom, allowOrigin ? middle : nil)
      XCTAssertFalse(decision(sibling, updated, &tracker).isAllowed)
    }
  }

  func testLaterParentReplacementDoesNotChangeAnExistingChildsAncestors() throws {
    let root = try program(10, "origin")
    let child = try program(20, "tool")
    var replacement = try program(10, "replacement")
    replacement.instance = ProcessInstanceKey(processID: 10, processVersion: 2)
    let original = policy(allows: [root])
    var tracker = tracker(original)
    try launch(root, in: &tracker)
    tracker.observeFork(parent: root, child: child)
    tracker.observeExec(from: root, to: replacement)
    let updated = policy(allows: [root, replacement], descendants: [replacement])
    tracker.configure(policies: [updated])
    XCTAssertEqual(decision(child, updated, &tracker).reason, .actorNotAllowed)
  }

  func testEnablingDelegationCannotRepairMissingOrInvalidatedHistory() throws {
    let root = try program(10, "origin")
    let child = try program(20, "tool")
    let original = policy(allows: [root])
    let enabled = policy(allows: [root], descendants: [root])
    for reason in [
      ExecutionOriginUncertainty.beforeObservation, .eventLoss, .stateLimit, .policyChanged,
      .identityChanged, .decodeFailure, .unavailableEventVersion,
    ] {
      var tracker = tracker(original)
      if reason != .beforeObservation { try launch(root, in: &tracker) }
      tracker.observeFork(parent: root, child: child)
      if reason != .beforeObservation { tracker.invalidate(reason) }
      tracker.configure(policies: [enabled])
      let result = decision(child, enabled, &tracker)
      XCTAssertEqual(result.reason, .incompleteHistory)
      XCTAssertEqual(result.uncertainty, reason)
      XCTAssertNil(result.inheritedFrom)
    }
  }

  func testAncestorFactsRemainBoundedBeforeDelegationIsEnabled() throws {
    let root = try program(10, "origin")
    let original = policy(allows: [root])
    var tracker = ExecutionOriginTracker(
      bootIdentifier: "example-boot", maximumEstimatedDataBytes: 8_192)
    tracker.configure(policies: [original])
    try launch(root, in: &tracker)
    var actor = root
    for version in 2...100 {
      var next = try program(10, "tool-\(version)")
      next.instance = ProcessInstanceKey(processID: 10, processVersion: Int32(version))
      tracker.observeExec(from: actor, to: next)
      actor = next
      XCTAssertLessThanOrEqual(
        tracker.status.estimatedDataBytes, tracker.status.maximumEstimatedDataBytes)
    }
    XCTAssertGreaterThan(tracker.status.invalidationCount, 0)
    let enabled = policy(allows: [root], descendants: [root])
    tracker.configure(policies: [enabled])
    XCTAssertEqual(decision(actor, enabled, &tracker).reason, .incompleteHistory)
  }

  func testUnrelatedProcessesAndReusedPIDsNeverReceiveTheGrant() throws {
    let root = try program(10, "agent")
    let child = try program(20, "tool")
    let other = try program(30, "other")
    let policy = policy(allows: [root, other], descendants: [root])
    var tracker = tracker(policy)
    try launch(root, in: &tracker)
    tracker.observeFork(parent: root, child: child)
    XCTAssertTrue(decision(child, policy, &tracker).isAllowed)
    tracker.observeExit(child.instance)
    var reused = child
    reused.instance = ProcessInstanceKey(processID: 20, processVersion: 2)
    try launch(other, in: &tracker)
    tracker.observeFork(parent: other, child: reused)
    XCTAssertEqual(decision(reused, policy, &tracker).reason, .actorNotAllowed)
    var unobserved = child
    unobserved.instance = ProcessInstanceKey(processID: 40, processVersion: 1)
    XCTAssertEqual(decision(unobserved, policy, &tracker).reason, .incompleteHistory)
  }

  func testMissingHistoryAndStateLossOverrideAnInheritedGrant() throws {
    let root = try program(10, "agent")
    let child = try program(20, "tool")
    let policy = policy(allows: [root], descendants: [root])
    var unobserved = tracker(policy)
    unobserved.observeFork(parent: root, child: child)
    XCTAssertEqual(decision(child, policy, &unobserved).reason, .incompleteHistory)
    for reason in [ExecutionOriginUncertainty.eventLoss, .stateLimit, .decodeFailure] {
      var tracker = tracker(policy)
      try launch(root, in: &tracker)
      tracker.observeFork(parent: root, child: child)
      tracker.invalidate(reason)
      let result = decision(child, policy, &tracker)
      XCTAssertEqual(result.reason, .incompleteHistory)
      XCTAssertNil(result.inheritedFrom)
    }
  }

  func testDelegationIsScopedToEachPolicyAndDirectMatchesHavePriority() throws {
    let root = try program(10, "agent")
    let child = try program(20, "tool")
    let delegated = policy(allows: [root], descendants: [root])
    let strict = policy(allows: [root])
    let direct = policy(allows: [root, child], descendants: [root])
    var tracker = tracker(delegated)
    tracker.configure(policies: [delegated, strict, direct])
    try launch(root, in: &tracker)
    tracker.observeFork(parent: root, child: child)
    XCTAssertEqual(decision(child, delegated, &tracker).reason, .allowedInherited)
    XCTAssertEqual(decision(child, strict, &tracker).reason, .actorNotAllowed)
    XCTAssertEqual(decision(child, direct, &tracker).reason, .allowed)
    XCTAssertNil(decision(child, direct, &tracker).inheritedFrom)
    var blacklist = delegated
    blacklist = ExecutionOriginPolicySnapshot(
      isBlacklistEnabled: true,
      allowRules: delegated.allowRules, denyRules: [])
    XCTAssertEqual(decision(child, blacklist, &tracker).reason, .blacklistAllowed)
    XCTAssertNil(decision(child, blacklist, &tracker).inheritedFrom)
  }

  func testSystemIntermediariesDoNotBecomeDelegationSources() throws {
    let root = try program(10, "origin")
    let child = try program(20, "tool")
    let anchor = try launchd()
    let policy = policy(allows: [root, anchor], descendants: [anchor])
    var tracker = tracker(policy)
    try launch(root, in: &tracker)
    tracker.observeFork(parent: root, child: child)
    XCTAssertEqual(decision(child, policy, &tracker).reason, .actorNotAllowed)
  }

  private func policy(
    allows: [ExecutionProgram], descendants: [ExecutionProgram] = [],
    denies: [ExecutionProgram] = []
  ) -> ExecutionOriginPolicySnapshot {
    func rule(_ program: ExecutionProgram) -> AllowRule {
      AllowRule(
        id: program.signingIdentifier!, identity: program.identity!,
        allowsDescendants: descendants.contains(program))
    }
    return ExecutionOriginPolicySnapshot(allowRules: allows.map(rule), denyRules: denies.map(rule))
  }

  private func tracker(_ policy: ExecutionOriginPolicySnapshot) -> ExecutionOriginTracker {
    var tracker = ExecutionOriginTracker(bootIdentifier: "example-boot")
    tracker.configure(policies: [policy])
    return tracker
  }

  private func decision(
    _ actor: ExecutionProgram, _ policy: ExecutionOriginPolicySnapshot,
    _ tracker: inout ExecutionOriginTracker
  ) -> ExecutionOriginDecision {
    tracker.evaluate(tracker.summary(for: actor), policy: policy)
  }

  private func launch(_ target: ExecutionProgram, in tracker: inout ExecutionOriginTracker) throws {
    let anchor = try launchd()
    var child = anchor
    child.instance = ProcessInstanceKey(processID: target.instance.processID, processVersion: 0)
    tracker.observeFork(parent: anchor, child: child)
    tracker.observeExec(from: child, to: target)
  }

  private func launchd() throws -> ExecutionProgram {
    var anchor = try program(1, "launchd")
    anchor.isPlatformBinary = true
    anchor.signingIdentifier = "com.apple.xpc.launchd"
    anchor.executablePath = "/sbin/launchd"
    return anchor
  }

  private func program(_ pid: Int32, _ name: String) throws -> ExecutionProgram {
    ExecutionProgram(
      facts: ProcessFacts(
        auditToken: try AuditTokenKey(words: Array(repeating: UInt32(pid), count: 8)),
        processInstance: ProcessInstanceKey(processID: pid, processVersion: 1),
        teamIdentifier: "TEAM123456", signingIdentifier: "com.example.\(name)",
        isPlatformBinary: false, codeSigningFlags: 1), executablePath: "/example/\(name)")
  }
}
