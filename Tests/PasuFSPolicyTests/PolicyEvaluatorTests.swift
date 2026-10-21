import XCTest

@testable import PasuFSPolicy

final class PolicyEvaluatorTests: XCTestCase {
  func testNeutralMatcherDistinguishesDirectInheritedAndNoMatch() throws {
    let root = try token(1)
    let child = try token(2)
    var evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))
    let rootFacts = facts(
      token: root,
      team: "TEAM123456",
      signing: "com.example.Editor"
    )

    evaluator.observeExec(rootFacts)
    evaluator.observeFork(parent: instance(root), child: instance(child))

    XCTAssertEqual(evaluator.match(for: rootFacts), .direct(ruleID: rootRule.id))
    XCTAssertEqual(
      evaluator.match(for: facts(token: child)),
      .inherited(ruleID: rootRule.id)
    )
    XCTAssertEqual(evaluator.match(for: facts(token: try token(3))), .none)
  }

  private let rootRule = AllowRule(
    id: "allow.example.editor",
    program: SignedProgramIdentity(
      teamIdentifier: "TEAM123456",
      signingIdentifier: "com.example.Editor"
    ),
    allowsDescendants: true
  )

  private let finderRule = AllowRule(
    id: "allow.apple.finder",
    identity: .platformBinary(signingIdentifier: "com.apple.finder"),
    allowsDescendants: false
  )

  func testRejectsMalformedAuditToken() {
    XCTAssertThrowsError(try AuditTokenKey(words: [1, 2, 3])) { error in
      XCTAssertEqual(error as? AuditTokenKeyError, .invalidWordCount(3))
    }
  }

  func testDirectSigningIdentityIsAllowed() throws {
    let evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))
    let process = facts(
      token: try token(1),
      team: "TEAM123456",
      signing: "com.example.Editor"
    )

    XCTAssertEqual(
      evaluator.decision(for: process),
      .allowedDirect(ruleID: rootRule.id)
    )
  }

  func testDifferentTeamIdentityIsDenied() throws {
    let evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))
    let process = facts(
      token: try token(2),
      team: "OTHERTEAM1",
      signing: "com.example.Editor"
    )

    XCTAssertEqual(evaluator.decision(for: process), .denied)
  }

  func testDifferentSigningIdentifierIsDenied() throws {
    let evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))
    let process = facts(
      token: try token(21),
      team: "TEAM123456",
      signing: "com.example.Impersonator"
    )

    XCTAssertEqual(evaluator.decision(for: process), .denied)
  }

  func testMultipleDirectIdentitiesAreAllowed() throws {
    let evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule, finderRule]))
    let editor = facts(
      token: try token(3),
      team: "TEAM123456",
      signing: "com.example.Editor"
    )
    let finder = facts(
      token: try token(4),
      signing: "com.apple.finder",
      isPlatformBinary: true
    )

    XCTAssertEqual(
      evaluator.decision(for: editor),
      .allowedDirect(ruleID: rootRule.id)
    )
    XCTAssertEqual(
      evaluator.decision(for: finder),
      .allowedDirect(ruleID: finderRule.id)
    )
  }

  func testPlatformRuleRejectsNonPlatformImpersonator() throws {
    let evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [finderRule]))
    let impersonator = facts(
      token: try token(5),
      team: "ATTACKER01",
      signing: "com.apple.finder"
    )

    XCTAssertEqual(evaluator.decision(for: impersonator), .denied)
  }

  func testPlatformRuleRejectsDifferentSigningIdentifier() throws {
    let evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [finderRule]))
    let otherPlatformBinary = facts(
      token: try token(7),
      signing: "com.apple.TextEdit",
      isPlatformBinary: true
    )

    XCTAssertEqual(evaluator.decision(for: otherPlatformBinary), .denied)
  }

  func testTeamSignedRuleRejectsPlatformBinary() throws {
    let evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))
    let platformBinary = facts(
      token: try token(6),
      team: "TEAM123456",
      signing: "com.example.Editor",
      isPlatformBinary: true
    )

    XCTAssertEqual(evaluator.decision(for: platformBinary), .denied)
  }

  func testObservedChildAndGrandchildInheritAccess() throws {
    let root = try token(10)
    let child = try token(20)
    let grandchild = try token(30)
    var evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))

    evaluator.observeExec(
      facts(
        token: root,
        team: "TEAM123456",
        signing: "com.example.Editor"
      )
    )
    evaluator.observeFork(parent: instance(root), child: instance(child))
    evaluator.observeFork(parent: instance(child), child: instance(grandchild))

    XCTAssertEqual(
      evaluator.decision(for: facts(token: child)),
      .allowedInherited(ruleID: rootRule.id)
    )
    XCTAssertEqual(
      evaluator.decision(for: facts(token: grandchild)),
      .allowedInherited(ruleID: rootRule.id)
    )
  }

  func testInheritedAccessSurvivesExecIntoDifferentProgram() throws {
    let root = try token(40)
    let childBeforeExecToken = try token(41)
    let childAfterCredentialChangeToken = try token(410)
    let childAfterExecToken = try token(42)
    let grandchild = try token(43)
    let childBeforeExec = ProcessInstanceKey(processID: 41, processVersion: 1)
    let childAfterExec = ProcessInstanceKey(processID: 41, processVersion: 2)
    var evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))

    evaluator.observeExec(
      facts(
        token: root,
        team: "TEAM123456",
        signing: "com.example.Editor"
      )
    )
    evaluator.observeFork(parent: instance(root), child: childBeforeExec)
    XCTAssertEqual(
      evaluator.decision(
        for: facts(
          token: childAfterCredentialChangeToken,
          processInstance: childBeforeExec
        )
      ),
      .allowedInherited(ruleID: rootRule.id)
    )
    evaluator.observeExec(
      from: childBeforeExec,
      to: facts(
        token: childAfterExecToken,
        processInstance: childAfterExec,
        team: "SHELLTEAM1",
        signing: "com.example.Shell"
      )
    )
    evaluator.observeFork(parent: childAfterExec, child: instance(grandchild))

    XCTAssertEqual(
      evaluator.decision(
        for: facts(
          token: childAfterExecToken,
          processInstance: childAfterExec,
          team: "SHELLTEAM1",
          signing: "com.example.Shell"
        )
      ),
      .allowedInherited(ruleID: rootRule.id)
    )
    XCTAssertEqual(
      evaluator.decision(for: facts(token: grandchild)),
      .allowedInherited(ruleID: rootRule.id)
    )
    XCTAssertEqual(
      evaluator.decision(
        for: facts(
          token: childBeforeExecToken,
          processInstance: childBeforeExec
        )
      ),
      .denied
    )
  }

  func testUnrelatedInstanceOfDescendantExecutableIsDenied() throws {
    let evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))
    let unrelatedShell = facts(
      token: try token(50),
      team: "SHELLTEAM1",
      signing: "com.example.Shell"
    )

    XCTAssertEqual(evaluator.decision(for: unrelatedShell), .denied)
  }

  func testParentExitDoesNotRevokeLivingChild() throws {
    let root = try token(60)
    let child = try token(61)
    var evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))

    evaluator.observeExec(
      facts(
        token: root,
        team: "TEAM123456",
        signing: "com.example.Editor"
      )
    )
    evaluator.observeFork(parent: instance(root), child: instance(child))
    evaluator.observeExit(instance(root))

    XCTAssertEqual(
      evaluator.decision(for: facts(token: child)),
      .allowedInherited(ruleID: rootRule.id)
    )
  }

  func testDescendantInheritanceRemainsScopedToItsRule() throws {
    let finder = try token(65)
    let finderChild = try token(66)
    let editor = try token(67)
    let editorChild = try token(68)
    var evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [finderRule, rootRule]))

    evaluator.observeExec(
      facts(
        token: finder,
        signing: "com.apple.finder",
        isPlatformBinary: true
      )
    )
    evaluator.observeFork(parent: instance(finder), child: instance(finderChild))
    evaluator.observeExec(
      facts(
        token: editor,
        team: "TEAM123456",
        signing: "com.example.Editor"
      )
    )
    evaluator.observeFork(parent: instance(editor), child: instance(editorChild))

    XCTAssertEqual(evaluator.decision(for: facts(token: finderChild)), .denied)
    XCTAssertEqual(
      evaluator.decision(for: facts(token: editorChild)),
      .allowedInherited(ruleID: rootRule.id)
    )
  }

  func testPolicyReplacementRevokesInheritedAccess() throws {
    let root = try token(70)
    let child = try token(71)
    var evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))

    evaluator.observeExec(
      facts(
        token: root,
        team: "TEAM123456",
        signing: "com.example.Editor"
      )
    )
    evaluator.observeFork(parent: instance(root), child: instance(child))
    evaluator.replacePolicy(with: PolicySnapshot(rules: []))

    XCTAssertEqual(evaluator.decision(for: facts(token: child)), .denied)
  }

  func testPolicyReplacementRevokesLineageWhenIdentityChangesUnderSameRuleID() throws {
    var evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))
    let parent = try token(70)
    let child = try token(71)
    evaluator.observeExec(
      facts(
        token: parent,
        team: "TEAM123456",
        signing: "com.example.Editor"
      )
    )
    evaluator.observeFork(
      parent: facts(token: parent).processInstance,
      child: facts(token: child).processInstance
    )

    let changedIdentity = AllowRule(
      id: rootRule.id,
      program: SignedProgramIdentity(
        teamIdentifier: "OTHERTEAM1",
        signingIdentifier: "com.example.OtherEditor"
      ),
      allowsDescendants: true
    )
    evaluator.replacePolicy(with: PolicySnapshot(rules: [changedIdentity]))

    XCTAssertEqual(evaluator.decision(for: facts(token: child)), .denied)
  }

  func testDirectlyMatchingParentWithUnobservedExecStillPassesAccessDown() throws {
    let root = try token(60)
    let childBeforeExec = ProcessInstanceKey(processID: 61, processVersion: 1)
    let childAsSandbox = ProcessInstanceKey(processID: 61, processVersion: 2)
    let childAsShell = ProcessInstanceKey(processID: 61, processVersion: 3)
    var evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))
    let rootFacts = facts(
      token: root,
      team: "TEAM123456",
      signing: "com.example.Editor"
    )
    let childFacts = facts(
      token: try token(61),
      processInstance: childBeforeExec,
      team: "TEAM123456",
      signing: "com.example.Editor"
    )
    let sandboxFacts = facts(
      token: try token(62),
      processInstance: childAsSandbox,
      signing: "com.apple.sandbox-exec",
      isPlatformBinary: true
    )
    let shellFacts = facts(
      token: try token(63),
      processInstance: childAsShell,
      signing: "com.apple.zsh",
      isPlatformBinary: true
    )

    // The root's exec happened before observation began, so only its fork is seen.
    evaluator.observeFork(parent: rootFacts, child: childBeforeExec)
    evaluator.observeExec(from: childFacts, to: sandboxFacts)
    evaluator.observeExec(from: sandboxFacts, to: shellFacts)

    XCTAssertEqual(evaluator.decision(for: rootFacts), .allowedDirect(ruleID: rootRule.id))
    XCTAssertEqual(
      evaluator.decision(for: shellFacts),
      .allowedInherited(ruleID: rootRule.id)
    )
  }

  func testDirectlyMatchingSourceOfUnobservedExecPassesAccessToNewImage() throws {
    let before = ProcessInstanceKey(processID: 70, processVersion: 1)
    let after = ProcessInstanceKey(processID: 70, processVersion: 2)
    var evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))
    let shellFacts = facts(
      token: try token(71),
      processInstance: after,
      signing: "com.apple.zsh",
      isPlatformBinary: true
    )

    evaluator.observeExec(
      from: facts(
        token: try token(70),
        processInstance: before,
        team: "TEAM123456",
        signing: "com.example.Editor"
      ),
      to: shellFacts
    )

    XCTAssertEqual(
      evaluator.decision(for: shellFacts),
      .allowedInherited(ruleID: rootRule.id)
    )
  }

  func testDirectlyMatchingParentWithoutDescendantPermissionPassesNothing() throws {
    let finder = try token(80)
    let child = try token(81)
    var evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [finderRule]))

    evaluator.observeFork(
      parent: facts(
        token: finder,
        signing: "com.apple.finder",
        isPlatformBinary: true
      ),
      child: instance(child)
    )

    XCTAssertEqual(evaluator.decision(for: facts(token: child)), .denied)
  }

  private func token(_ seed: UInt32) throws -> AuditTokenKey {
    try AuditTokenKey(words: (0..<8).map { seed + UInt32($0) })
  }

  private func facts(
    token: AuditTokenKey,
    processInstance: ProcessInstanceKey? = nil,
    team: String? = nil,
    signing: String? = nil,
    isPlatformBinary: Bool = false
  ) -> ProcessFacts {
    ProcessFacts(
      auditToken: token,
      processInstance: processInstance ?? instance(token),
      teamIdentifier: team,
      signingIdentifier: signing,
      isPlatformBinary: isPlatformBinary
    )
  }

  private func instance(_ token: AuditTokenKey) -> ProcessInstanceKey {
    ProcessInstanceKey(
      processID: Int32(token.words[0]),
      processVersion: 1
    )
  }
}
