import XCTest

@testable import PasuFSPolicy

final class PolicyEvaluatorTests: XCTestCase {
  private let rootRule = AllowRule(
    id: "allow.example.editor",
    program: SignedProgramIdentity(
      teamIdentifier: "TEAM123456",
      signingIdentifier: "com.example.Editor"
    ),
    allowsDescendants: true
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

  func testDifferentSigningIdentityIsDenied() throws {
    let evaluator = PolicyEvaluator(policy: PolicySnapshot(rules: [rootRule]))
    let process = facts(
      token: try token(2),
      team: "OTHERTEAM1",
      signing: "com.example.Editor"
    )

    XCTAssertEqual(evaluator.decision(for: process), .denied)
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

  private func token(_ seed: UInt32) throws -> AuditTokenKey {
    try AuditTokenKey(words: (0..<8).map { seed + UInt32($0) })
  }

  private func facts(
    token: AuditTokenKey,
    processInstance: ProcessInstanceKey? = nil,
    team: String? = nil,
    signing: String? = nil
  ) -> ProcessFacts {
    ProcessFacts(
      auditToken: token,
      processInstance: processInstance ?? instance(token),
      teamIdentifier: team,
      signingIdentifier: signing
    )
  }

  private func instance(_ token: AuditTokenKey) -> ProcessInstanceKey {
    ProcessInstanceKey(
      processID: Int32(token.words[0]),
      processVersion: 1
    )
  }
}
