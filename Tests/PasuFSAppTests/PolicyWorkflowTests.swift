import Foundation
import PasuFSConfiguration
import PasuFSHostCore
import XCTest

@testable import PasuFSApp

@MainActor
final class PolicyWorkflowTests: XCTestCase {
  func testCreatingAPolicyAddsAnUnsavedDraftWithTheChosenBehavior() {
    let model = AppModel(activationController: EmptyLifecycle())
    model.createPolicy(
      name: "  Project Secrets  ", protectedRootPath: "/Users/example/Secrets", mode: .audit)

    let id = try! XCTUnwrap(model.selectedPolicyID)
    let draft = try! XCTUnwrap(model.policyDraft(id: id))
    XCTAssertEqual(draft.name, "Project Secrets")
    XCTAssertEqual(draft.mode, .audit)
    XCTAssertFalse(draft.isBlacklistEnabled)
    XCTAssertEqual(draft.allowRules, [])
    XCTAssertEqual(draft.denyRules, [])
    XCTAssertEqual(draft.protectedRootPath, "/Users/example/Secrets")
    XCTAssertNil(model.activePolicy(id: id))
    XCTAssertTrue(model.isPolicyDirty(id))
  }

  func testFolderConflictsConsiderOtherDrafts() {
    let model = AppModel(activationController: EmptyLifecycle())
    model.createPolicy(
      name: "Secrets", protectedRootPath: "/Users/example/Secrets", mode: .audit)
    let id = try! XCTUnwrap(model.selectedPolicyID)

    XCTAssertEqual(
      model.conflictingPolicyName(mode: .audit, path: "/Users/example/Secrets/"), "Secrets")
    XCTAssertNil(model.conflictingPolicyName(mode: .protection, path: "/Users/example/Secrets"))
    XCTAssertNil(
      model.conflictingPolicyName(mode: .audit, path: "/Users/example/Secrets", excluding: id))
  }

  func testRulesGoToTheChosenListWithDescendantsOffByDefault() throws {
    let model = AppModel(activationController: EmptyLifecycle())
    model.createPolicy(
      name: "Keys", protectedRootPath: "/Users/example/Keys", mode: .protection)
    let id = try XCTUnwrap(model.selectedPolicyID)

    let candidate = model.manualCandidate(
      kind: .teamSigned, teamIdentifier: " abcde12345 ", signingIdentifier: " com.example.tool ")
    XCTAssertEqual(candidate.teamIdentifier, "ABCDE12345")
    XCTAssertEqual(candidate.signingIdentifier, "com.example.tool")
    try model.addRule(policyID: id, to: .allow, from: candidate)

    let rule = try XCTUnwrap(model.policyDraft(id: id)?.allowRules.first)
    XCTAssertEqual(rule.kind, .teamSigned)
    XCTAssertEqual(rule.teamIdentifier, "ABCDE12345")
    XCTAssertFalse(rule.allowsDescendants)
    XCTAssertEqual(model.policyDraft(id: id)?.denyRules, [])
    XCTAssertThrowsError(try model.addRule(policyID: id, to: .allow, from: candidate))

    // The same program may be in the other list, with its own rule ID.
    try model.addRule(policyID: id, to: .deny, from: candidate)
    let denyRule = try XCTUnwrap(model.policyDraft(id: id)?.denyRules.first)
    XCTAssertNotEqual(denyRule.id, rule.id)
    XCTAssertNoThrow(try model.candidateDocument(replacing: id, with: model.policyDraft(id: id)))

    // Rules are changed and removed by ID, whichever list holds them.
    var disabled = denyRule
    disabled.isEnabled = false
    model.updateRule(policyID: id, rule: disabled)
    XCTAssertEqual(model.policyDraft(id: id)?.denyRules, [disabled])
    XCTAssertEqual(model.policyDraft(id: id)?.allowRules, [rule])
    model.removeRule(policyID: id, ruleID: denyRule.id)
    XCTAssertEqual(model.policyDraft(id: id)?.denyRules, [])
    XCTAssertEqual(model.policyDraft(id: id)?.allowRules, [rule])

    let platform = model.manualCandidate(
      kind: .platformBinary, teamIdentifier: "IGNORED", signingIdentifier: "com.apple.example")
    XCTAssertNil(platform.teamIdentifier)
    XCTAssertThrowsError(
      try model.addRule(
        policyID: id, to: .allow,
        from: model.manualCandidate(
          kind: .platformBinary, teamIdentifier: "", signingIdentifier: "  ")))
  }

  func testDescendantOptInIsLimitedToAllowRulesAndSurvivesEditing() throws {
    let model = AppModel(activationController: EmptyLifecycle())
    model.createPolicy(
      name: "Example", protectedRootPath: "/Users/example/Protected",
      mode: .protection)
    let id = try XCTUnwrap(model.selectedPolicyID)
    let candidate = model.manualCandidate(
      kind: .teamSigned, teamIdentifier: "TEAM123456",
      signingIdentifier: "com.example.agent")
    try model.addRule(policyID: id, to: .allow, from: candidate, allowsDescendants: true)
    try model.addRule(policyID: id, to: .deny, from: candidate, allowsDescendants: true)
    XCTAssertFalse(try XCTUnwrap(model.policyDraft(id: id)?.denyRules.first).allowsDescendants)
    var allow = try XCTUnwrap(model.policyDraft(id: id)?.allowRules.first)
    XCTAssertTrue(allow.allowsDescendants)
    model.setAllowListInUse(policyID: id, false)
    model.setAllowListInUse(policyID: id, true)
    XCTAssertEqual(model.policyDraft(id: id)?.allowRules.first, allow)
    allow.allowsDescendants = false
    model.updateRule(policyID: id, rule: allow)
    let saved = try model.candidateDocument(replacing: id, with: model.policyDraft(id: id))
    XCTAssertFalse(try XCTUnwrap(saved.policies.first?.allowRules.first).allowsDescendants)
  }

  func testAddingSeveralProgramsAtOnceIsAllOrNothing() throws {
    let model = AppModel(activationController: EmptyLifecycle())
    model.createPolicy(name: "Keys", protectedRootPath: "/Users/example/Keys", mode: .protection)
    let id = try XCTUnwrap(model.selectedPolicyID)
    let agent = model.manualCandidate(
      kind: .teamSigned, teamIdentifier: "TEAM123456", signingIdentifier: "com.example.agent")
    let shell = model.manualCandidate(
      kind: .platformBinary, teamIdentifier: "", signingIdentifier: "com.apple.zsh")
    try model.addRules(policyID: id, to: .allow, from: [agent, shell], allowsDescendants: true)
    var rules = try XCTUnwrap(model.policyDraft(id: id)?.allowRules)
    XCTAssertEqual(rules.map(\.signingIdentifier), ["com.example.agent", "com.apple.zsh"])
    XCTAssertEqual(rules.map(\.allowsDescendants), [true, true])
    XCTAssertEqual(Set(rules.map(\.id)).count, 2)

    // A program already in the list, named twice, or without a complete identity stops the
    // whole addition.
    let tool = model.manualCandidate(
      kind: .platformBinary, teamIdentifier: "", signingIdentifier: "com.apple.tool")
    XCTAssertThrowsError(try model.addRules(policyID: id, to: .allow, from: [tool, agent]))
    XCTAssertThrowsError(try model.addRules(policyID: id, to: .allow, from: [tool, tool]))
    let incomplete = model.manualCandidate(
      kind: .teamSigned, teamIdentifier: "", signingIdentifier: "com.example.noteam")
    XCTAssertThrowsError(try model.addRules(policyID: id, to: .allow, from: [tool, incomplete]))
    XCTAssertEqual(model.policyDraft(id: id)?.allowRules, rules)

    try model.addRules(policyID: id, to: .deny, from: [tool, agent], allowsDescendants: true)
    rules = try XCTUnwrap(model.policyDraft(id: id)?.denyRules)
    XCTAssertEqual(rules.map(\.signingIdentifier), ["com.apple.tool", "com.example.agent"])
    XCTAssertEqual(rules.map(\.allowsDescendants), [false, false])
  }

  func testCopyingRulesOfAnotherPolicyKeepsTheirSettingsAndIsAllOrNothing() throws {
    let model = AppModel(activationController: EmptyLifecycle())
    model.createPolicy(
      name: "Source", protectedRootPath: "/Users/example/Source", mode: .protection)
    let sourceID = try XCTUnwrap(model.selectedPolicyID)
    let agent = model.manualCandidate(
      kind: .teamSigned, teamIdentifier: "team123456", signingIdentifier: "com.example.agent")
    let shell = model.manualCandidate(
      kind: .platformBinary, teamIdentifier: "", signingIdentifier: "com.apple.zsh")
    try model.addRule(policyID: sourceID, to: .allow, from: agent, allowsDescendants: true)
    try model.addRule(policyID: sourceID, to: .allow, from: shell)
    var off = try XCTUnwrap(model.policyDraft(id: sourceID)?.allowRules.last)
    off.isEnabled = false
    model.updateRule(policyID: sourceID, rule: off)
    let originals = try XCTUnwrap(model.policyDraft(id: sourceID)?.allowRules)

    model.createPolicy(name: "Target", protectedRootPath: "/Users/example/Target", mode: .audit)
    let targetID = try XCTUnwrap(model.selectedPolicyID)
    XCTAssertFalse(
      model.policyContainsIdentity(policyID: targetID, list: .allow, rule: originals[0]))
    try model.addRules(policyID: targetID, to: .allow, copying: originals)
    let copies = try XCTUnwrap(model.policyDraft(id: targetID)?.allowRules)
    XCTAssertEqual(copies.map(\.signingIdentifier), ["com.example.agent", "com.apple.zsh"])
    XCTAssertEqual(copies.map(\.teamIdentifier), ["TEAM123456", nil])
    XCTAssertEqual(copies.map(\.allowsDescendants), [true, false])
    XCTAssertEqual(copies.map(\.isEnabled), [true, false])
    XCTAssertTrue(Set(copies.map(\.id)).isDisjoint(with: originals.map(\.id)))
    XCTAssertEqual(Set(copies.map(\.id)).count, 2)
    XCTAssertTrue(
      model.policyContainsIdentity(policyID: targetID, list: .allow, rule: originals[0]))
    XCTAssertEqual(model.policyDraft(id: sourceID)?.allowRules, originals)
    XCTAssertNoThrow(
      try model.candidateDocument(replacing: targetID, with: model.policyDraft(id: targetID)))

    // A program already in the list, or one named twice, stops the whole copy.
    XCTAssertThrowsError(try model.addRules(policyID: targetID, to: .allow, copying: originals))
    XCTAssertThrowsError(
      try model.addRules(policyID: targetID, to: .deny, copying: [originals[0], originals[0]]))
    XCTAssertEqual(model.policyDraft(id: targetID)?.allowRules, copies)
    XCTAssertEqual(model.policyDraft(id: targetID)?.denyRules, [])

    // Programs to Block has no descendant option; the rule's state is kept.
    try model.addRules(policyID: targetID, to: .deny, copying: originals)
    let blocked = try XCTUnwrap(model.policyDraft(id: targetID)?.denyRules)
    XCTAssertEqual(blocked.map(\.allowsDescendants), [false, false])
    XCTAssertEqual(blocked.map(\.isEnabled), [true, false])
  }

  func testDuplicatingAPolicyCopiesItsListsAndSettingsWithoutTheFolder() throws {
    let model = AppModel(activationController: EmptyLifecycle())
    model.createPolicy(name: "Keys", protectedRootPath: "/Users/example/Keys", mode: .protection)
    let id = try XCTUnwrap(model.selectedPolicyID)
    try model.addRule(
      policyID: id, to: .allow,
      from: model.manualCandidate(
        kind: .teamSigned, teamIdentifier: "TEAM123456", signingIdentifier: "com.example.agent"),
      allowsDescendants: true)
    try model.addRule(
      policyID: id, to: .deny,
      from: model.manualCandidate(
        kind: .platformBinary, teamIdentifier: "", signingIdentifier: "com.apple.cat"))
    model.setAllowListInUse(policyID: id, false)
    model.createPolicy(name: "Other", protectedRootPath: "/Users/example/Other", mode: .audit)
    model.pendingFolderEntryPolicyID = nil
    let before = try XCTUnwrap(model.policyDraft(id: id))

    model.duplicatePolicy(id: id)
    let copyID = try XCTUnwrap(model.selectedPolicyID)
    XCTAssertNotEqual(copyID, id)
    let copy = try XCTUnwrap(model.policyDraft(id: copyID))
    XCTAssertEqual(copy.name, "Keys copy")
    XCTAssertEqual(copy.protectedRootPath, "")
    XCTAssertEqual(copy.mode, .protection)
    XCTAssertTrue(copy.isBlacklistEnabled)
    XCTAssertEqual(copy.allowRules.map(\.signingIdentifier), ["com.example.agent"])
    XCTAssertEqual(copy.allowRules.map(\.allowsDescendants), [true])
    XCTAssertEqual(copy.denyRules.map(\.signingIdentifier), ["com.apple.cat"])
    XCTAssertTrue(
      Set((copy.allowRules + copy.denyRules).map(\.id)).isDisjoint(
        with: (before.allowRules + before.denyRules).map(\.id)))
    XCTAssertEqual(model.policyDraft(id: id), before)
    XCTAssertEqual(model.sidebarPolicies.map(\.name), ["Keys", "Keys copy", "Other"])
    XCTAssertEqual(model.pendingFolderEntryPolicyID, copyID)
    XCTAssertNil(model.activePolicy(id: copyID))
    XCTAssertTrue(model.isPolicyDirty(copyID))
    model.updatePolicyDraft(id: copyID) { $0.protectedRootPath = "/Users/example/Copy" }
    XCTAssertNoThrow(
      try model.candidateDocument(replacing: copyID, with: model.policyDraft(id: copyID)))

    // The next copy of the same policy gets the next free number, counting other drafts' names.
    model.duplicatePolicy(id: id)
    let secondID = try XCTUnwrap(model.selectedPolicyID)
    XCTAssertEqual(model.policyDraft(id: secondID)?.name, "Keys copy 2")
    XCTAssertEqual(
      model.sidebarPolicies.map(\.name), ["Keys", "Keys copy 2", "Keys copy", "Other"])
  }

  func testCopyNamesFitTheLengthLimitAndAnEmptyNameIsNumbered() throws {
    let model = AppModel(activationController: EmptyLifecycle())
    let long = String(repeating: "k", count: PolicySetDocument.maximumPolicyNameLength)
    model.createPolicy(name: long, protectedRootPath: "/Users/example/Long", mode: .audit)
    let id = try XCTUnwrap(model.selectedPolicyID)
    model.duplicatePolicy(id: id)
    let copyID = try XCTUnwrap(model.selectedPolicyID)
    let name = try XCTUnwrap(model.policyDraft(id: copyID)?.name)
    XCTAssertEqual(name.count, PolicySetDocument.maximumPolicyNameLength)
    XCTAssertTrue(name.hasSuffix(" copy"))
    model.updatePolicyDraft(id: copyID) { $0.protectedRootPath = "/Users/example/Copy" }
    XCTAssertNoThrow(
      try model.candidateDocument(replacing: copyID, with: model.policyDraft(id: copyID)))

    model.updatePolicyDraft(id: id) { $0.name = "" }
    model.duplicatePolicy(id: id)
    let numbered = try XCTUnwrap(model.policyDraft(id: try XCTUnwrap(model.selectedPolicyID)))
    XCTAssertEqual(numbered.name, "Policy 1")
  }

  func testProgramSummariesGroupRecordsBySigningIdentity() {
    let policyID = UUID()
    let records = [
      record(team: "ABCDE12345", signing: "com.example.agent", decision: .wouldDeny, second: 1),
      record(team: "ABCDE12345", signing: "com.example.agent", decision: .wouldDeny, second: 3),
      record(platformSigning: "com.apple.git", decision: .wouldAllow, second: 2),
      record(path: "/opt/example/bin/tool", decision: .wouldDeny, second: 4),
    ].map { withPolicy($0, policyID) }

    let summaries = PolicyProgramSummarizer.summaries(
      records: records, policyID: policyID, displayName: { signing, _ in signing })

    XCTAssertEqual(summaries.count, 3)
    let agent = try! XCTUnwrap(summaries.first { $0.id == "team:ABCDE12345:com.example.agent" })
    XCTAssertEqual(agent.observationCount, 2)
    XCTAssertEqual(agent.deniedCount, 2)
    XCTAssertEqual(agent.latestDecision, .wouldDeny)
    XCTAssertEqual(agent.ruleCandidate?.kind, .teamSigned)
    let tool = try! XCTUnwrap(summaries.first { $0.id == "unsigned:/opt/example/bin/tool" })
    XCTAssertNil(tool.ruleCandidate)
    XCTAssertEqual(summaries.first?.id, "unsigned:/opt/example/bin/tool")
  }

  func testProgramSummariesAddTheRequestsEachRecordStandsFor() throws {
    let policyID = UUID()
    var storm = withPolicy(
      record(team: "ABCDE12345", signing: "com.example.agent", decision: .wouldDeny, second: 1),
      policyID)
    storm.requestCount = 20_000
    storm.lastTimestamp = Date(timeIntervalSince1970: 1_800_000_009)
    let single = withPolicy(
      record(team: "ABCDE12345", signing: "com.example.agent", decision: .wouldAllow, second: 5),
      policyID)
    var allowed = withPolicy(
      record(team: "ABCDE12345", signing: "com.example.agent", decision: .wouldAllow, second: 6),
      policyID)
    allowed.requestCount = 3

    let summaries = PolicyProgramSummarizer.summaries(
      records: [storm, single, allowed], policyID: policyID, displayName: { signing, _ in signing })

    let agent = try XCTUnwrap(summaries.first)
    XCTAssertEqual(summaries.count, 1)
    XCTAssertEqual(agent.observationCount, 20_004)
    XCTAssertEqual(agent.deniedCount, 20_000)
    XCTAssertEqual(agent.allowedCount, 4)
    // The last request of the storm is the program's latest access.
    XCTAssertEqual(agent.lastSeen, Date(timeIntervalSince1970: 1_800_000_009))
    XCTAssertEqual(agent.latestDecision, .wouldDeny)
    XCTAssertEqual(agent.ruleCandidate?.observationCount, 20_004)
    XCTAssertEqual(PolicyLogRow(record: storm).requestCount, 20_000)
    XCTAssertEqual(PolicyLogRow(record: single).requestCount, 1)
  }

  func testProgramSummariesMarkALatestDecisionFromAnEarlierRevision() throws {
    let policyID = UUID()
    let scanner = [1.0, 2.0].map { second in
      withRevision(
        withPolicy(
          record(platformSigning: "com.example.scanner", decision: .deny, second: second), policyID),
        66)
    }
    // The agent was denied under revision 66 and allowed after the policies changed.
    let agent = [
      withRevision(
        withPolicy(
          record(team: "ABCDE12345", signing: "com.example.agent", decision: .deny, second: 3),
          policyID),
        66),
      withRevision(
        withPolicy(
          record(team: "ABCDE12345", signing: "com.example.agent", decision: .allow, second: 4),
          policyID),
        71),
    ]
    // A record from a revision the app has not loaded yet is not marked.
    let tool = withRevision(
      withPolicy(record(platformSigning: "com.example.tool", decision: .deny, second: 5), policyID),
      72)

    let summaries = PolicyProgramSummarizer.summaries(
      records: scanner + agent + [tool], policyID: policyID, currentRevision: 71,
      displayName: { signing, _ in signing })

    let scannerSummary = try XCTUnwrap(summaries.first { $0.id == "platform:com.example.scanner" })
    XCTAssertEqual(scannerSummary.latestDecision, .deny)
    XCTAssertEqual(scannerSummary.latestDecisionRevision, 66)
    XCTAssertEqual(scannerSummary.currentRevision, 71)
    XCTAssertTrue(scannerSummary.latestDecisionPrecedesCurrentRevision)
    XCTAssertEqual(scannerSummary.deniedCount, 2)
    let agentSummary = try XCTUnwrap(
      summaries.first { $0.id == "team:ABCDE12345:com.example.agent" })
    XCTAssertEqual(agentSummary.latestDecision, .allow)
    XCTAssertEqual(agentSummary.latestDecisionRevision, 71)
    XCTAssertFalse(agentSummary.latestDecisionPrecedesCurrentRevision)
    // The counts still add up the records of every revision.
    XCTAssertEqual(agentSummary.deniedCount, 1)
    XCTAssertEqual(agentSummary.allowedCount, 1)
    let toolSummary = try XCTUnwrap(summaries.first { $0.id == "platform:com.example.tool" })
    XCTAssertFalse(toolSummary.latestDecisionPrecedesCurrentRevision)
  }

  func testProgramSummariesKeepTheRevisionOfTheRecordThatDecided() throws {
    let policyID = UUID()
    let decided = withRevision(
      withPolicy(
        record(platformSigning: "com.example.scanner", decision: .deny, second: 1), policyID),
      66)
    // A later record with no decision updates the last access but not the latest decision.
    let undecided = withRevision(
      record(platformSigning: "com.example.scanner", decision: .allow, second: 2), 71)
    let unnumbered = withPolicy(
      record(platformSigning: "com.example.tool", decision: .deny, second: 3), policyID)

    let summaries = PolicyProgramSummarizer.summaries(
      records: [decided, undecided, unnumbered], policyID: policyID, currentRevision: 71,
      displayName: { signing, _ in signing })

    let scanner = try XCTUnwrap(summaries.first { $0.id == "platform:com.example.scanner" })
    XCTAssertEqual(scanner.lastSeen, undecided.timestamp)
    XCTAssertEqual(scanner.latestDecision, .deny)
    XCTAssertEqual(scanner.latestDecisionRevision, 66)
    XCTAssertTrue(scanner.latestDecisionPrecedesCurrentRevision)
    // A record that names no revision is not marked: nothing shows it is from an earlier one.
    let tool = try XCTUnwrap(summaries.first { $0.id == "platform:com.example.tool" })
    XCTAssertNil(tool.latestDecisionRevision)
    XCTAssertFalse(tool.latestDecisionPrecedesCurrentRevision)
    // Without the revision in use, no decision is marked.
    let unknown = PolicyProgramSummarizer.summaries(
      records: [decided], policyID: policyID, displayName: { signing, _ in signing })
    XCTAssertFalse(try XCTUnwrap(unknown.first).latestDecisionPrecedesCurrentRevision)
  }

  func testSavingMarksTheDecisionsMadeBeforeTheSave() async throws {
    let policy = DirectoryPolicy(
      name: "Secrets", mode: .audit, policyType: .whitelist,
      protectedRootPath: FileManager.default.temporaryDirectory.path, rules: [])
    let model = AppModel(
      initialPolicySet: PolicySetDocument(setIdentifier: UUID(), revision: 3, policies: [policy]),
      activationController: EmptyLifecycle(),
      runtimeController: AcceptingRuntime())
    try XCTUnwrap(model.policyLogState(policyID: policy.id)).batch = AuditLogBatch(records: [
      withRevision(
        withPolicy(
          record(platformSigning: "com.example.scanner", decision: .wouldDeny, second: 1), policy.id
        ),
        3)
    ])
    let before = try XCTUnwrap(model.policyProgramSummaries(policyID: policy.id).first)
    XCTAssertEqual(before.currentRevision, 3)
    XCTAssertFalse(before.latestDecisionPrecedesCurrentRevision)

    await model.switchToProtection(policyID: policy.id)

    XCTAssertNil(model.lastError)
    let after = try XCTUnwrap(model.policyProgramSummaries(policyID: policy.id).first)
    XCTAssertEqual(after.currentRevision, 4)
    XCTAssertEqual(after.latestDecision, .wouldDeny)
    XCTAssertTrue(after.latestDecisionPrecedesCurrentRevision)
  }

  func testSwitchingToProtectionSavesTheDraft() async throws {
    let setID = UUID()
    let policy = DirectoryPolicy(
      name: "Secrets", mode: .audit, policyType: .whitelist,
      protectedRootPath: FileManager.default.temporaryDirectory.path, rules: [])
    let runtime = AcceptingRuntime()
    let model = AppModel(
      initialPolicySet: PolicySetDocument(setIdentifier: setID, revision: 3, policies: [policy]),
      activationController: EmptyLifecycle(),
      runtimeController: runtime)

    await model.switchToProtection(policyID: policy.id)

    XCTAssertNil(model.lastError)
    XCTAssertEqual(model.activePolicy(id: policy.id)?.mode, .protection)
    XCTAssertEqual(model.activeRevision, 4)
    XCTAssertFalse(model.isPolicyDirty(policy.id))
    let applied = await runtime.appliedRevisions
    XCTAssertEqual(applied, [4])
  }

  func testRecentDenialsComeFromPolicyLogsNewestFirstWithoutDuplicates() throws {
    let folder = FileManager.default.temporaryDirectory.path
    let first = DirectoryPolicy(
      name: "First", mode: .protection, policyType: .whitelist,
      protectedRootPath: folder + "/first", rules: [])
    let second = DirectoryPolicy(
      name: "Second", mode: .protection, policyType: .whitelist,
      protectedRootPath: folder + "/second", rules: [])
    let model = AppModel(
      initialPolicySet: PolicySetDocument(
        setIdentifier: UUID(), revision: 1, policies: [first, second]),
      activationController: EmptyLifecycle())
    let base = Date(timeIntervalSince1970: 1_800_000_000)
    let shared = AuditEventRecord(
      timestamp: base.addingTimeInterval(9), eventType: "AUTH_OPEN", policyDecision: "deny",
      kernelResponse: "deny")
    try XCTUnwrap(model.policyLogState(policyID: first.id)).batch = AuditLogBatch(records: [
      AuditEventRecord(
        timestamp: base, eventType: "AUTH_OPEN", policyDecision: "deny", kernelResponse: "deny"),
      AuditEventRecord(
        timestamp: base.addingTimeInterval(5), eventType: "AUTH_OPEN",
        policyDecision: "audit-only", kernelResponse: "allow"),
      shared,
    ])
    try XCTUnwrap(model.policyLogState(policyID: second.id)).batch = AuditLogBatch(records: [
      shared
    ])

    let recent = model.recentDenials(limit: 5)
    XCTAssertEqual(recent.map(\.record.timestamp), [base.addingTimeInterval(9), base])
    XCTAssertEqual(model.recentDenials(limit: 1).count, 1)

    model.showPolicyLogRecord(policyID: second.id, recordID: shared.id)
    XCTAssertEqual(model.selectedSection, .policy(second.id))
    XCTAssertEqual(model.pendingPolicyLogPolicyID, second.id)
    let log = try XCTUnwrap(model.policyLogState(policyID: second.id))
    XCTAssertEqual(log.selectedEventIDs, [shared.id])
    XCTAssertEqual(log.presentation, .events)
    XCTAssertTrue(log.wantsInspector)
    // The Log tab shows the inspector itself once the window has dropped its minimum width.
    XCTAssertFalse(log.showsInspector)

    // The window keeps its minimum width until that Log tab is on screen.
    XCTAssertFalse(model.relaxesMainWindowMinimumWidth)
    log.isOnScreen = true
    XCTAssertTrue(model.relaxesMainWindowMinimumWidth)
    log.wantsInspector = false
    XCTAssertFalse(model.relaxesMainWindowMinimumWidth)
    log.wantsInspector = true
    model.selectedSection = .overview
    XCTAssertFalse(model.relaxesMainWindowMinimumWidth)
  }

  // MARK: - Helpers

  private func record(
    team: String? = nil, signing: String? = nil, platformSigning: String? = nil,
    path: String? = nil, decision: PolicyEvaluationDecision, second: Double
  ) -> AuditEventRecord {
    AuditEventRecord(
      timestamp: Date(timeIntervalSince1970: 1_800_000_000 + second),
      eventType: "AUTH_OPEN",
      executablePath: path ?? "/example/bin/program",
      teamIdentifier: team,
      signingIdentifier: platformSigning ?? signing,
      isPlatformBinary: platformSigning != nil ? true : (team != nil ? false : nil),
      targetPath: "/Users/example/Secrets/file-\(Int(second))",
      policyDecision: decision.rawValue,
      kernelResponse: "allow")
  }

  private func withPolicy(_ record: AuditEventRecord, _ policyID: UUID) -> AuditEventRecord {
    var record = record
    record.policyEvaluations = [
      PolicyEvaluationRecord(
        policyIdentifier: policyID, policyName: "Secrets", mode: .audit, policyType: .whitelist,
        match: .none, decision: PolicyEvaluationDecision(rawValue: record.policyDecision)!)
    ]
    return record
  }

  private func withRevision(_ record: AuditEventRecord, _ revision: UInt64) -> AuditEventRecord {
    var record = record
    record.policyRevision = revision
    return record
  }
}

/// Reports no installed extension without contacting macOS.
private struct EmptyLifecycle: ExtensionLifecycleControlling {
  func installationStateLauncher() -> any InstallationStateChildLaunching {
    inProcessInstallationStateLauncher()
  }

  func activationEvents() -> AsyncStream<ActivationEvent> { finished() }
  func deactivationEvents() -> AsyncStream<ActivationEvent> { finished() }
  func propertiesEvents() -> AsyncStream<ActivationEvent> {
    AsyncStream { continuation in
      continuation.yield(.properties([]))
      continuation.finish()
    }
  }

  private func finished() -> AsyncStream<ActivationEvent> {
    AsyncStream { $0.finish() }
  }
}

private actor AcceptingRuntime: ExtensionRuntimeControlling {
  private(set) var appliedRevisions: [UInt64] = []

  func applyPolicySet(
    _ document: PolicySetDocument, authorization: Data?, savedPolicyIdentifier: UUID?
  ) async throws -> PolicyApplyReceipt {
    appliedRevisions.append(document.revision)
    return PolicyApplyReceipt(
      result: .accepted, acceptedSetIdentifier: document.setIdentifier,
      acceptedRevision: document.revision,
      acceptedDigest: try PolicySetDocumentCodec.digest(of: document))
  }

  func queryStatus() async throws -> ExtensionStatusSnapshot {
    throw ExtensionControlClientError.interfaceUnavailable
  }

  func queryPolicySet() async throws -> PolicySetDocument { throw Unused.call }

  func readAuditLog(maximumLineCount: Int) async throws -> AuditLogBatch { throw Unused.call }

  func invalidate() {}

  private enum Unused: Error { case call }
}
