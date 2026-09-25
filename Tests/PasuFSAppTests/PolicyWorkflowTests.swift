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
      name: "  Project Secrets  ", protectedRootPath: "/Users/example/Secrets", mode: .audit,
      policyType: .whitelist)

    let id = try! XCTUnwrap(model.selectedPolicyID)
    let draft = try! XCTUnwrap(model.policyDraft(id: id))
    XCTAssertEqual(draft.name, "Project Secrets")
    XCTAssertEqual(draft.mode, .audit)
    XCTAssertEqual(draft.policyType, .whitelist)
    XCTAssertEqual(draft.protectedRootPath, "/Users/example/Secrets")
    XCTAssertNil(model.activePolicy(id: id))
    XCTAssertTrue(model.isPolicyDirty(id))
  }

  func testFolderConflictsConsiderOtherDrafts() {
    let model = AppModel(activationController: EmptyLifecycle())
    model.createPolicy(
      name: "Secrets", protectedRootPath: "/Users/example/Secrets", mode: .audit,
      policyType: .whitelist)
    let id = try! XCTUnwrap(model.selectedPolicyID)

    XCTAssertEqual(
      model.conflictingPolicyName(mode: .audit, path: "/Users/example/Secrets/"), "Secrets")
    XCTAssertNil(model.conflictingPolicyName(mode: .protection, path: "/Users/example/Secrets"))
    XCTAssertNil(
      model.conflictingPolicyName(mode: .audit, path: "/Users/example/Secrets", excluding: id))
  }

  func testRulesAddedFromAProgramKeepTheChildProcessChoice() throws {
    let model = AppModel(activationController: EmptyLifecycle())
    model.createPolicy(
      name: "Keys", protectedRootPath: "/Users/example/Keys", mode: .protection,
      policyType: .whitelist)
    let id = try XCTUnwrap(model.selectedPolicyID)

    let candidate = model.manualCandidate(
      kind: .teamSigned, teamIdentifier: " abcde12345 ", signingIdentifier: " com.example.tool ")
    XCTAssertEqual(candidate.teamIdentifier, "ABCDE12345")
    XCTAssertEqual(candidate.signingIdentifier, "com.example.tool")
    try model.addRule(policyID: id, from: candidate, allowsDescendants: true)

    let rule = try XCTUnwrap(model.policyDraft(id: id)?.rules.first)
    XCTAssertEqual(rule.kind, .teamSigned)
    XCTAssertEqual(rule.teamIdentifier, "ABCDE12345")
    XCTAssertTrue(rule.allowsDescendants)
    XCTAssertThrowsError(try model.addRule(policyID: id, from: candidate))

    let platform = model.manualCandidate(
      kind: .platformBinary, teamIdentifier: "IGNORED", signingIdentifier: "com.apple.example")
    XCTAssertNil(platform.teamIdentifier)
    XCTAssertThrowsError(
      try model.addRule(
        policyID: id,
        from: model.manualCandidate(
          kind: .platformBinary, teamIdentifier: "", signingIdentifier: "  ")))
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

  func testProjectedDenialsFollowTheDraftRules() {
    let policyID = UUID()
    let records = [
      record(team: "ABCDE12345", signing: "com.example.agent", decision: .wouldDeny, second: 1),
      record(platformSigning: "com.apple.git", decision: .wouldAllow, second: 2),
      record(path: "/opt/example/bin/tool", decision: .wouldDeny, second: 3),
    ].map { withPolicy($0, policyID) }
    let summaries = PolicyProgramSummarizer.summaries(
      records: records, policyID: policyID, displayName: { signing, _ in signing })

    let noRules = PolicyProgramSummarizer.projectedDenials(
      summaries: summaries, policyType: .whitelist, rules: [])
    XCTAssertEqual(
      Set(noRules.map(\.id)),
      ["team:ABCDE12345:com.example.agent", "unsigned:/opt/example/bin/tool"])

    let allowed = PolicyRule.teamSigned(
      id: "rule.agent", teamIdentifier: "ABCDE12345", signingIdentifier: "com.example.agent",
      allowsDescendants: false)
    let withRule = PolicyProgramSummarizer.projectedDenials(
      summaries: summaries, policyType: .whitelist, rules: [allowed])
    XCTAssertEqual(withRule.map(\.id), ["unsigned:/opt/example/bin/tool"])

    var disabled = allowed
    disabled.isEnabled = false
    XCTAssertTrue(
      PolicyProgramSummarizer.projectedDenials(
        summaries: summaries, policyType: .blacklist, rules: [disabled]
      ).isEmpty)
    XCTAssertEqual(
      PolicyProgramSummarizer.projectedDenials(
        summaries: summaries, policyType: .blacklist, rules: [allowed]
      ).map(\.id), ["team:ABCDE12345:com.example.agent"])
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
}

/// Reports no installed extension without contacting macOS.
private struct EmptyLifecycle: ExtensionLifecycleControlling {
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

  func applyPolicySet(_ document: PolicySetDocument) async throws -> PolicyApplyReceipt {
    appliedRevisions.append(document.revision)
    return PolicyApplyReceipt(
      result: .accepted, acceptedSetIdentifier: document.setIdentifier,
      acceptedRevision: document.revision, acceptedDigest: "digest")
  }

  func queryStatus() async throws -> ExtensionStatusSnapshot {
    throw ExtensionControlClientError.interfaceUnavailable
  }

  func queryPolicySet() async throws -> PolicySetDocument { throw Unused.call }

  func applySystemCompatibilitySettings(
    _ document: SystemCompatibilitySettingsDocument
  ) async throws -> SystemCompatibilitySettingsApplyReceipt { throw Unused.call }

  func querySystemCompatibilityState() async throws -> SystemCompatibilityStateSnapshot {
    throw Unused.call
  }

  func readAuditLog(maximumLineCount: Int) async throws -> AuditLogBatch { throw Unused.call }

  func invalidate() {}

  private enum Unused: Error { case call }
}
