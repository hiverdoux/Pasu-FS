import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSApp

@MainActor
final class AppModelPolicyTests: XCTestCase {
  func testSavingCandidateIncludesOnlySelectedDirtyPolicy() throws {
    let active = makePolicySet()
    let model = AppModel(initialPolicySet: active)
    let firstID = active.policies[0].id
    let secondID = active.policies[1].id

    model.updatePolicyDraft(id: firstID) { $0.name = "Changed First" }
    model.updatePolicyDraft(id: secondID) { $0.name = "Changed Second" }

    let candidate = try model.candidateDocument(
      replacing: firstID,
      with: model.policyDraft(id: firstID)
    )
    XCTAssertEqual(candidate.policies[0].name, "Changed First")
    XCTAssertEqual(candidate.policies[1].name, active.policies[1].name)

    model.installActivePolicySet(candidate, markingClean: firstID)
    XCTAssertFalse(model.isPolicyDirty(firstID))
    XCTAssertTrue(model.isPolicyDirty(secondID))
    XCTAssertEqual(model.policyDraft(id: secondID)?.name, "Changed Second")
  }

  func testNewPoliciesUseAvailableNamesAndPreserveDraftsAcrossSelection() {
    let empty = PolicySetDocument(
      setIdentifier: uuid(100),
      revision: 1,
      policies: []
    )
    let model = AppModel(initialPolicySet: empty)

    model.createNewPolicy()
    let firstID = try! XCTUnwrap(model.selectedPolicyID)
    model.updatePolicyDraft(id: firstID) { $0.protectedRootPath = "/Users/example/First" }
    model.createNewPolicy()
    let secondID = try! XCTUnwrap(model.selectedPolicyID)

    XCTAssertEqual(model.policyDraft(id: firstID)?.name, "Policy 1")
    XCTAssertEqual(model.policyDraft(id: secondID)?.name, "Policy 2")
    XCTAssertEqual(model.policyDraft(id: firstID)?.protectedRootPath, "/Users/example/First")
    XCTAssertEqual(model.sidebarPolicies.count, 2)
  }

  func testUnsavedCreationOrderSurvivesSavingPoliciesInReverseOrder() throws {
    let empty = PolicySetDocument(
      setIdentifier: uuid(100),
      revision: 1,
      policies: []
    )
    let model = AppModel(initialPolicySet: empty)
    model.createNewPolicy()
    let firstID = try XCTUnwrap(model.selectedPolicyID)
    model.updatePolicyDraft(id: firstID) {
      $0.mode = .audit
      $0.protectedRootPath = "/Users/example/First"
    }
    model.createNewPolicy()
    let secondID = try XCTUnwrap(model.selectedPolicyID)
    model.updatePolicyDraft(id: secondID) {
      $0.mode = .audit
      $0.protectedRootPath = "/Users/example/Second"
    }

    let secondCandidate = try model.candidateDocument(
      replacing: secondID,
      with: model.policyDraft(id: secondID)
    )
    model.installActivePolicySet(secondCandidate, markingClean: secondID)
    XCTAssertEqual(model.sidebarPolicies.map(\.id), [firstID, secondID])

    let firstCandidate = try model.candidateDocument(
      replacing: firstID,
      with: model.policyDraft(id: firstID)
    )
    XCTAssertEqual(firstCandidate.policies.map(\.id), [firstID, secondID])
  }

  func testRemovingLastPolicyProducesAValidEmptySetCandidate() throws {
    let active = PolicySetDocument(
      setIdentifier: uuid(100),
      revision: 4,
      policies: [makePolicySet().policies[0]]
    )
    let model = AppModel(initialPolicySet: active)
    let candidate = try model.candidateDocument(
      replacing: active.policies[0].id,
      with: nil
    )

    XCTAssertTrue(candidate.policies.isEmpty)
    XCTAssertEqual(candidate.revision, 5)
    XCTAssertNoThrow(try candidate.validate())
  }

  func testTypeChangeCanPreserveOrDeleteRulesAndRevertRestoresActivePolicy() {
    let active = makePolicySet()
    let model = AppModel(initialPolicySet: active)
    let policyID = active.policies[0].id

    model.applyPolicyTypeChange(
      policyID: policyID,
      to: .blacklist,
      deletingAllRules: false
    )
    XCTAssertEqual(model.policyDraft(id: policyID)?.policyType, .blacklist)
    XCTAssertEqual(model.policyDraft(id: policyID)?.rules.count, 1)

    model.applyPolicyTypeChange(
      policyID: policyID,
      to: .whitelist,
      deletingAllRules: true
    )
    XCTAssertTrue(model.policyDraft(id: policyID)?.rules.isEmpty == true)

    model.revertPolicy(id: policyID)
    XCTAssertEqual(
      model.policyDraft(id: policyID), DirectoryPolicyDraft(policy: active.policies[0]))
    XCTAssertFalse(model.isPolicyDirty(policyID))
  }

  func testAuditCandidatesDeduplicateSupportedSigningIdentities() throws {
    let active = makePolicySet()
    let model = AppModel(initialPolicySet: active)
    let policyID = active.policies[0].id
    model.auditBatch = AuditLogBatch(records: [
      AuditEventRecord(
        timestamp: Date(timeIntervalSince1970: 10),
        eventType: "AUTH_OPEN",
        executablePath: "/Applications/Editor.app/Contents/MacOS/Editor",
        teamIdentifier: "team123456",
        signingIdentifier: "com.example.Editor",
        isPlatformBinary: false,
        policyDecision: "denied",
        kernelResponse: "deny"
      ),
      AuditEventRecord(
        timestamp: Date(timeIntervalSince1970: 20),
        eventType: "AUTH_OPEN",
        executablePath: "/Applications/Editor.app/Contents/MacOS/Editor",
        teamIdentifier: "TEAM123456",
        signingIdentifier: "com.example.Editor",
        isPlatformBinary: false,
        policyDecision: "allowed",
        kernelResponse: "allow"
      ),
      AuditEventRecord(
        timestamp: Date(timeIntervalSince1970: 30),
        eventType: "AUTH_OPEN",
        signingIdentifier: "unsigned.tool",
        policyDecision: "denied",
        kernelResponse: "deny"
      ),
      AuditEventRecord(
        timestamp: Date(timeIntervalSince1970: 40),
        eventType: "AUTH_OPEN",
        teamIdentifier: "AMBIGUOUS1",
        signingIdentifier: "legacy.without-platform-fact",
        policyDecision: "denied",
        kernelResponse: "deny"
      ),
    ])

    let candidates = model.auditRuleCandidates
    XCTAssertEqual(candidates.count, 1)
    let candidate = try XCTUnwrap(candidates.first)
    XCTAssertEqual(candidate.teamIdentifier, "TEAM123456")
    XCTAssertEqual(candidate.observationCount, 2)
    XCTAssertEqual(candidate.lastSeen, Date(timeIntervalSince1970: 20))

    XCTAssertTrue(model.policyContainsIdentity(policyID: policyID, candidate: candidate))
    XCTAssertThrowsError(try model.addRule(policyID: policyID, from: candidate))
  }

  private func makePolicySet() -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: uuid(100),
      revision: 4,
      policies: [
        DirectoryPolicy(
          id: uuid(1),
          name: "First",
          mode: .protection,
          policyType: .whitelist,
          protectedRootPath: "/Users/example/First",
          rules: [editorRule]
        ),
        DirectoryPolicy(
          id: uuid(2),
          name: "Second",
          mode: .audit,
          policyType: .blacklist,
          protectedRootPath: "/Users/example/Second",
          rules: []
        ),
      ]
    )
  }

  private var editorRule: PolicyRule {
    .teamSigned(
      id: "rule.editor",
      teamIdentifier: "TEAM123456",
      signingIdentifier: "com.example.Editor",
      allowsDescendants: false
    )
  }

  private func uuid(_ value: Int) -> UUID {
    UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", value))!
  }
}
