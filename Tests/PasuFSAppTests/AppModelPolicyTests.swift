import Darwin
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

  func testSystemCompatibilityAuditCandidatesUsePolicyEvaluationNotKernelResponse() throws {
    var active = makePolicySet()
    active.policies[0].mode = .audit
    let model = AppModel(initialPolicySet: active)
    let policy = active.policies[0]
    let signingIdentifier = "com.apple.example.backupd"
    func evaluation(
      mode: PolicyMode = .audit,
      policyType: PolicyType = .whitelist,
      match: PolicyRuleMatchKind = .none,
      decision: PolicyEvaluationDecision
    ) -> PolicyEvaluationRecord {
      PolicyEvaluationRecord(
        policyIdentifier: policy.id,
        policyName: policy.name,
        mode: mode,
        policyType: policyType,
        match: match,
        decision: decision
      )
    }
    model.auditBatch = AuditLogBatch(records: [
      AuditEventRecord(
        timestamp: Date(timeIntervalSince1970: 10),
        policySetIdentifier: active.setIdentifier,
        policyRevision: active.revision,
        eventType: "AUTH_OPEN",
        executablePath: "/System/Library/PrivateFrameworks/Example.framework/exampled",
        signingIdentifier: signingIdentifier,
        isPlatformBinary: true,
        codeSigningFlags: 0x0400_0001,
        operatingSystemBuild: "23A000",
        targetPath: "/Users/example/First/a",
        pathWasTruncated: false,
        requestedFlags: Int32(FREAD),
        policyDecision: "audit-only",
        kernelResponse: "allow",
        policyEvaluations: [evaluation(mode: .audit, decision: .wouldDeny)]
      ),
      AuditEventRecord(
        timestamp: Date(timeIntervalSince1970: 20),
        policySetIdentifier: active.setIdentifier,
        policyRevision: active.revision,
        eventType: "AUTH_OPEN",
        signingIdentifier: signingIdentifier,
        isPlatformBinary: true,
        codeSigningFlags: 0x0400_0001,
        operatingSystemBuild: "23A000",
        targetPath: "/Users/example/First/b",
        pathWasTruncated: false,
        requestedFlags: Int32(FREAD | FWRITE),
        policyDecision: "audit-only",
        kernelResponse: "allow",
        policyEvaluations: [evaluation(decision: .wouldDeny)]
      ),
      AuditEventRecord(
        timestamp: Date(timeIntervalSince1970: 25),
        policySetIdentifier: active.setIdentifier,
        policyRevision: active.revision,
        eventType: "AUTH_OPEN",
        signingIdentifier: signingIdentifier,
        isPlatformBinary: true,
        codeSigningFlags: 0x0400_0001,
        operatingSystemBuild: "23A001",
        targetPath: "/Users/example/First/new-build",
        pathWasTruncated: false,
        requestedFlags: Int32(FWRITE),
        policyDecision: "audit-only",
        kernelResponse: "allow",
        policyEvaluations: [evaluation(decision: .wouldDeny)]
      ),
      AuditEventRecord(
        timestamp: Date(timeIntervalSince1970: 30),
        policySetIdentifier: active.setIdentifier,
        policyRevision: active.revision,
        eventType: "AUTH_OPEN",
        signingIdentifier: signingIdentifier,
        isPlatformBinary: true,
        codeSigningFlags: 0x0400_0001,
        operatingSystemBuild: "23A000",
        targetPath: "/Users/example/First/c",
        pathWasTruncated: false,
        requestedFlags: Int32(FREAD),
        policyDecision: "denied",
        kernelResponse: "deny",
        policyEvaluations: [
          evaluation(policyType: .blacklist, decision: .deny),
          evaluation(match: .direct, decision: .deny),
        ]
      ),
    ])

    let candidates = model.systemCompatibilityAuditCandidates(policyID: policy.id)
    let candidate = try XCTUnwrap(
      candidates.first { $0.operatingSystemBuild == "23A000" }
    )
    XCTAssertEqual(candidates.count, 2)
    XCTAssertEqual(candidate.signingIdentifier, signingIdentifier)
    XCTAssertEqual(candidate.operatingSystemBuild, "23A000")
    XCTAssertEqual(candidate.observationCount, 2)
    XCTAssertEqual(candidate.requestedFlagValues, [UInt32(FREAD), UInt32(FREAD | FWRITE)])
    XCTAssertEqual(candidate.requestedFlagUnion, UInt32(FREAD | FWRITE))
    XCTAssertEqual(candidate.codeSigningFlagValues, [0x0400_0001])
    XCTAssertEqual(candidate.uniqueTargetPathCount, 2)
    XCTAssertTrue(candidate.hasCompleteEvidence)
    XCTAssertEqual(
      candidates.first { $0.operatingSystemBuild == "23A001" }?.observationCount,
      1
    )
    XCTAssertTrue(model.systemCompatibilityAuditCandidates(policyID: uuid(999)).isEmpty)
  }

  func testSystemCompatibilityCatalogStaysSeparateFromPolicyDrafts() throws {
    let active = makePolicySet()
    let profile = SystemCompatibilityProfile(
      id: "system.example.read",
      displayName: "Example system feature",
      roleDescription: "Reads files for one verified operating-system feature.",
      consequence: "The operating system may retain a derived copy.",
      evidence: SystemCompatibilityProfileEvidence(
        capabilityClass: .singlePurposeAutonomousService,
        acceptsArbitraryThirdPartyCommandsOrPaths: false,
        observedOSBuilds: ["23A000"],
        observedDate: "2026-08-27",
        evidenceReference: "docs/experiments/example-system-profile.md",
        capabilityAssessment: "Synthetic evidence used only by unit tests."
      ),
      actors: [
        SystemCompatibilityProfileActor(
          signingIdentifier: "com.apple.example.worker",
          allowedOpenFlags: UInt32(FREAD),
          supportedOSRange: SystemCompatibilityOSRange(
            minimum: SystemCompatibilityOSVersion(major: 14),
            maximumExclusive: SystemCompatibilityOSVersion(major: 15)
          ),
          supportedOSBuilds: ["23A000"]
        )
      ]
    )
    let model = AppModel(
      initialPolicySet: active,
      systemCompatibilityCatalog: SystemCompatibilityCatalog(profiles: [profile])
    )
    let policyID = active.policies[0].id

    let items = model.systemCompatibilityProfileItems(policyID: policyID)
    XCTAssertEqual(items.map(\.profile.id), [profile.id])
    XCTAssertEqual(items.map(\.state), [.disabled])
    XCTAssertFalse(model.isPolicyDirty(policyID))
    XCTAssertEqual(model.activePolicy(id: policyID), active.policies[0])
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
