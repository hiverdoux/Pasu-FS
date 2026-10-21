import Foundation
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSIPC
import PasuFSPolicy
import XCTest

@testable import PasuFSApp

/// The app's side of the two-list contract: what is saved, what the extension confirmed as in
/// effect, and how lost replies, missing capabilities and recovery states are handled.
@MainActor
final class ExecutionOriginIntegrationTests: XCTestCase {
  func testSaveIsConfirmedOnlyWhenTheStatusReportsItsRevisionAndDigest() async throws {
    let (model, runtime, policy) = try await connectedModel()
    await runtime.setKeepsReportingRevision(3)

    model.setAllowListInUse(policyID: policy.id, false)
    await model.savePolicy(id: policy.id)

    XCTAssertNil(model.lastError)
    XCTAssertFalse(model.isPolicyDirty(policy.id))
    XCTAssertEqual(model.activePolicy(id: policy.id)?.isBlacklistEnabled, true)
    XCTAssertEqual(model.activePolicy(id: policy.id)?.allowRules, policy.allowRules)
    XCTAssertEqual(model.unconfirmedSave?.acceptedRevision, 4)
    XCTAssertTrue(model.attentionItems().contains { $0.id == "unconfirmedSave" })

    await runtime.setKeepsReportingRevision(nil)
    await model.refreshHealth()
    XCTAssertNil(model.unconfirmedSave)
    XCTAssertFalse(model.attentionItems().contains { $0.id == "unconfirmedSave" })
  }

  func testLostReplyIsSettledByReadingTheStoredPolicies() async throws {
    let (model, runtime, policy) = try await connectedModel()

    // The extension stored the change, but its reply never arrived.
    await runtime.setApplyBehavior(.storeThenTimeOut)
    model.updatePolicyDraft(id: policy.id) { $0.mode = .protection }
    await model.savePolicy(id: policy.id)
    XCTAssertNil(model.lastError)
    XCTAssertEqual(model.activeRevision, 4)
    XCTAssertFalse(model.isPolicyDirty(policy.id))

    // The request never reached the extension.
    await runtime.setApplyBehavior(.timeOut)
    model.updatePolicyDraft(id: policy.id) { $0.name = "Renamed" }
    await model.savePolicy(id: policy.id)
    XCTAssertNotNil(model.lastError)
    XCTAssertEqual(model.activeRevision, 4)
    XCTAssertTrue(model.isPolicyDirty(policy.id))
    let applied = await runtime.appliedRevisions
    XCTAssertEqual(applied, [4, 5])
  }

  func testUnreadableOutcomeBlocksAnotherRevisionUntilItIsKnown() async throws {
    let (model, runtime, policy) = try await connectedModel()

    await runtime.setApplyBehavior(.storeThenTimeOut)
    await runtime.setIsReachable(false)
    model.updatePolicyDraft(id: policy.id) { $0.mode = .protection }
    await model.savePolicy(id: policy.id)
    XCTAssertNotNil(model.lastError)
    XCTAssertNotNil(model.draftValidationMessage(for: policy.id))

    // Saving again must not use another revision while the first outcome is unknown.
    await runtime.setApplyBehavior(.accept)
    await model.savePolicy(id: policy.id)
    var applied = await runtime.appliedRevisions
    XCTAssertEqual(applied, [4])

    await runtime.setIsReachable(true)
    await model.refreshHealth()
    XCTAssertNil(model.lastError)
    XCTAssertNil(model.draftValidationMessage(for: policy.id))
    XCTAssertEqual(model.activeRevision, 4)
    XCTAssertEqual(model.activePolicy(id: policy.id)?.mode, .protection)
    XCTAssertFalse(model.isPolicyDirty(policy.id))
    applied = await runtime.appliedRevisions
    XCTAssertEqual(applied, [4])
  }

  func testRejectedSaveKeepsTheDraftAndReloadsNewerPolicies() async throws {
    let (model, runtime, policy) = try await connectedModel()
    var newer = try XCTUnwrap(model.activePolicySet)
    newer.revision = 9
    newer.policies[0].name = "Changed Elsewhere"
    await runtime.replaceStored(newer)
    await runtime.setKeepsReportingRevision(3)

    model.updatePolicyDraft(id: policy.id) { $0.mode = .protection }
    await model.savePolicy(id: policy.id)

    XCTAssertNotNil(model.lastError)
    XCTAssertEqual(model.policyDraft(id: policy.id)?.mode, .protection)
    XCTAssertTrue(model.isPolicyDirty(policy.id))

    // The next save builds on the policies that are stored now.
    await runtime.setKeepsReportingRevision(nil)
    await model.refreshHealth()
    XCTAssertEqual(model.activeRevision, 9)
    XCTAssertEqual(model.activePolicy(id: policy.id)?.name, "Changed Elsewhere")
    XCTAssertEqual(
      try model.candidateDocument(replacing: policy.id, with: model.policyDraft(id: policy.id))
        .revision, 10)
  }

  func testMissingCapabilityReportBlocksSaving() async throws {
    let (model, runtime, policy) = try await connectedModel()
    XCTAssertEqual(model.executionOriginSupport, .supported)

    await runtime.setReportsCapabilities(false)
    await model.refreshHealth()
    XCTAssertEqual(model.executionOriginSupport, .unsupported)
    XCTAssertTrue(model.attentionItems().contains { $0.id == "originSupport" })

    model.updatePolicyDraft(id: policy.id) { $0.mode = .protection }
    XCTAssertNotNil(model.draftValidationMessage(for: policy.id))
    await model.savePolicy(id: policy.id)
    XCTAssertNotNil(model.lastError)
    let applied = await runtime.appliedRevisions
    XCTAssertEqual(applied, [])
  }

  func testRecoveryPoliciesAreNotPresentedAsTheSavedConfiguration() async throws {
    let (model, runtime, policy) = try await connectedModel()
    XCTAssertNil(model.policyStorageState.flatMap(PolicyStorageText.summary))

    // The extension lost both copies and serves a document without programs.
    var emergency = try XCTUnwrap(model.activePolicySet)
    emergency.policies = emergency.policies.map {
      DirectoryPolicy(
        id: $0.id, name: $0.name, mode: $0.mode, protectedRootPath: $0.protectedRootPath)
    }
    await runtime.replaceStored(emergency)
    await runtime.setStorageState(.denyAllRecovery)
    await runtime.restart()
    await model.refreshHealth()

    XCTAssertTrue(model.isServingRecoveryPolicies)
    XCTAssertTrue(model.savedPoliciesNeedSaving)
    XCTAssertEqual(model.activePolicy(id: policy.id)?.allowRules, [])
    XCTAssertEqual(model.activePolicy(id: policy.id)?.isBlacklistEnabled, false)
    XCTAssertTrue(model.attentionItems().contains { $0.id == "policyStorage" })

    await runtime.setStorageState(.unavailable)
    await model.refreshHealth()
    XCTAssertEqual(model.status.tone, .attention)
    XCTAssertTrue(model.savedPoliciesNeedSaving)

    for state in [PolicyStorageState.migrated, .recovered] {
      await runtime.setStorageState(state)
      await model.refreshHealth()
      XCTAssertFalse(model.savedPoliciesNeedSaving)
      XCTAssertTrue(model.attentionItems().contains { $0.id == "policyStorage" })
    }
  }

  func testPoliciesAreReadAgainAfterTheConnectionReturns() async throws {
    let (model, runtime, policy) = try await connectedModel()
    let queriesBefore = await runtime.policyQueryCount

    await model.refreshHealth()
    var queries = await runtime.policyQueryCount
    XCTAssertEqual(queries, queriesBefore)

    // Same set, revision and digest, but the status came after a lost connection.
    await runtime.setIsReachable(false)
    await model.refreshHealth()
    XCTAssertEqual(model.executionOriginSupport, .unknown)
    await runtime.setIsReachable(true)
    await model.refreshHealth()
    queries = await runtime.policyQueryCount
    XCTAssertEqual(queries, queriesBefore + 1)
    XCTAssertEqual(model.activePolicy(id: policy.id)?.name, policy.name)
  }

  func testDecisionEvidenceAndBackendMessagesHaveScreenText() {
    let reasons: [ExecutionOriginDecisionReason] = [
      .allowed, .allowedInherited, .blacklistAllowed, .emptyAllowList, .originNotAllowed,
      .actorNotAllowed,
      .deniedInHistory, .incompleteHistory, .noFirstProgram,
    ]
    XCTAssertEqual(Set(reasons.map(OriginText.reason)).count, reasons.count)
    let uncertainties: [ExecutionOriginUncertainty] = [
      .beforeObservation, .eventLoss, .stateLimit, .policyChanged, .identityChanged,
      .decodeFailure, .unavailableEventVersion,
    ]
    XCTAssertEqual(Set(uncertainties.map(OriginText.uncertainty)).count, uncertainties.count)

    for message in [
      "Policy storage migrated. Review and enable descendant access for each allowed program.",
      "The latest committed policy was recovered from its verified copy.",
      "Both current policy copies are unavailable. Known Protection scopes deny all access until a newer valid policy is saved.",
      "Recovery protection denies access in known Protection scopes until a newer valid policy is saved.",
      PolicyUpdateError.revisionDowngrade(candidate: 4, active: 9).description,
      PolicyUpdateError.revisionCollision(4).description,
      PolicyUpdateError.setIdentifierMismatch(candidate: UUID(), active: UUID()).description,
      "The protected root does not exist: /Users/example/Missing",
    ] {
      XCTAssertNotEqual(RuntimeText.localized(message), message)
    }
    XCTAssertTrue(
      RuntimeText.localized("The protected root does not exist: /Users/example/Missing")
        .hasSuffix("/Users/example/Missing"))
    XCTAssertFalse(
      UserFacingError.message(ProgramRuleReaderError.unsupportedIdentity).isEmpty)
  }

  func testFirstProgramsAreOfferedAsRuleCandidates() async throws {
    let (model, _, policy) = try await connectedModel()
    // The extension creates this evidence itself, so the test decodes it as a log reader does.
    let evidence = """
      {"bootIdentifier":"example-boot","isAllowed":false,"reason":"originNotAllowed",
       "isBlacklistEnabled":false,
       "origin":{"instance":{"processID":812,"processVersion":4},
         "executablePath":"/Applications/Example Launcher.app/Contents/MacOS/Launcher",
         "teamIdentifier":"fghij67890","signingIdentifier":"com.example.launcher",
         "isPlatformBinary":false,"codeSigningFlags":1,"pathWasTruncated":false},
       "actor":{"instance":{"processID":5531,"processVersion":9},"executablePath":"/bin/cat",
         "signingIdentifier":"com.apple.cat","isPlatformBinary":true,"codeSigningFlags":1,
         "pathWasTruncated":false}}
      """
    let origin = try JSONDecoder().decode(
      ExecutionOriginDecision.self, from: Data(evidence.utf8))
    let record = AuditEventRecord(
      eventType: "AUTH_OPEN", executablePath: "/bin/cat", signingIdentifier: "com.apple.cat",
      isPlatformBinary: true, policyDecision: "audit-only", kernelResponse: "allow",
      policyEvaluations: [
        PolicyEvaluationRecord(
          policyIdentifier: policy.id, policyName: policy.name, mode: .audit,
          policyType: .whitelist, match: .none, decision: .wouldDeny, executionOrigin: origin)
      ])
    try XCTUnwrap(model.policyLogState(policyID: policy.id)).batch = AuditLogBatch(records: [
      record, record,
    ])

    let candidates = model.ruleCandidates(policyID: policy.id)
    XCTAssertEqual(
      Set(candidates.map(\.id)), ["platform:com.apple.cat", "team:FGHIJ67890:com.example.launcher"])
    XCTAssertEqual(candidates.map(\.observationCount), [2, 2])
    let launcher = try XCTUnwrap(candidates.first { $0.kind == .teamSigned })
    try model.addRule(policyID: policy.id, to: .allow, from: launcher)
    XCTAssertEqual(
      model.policyDraft(id: policy.id)?.allowRules.last?.teamIdentifier, "FGHIJ67890")
  }

  func testRuleCountsNameOnlyTheListsInUse() {
    let allow = PolicyRule.platformBinary(
      id: "rule.allow", signingIdentifier: "com.apple.example", allowsDescendants: false)
    var off = PolicyRule.platformBinary(
      id: "rule.off", signingIdentifier: "com.apple.other", allowsDescendants: false)
    off.isEnabled = false
    let deny = PolicyRule.teamSigned(
      id: "rule.deny", teamIdentifier: "ABCDE12345", signingIdentifier: "com.example.tool",
      allowsDescendants: false)
    var policy = DirectoryPolicy(
      name: "Keys", mode: .protection, protectedRootPath: "/Users/example/Keys",
      allowRules: [allow, off], denyRules: [deny])

    XCTAssertEqual(policy.rulesInUse.allow, 1)
    XCTAssertEqual(policy.rulesInUse.deny, 1)
    policy.isBlacklistEnabled = true
    XCTAssertEqual(policy.rulesInUse.allow, 0)
    XCTAssertEqual(policy.rulesInUse.deny, 1)
    XCTAssertEqual(policy.allowRules.count, 2)
  }

  // MARK: - Retired folder paths

  func testRetiredPathsAreShownUntilThePolicyIsSavedAgain() async throws {
    let (model, runtime, policy) = try await connectedModel()
    XCTAssertEqual(model.retiredFolderPathCount, 0)
    await runtime.setRetired(["/Users/example/Old/Secrets"], for: policy.id)
    await runtime.setRetired(["/Users/example/Gone"], for: UUID())
    await model.refreshHealth()

    XCTAssertEqual(model.retiredFolderPaths(policyID: policy.id), ["/Users/example/Old/Secrets"])
    XCTAssertEqual(model.retiredFolderPathCount, 2)
    let items = model.attentionItems().filter { $0.id.hasPrefix("retiredFolderPaths") }
    // A policy the app does not have is not listed.
    XCTAssertEqual(items.count, 1)
    XCTAssertEqual(items.first?.action, .showPolicy(policy.id))
    XCTAssertEqual(items.first?.detail, "/Users/example/Old/Secrets")
    // Nothing was edited; the save that releases the path sends the policy as it is.
    XCTAssertFalse(model.isPolicyDirty(policy.id))
    await model.savePolicy(id: policy.id)

    XCTAssertNil(model.lastError)
    XCTAssertEqual(model.activeRevision, 4)
    let saved = await runtime.savedPolicyIdentifiers
    XCTAssertEqual(saved, [policy.id])
    XCTAssertEqual(model.retiredFolderPaths(policyID: policy.id), [])
    XCTAssertFalse(model.attentionItems().contains { $0.id.hasPrefix("retiredFolderPaths") })
  }

  // MARK: - Unchecked requests

  func testUncheckedRequestsNeedAttentionOnlyOnceCounted() async throws {
    let (model, runtime, _) = try await connectedModel()
    XCTAssertNil(model.uncheckedRequestMetrics)
    var metrics = UncheckedRequestMetrics()
    metrics.missedMessages = 4
    metrics.missedProcessEvents = 4
    await runtime.setUncheckedRequests(metrics)
    await model.refreshHealth()
    XCTAssertEqual(model.uncheckedRequestMetrics, metrics)
    XCTAssertFalse(model.attentionItems().contains { $0.id == "uncheckedRequests" })

    metrics.estimatedCount = 3
    metrics.lastEstimatedCount = 3
    metrics.lastObservedAt = Date(timeIntervalSince1970: 1_800_000_000)
    await runtime.setUncheckedRequests(metrics)
    await model.refreshHealth()
    let item = try XCTUnwrap(model.attentionItems().first { $0.id == "uncheckedRequests" })
    XCTAssertEqual(item.action, .diagnostics)
    XCTAssertTrue(item.text.contains("3"))
    XCTAssertEqual(
      item.text,
      String(
        localized:
          "macOS allowed up to \(UInt64(3)) requests without asking Pasu FS during this run."))
  }

  func testUncheckedRequestsFollowTheDeadlineMissMode() async throws {
    let (model, runtime, _) = try await connectedModel()
    XCTAssertNil(model.deadlineMissMode)
    var metrics = UncheckedRequestMetrics()
    metrics.estimatedCount = 5
    await runtime.setUncheckedRequests(metrics)
    let denied = String(
      localized: "macOS denied up to \(UInt64(5)) requests without asking Pasu FS during this run.")
    let allowed = String(
      localized: "macOS allowed up to \(UInt64(5)) requests without asking Pasu FS during this run."
    )
    let cases: [(DeadlineMissModeStatus, String)] = [
      (DeadlineMissModeStatus(setting: .failClosed), denied),
      (DeadlineMissModeStatus(setting: .killUnavailable), allowed),
      (DeadlineMissModeStatus(setting: .killAfterFailure, error: "failed"), allowed),
    ]
    for (mode, text) in cases {
      await runtime.setDeadlineMissMode(mode)
      await model.refreshHealth()
      XCTAssertEqual(model.deadlineMissMode, mode)
      let item = try XCTUnwrap(model.attentionItems().first { $0.id == "uncheckedRequests" })
      XCTAssertEqual(item.text, text)
    }
  }

  // MARK: - Helpers

  /// A model that has read an authenticated status and one saved Audit policy at revision 3.
  private func connectedModel() async throws -> (AppModel, ScriptedRuntime, DirectoryPolicy) {
    let policy = DirectoryPolicy(
      name: "Secrets", mode: .audit,
      protectedRootPath: FileManager.default.temporaryDirectory.path,
      allowRules: [
        .teamSigned(
          id: "rule.editor", teamIdentifier: "ABCDE12345",
          signingIdentifier: "com.example.editor", allowsDescendants: false)
      ])
    let runtime = ScriptedRuntime(
      stored: PolicySetDocument(setIdentifier: UUID(), revision: 3, policies: [policy]))
    let model = AppModel(
      activationController: EnabledLifecycle(), runtimeController: runtime)
    await model.refreshHealth()
    XCTAssertEqual(model.activeRevision, 3)
    XCTAssertNil(model.lastError)
    return (model, runtime, policy)
  }
}

/// Reports one enabled extension without contacting macOS.
private struct EnabledLifecycle: ExtensionLifecycleControlling {
  func installationStateLauncher() -> any InstallationStateChildLaunching {
    inProcessInstallationStateLauncher()
  }

  func activationEvents() -> AsyncStream<ActivationEvent> { AsyncStream { $0.finish() } }
  func deactivationEvents() -> AsyncStream<ActivationEvent> { AsyncStream { $0.finish() } }
  func propertiesEvents() -> AsyncStream<ActivationEvent> {
    AsyncStream { continuation in
      continuation.yield(
        .properties([
          ExtensionInstallationProperties(
            bundleIdentifier: ActivationController.extensionIdentifier, bundleVersion: "1",
            bundleShortVersion: "1.0", isEnabled: true, isAwaitingUserApproval: false,
            isUninstalling: false)
        ]))
      continuation.finish()
    }
  }
}

/// An extension stand-in that stores policy sets with the real update rules.
private actor ScriptedRuntime: ExtensionRuntimeControlling {
  enum ApplyBehavior {
    case accept
    case storeThenTimeOut
    case timeOut
  }

  private var stored: PolicySetDocument?
  private var runtimeIdentifier = UUID()
  private var applyBehavior = ApplyBehavior.accept
  private var isReachable = true
  private var reportsCapabilities = true
  private var storageState = PolicyStorageState.ready
  /// A revision the status keeps reporting as in effect although a newer one is stored.
  private var keepsReportingRevision: UInt64?
  private(set) var appliedRevisions: [UInt64] = []
  private(set) var savedPolicyIdentifiers: [UUID?] = []
  private(set) var policyQueryCount = 0
  /// Retired folder paths by policy, released like the extension does when a policy is saved.
  private var retired: [UUID: [String]] = [:]
  private var uncheckedRequests: UncheckedRequestMetrics?
  private var deadlineMissMode: DeadlineMissModeStatus?

  init(stored: PolicySetDocument?) { self.stored = stored }

  func setRetired(_ paths: [String], for policy: UUID) { retired[policy] = paths }
  func setUncheckedRequests(_ metrics: UncheckedRequestMetrics) { uncheckedRequests = metrics }
  func setDeadlineMissMode(_ mode: DeadlineMissModeStatus) { deadlineMissMode = mode }

  func setApplyBehavior(_ behavior: ApplyBehavior) { applyBehavior = behavior }
  func setIsReachable(_ value: Bool) { isReachable = value }
  func setReportsCapabilities(_ value: Bool) { reportsCapabilities = value }
  func setStorageState(_ state: PolicyStorageState) { storageState = state }
  func setKeepsReportingRevision(_ revision: UInt64?) { keepsReportingRevision = revision }
  func replaceStored(_ document: PolicySetDocument) { stored = document }
  func restart() { runtimeIdentifier = UUID() }

  func applyPolicySet(
    _ document: PolicySetDocument, authorization: Data?, savedPolicyIdentifier: UUID?
  ) async throws -> PolicyApplyReceipt {
    appliedRevisions.append(document.revision)
    savedPolicyIdentifiers.append(savedPolicyIdentifier)
    if applyBehavior == .timeOut { throw ExtensionControlClientError.requestTimedOut }
    do {
      _ = try PolicyUpdateValidator.validate(candidate: document, against: stored)
    } catch {
      throw PasuFSXPCError.wrap(error, code: .policyRejected)
    }
    stored = document
    if let savedPolicyIdentifier { retired[savedPolicyIdentifier] = nil }
    if applyBehavior == .storeThenTimeOut { throw ExtensionControlClientError.requestTimedOut }
    return PolicyApplyReceipt(
      result: .accepted, acceptedSetIdentifier: document.setIdentifier,
      acceptedRevision: document.revision,
      acceptedDigest: try PolicySetDocumentCodec.digest(of: document))
  }

  func queryStatus() async throws -> ExtensionStatusSnapshot {
    guard isReachable else { throw ExtensionControlClientError.interfaceUnavailable }
    let revision = keepsReportingRevision ?? stored?.revision
    let isCurrent = revision == stored?.revision
    return ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: runtimeIdentifier,
      phase: .monitoring,
      activePolicySetIdentifier: stored?.setIdentifier,
      activePolicyRevision: revision,
      activePolicyDigest: isCurrent
        ? try stored.map { try PolicySetDocumentCodec.digest(of: $0) } : "superseded",
      auditPolicyCount: stored?.policies.count ?? 0,
      uncheckedRequests: uncheckedRequests,
      policyStorageState: storageState,
      executionOriginCapabilities: reportsCapabilities ? ExecutionOriginCapabilities() : nil,
      retiredFolderPaths: retired.sorted { $0.key.uuidString < $1.key.uuidString }.map {
        PolicyRetiredFolderPaths(policyIdentifier: $0.key, paths: $0.value)
      },
      deadlineMissMode: deadlineMissMode)
  }

  func queryPolicySet() async throws -> PolicySetDocument {
    guard isReachable else { throw ExtensionControlClientError.interfaceUnavailable }
    policyQueryCount += 1
    guard let stored else {
      throw PasuFSXPCError.make(.invalidRequest, description: "No accepted policy set is stored.")
    }
    return stored
  }

  func readAuditLog(maximumLineCount: Int) async throws -> AuditLogBatch { throw Unused.call }

  func invalidate() {}

  private enum Unused: Error { case call }
}
