import Foundation
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSIPC
import XCTest

@testable import PasuFSApp

@MainActor
final class PolicyAuthorizationTests: XCTestCase {
  func testWeakeningSaveCarriesAnAuthorizationAndStrengtheningSaveDoesNot() async throws {
    let policy = protectionPolicy()
    let runtime = RecordingRuntime()
    let authorizer = FakePolicyChangeAuthorizer()
    let model = makeModel(policy, runtime: runtime, authorizer: authorizer)

    XCTAssertFalse(model.savingWeakensProtection(policyID: policy.id))
    model.updatePolicyDraft(id: policy.id) { $0.mode = .audit }
    XCTAssertTrue(model.savingWeakensProtection(policyID: policy.id))
    await model.savePolicy(id: policy.id)

    XCTAssertNil(model.lastError)
    XCTAssertEqual(authorizer.weakeningFlags, [true])
    XCTAssertEqual(model.activePolicy(id: policy.id)?.mode, .audit)
    XCTAssertFalse(model.isPolicyDirty(policy.id))
    var applied = await runtime.applied
    XCTAssertEqual(applied.map(\.authorization), [FakePolicyChangeAuthorizer.token])

    model.updatePolicyDraft(id: policy.id) { $0.mode = .protection }
    XCTAssertFalse(model.savingWeakensProtection(policyID: policy.id))
    await model.savePolicy(id: policy.id)

    XCTAssertNil(model.lastError)
    XCTAssertEqual(authorizer.weakeningFlags, [true, false])
    XCTAssertEqual(model.activePolicy(id: policy.id)?.mode, .protection)
    applied = await runtime.applied
    XCTAssertEqual(applied.map(\.authorization), [FakePolicyChangeAuthorizer.token, nil])
    XCTAssertEqual(applied.map(\.revision), [4, 5])
    // Each save names the saved policy, so the extension releases its retired folder paths.
    XCTAssertEqual(applied.map(\.savedPolicyIdentifier), [policy.id, policy.id])
  }

  func testCanceledAuthenticationInTheExtensionKeepsTheDraftAndTheSavedPolicy() async throws {
    let policy = protectionPolicy()
    let runtime = RecordingRuntime()
    await runtime.setFailure(
      PasuFSXPCError.make(
        .authorizationCanceled, description: "Administrator authentication was canceled."))
    let authorizer = FakePolicyChangeAuthorizer()
    let model = makeModel(policy, runtime: runtime, authorizer: authorizer)
    model.updatePolicyDraft(id: policy.id) { $0.denyRules = [] }

    await model.savePolicy(id: policy.id)

    XCTAssertEqual(authorizer.weakeningFlags, [true])
    XCTAssertTrue(try XCTUnwrap(model.lastError).contains("canceled"))
    XCTAssertTrue(model.isPolicyDirty(policy.id))
    XCTAssertEqual(model.policyDraft(id: policy.id)?.denyRules, [])
    XCTAssertEqual(model.activePolicy(id: policy.id), policy)
    XCTAssertEqual(model.activeRevision, 3)
    XCTAssertFalse(model.isBusy)
    XCTAssertTrue(model.savingWeakensProtection(policyID: policy.id))
    let applied = await runtime.applied
    XCTAssertEqual(applied.map(\.authorization), [FakePolicyChangeAuthorizer.token])
    // A refused authorization is a definite answer, not a lost reply.
    let queries = await runtime.policyQueries
    XCTAssertEqual(queries, 0)
  }

  func testLocalAuthorizationFailureIsNotTreatedAsALostReply() async throws {
    let policy = protectionPolicy()
    let runtime = RecordingRuntime()
    let authorizer = FakePolicyChangeAuthorizer()
    authorizer.failure = AdministrativeAuthorizationError.canceled
    let model = makeModel(policy, runtime: runtime, authorizer: authorizer)
    model.updatePolicyDraft(id: policy.id) { $0.isBlacklistEnabled = true }

    await model.savePolicy(id: policy.id)

    XCTAssertTrue(try XCTUnwrap(model.lastError).contains("canceled"))
    XCTAssertTrue(model.isPolicyDirty(policy.id))
    XCTAssertEqual(model.policyDraft(id: policy.id)?.isBlacklistEnabled, true)
    XCTAssertEqual(model.activePolicy(id: policy.id), policy)
    let applied = await runtime.applied
    XCTAssertTrue(applied.isEmpty)
    let queries = await runtime.policyQueries
    XCTAssertEqual(queries, 0)
  }

  func testDeletingASavedPolicyIsAWeakeningChange() async throws {
    let policy = protectionPolicy()
    let runtime = RecordingRuntime()
    let authorizer = FakePolicyChangeAuthorizer()
    let model = makeModel(policy, runtime: runtime, authorizer: authorizer)

    await model.deletePolicy(id: policy.id)

    XCTAssertNil(model.lastError)
    XCTAssertEqual(authorizer.weakeningFlags, [true])
    XCTAssertNil(model.activePolicy(id: policy.id))
    XCTAssertNil(model.policyDraft(id: policy.id))
    let applied = await runtime.applied
    XCTAssertEqual(applied.map(\.authorization), [FakePolicyChangeAuthorizer.token])
    // A deletion is not a save of the policy.
    XCTAssertEqual(applied.map(\.savedPolicyIdentifier), [nil])
  }

  func testNewPolicyIsSavedWithoutAuthorization() async throws {
    let runtime = RecordingRuntime()
    let authorizer = FakePolicyChangeAuthorizer()
    let model = AppModel(
      activationController: EmptyLifecycle(), runtimeController: runtime,
      policyChangeAuthorizer: authorizer)
    model.createPolicy(
      name: "Secrets", protectedRootPath: FileManager.default.temporaryDirectory.path,
      mode: .protection)
    let id = try XCTUnwrap(model.selectedPolicyID)
    XCTAssertFalse(model.savingWeakensProtection(policyID: id))

    await model.savePolicy(id: id)

    XCTAssertNil(model.lastError)
    XCTAssertEqual(authorizer.weakeningFlags, [false])
    let applied = await runtime.applied
    XCTAssertEqual(applied.map(\.authorization), [nil])
  }

  func testTurningOnACompatibilityProfileIsSavedWithAuthorization() async throws {
    let policy = protectionPolicy()
    let runtime = RecordingRuntime()
    let authorizer = FakePolicyChangeAuthorizer()
    let model = makeModel(policy, runtime: runtime, authorizer: authorizer)
    let container = BuiltInSystemCompatibilityCatalog.containerManagementIdentifier
    let xprotect = BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier
    XCTAssertNil(model.systemCompatibilityState(policyID: policy.id, profileIdentifier: container))

    model.setSystemCompatibilityProfile(xprotect, isOn: true, policyID: policy.id)
    model.setSystemCompatibilityProfile(container, isOn: true, policyID: policy.id)
    XCTAssertEqual(
      model.policyDraft(id: policy.id)?.systemCompatibilityProfiles.map(\.profileIdentifier),
      [container, xprotect])
    XCTAssertEqual(
      model.systemCompatibilityState(policyID: policy.id, profileIdentifier: container), .active)
    XCTAssertTrue(model.savingWeakensProtection(policyID: policy.id))
    await model.savePolicy(id: policy.id)

    XCTAssertNil(model.lastError)
    XCTAssertEqual(authorizer.weakeningFlags, [true])
    XCTAssertEqual(
      model.activePolicy(id: policy.id)?.systemCompatibilityProfiles,
      try [container, xprotect].map {
        try BuiltInSystemCompatibilityCatalog.catalog.policyEntry(profileIdentifier: $0)
      })

    // Turning a profile off and on again restores the saved policy exactly.
    model.setSystemCompatibilityProfile(container, isOn: false, policyID: policy.id)
    XCTAssertTrue(model.isPolicyDirty(policy.id))
    XCTAssertFalse(model.savingWeakensProtection(policyID: policy.id))
    model.setSystemCompatibilityProfile(container, isOn: true, policyID: policy.id)
    XCTAssertFalse(model.isPolicyDirty(policy.id))

    // Turning one off needs no authorization.
    model.setSystemCompatibilityProfile(xprotect, isOn: false, policyID: policy.id)
    await model.savePolicy(id: policy.id)
    XCTAssertNil(model.lastError)
    XCTAssertEqual(authorizer.weakeningFlags, [true, false])
  }

  /// The Finder Copy profile appears with the other built-in profiles and, like them, reduces
  /// protection when it is turned on.
  func testTurningOnFinderCopyIsSavedWithAuthorization() async throws {
    let policy = protectionPolicy()
    let runtime = RecordingRuntime()
    let authorizer = FakePolicyChangeAuthorizer()
    let model = makeModel(policy, runtime: runtime, authorizer: authorizer)
    let finderCopy = BuiltInSystemCompatibilityCatalog.finderCopyIdentifier
    XCTAssertEqual(model.systemCompatibilityCatalog.profiles.last?.id, finderCopy)

    model.setSystemCompatibilityProfile(finderCopy, isOn: true, policyID: policy.id)
    XCTAssertEqual(
      model.systemCompatibilityState(policyID: policy.id, profileIdentifier: finderCopy), .active)
    XCTAssertTrue(model.savingWeakensProtection(policyID: policy.id))
    await model.savePolicy(id: policy.id)

    XCTAssertNil(model.lastError)
    XCTAssertEqual(authorizer.weakeningFlags, [true])
    XCTAssertEqual(
      model.activePolicy(id: policy.id)?.systemCompatibilityProfiles,
      [try BuiltInSystemCompatibilityCatalog.catalog.policyEntry(profileIdentifier: finderCopy)])
    let applied = await runtime.applied
    XCTAssertEqual(applied.map(\.authorization), [FakePolicyChangeAuthorizer.token])

    model.setSystemCompatibilityProfile(finderCopy, isOn: false, policyID: policy.id)
    XCTAssertFalse(model.savingWeakensProtection(policyID: policy.id))
    await model.savePolicy(id: policy.id)
    XCTAssertNil(model.lastError)
    XCTAssertEqual(authorizer.weakeningFlags, [true, false])
    XCTAssertEqual(model.activePolicy(id: policy.id)?.systemCompatibilityProfiles, [])
  }

  func testAProfileTheCatalogChangedNeedsReviewUntilTurnedOnAgain() throws {
    var policy = protectionPolicy()
    let container = BuiltInSystemCompatibilityCatalog.containerManagementIdentifier
    policy.systemCompatibilityProfiles = [
      PolicySystemCompatibilityProfile(
        profileIdentifier: container, authorizationDigest: String(repeating: "0", count: 64)),
      PolicySystemCompatibilityProfile(
        profileIdentifier: "com.example.retired",
        authorizationDigest: String(repeating: "0", count: 64)),
    ]
    let model = makeModel(
      policy, runtime: RecordingRuntime(), authorizer: FakePolicyChangeAuthorizer())
    XCTAssertEqual(
      model.systemCompatibilityState(policyID: policy.id, profileIdentifier: container),
      .needsReview)
    XCTAssertEqual(
      model.systemCompatibilityState(policyID: policy.id, profileIdentifier: "com.example.retired"),
      .missingProfile)
    XCTAssertNotNil(SystemCompatibilityProfileState.needsReview.inactiveReason)
    XCTAssertFalse(model.savingWeakensProtection(policyID: policy.id))

    model.setSystemCompatibilityProfile(container, isOn: false, policyID: policy.id)
    model.setSystemCompatibilityProfile(container, isOn: true, policyID: policy.id)
    XCTAssertEqual(
      model.systemCompatibilityState(policyID: policy.id, profileIdentifier: container), .active)
    XCTAssertTrue(model.savingWeakensProtection(policyID: policy.id))
    // A profile this version doesn't offer can only be turned off.
    model.setSystemCompatibilityProfile("com.example.retired", isOn: true, policyID: policy.id)
    model.setSystemCompatibilityProfile("com.example.retired", isOn: false, policyID: policy.id)
    XCTAssertEqual(
      model.policyDraft(id: policy.id)?.systemCompatibilityProfiles.map(\.profileIdentifier),
      [container])
  }

  // MARK: - Helpers

  private func protectionPolicy() -> DirectoryPolicy {
    DirectoryPolicy(
      name: "Secrets", mode: .protection, isBlacklistEnabled: false,
      protectedRootPath: FileManager.default.temporaryDirectory.path,
      allowRules: [
        .teamSigned(
          id: "rule.allow", teamIdentifier: "TEAM000001", signingIdentifier: "com.example.editor",
          allowsDescendants: false)
      ],
      denyRules: [
        .teamSigned(
          id: "rule.deny", teamIdentifier: "TEAM000001", signingIdentifier: "com.example.sync",
          allowsDescendants: false)
      ])
  }

  private func makeModel(
    _ policy: DirectoryPolicy, runtime: RecordingRuntime, authorizer: FakePolicyChangeAuthorizer
  ) -> AppModel {
    AppModel(
      initialPolicySet: PolicySetDocument(setIdentifier: UUID(), revision: 3, policies: [policy]),
      activationController: EmptyLifecycle(), runtimeController: runtime,
      policyChangeAuthorizer: authorizer)
  }
}

/// Decides like the system authorizer, but hands the runtime a fixed token instead of a
/// macOS authorization session.
@MainActor
private final class FakePolicyChangeAuthorizer: PolicyChangeAuthorizing {
  static let token = Data("authorization-session".utf8)
  private(set) var weakeningFlags: [Bool] = []
  var failure: (any Error)?

  func apply(
    _ document: PolicySetDocument, weakening: Bool, savedPolicyIdentifier: UUID?,
    using client: any ExtensionRuntimeControlling
  ) async throws -> PolicyApplyReceipt {
    weakeningFlags.append(weakening)
    if let failure { throw failure }
    return try await client.applyPolicySet(
      document, authorization: weakening ? Self.token : nil,
      savedPolicyIdentifier: savedPolicyIdentifier)
  }
}

private actor RecordingRuntime: ExtensionRuntimeControlling {
  struct Application: Equatable {
    var revision: UInt64
    var authorization: Data?
    var savedPolicyIdentifier: UUID?
  }

  private(set) var applied: [Application] = []
  private(set) var policyQueries = 0
  private var failure: NSError?

  func setFailure(_ failure: NSError?) { self.failure = failure }

  func applyPolicySet(
    _ document: PolicySetDocument, authorization: Data?, savedPolicyIdentifier: UUID?
  ) async throws -> PolicyApplyReceipt {
    applied.append(
      Application(
        revision: document.revision, authorization: authorization,
        savedPolicyIdentifier: savedPolicyIdentifier))
    if let failure { throw failure }
    return PolicyApplyReceipt(
      result: .accepted, acceptedSetIdentifier: document.setIdentifier,
      acceptedRevision: document.revision,
      acceptedDigest: try PolicySetDocumentCodec.digest(of: document))
  }

  func queryStatus() async throws -> ExtensionStatusSnapshot {
    throw ExtensionControlClientError.interfaceUnavailable
  }

  func queryPolicySet() async throws -> PolicySetDocument {
    policyQueries += 1
    throw Unused.call
  }

  func readAuditLog(maximumLineCount: Int) async throws -> AuditLogBatch { throw Unused.call }

  func invalidate() {}

  private enum Unused: Error { case call }
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
