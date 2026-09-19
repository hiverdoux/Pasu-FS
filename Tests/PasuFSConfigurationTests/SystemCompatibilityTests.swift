import Darwin
import Foundation
import PasuFSPolicy
import XCTest

@testable import PasuFSConfiguration

final class SystemCompatibilityTests: XCTestCase {
  func testAuthorizationDigestIgnoresPresentationButChangesWithAuthority() throws {
    let original = makeProfile()
    let originalCatalog = SystemCompatibilityCatalog(profiles: [original])
    let originalDigest = try originalCatalog.authorizationDigest(for: original)

    var renamed = original
    renamed.displayName = "Renamed presentation"
    renamed.roleDescription = "Different explanation"
    renamed.consequence = "Different consequence"
    let renamedCatalog = SystemCompatibilityCatalog(profiles: [renamed])
    XCTAssertEqual(
      try renamedCatalog.authorizationDigest(for: renamed),
      originalDigest
    )
    XCTAssertNotEqual(
      try renamedCatalog.catalogDigest(),
      try originalCatalog.catalogDigest()
    )

    var expanded = original
    expanded.actors[0].allowedOpenFlags |= UInt32(FWRITE)
    let expandedCatalog = SystemCompatibilityCatalog(profiles: [expanded])
    XCTAssertNotEqual(
      try expandedCatalog.authorizationDigest(for: expanded),
      originalDigest
    )

    var signatureConstrained = original
    signatureConstrained.actors[0].requiredCodeSigningFlags = 0x0000_0001
    let constrainedCatalog = SystemCompatibilityCatalog(profiles: [signatureConstrained])
    XCTAssertNotEqual(
      try constrainedCatalog.authorizationDigest(for: signatureConstrained),
      originalDigest
    )

    var reobserved = original
    reobserved.evidence.observedDate = "2026-08-28"
    let reobservedCatalog = SystemCompatibilityCatalog(profiles: [reobserved])
    XCTAssertEqual(
      try reobservedCatalog.authorizationDigest(for: reobserved),
      originalDigest
    )
    XCTAssertNotEqual(
      try reobservedCatalog.catalogDigest(),
      try originalCatalog.catalogDigest()
    )

    var newBuild = original
    newBuild.evidence.observedOSBuilds.append("23A001")
    newBuild.actors[0].supportedOSBuilds.append("23A001")
    let newBuildCatalog = SystemCompatibilityCatalog(profiles: [newBuild])
    XCTAssertNotEqual(
      try newBuildCatalog.authorizationDigest(for: newBuild),
      originalDigest
    )
  }

  func testCatalogRejectsCapabilityConduitsAndUnboundedOrUnverifiedBuilds() throws {
    var conduit = makeProfile()
    conduit.actors[0].signingIdentifier = "com.apple.Terminal"
    XCTAssertThrowsError(try SystemCompatibilityCatalog(profiles: [conduit]).validate())

    var measuredFileTool = makeProfile()
    measuredFileTool.actors[0].signingIdentifier = "com.apple.ls"
    XCTAssertThrowsError(
      try SystemCompatibilityCatalog(profiles: [measuredFileTool]).validate()
    ) { error in
      XCTAssertEqual(
        error as? SystemCompatibilityValidationError,
        .forbiddenCapabilityConduit(
          profile: measuredFileTool.id,
          signingIdentifier: "com.apple.ls"
        )
      )
    }

    var unbounded = makeProfile()
    unbounded.actors[0].supportedOSRange.maximumExclusive = nil
    XCTAssertThrowsError(try SystemCompatibilityCatalog(profiles: [unbounded]).validate())

    var unevidenced = makeProfile()
    unevidenced.actors[0].supportedOSBuilds = ["23A999"]
    XCTAssertThrowsError(try SystemCompatibilityCatalog(profiles: [unevidenced]).validate())

    var arbitraryBroker = makeProfile()
    arbitraryBroker.evidence.acceptsArbitraryThirdPartyCommandsOrPaths = true
    XCTAssertThrowsError(
      try SystemCompatibilityCatalog(profiles: [arbitraryBroker]).validate()
    )
  }

  func testDigestCanonicalizationIgnoresProfileAndActorOrdering() throws {
    let first = makeProfile(id: "system.example.first")
    var second = makeProfile(id: "system.example.second")
    second.actors.reverse()

    let forward = SystemCompatibilityCatalog(profiles: [first, second])
    let reverse = SystemCompatibilityCatalog(profiles: [second, first])

    XCTAssertEqual(try forward.catalogDigest(), try reverse.catalogDigest())
    XCTAssertEqual(
      try forward.authorizationDigest(profileIdentifier: second.id),
      try reverse.authorizationDigest(profileIdentifier: second.id)
    )
    XCTAssertEqual(try BuiltInSystemCompatibilityCatalog.catalog.catalogDigest().count, 64)
  }

  func testSettingsCodecRoundTripAndStrictUnknownKeyRejection() throws {
    let policy = makePolicy()
    let catalog = SystemCompatibilityCatalog(profiles: [makeProfile()])
    let digest = try catalog.authorizationDigest(profileIdentifier: "system.example.profile")
    let document = makeSettings(
      policy: policy,
      approval: ApprovedSystemCompatibilityProfile(
        profileIdentifier: "system.example.profile",
        approvedAuthorizationDigest: digest,
        isEnabled: true
      )
    )

    let data = try SystemCompatibilitySettingsCodec.encode(document)
    XCTAssertEqual(try SystemCompatibilitySettingsCodec.decode(data), document)
    XCTAssertEqual(try SystemCompatibilitySettingsCodec.digest(of: document).count, 64)

    var object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: data) as? [String: Any]
    )
    object["unexpected"] = true
    XCTAssertThrowsError(
      try SystemCompatibilitySettingsCodec.decode(
        JSONSerialization.data(withJSONObject: object)
      )
    ) { error in
      XCTAssertEqual(
        error as? SystemCompatibilitySettingsCodecError,
        .unknownTopLevelKeys(["unexpected"])
      )
    }
  }

  func testApplyRequestCarriesPerRequestCatalogDigest() throws {
    let digest = try BuiltInSystemCompatibilityCatalog.catalog.catalogDigest()
    let request = SystemCompatibilitySettingsApplyRequest(
      catalogDigest: digest,
      settingsData: Data([1, 2, 3])
    )
    let decoded = try JSONDecoder().decode(
      SystemCompatibilitySettingsApplyRequest.self,
      from: JSONEncoder().encode(request)
    )

    XCTAssertEqual(decoded, request)
    XCTAssertTrue(SystemCompatibilityDigest.isCanonicalSHA256(decoded.catalogDigest))
    XCTAssertFalse(SystemCompatibilityDigest.isCanonicalSHA256(""))
    XCTAssertFalse(
      SystemCompatibilityDigest.isCanonicalSHA256(String(repeating: "A", count: 64))
    )
  }

  func testStorageWarningSurvivesResolutionRefreshUntilExplicitlyCleared() {
    var warnings = SystemCompatibilityWarningState()
    warnings.recordStorageRejection()

    warnings.replaceResolutionWarning(nil)
    XCTAssertEqual(
      warnings.combinedWarning,
      SystemCompatibilityWarningState.storageRejectionMessage
    )
    XCTAssertFalse(warnings.combinedWarning?.contains("Error Domain") == true)

    warnings.replaceResolutionWarning("One enabled profile needs review.")
    XCTAssertEqual(
      warnings.combinedWarning,
      SystemCompatibilityWarningState.storageRejectionMessage
        + " One enabled profile needs review."
    )

    warnings.clearStorageWarning()
    XCTAssertNil(warnings.storageWarning)
    XCTAssertEqual(warnings.combinedWarning, "One enabled profile needs review.")

    warnings.replaceResolutionWarning(nil)
    XCTAssertNil(warnings.combinedWarning)
  }

  func testResolverActivatesOnlyCurrentEnabledApproval() throws {
    let policy = makePolicy()
    let policySet = makePolicySet(policy)
    let profile = makeProfile()
    let catalog = SystemCompatibilityCatalog(profiles: [profile])
    let digest = try catalog.authorizationDigest(for: profile)
    let settings = makeSettings(
      policy: policy,
      approval: ApprovedSystemCompatibilityProfile(
        profileIdentifier: profile.id,
        approvedAuthorizationDigest: digest,
        isEnabled: true
      )
    )

    let resolution = try SystemCompatibilityResolver.resolve(
      settings: settings,
      policySet: policySet,
      catalog: catalog,
      operatingSystemVersion: OperatingSystemVersion(
        majorVersion: 14,
        minorVersion: 0,
        patchVersion: 0
      ),
      operatingSystemBuild: "23A000"
    )
    XCTAssertEqual(resolution.profileResolutions.map(\.state), [.active])
    XCTAssertEqual(resolution.activeProfilesByPolicy[policy.id]?.count, 1)
    let unobservedBuild = try SystemCompatibilityResolver.resolve(
      settings: settings,
      policySet: policySet,
      catalog: catalog,
      operatingSystemVersion: OperatingSystemVersion(
        majorVersion: 14,
        minorVersion: 0,
        patchVersion: 0
      ),
      operatingSystemBuild: "23A999"
    )
    XCTAssertEqual(unobservedBuild.profileResolutions.map(\.state), [.unsupportedOS])
    XCTAssertTrue(unobservedBuild.activeProfilesByPolicy.isEmpty)
    XCTAssertNoThrow(
      try SystemCompatibilityResolver.validateForApply(
        settings,
        policySet: policySet,
        catalog: catalog,
        operatingSystemVersion: OperatingSystemVersion(
          majorVersion: 14,
          minorVersion: 0,
          patchVersion: 0
        ),
        operatingSystemBuild: "23A000"
      )
    )
  }

  func testResolverRequiresReviewForAuthorizationChangeAndContextChange() throws {
    let policy = makePolicy()
    let policySet = makePolicySet(policy)
    let original = makeProfile()
    let originalCatalog = SystemCompatibilityCatalog(profiles: [original])
    let originalDigest = try originalCatalog.authorizationDigest(for: original)
    let settings = makeSettings(
      policy: policy,
      approval: ApprovedSystemCompatibilityProfile(
        profileIdentifier: original.id,
        approvedAuthorizationDigest: originalDigest,
        isEnabled: true
      )
    )

    var changed = original
    changed.actors[0].allowedOpenFlags |= UInt32(FWRITE)
    let changedCatalog = SystemCompatibilityCatalog(profiles: [changed])
    let changedResolution = try SystemCompatibilityResolver.resolve(
      settings: settings,
      policySet: policySet,
      catalog: changedCatalog
    )
    XCTAssertEqual(changedResolution.profileResolutions.map(\.state), [.needsReview])
    XCTAssertTrue(changedResolution.activeProfilesByPolicy.isEmpty)

    var movedPolicy = policy
    movedPolicy.protectedRootPath = "/Users/example/Other"
    let movedResolution = try SystemCompatibilityResolver.resolve(
      settings: settings,
      policySet: makePolicySet(movedPolicy),
      catalog: originalCatalog
    )
    XCTAssertEqual(
      movedResolution.profileResolutions.map(\.state),
      [.policyContextChanged]
    )
  }

  func testDisabledMissingProfileIsPreservedButCannotBecomeActive() throws {
    let policy = makePolicy()
    let policySet = makePolicySet(policy)
    let missing = ApprovedSystemCompatibilityProfile(
      profileIdentifier: "system.example.missing",
      approvedAuthorizationDigest: String(repeating: "a", count: 64),
      isEnabled: false
    )
    let disabledSettings = makeSettings(policy: policy, approval: missing)
    let emptyCatalog = SystemCompatibilityCatalog(profiles: [])

    XCTAssertNoThrow(
      try SystemCompatibilityResolver.validateForApply(
        disabledSettings,
        policySet: policySet,
        catalog: emptyCatalog
      )
    )

    var enabledSettings = disabledSettings
    enabledSettings.bindings[0].profiles[0].isEnabled = true
    XCTAssertThrowsError(
      try SystemCompatibilityResolver.validateForApply(
        enabledSettings,
        policySet: policySet,
        catalog: emptyCatalog
      )
    )
  }

  func testStaleSettingsForAnotherPolicySetFailClosedWithoutRejectingPolicy() throws {
    let policy = makePolicy()
    let policySet = makePolicySet(policy)
    let profile = makeProfile()
    let catalog = SystemCompatibilityCatalog(profiles: [profile])
    let digest = try catalog.authorizationDigest(for: profile)
    var settings = makeSettings(
      policy: policy,
      approval: ApprovedSystemCompatibilityProfile(
        profileIdentifier: profile.id,
        approvedAuthorizationDigest: digest,
        isEnabled: true
      )
    )
    settings.policySetIdentifier = UUID(
      uuidString: "DDDDDDDD-DDDD-DDDD-DDDD-DDDDDDDDDDDD"
    )!

    let resolution = try SystemCompatibilityResolver.resolve(
      settings: settings,
      policySet: policySet,
      catalog: catalog
    )
    XCTAssertTrue(resolution.activeProfilesByPolicy.isEmpty)
    XCTAssertEqual(
      resolution.profileResolutions.map(\.state),
      [.policyContextChanged]
    )
    XCTAssertThrowsError(
      try SystemCompatibilityResolver.validateForApply(
        settings,
        policySet: policySet,
        catalog: catalog
      )
    )
  }

  func testExistingInactiveApprovalCanBeCarriedButNotChanged() throws {
    let policy = makePolicy()
    let profile = makeProfile()
    let secondProfile = makeProfile(id: "system.example.second")
    let catalog = SystemCompatibilityCatalog(profiles: [profile, secondProfile])
    let digest = try catalog.authorizationDigest(for: profile)
    let active = makeSettings(
      policy: policy,
      approval: ApprovedSystemCompatibilityProfile(
        profileIdentifier: profile.id,
        approvedAuthorizationDigest: digest,
        isEnabled: true
      )
    )
    var movedPolicy = policy
    movedPolicy.protectedRootPath = "/Users/example/Moved"
    var secondPolicy = policy
    secondPolicy.id = UUID(uuidString: "33333333-3333-3333-3333-333333333333")!
    secondPolicy.name = "Second"
    secondPolicy.protectedRootPath = "/Users/example/Second"
    let movedPolicySet = PolicySetDocument(
      setIdentifier: makePolicySet(policy).setIdentifier,
      revision: 2,
      policies: [movedPolicy, secondPolicy]
    )
    var carried = active
    carried.revision += 1
    carried.bindings.append(
      PolicySystemCompatibilityBinding(
        policy: secondPolicy,
        profiles: [
          ApprovedSystemCompatibilityProfile(
            profileIdentifier: secondProfile.id,
            approvedAuthorizationDigest: try catalog.authorizationDigest(for: secondProfile),
            isEnabled: true
          )
        ]
      )
    )

    XCTAssertNoThrow(
      try SystemCompatibilityResolver.validateForApply(
        carried,
        against: active,
        policySet: movedPolicySet,
        catalog: catalog,
        operatingSystemVersion: OperatingSystemVersion(
          majorVersion: 14,
          minorVersion: 0,
          patchVersion: 0
        ),
        operatingSystemBuild: "23A000"
      )
    )

    var changed = carried
    changed.bindings[0].profiles[0].approvedAuthorizationDigest =
      String(repeating: "f", count: 64)
    XCTAssertThrowsError(
      try SystemCompatibilityResolver.validateForApply(
        changed,
        against: active,
        policySet: movedPolicySet,
        catalog: catalog,
        operatingSystemVersion: OperatingSystemVersion(
          majorVersion: 14,
          minorVersion: 0,
          patchVersion: 0
        ),
        operatingSystemBuild: "23A000"
      )
    )
  }

  func testReconcilerRemovesOrphanedBindingsAndMissingProfiles() throws {
    let removedPolicy = makePolicy()
    var blacklistPolicy = makePolicy()
    blacklistPolicy.id = UUID(uuidString: "11111111-1111-1111-1111-111111111111")!
    blacklistPolicy.name = "Blacklist"
    blacklistPolicy.policyType = .blacklist
    var approvedBlacklistContext = blacklistPolicy
    approvedBlacklistContext.policyType = .whitelist
    var retainedPolicy = makePolicy()
    retainedPolicy.id = UUID(uuidString: "22222222-2222-2222-2222-222222222222")!
    retainedPolicy.name = "Retained"
    retainedPolicy.protectedRootPath = "/Users/example/Retained"

    let profile = makeProfile()
    let catalog = SystemCompatibilityCatalog(profiles: [profile])
    let digest = try catalog.authorizationDigest(for: profile)
    let validApproval = ApprovedSystemCompatibilityProfile(
      profileIdentifier: profile.id,
      approvedAuthorizationDigest: digest,
      isEnabled: true
    )
    let missingApproval = ApprovedSystemCompatibilityProfile(
      profileIdentifier: "system.example.removed",
      approvedAuthorizationDigest: String(repeating: "a", count: 64),
      isEnabled: true
    )
    let settings = SystemCompatibilitySettingsDocument(
      settingsIdentifier: UUID(uuidString: "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC")!,
      revision: 1,
      policySetIdentifier: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
      bindings: [
        PolicySystemCompatibilityBinding(policy: removedPolicy, profiles: [validApproval]),
        PolicySystemCompatibilityBinding(
          policy: approvedBlacklistContext,
          profiles: [validApproval]
        ),
        PolicySystemCompatibilityBinding(
          policy: retainedPolicy,
          profiles: [validApproval, missingApproval]
        ),
      ]
    )
    let policySet = PolicySetDocument(
      setIdentifier: settings.policySetIdentifier,
      revision: 2,
      policies: [blacklistPolicy, retainedPolicy]
    )

    let result = try SystemCompatibilitySettingsReconciler.reconcile(
      settings,
      policySet: policySet,
      catalog: catalog
    )

    XCTAssertEqual(result.removedPolicyBindingCount, 2)
    XCTAssertEqual(result.removedProfileApprovalCount, 1)
    XCTAssertEqual(result.document.bindings.map(\.policyIdentifier), [retainedPolicy.id])
    XCTAssertEqual(result.document.bindings[0].profiles, [validApproval])
  }

  func testActorRequiresExactPlatformIdentityAndWholeFlagSubset() throws {
    let actor = makeProfile().actors[0]
    let platform = try processFacts(
      signingIdentifier: actor.signingIdentifier,
      isPlatformBinary: true
    )
    let impersonator = try processFacts(
      signingIdentifier: actor.signingIdentifier,
      isPlatformBinary: false
    )

    XCTAssertTrue(actor.allows(process: platform, requestedOpenFlags: UInt32(FREAD)))
    XCTAssertFalse(
      actor.allows(
        process: platform,
        requestedOpenFlags: UInt32(FREAD | FWRITE)
      )
    )
    XCTAssertFalse(actor.allows(process: impersonator, requestedOpenFlags: UInt32(FREAD)))
  }

  func testSettingsRevisionRejectsCollisionAndRollback() throws {
    let policy = makePolicy()
    let approval = ApprovedSystemCompatibilityProfile(
      profileIdentifier: "system.example.profile",
      approvedAuthorizationDigest: String(repeating: "a", count: 64),
      isEnabled: false
    )
    let active = makeSettings(policy: policy, approval: approval)
    XCTAssertEqual(
      try SystemCompatibilitySettingsUpdateValidator.validate(
        candidate: active,
        against: active
      ),
      .unchanged
    )

    var collision = active
    collision.bindings[0].profiles[0].approvedAuthorizationDigest =
      String(repeating: "b", count: 64)
    XCTAssertThrowsError(
      try SystemCompatibilitySettingsUpdateValidator.validate(
        candidate: collision,
        against: active
      )
    )

    var newer = active
    newer.revision = 2
    XCTAssertEqual(
      try SystemCompatibilitySettingsUpdateValidator.validate(
        candidate: newer,
        against: active
      ),
      .accepted
    )
    XCTAssertThrowsError(
      try SystemCompatibilitySettingsUpdateValidator.validate(
        candidate: active,
        against: newer
      )
    )
  }

  private func makeProfile(
    id: String = "system.example.profile"
  ) -> SystemCompatibilityProfile {
    SystemCompatibilityProfile(
      id: id,
      displayName: "Example system feature",
      roleDescription: "Reads protected files for one operating-system feature.",
      consequence: "A derived copy may be stored by the operating system.",
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
        ),
        SystemCompatibilityProfileActor(
          signingIdentifier: "com.apple.example.helper",
          allowedOpenFlags: UInt32(FREAD),
          supportedOSRange: SystemCompatibilityOSRange(
            minimum: SystemCompatibilityOSVersion(major: 14),
            maximumExclusive: SystemCompatibilityOSVersion(major: 15)
          ),
          supportedOSBuilds: ["23A000"]
        ),
      ]
    )
  }

  private func makePolicy() -> DirectoryPolicy {
    DirectoryPolicy(
      id: UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!,
      name: "Protected Files",
      mode: .protection,
      policyType: .whitelist,
      protectedRootPath: "/Users/example/Protected",
      rules: [
        .platformBinary(
          id: "rule.finder",
          signingIdentifier: "com.apple.finder",
          allowsDescendants: false
        )
      ]
    )
  }

  private func makePolicySet(_ policy: DirectoryPolicy) -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
      revision: 1,
      policies: [policy]
    )
  }

  private func makeSettings(
    policy: DirectoryPolicy,
    approval: ApprovedSystemCompatibilityProfile
  ) -> SystemCompatibilitySettingsDocument {
    SystemCompatibilitySettingsDocument(
      settingsIdentifier: UUID(uuidString: "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC")!,
      revision: 1,
      policySetIdentifier: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
      bindings: [
        PolicySystemCompatibilityBinding(policy: policy, profiles: [approval])
      ]
    )
  }

  private func processFacts(
    signingIdentifier: String,
    isPlatformBinary: Bool
  ) throws -> ProcessFacts {
    ProcessFacts(
      auditToken: try AuditTokenKey(words: Array(repeating: 1, count: 8)),
      processInstance: ProcessInstanceKey(processID: 1, processVersion: 1),
      teamIdentifier: nil,
      signingIdentifier: signingIdentifier,
      isPlatformBinary: isPlatformBinary
    )
  }
}
