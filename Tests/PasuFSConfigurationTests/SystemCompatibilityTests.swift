import Darwin
import Foundation
import PasuFSPolicy
import XCTest

@testable import PasuFSConfiguration

final class SystemCompatibilityTests: XCTestCase {
  private static let version26 = OperatingSystemVersion(
    majorVersion: 26, minorVersion: 6, patchVersion: 2)

  func testAuthorizationDigestCoversAuthorityOnly() throws {
    let original = makeProfile()
    let originalCatalog = SystemCompatibilityCatalog(profiles: [original])
    let originalDigest = try originalCatalog.authorizationDigest(for: original)

    var renamed = original
    renamed.displayName = "Renamed presentation"
    renamed.roleDescription = "Different explanation"
    renamed.consequence = "Different consequence"
    renamed.evidence.observedDate = "2026-08-28"
    renamed.evidence.observedOSBuilds.append("26A001")
    renamed.actors[0].observedOSBuilds.append("26A001")
    let renamedCatalog = SystemCompatibilityCatalog(profiles: [renamed])
    XCTAssertEqual(try renamedCatalog.authorizationDigest(for: renamed), originalDigest)
    XCTAssertNotEqual(try renamedCatalog.catalogDigest(), try originalCatalog.catalogDigest())

    let broadenings: [(String, (inout SystemCompatibilityProfile) -> Void)] = [
      ("open flags", { $0.actors[0].allowedOpenFlags |= UInt32(FWRITE) }),
      ("request kinds", { $0.actors[0].allowedRequests.append(.unlink) }),
      ("required flags", { $0.actors[0].requiredCodeSigningFlags &= ~UInt32(0x200) }),
      ("forbidden flags", { $0.actors[0].forbiddenCodeSigningFlags |= 0x8 }),
      ("OS range", { $0.actors[0].supportedOSRange.maximumExclusive?.major = 29 }),
      ("effective users", { $0.actors[0].allowedEffectiveUsers = .rootOrFolderOwner }),
      ("path form", { $0.pathForm = .appContainer }),
      ("actors", { $0.actors.append(self.makeActor("com.apple.example.extra")) }),
    ]
    for (label, change) in broadenings {
      var changed = original
      change(&changed)
      let catalog = SystemCompatibilityCatalog(profiles: [changed])
      XCTAssertNotEqual(try catalog.authorizationDigest(for: changed), originalDigest, label)
    }
  }

  func testDigestsIgnoreProfileActorAndRequestOrder() throws {
    let first = makeProfile(id: "system.example.first")
    var second = makeProfile(id: "system.example.second")
    second.actors.reverse()
    second.actors[0].allowedRequests.reverse()
    let forward = SystemCompatibilityCatalog(profiles: [first, second])
    let reverse = SystemCompatibilityCatalog(profiles: [second, first])
    XCTAssertEqual(try forward.catalogDigest(), try reverse.catalogDigest())
    XCTAssertEqual(
      try forward.authorizationDigest(profileIdentifier: second.id),
      try SystemCompatibilityCatalog(profiles: [makeProfile(id: second.id)])
        .authorizationDigest(profileIdentifier: second.id))
  }

  func testCatalogRejectsConduitsWeakSignaturesAndInconsistentActors() throws {
    let invalid: [(String, (inout SystemCompatibilityProfile) -> Void)] = [
      ("terminal", { $0.actors[0].signingIdentifier = "com.apple.Terminal" }),
      ("tmutil", { $0.actors[0].signingIdentifier = "com.apple.tmutil" }),
      ("finder", { $0.actors[0].signingIdentifier = "com.apple.finder" }),
      (
        "finder scripting helper",
        {
          $0.actors[0].signingIdentifier =
            "com.apple.desktopservices.desktopservicesscriptinghelper"
        }
      ),
      (
        "only launchers",
        {
          for index in $0.actors.indices {
            $0.actors[index].allowedRequests = []
            $0.actors[index].allowedOpenFlags = 0
          }
        }
      ),
      ("repeated request", { $0.actors[0].allowedRequests = [.open, .open] }),
      ("open flags without open", { $0.actors[0].allowedRequests = [.rename] }),
      (
        "open without flags",
        {
          $0.actors[0].allowedRequests = [.open]
          $0.actors[0].allowedOpenFlags = 0
        }
      ),
      ("platform flag not required", { $0.actors[0].requiredCodeSigningFlags = 0x1 }),
      ("ad hoc not forbidden", { $0.actors[0].forbiddenCodeSigningFlags = 0 }),
      ("conflicting flags", { $0.actors[0].forbiddenCodeSigningFlags |= 0x200 }),
      ("open-ended range", { $0.actors[0].supportedOSRange.maximumExclusive = nil }),
      ("build without evidence", { $0.actors[0].observedOSBuilds = ["26A999"] }),
      ("repeated actor", { $0.actors.append($0.actors[0]) }),
      ("broker", { $0.evidence.acceptsArbitraryThirdPartyCommandsOrPaths = true }),
      (
        "broker for any client",
        {
          $0.evidence.capabilityClass = .platformClientBroker
          $0.evidence.acceptsArbitraryThirdPartyCommandsOrPaths = true
        }
      ),
      ("local evidence", { $0.evidence.evidenceReference = "/Users/example/notes.md" }),
      ("bad date", { $0.evidence.observedDate = "2026-02-30" }),
    ]
    XCTAssertNoThrow(try SystemCompatibilityCatalog(profiles: [makeProfile()]).validate())
    var broker = makeProfile()
    broker.evidence.capabilityClass = .platformClientBroker
    XCTAssertNoThrow(try SystemCompatibilityCatalog(profiles: [broker]).validate())
    for (label, change) in invalid {
      var profile = makeProfile()
      change(&profile)
      XCTAssertThrowsError(try SystemCompatibilityCatalog(profiles: [profile]).validate(), label)
    }
    var conduit = makeProfile()
    conduit.actors[0].signingIdentifier = "com.apple.ls"
    XCTAssertThrowsError(try SystemCompatibilityCatalog(profiles: [conduit]).validate()) {
      XCTAssertEqual(
        $0 as? SystemCompatibilityValidationError,
        .forbiddenCapabilityConduit(profile: conduit.id, signingIdentifier: "com.apple.ls"))
    }
  }

  func testActorMatchesIdentityAndAllowsItsRequestsOnly() throws {
    let actor = makeActor(
      "com.apple.example.worker", requests: [.open, .rename],
      openFlags: SystemCompatibilityOpenFlags.readOnly)
    let flags = SystemCompatibilityCodeSigning.minimumRequired | SystemCompatibilityCodeSigning.kill
    XCTAssertTrue(actor.matches(try facts("com.apple.example.worker", flags: flags)))
    XCTAssertFalse(actor.matches(try facts("com.apple.example.other", flags: flags)))
    XCTAssertFalse(
      actor.matches(try facts("com.apple.example.worker", flags: flags, platform: false)))
    XCTAssertFalse(actor.matches(try facts("com.apple.example.worker", flags: flags | 0x2)))
    XCTAssertFalse(actor.matches(try facts("com.apple.example.worker", flags: flags & ~0x200)))

    XCTAssertTrue(actor.allows(.open, openFlags: 0x1 | 0x0010_0000 | 0x0100_0000))
    XCTAssertFalse(actor.allows(.open, openFlags: 0x1 | 0x2))
    XCTAssertFalse(actor.allows(.open, openFlags: 0x1 | 0x400))
    XCTAssertFalse(actor.allows(.open, openFlags: nil))
    XCTAssertTrue(actor.allows(.rename, openFlags: nil))
    XCTAssertFalse(actor.allows(.unlink, openFlags: nil))
    XCTAssertFalse(actor.allows(.create, openFlags: nil))
    XCTAssertEqual(
      SystemCompatibilityOpenFlags.readOnly & SystemCompatibilityOpenFlags.modifying, 0)
  }

  func testResolverReportsEveryState() throws {
    let catalog = SystemCompatibilityCatalog(profiles: [makeProfile()])
    let current = try catalog.policyEntry(profileIdentifier: "system.example.profile")
    let stale = PolicySystemCompatibilityProfile(
      profileIdentifier: current.profileIdentifier,
      authorizationDigest: String(repeating: "e", count: 64))
    let missing = PolicySystemCompatibilityProfile(
      profileIdentifier: "system.example.gone",
      authorizationDigest: String(repeating: "f", count: 64))

    let set = makePolicySet(
      makePolicy(id: 1, profiles: [current]), makePolicy(id: 2, profiles: [stale, missing]),
      makePolicy(id: 3))
    let resolution = try SystemCompatibilityResolver.resolve(
      policySet: set, catalog: catalog, operatingSystemVersion: Self.version26)
    XCTAssertEqual(
      resolution.profileResolutions.map(\.state), [.active, .needsReview, .missingProfile])
    XCTAssertEqual(resolution.activeProfileCount, 1)
    XCTAssertEqual(resolution.activeProfilesByPolicy.count, 1)
    let active = try XCTUnwrap(resolution.activeProfilesByPolicy[set.policies[0].id]?.first)
    XCTAssertEqual(active.profileIdentifier, "system.example.profile")
    XCTAssertEqual(active.authorizationDigest, current.authorizationDigest)
    XCTAssertEqual(
      resolution.profileResolutions[1].currentAuthorizationDigest, current.authorizationDigest)
    XCTAssertEqual(
      resolution.inactiveProfileWarning, "2 enabled system-compatibility profiles are inactive.")

    for major in [25, 28] {
      let other = OperatingSystemVersion(majorVersion: major, minorVersion: 0, patchVersion: 0)
      let unsupported = try SystemCompatibilityResolver.resolve(
        policySet: makePolicySet(makePolicy(id: 1, profiles: [current])), catalog: catalog,
        operatingSystemVersion: other)
      XCTAssertEqual(unsupported.profileResolutions.map(\.state), [.unsupportedOS])
      XCTAssertTrue(unsupported.activeProfilesByPolicy.isEmpty)
      XCTAssertEqual(
        unsupported.inactiveProfileWarning,
        "System-compatibility profile system.example.profile is inactive: unsupportedOS.")
    }
    XCTAssertNil(
      try SystemCompatibilityResolver.resolve(
        policySet: makePolicySet(makePolicy(id: 3)), catalog: catalog
      ).inactiveProfileWarning)
  }

  func testOnlyANewlyTurnedOnProfileMustBeActive() throws {
    let catalog = SystemCompatibilityCatalog(profiles: [makeProfile()])
    let current = try catalog.policyEntry(profileIdentifier: "system.example.profile")
    let stale = PolicySystemCompatibilityProfile(
      profileIdentifier: current.profileIdentifier,
      authorizationDigest: String(repeating: "e", count: 64))
    func check(_ candidate: PolicySetDocument, _ stored: PolicySetDocument?) throws {
      let resolution = try SystemCompatibilityResolver.resolve(
        policySet: candidate, catalog: catalog, operatingSystemVersion: Self.version26)
      try SystemCompatibilityResolver.validateNewlyTurnedOn(
        candidate: candidate, comparedTo: stored, resolution: resolution)
    }
    let withStale = makePolicySet(makePolicy(id: 1, profiles: [stale]))
    XCTAssertThrowsError(try check(withStale, nil)) {
      XCTAssertEqual(
        $0 as? SystemCompatibilityValidationError,
        .profileCannotBeTurnedOn("system.example.profile", .needsReview))
    }
    var renamed = withStale
    renamed.revision += 1
    renamed.policies[0].name = "Renamed"
    XCTAssertNoThrow(try check(renamed, withStale))
    XCTAssertNoThrow(try check(makePolicySet(makePolicy(id: 1, profiles: [current])), withStale))
    XCTAssertNoThrow(try check(makePolicySet(makePolicy(id: 1)), withStale))
  }

  func testBuiltInCatalogIsValid() throws {
    let catalog = BuiltInSystemCompatibilityCatalog.catalog
    XCTAssertNoThrow(try catalog.validate())
    XCTAssertEqual(
      catalog.profiles.map(\.id),
      [
        BuiltInSystemCompatibilityCatalog.containerManagementIdentifier,
        BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier,
        BuiltInSystemCompatibilityCatalog.finderCopyIdentifier,
      ])
    let digests = try catalog.profiles.map { try catalog.authorizationDigest(for: $0) }
    XCTAssertEqual(Set(digests).count, 3)
    XCTAssertEqual(try catalog.catalogDigest().count, 64)
    for profile in catalog.profiles {
      XCTAssertFalse(profile.evidence.evidenceReference.contains("/Users/"), profile.id)
      for actor in profile.actors {
        XCTAssertTrue(actor.signingIdentifier.hasPrefix("com.apple."), actor.signingIdentifier)
        XCTAssertNotNil(actor.supportedOSRange.maximumExclusive)
        XCTAssertTrue(actor.supportedOSRange.contains(Self.version26))
      }
    }
    // Every request observed for the container services and XProtect was an open for reading.
    for identifier in [
      BuiltInSystemCompatibilityCatalog.containerManagementIdentifier,
      BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier,
    ] {
      for actor in try XCTUnwrap(catalog.profile(identifier: identifier)).actors {
        XCTAssertTrue(actor.allowedRequests.allSatisfy { $0 == .open }, actor.signingIdentifier)
        XCTAssertEqual(actor.allowedOpenFlags & SystemCompatibilityOpenFlags.modifying, 0)
      }
    }
    let container = try XCTUnwrap(
      catalog.profile(identifier: BuiltInSystemCompatibilityCatalog.containerManagementIdentifier))
    XCTAssertEqual(container.pathForm, .appContainer)
    XCTAssertEqual(
      Dictionary(
        uniqueKeysWithValues: container.actors.map {
          ($0.signingIdentifier, $0.allowedEffectiveUsers)
        }),
      [
        "com.apple.containermanagerd": .rootOrFolderOwner,
        "com.apple.containermanagerd_system": .root,
        "com.apple.secinitd": .rootOrFolderOwner,
        "com.apple.apfsd": .root,
      ])
    let remediation = try XCTUnwrap(
      catalog.profile(identifier: BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier))
    XCTAssertEqual(remediation.pathForm, .anyPath)
    XCTAssertEqual(
      remediation.actors.filter(\.isLauncher).map(\.signingIdentifier),
      ["com.apple.XprotectFramework.PluginService"])
    // The analysis service is admitted only as root, the instance that syspolicyd uses; the
    // remediator plug-ins also as the folder's owner.
    let analysis = try XCTUnwrap(
      remediation.actors.first {
        $0.signingIdentifier == "com.apple.XprotectFramework.AnalysisService"
      })
    XCTAssertEqual(analysis.allowedEffectiveUsers, .root)
    XCTAssertEqual(analysis.observedOSBuilds, ["25G83", "26A434", "26B5101f"])
    XCTAssertEqual(remediation.evidence.observedOSBuilds, ["25G83", "26A434", "26B5101f"])
    XCTAssertEqual(remediation.evidence.capabilityClass, .platformClientBroker)
    XCTAssertFalse(remediation.evidence.acceptsArbitraryThirdPartyCommandsOrPaths)
    let plugIns = remediation.actors.filter { !$0.isLauncher && $0 != analysis }
    XCTAssertEqual(plugIns.count, 25)
    XCTAssertTrue(
      plugIns.allSatisfy {
        $0.signingIdentifier.hasPrefix("com.apple.XProtectFramework.plugins.")
          && $0.allowedEffectiveUsers == .rootOrFolderOwner
      })
  }

  /// The Finder copy profile lets one helper make exactly the requests it was seen to make.
  func testFinderCopyProfileAllowsOnlyTheObservedRequests() throws {
    let profile = try XCTUnwrap(
      BuiltInSystemCompatibilityCatalog.catalog.profile(
        identifier: BuiltInSystemCompatibilityCatalog.finderCopyIdentifier))
    XCTAssertEqual(profile.pathForm, .anyPath)
    XCTAssertEqual(profile.evidence.capabilityClass, .platformClientBroker)
    XCTAssertFalse(profile.evidence.acceptsArbitraryThirdPartyCommandsOrPaths)
    XCTAssertEqual(profile.evidence.observedOSBuilds, ["25G83", "26A434"])
    XCTAssertEqual(profile.actors.count, 1)
    let helper = profile.actors[0]
    XCTAssertEqual(helper.signingIdentifier, "com.apple.DesktopServicesHelper")
    XCTAssertFalse(helper.isLauncher)
    XCTAssertEqual(helper.allowedEffectiveUsers, .rootOrFolderOwner)
    XCTAssertEqual(
      helper.requiredCodeSigningFlags,
      SystemCompatibilityCodeSigning.minimumRequired | SystemCompatibilityCodeSigning.kill)
    XCTAssertEqual(
      helper.forbiddenCodeSigningFlags, SystemCompatibilityCodeSigning.minimumForbidden)
    XCTAssertEqual(
      helper.supportedOSRange,
      SystemCompatibilityOSRange(
        minimum: SystemCompatibilityOSVersion(major: 26),
        maximumExclusive: SystemCompatibilityOSVersion(major: 28)))
    let observed: Set<SystemCompatibilityRequestKind> = [
      .create, .open, .truncate, .clone, .setAttributeList, .setExtendedAttribute,
      .deleteExtendedAttribute,
    ]
    XCTAssertEqual(Set(helper.allowedRequests), observed)
    XCTAssertEqual(
      helper.allowedOpenFlags,
      UInt32(FREAD | FWRITE | O_NONBLOCK | O_EVTONLY | O_DIRECTORY | O_CLOEXEC))
    XCTAssertEqual(helper.allowedOpenFlags & SystemCompatibilityOpenFlags.modifying, UInt32(FWRITE))

    // The opens seen on macOS 27: a source file, a source folder, a new folder; on macOS 26,
    // a restored file.
    for flags in [0x8001, 0x0110_0001, 0x8005, 0x2] {
      XCTAssertTrue(helper.allows(.open, openFlags: UInt32(flags)), String(flags, radix: 16))
    }
    for flag in [O_CREAT, O_TRUNC, O_APPEND, O_EXCL, O_NOFOLLOW, O_SYMLINK] {
      XCTAssertFalse(helper.allows(.open, openFlags: UInt32(FWRITE | flag)), "\(flag)")
    }
    for request in SystemCompatibilityRequestKind.allCases {
      XCTAssertEqual(
        helper.allows(request, openFlags: UInt32(FREAD)), observed.contains(request),
        request.rawValue)
    }
  }

  /// Policies store each profile's authorization digest. Adding a profile to the catalog must
  /// leave the digests of the profiles already there unchanged, so their approvals stay valid;
  /// a profile whose programs or requests change gets a new digest, so it must be approved again.
  func testDigestsOfEarlierProfilesAreUnchanged() throws {
    let catalog = BuiltInSystemCompatibilityCatalog.catalog
    XCTAssertEqual(SystemCompatibilityCatalog.currentSchemaVersion, 3)
    XCTAssertEqual(
      try catalog.authorizationDigest(
        profileIdentifier: BuiltInSystemCompatibilityCatalog.containerManagementIdentifier),
      "b91d4cb4ceb550c51d6fac3fa8ce88049c521aa79dc04b0080a890aa3770d185")
    XCTAssertEqual(
      try catalog.authorizationDigest(
        profileIdentifier: BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier),
      "a0af091707ad98dcc4c7d776ad8d2f00d1765daf7b58a9c833b8d60feeeed7d9")
  }

  func testEffectiveUserRule() {
    let rootOnly = makeActor()
    var owner = makeActor()
    owner.allowedEffectiveUsers = .rootOrFolderOwner
    XCTAssertTrue(rootOnly.allowsEffectiveUser(0, folderOwnerUserID: 501))
    XCTAssertFalse(rootOnly.allowsEffectiveUser(501, folderOwnerUserID: 501))
    XCTAssertTrue(owner.allowsEffectiveUser(0, folderOwnerUserID: nil))
    XCTAssertTrue(owner.allowsEffectiveUser(501, folderOwnerUserID: 501))
    XCTAssertFalse(owner.allowsEffectiveUser(502, folderOwnerUserID: 501))
    XCTAssertFalse(owner.allowsEffectiveUser(501, folderOwnerUserID: nil))
    XCTAssertFalse(owner.allowsEffectiveUser(nil, folderOwnerUserID: 501))
  }

  func testAppContainerPathForm() {
    let form = SystemCompatibilityPathForm.appContainer
    let home = "/Users/example"
    for path in [
      "/Users/example/Library/Containers/com.example.App",
      "/Users/example/Library/Containers/com.example.App/Data/Documents/a.txt",
      "/Users/example/Library/Group Containers/group.com.example/b",
      "/users/EXAMPLE/library/containers/com.example.App",
    ] {
      XCTAssertTrue(form.admits(path, ownerHome: home, caseSensitive: false), path)
    }
    for path in [
      "/Users/example/Library/Containers",
      "/Users/example/Library/Group Containers",
      "/Users/example/Documents/Containers/x",
      "/Users/sample/Library/Containers/com.example.App",
      "/Users/example/Library/Containers/../Preferences/x",
      "relative/Library/Containers/x",
    ] {
      XCTAssertFalse(form.admits(path, ownerHome: home, caseSensitive: false), path)
    }
    XCTAssertFalse(
      form.admits(
        "/users/example/Library/Containers/x", ownerHome: home, caseSensitive: true))
    XCTAssertFalse(
      form.admits("/Users/example/Library/Containers/x", ownerHome: nil, caseSensitive: false))
    XCTAssertTrue(
      SystemCompatibilityPathForm.anyPath.admits("/anywhere", ownerHome: nil, caseSensitive: true))
  }

  // MARK: - Helpers

  private func makeActor(
    _ signing: String = "com.apple.example.worker",
    requests: [SystemCompatibilityRequestKind] = [.open],
    openFlags: UInt32 = UInt32(FREAD)
  ) -> SystemCompatibilityProfileActor {
    SystemCompatibilityProfileActor(
      signingIdentifier: signing,
      allowedRequests: requests,
      allowedOpenFlags: requests.contains(.open) ? openFlags : 0,
      requiredCodeSigningFlags: SystemCompatibilityCodeSigning.minimumRequired
        | SystemCompatibilityCodeSigning.kill,
      supportedOSRange: SystemCompatibilityOSRange(
        minimum: SystemCompatibilityOSVersion(major: 26),
        maximumExclusive: SystemCompatibilityOSVersion(major: 28)),
      observedOSBuilds: ["25G83"])
  }

  private func makeProfile(id: String = "system.example.profile") -> SystemCompatibilityProfile {
    SystemCompatibilityProfile(
      id: id,
      displayName: "Example",
      roleDescription: "Reads protected files for one operating-system feature.",
      consequence: "The feature can read this folder.",
      evidence: SystemCompatibilityProfileEvidence(
        capabilityClass: .singlePurposeAutonomousService,
        acceptsArbitraryThirdPartyCommandsOrPaths: false,
        observedOSBuilds: ["25G83"],
        observedDate: "2026-10-10",
        evidenceReference: "Synthetic evidence used only by unit tests.",
        capabilityAssessment: "Synthetic assessment used only by unit tests."),
      actors: [
        makeActor("com.apple.example.worker", requests: [.open, .rename]),
        makeActor("com.apple.example.helper"),
      ])
  }

  private func makePolicy(id: Int, profiles: [PolicySystemCompatibilityProfile] = [])
    -> DirectoryPolicy
  {
    DirectoryPolicy(
      id: UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", id))!,
      name: "Policy \(id)", mode: .protection,
      protectedRootPath: "/Users/example/Protected\(id)",
      systemCompatibilityProfiles: profiles)
  }

  private func makePolicySet(_ policies: DirectoryPolicy...) -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
      revision: 1, policies: policies)
  }

  private func facts(_ signing: String, flags: UInt32, platform: Bool = true) throws
    -> ProcessFacts
  {
    ProcessFacts(
      auditToken: try AuditTokenKey(words: Array(repeating: 1, count: 8)),
      processInstance: ProcessInstanceKey(processID: 1, processVersion: 1),
      teamIdentifier: nil, signingIdentifier: signing, isPlatformBinary: platform,
      codeSigningFlags: flags, effectiveUserID: 0, originalParentProcessID: 1)
  }
}
