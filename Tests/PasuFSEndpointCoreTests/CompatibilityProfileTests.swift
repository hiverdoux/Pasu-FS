import Darwin
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest

@testable import PasuFSEndpointCore

/// A compatibility profile turned on for a policy lets its Apple system processes make the
/// profile's requests without an observed history or an allow rule, when they run as root and
/// launchd started them; a blocked program in the history still denies.
final class CompatibilityProfileTests: XCTestCase {
  private static let daemonFlags =
    SystemCompatibilityCodeSigning.minimumRequired | SystemCompatibilityCodeSigning.kill
  private static let daemon = "com.apple.example.daemon"
  private static let helper = "com.apple.example.helper"
  private static let digest = String(repeating: "c", count: 64)

  private struct Fixture {
    let base: URL
    let home: URL
    let root: URL
    let nested: URL
    var inside: String { root.appendingPathComponent("sample.txt").path }
    var nestedFile: String { nested.appendingPathComponent("sample.txt").path }
  }

  func testDaemonWithoutHistoryIsAllowedOnlyWithTheProfile() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let daemon = try facts(signing: Self.daemon)

    let without = coordinator(fixture, profiles: [])
    let denied = without.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1)
    XCTAssertTrue(denied.isDenied)
    XCTAssertEqual(denied.policyEvaluations[0].executionOrigin?.reason, .incompleteHistory)

    let with = coordinator(fixture, profiles: [profile()])
    let allowed = with.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1)
    XCTAssertFalse(allowed.isDenied)
    XCTAssertEqual(allowed.policyDecision, "allowed")
    let evaluation = allowed.policyEvaluations[0]
    XCTAssertEqual(evaluation.match, .systemCompatibilityProfile)
    XCTAssertEqual(evaluation.decision, .allow)
    XCTAssertEqual(evaluation.systemCompatibilityProfileIdentifier, "example.profile")
    XCTAssertEqual(evaluation.systemCompatibilityAuthorizationDigest, Self.digest)
    XCTAssertNil(evaluation.ruleIdentifier)
    // The record keeps why the program lists alone would have denied the request.
    XCTAssertEqual(evaluation.executionOrigin?.reason, .incompleteHistory)
    XCTAssertEqual(evaluation.executionOrigin?.uncertainty, .beforeObservation)
  }

  func testDaemonThatLaunchdStartedBeforeObservationIsDecidedByTheLists() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let daemon = try startedByLaunchd(signing: Self.daemon)

    // The allow list doesn't name it: denied for its first program, not for a missing history.
    let allowList = coordinator(fixture, profiles: [], observationStart: Self.observationStart)
    let denied = allowList.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1)
    XCTAssertTrue(denied.isDenied)
    let origin = try XCTUnwrap(denied.policyEvaluations[0].executionOrigin)
    XCTAssertEqual(origin.reason, .originNotAllowed)
    XCTAssertNil(origin.uncertainty)
    XCTAssertEqual(origin.historyEvidence, .kernelLaunchdStart)

    // With the allow list off, nothing in its history is blocked.
    let blockList = coordinator(
      fixture, type: .blacklist, profiles: [], observationStart: Self.observationStart)
    let allowed = blockList.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1)
    XCTAssertFalse(allowed.isDenied)
    XCTAssertEqual(allowed.policyEvaluations[0].executionOrigin?.reason, .blacklistAllowed)

    // A block rule for it denies, whatever profile is on.
    let blocked = AllowRule(
      id: "rule.blocked", identity: .platformBinary(signingIdentifier: Self.daemon),
      allowsDescendants: false)
    let withRule = coordinator(
      fixture, type: .blacklist, denyRules: [blocked], profiles: [profile()],
      observationStart: Self.observationStart)
    let result = withRule.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1)
    XCTAssertTrue(result.isDenied)
    XCTAssertEqual(result.policyEvaluations[0].executionOrigin?.reason, .deniedInHistory)

    // Started after the observation start, the same daemon has no history.
    let late = try facts(
      seed: 11, signing: Self.daemon, parent: launchdFacts(),
      startTime: Self.observationStart.addingTimeInterval(1))
    let unobserved = blockList.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: late, requestedOpenFlags: 0x1)
    XCTAssertTrue(unobserved.isDenied)
    XCTAssertEqual(
      unobserved.policyEvaluations[0].executionOrigin?.uncertainty, .beforeObservation)
  }

  func testProfileAppliesWithEitherListSettingAndAnEmptyAllowList() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let daemon = try facts(signing: Self.daemon)
    for type in [PolicyType.whitelist, .blacklist] {
      let result = coordinator(fixture, type: type, profiles: [profile()]).evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1)
      XCTAssertFalse(result.isDenied, "\(type)")
      XCTAssertEqual(result.policyEvaluations[0].match, .systemCompatibilityProfile)
    }
  }

  func testBlockedProgramInTheHistoryWins() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let daemon = try facts(signing: Self.daemon)
    let blocked = AllowRule(
      id: "rule.blocked", identity: .platformBinary(signingIdentifier: Self.daemon),
      allowsDescendants: false)
    for type in [PolicyType.whitelist, .blacklist] {
      let target = coordinator(
        fixture, type: type, denyRules: [blocked], profiles: [profile()])
      let result = target.evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1)
      XCTAssertTrue(result.isDenied, "\(type)")
      XCTAssertEqual(result.policyEvaluations[0].executionOrigin?.reason, .deniedInHistory)
      XCTAssertNil(result.policyEvaluations[0].systemCompatibilityProfileIdentifier)
    }
  }

  func testRootIsRequired() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let target = coordinator(fixture, profiles: [profile()])
    for user in [UInt32(501), nil] {
      let process = try facts(signing: Self.daemon, effectiveUser: user)
      let result = target.evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: process, requestedOpenFlags: 0x1)
      XCTAssertTrue(result.isDenied, "\(String(describing: user))")
      XCTAssertNotEqual(result.policyEvaluations[0].match, .systemCompatibilityProfile)
    }
  }

  func testFolderOwnerMayRunAnActorThatAllowsIt() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let owner = getuid()
    var forOwner = actor(Self.daemon, requests: [.open])
    forOwner.allowedEffectiveUsers = .rootOrFolderOwner
    let ownerProfile = coordinator(fixture, profiles: [profile(actors: [forOwner])])
    let rootProfile = coordinator(
      fixture, profiles: [profile(actors: [actor(Self.daemon, requests: [.open])])])
    func result(_ target: EndpointEventCoordinator, user: UInt32) throws -> Bool {
      !target.evaluateOpen(
        path: fixture.inside, pathWasTruncated: false,
        process: try facts(signing: Self.daemon, effectiveUser: user), requestedOpenFlags: 0x1
      ).isDenied
    }
    XCTAssertTrue(try result(ownerProfile, user: owner))
    XCTAssertTrue(try result(ownerProfile, user: 0))
    XCTAssertFalse(try result(ownerProfile, user: owner &+ 1))
    XCTAssertFalse(try result(rootProfile, user: owner == 0 ? 501 : owner))
  }

  func testLauncherStartsActorsButGetsNoAccess() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let launcher = SystemCompatibilityProfileActor(
      signingIdentifier: Self.daemon, allowedRequests: [], allowedOpenFlags: 0,
      requiredCodeSigningFlags: Self.daemonFlags,
      supportedOSRange: SystemCompatibilityOSRange(
        minimum: SystemCompatibilityOSVersion(major: 26),
        maximumExclusive: SystemCompatibilityOSVersion(major: 28)),
      observedOSBuilds: ["25G83"])
    let target = coordinator(
      fixture, profiles: [profile(actors: [launcher, actor(Self.helper, requests: [.open])])])
    let service = try facts(seed: 40, signing: Self.daemon)
    try observeLaunch(service, in: target)
    XCTAssertTrue(
      target.evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: service, requestedOpenFlags: 0x1
      ).isDenied)
    let plugIn = try facts(seed: 41, signing: Self.helper, originalParent: 40)
    target.observeFork(parent: program(service), child: program(plugIn, as: service))
    target.observeExec(from: program(plugIn, as: service), to: program(plugIn))
    XCTAssertFalse(
      target.evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: plugIn, requestedOpenFlags: 0x1
      ).isDenied)
    // Started by the launcher before the extension observed it, a plug-in is not admitted.
    let unobserved = try facts(seed: 42, signing: Self.helper, originalParent: 40)
    XCTAssertTrue(
      target.evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: unobserved,
        requestedOpenFlags: 0x1
      ).isDenied)
  }

  func testPlugInOfAServiceThatPredatesTheExtension() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    var starter = SystemCompatibilityProfileActor(
      signingIdentifier: Self.daemon, allowedRequests: [], allowedOpenFlags: 0,
      requiredCodeSigningFlags: Self.daemonFlags,
      supportedOSRange: SystemCompatibilityOSRange(
        minimum: SystemCompatibilityOSVersion(major: 26),
        maximumExclusive: SystemCompatibilityOSVersion(major: 28)),
      observedOSBuilds: ["25G83"])
    var plugInActor = actor(Self.helper, requests: [.open])
    plugInActor.allowedEffectiveUsers = .rootOrFolderOwner
    let owner = getuid()

    // The service started before the extension, so only its plug-in's fork is observed.
    func admitted(
      service: ProcessFacts, plugInParent: ProcessFacts?, starter: SystemCompatibilityProfileActor,
      seed: Int32, user: UInt32 = 0
    ) throws -> Bool {
      let target = coordinator(fixture, profiles: [profile(actors: [starter, plugInActor])])
      let plugIn = try facts(
        seed: seed, signing: Self.helper, effectiveUser: user,
        originalParent: service.processInstance.processID, parent: plugInParent)
      target.observeFork(parent: program(service), child: program(plugIn, as: service))
      target.observeExec(from: program(plugIn, as: service), to: program(plugIn))
      return !target.evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: plugIn, requestedOpenFlags: 0x1
      ).isDenied
    }
    let rootService = try facts(seed: 60, signing: Self.daemon)
    XCTAssertTrue(
      try admitted(service: rootService, plugInParent: rootService, starter: starter, seed: 61))
    // Reparented, or with no parent reported: the forker can't be confirmed.
    XCTAssertFalse(
      try admitted(service: rootService, plugInParent: nil, starter: starter, seed: 62))
    // A service that launchd did not fork, such as one run from Terminal.
    let started = try facts(seed: 63, signing: Self.daemon, originalParent: 900)
    XCTAssertFalse(
      try admitted(service: started, plugInParent: started, starter: starter, seed: 64))
    // A parent that is not a program of the profile.
    let other = try facts(seed: 65, signing: "com.apple.example.other")
    XCTAssertFalse(try admitted(service: other, plugInParent: other, starter: starter, seed: 66))
    // A service running as the folder's owner counts only where the profile allows that user.
    let userService = try facts(seed: 67, signing: Self.daemon, effectiveUser: owner)
    XCTAssertFalse(
      try admitted(
        service: userService, plugInParent: userService, starter: starter, seed: 68, user: owner))
    starter.allowedEffectiveUsers = .rootOrFolderOwner
    XCTAssertTrue(
      try admitted(
        service: userService, plugInParent: userService, starter: starter, seed: 69, user: owner))
  }

  func testAppContainerProfileAppliesOnlyInsideContainers() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let container = fixture.home.appendingPathComponent("Library/Containers/com.example.App")
    try FileManager.default.createDirectory(at: container, withIntermediateDirectories: true)
    let resolved = ResolvedSystemCompatibilityProfile(
      profileIdentifier: "example.container", authorizationDigest: Self.digest,
      pathForm: .appContainer, actors: [actor(Self.daemon, requests: [.open])])
    func target(_ root: URL) -> EndpointEventCoordinator {
      let scope = ProtectedPathScope(
        canonicalRoot: root.path, caseSensitive: false, ownerUserID: getuid(),
        ownerHome: fixture.home.path)
      return EndpointEventCoordinator(
        policySetIdentifier: uuid(100),
        policies: [
          EndpointPolicyConfiguration(
            id: uuid(1), name: "Policy", mode: .protection, policyType: .whitelist,
            scope: scope, rules: PolicySnapshot(rules: []),
            systemCompatibilityProfiles: [resolved])
        ],
        policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed)
    }
    let daemon = try facts(signing: Self.daemon)
    XCTAssertFalse(
      target(container).evaluateOpen(
        path: container.appendingPathComponent("Data/a.txt").path, pathWasTruncated: false,
        process: daemon, requestedOpenFlags: 0x1
      ).isDenied)
    XCTAssertTrue(
      target(fixture.root).evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1
      ).isDenied)
    // A scope without an owner, such as one recovered from storage, admits nothing.
    let recovered = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        EndpointPolicyConfiguration(
          id: uuid(1), name: "Policy", mode: .protection, policyType: .whitelist,
          scope: ProtectedPathScope(canonicalRoot: container.path, caseSensitive: false),
          rules: PolicySnapshot(rules: []), systemCompatibilityProfiles: [resolved])
      ],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed)
    XCTAssertTrue(
      recovered.evaluateOpen(
        path: container.appendingPathComponent("Data/a.txt").path, pathWasTruncated: false,
        process: daemon, requestedOpenFlags: 0x1
      ).isDenied)
  }

  func testWithoutHistoryLaunchdMustBeTheOriginalParent() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let target = coordinator(
      fixture, profiles: [profile()], observationStart: Self.observationStart)
    for parent in [Int32(4_321), nil] {
      // Even a process older than the observation whose current parent is launchd: one with
      // another original parent was reparented to launchd, and gets no history.
      let process = try facts(
        signing: Self.daemon, originalParent: parent, parent: launchdFacts(),
        startTime: Self.observationStart.addingTimeInterval(-60))
      let result = target.evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: process, requestedOpenFlags: 0x1)
      XCTAssertTrue(result.isDenied, "\(String(describing: parent))")
      XCTAssertEqual(
        result.policyEvaluations[0].executionOrigin?.uncertainty, .beforeObservation,
        "\(String(describing: parent))")
    }
  }

  func testWithHistoryTheFirstProgramMustBeAnActorOfTheProfile() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let profile = profile(actors: [
      actor(Self.daemon, requests: [.open]), actor(Self.helper, requests: [.open]),
    ])

    // launchd -> xpcproxy -> daemon: the daemon is its own first program.
    let direct = coordinator(fixture, profiles: [profile])
    let daemon = try facts(seed: 20, signing: Self.daemon)
    try observeLaunch(daemon, in: direct)
    XCTAssertFalse(
      direct.evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1
      ).isDenied)

    // launchd -> daemon -> helper: a helper the daemon started.
    let helper = try facts(seed: 21, signing: Self.helper, originalParent: 20)
    direct.observeFork(parent: program(daemon), child: program(helper, as: daemon))
    direct.observeExec(from: program(helper, as: daemon), to: program(helper))
    let started = direct.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: helper, requestedOpenFlags: 0x1)
    XCTAssertFalse(started.isDenied)
    XCTAssertEqual(
      started.policyEvaluations[0].executionOrigin?.origin?.signingIdentifier, Self.daemon)

    // launchd -> Terminal -> actor (as with sudo): the user's session is in between, even
    // though the kernel reports launchd as the original parent of the process image.
    let session = coordinator(fixture, profiles: [profile])
    let terminal = try facts(seed: 30, signing: "com.apple.Terminal", effectiveUser: 501)
    try observeLaunch(terminal, in: session)
    let throughTerminal = try facts(seed: 31, signing: Self.daemon)
    session.observeFork(parent: program(terminal), child: program(throughTerminal, as: terminal))
    session.observeExec(from: program(throughTerminal, as: terminal), to: program(throughTerminal))
    let denied = session.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: throughTerminal,
      requestedOpenFlags: 0x1)
    XCTAssertTrue(denied.isDenied)
    XCTAssertEqual(
      denied.policyEvaluations[0].executionOrigin?.origin?.signingIdentifier, "com.apple.Terminal")

    // launchd -> daemon, before observation began: the kernel's facts begin a complete history
    // in which the daemon is its own first program, as after an observed launch.
    let early = coordinator(fixture, profiles: [profile], observationStart: Self.observationStart)
    let earlyDaemon = try startedByLaunchd(seed: 40, signing: Self.daemon)
    let restored = early.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: earlyDaemon,
      requestedOpenFlags: 0x1)
    XCTAssertFalse(restored.isDenied)
    XCTAssertEqual(restored.policyEvaluations[0].match, .systemCompatibilityProfile)
    let origin = try XCTUnwrap(restored.policyEvaluations[0].executionOrigin)
    XCTAssertNil(origin.uncertainty)
    XCTAssertEqual(origin.historyEvidence, .kernelLaunchdStart)
    XCTAssertEqual(origin.origin?.signingIdentifier, Self.daemon)

    // launchd -> Terminal before observation began -> an actor forked after it: Terminal is
    // the first program, so the profile doesn't admit the actor.
    let earlyTerminal = try startedByLaunchd(
      seed: 50, signing: "com.apple.Terminal", effectiveUser: 501)
    let fromTerminal = try facts(
      seed: 51, signing: Self.daemon, originalParent: 50, parent: earlyTerminal,
      startTime: Self.observationStart.addingTimeInterval(5))
    early.observeFork(
      parent: program(earlyTerminal), child: program(fromTerminal, as: earlyTerminal))
    early.observeExec(from: program(fromTerminal, as: earlyTerminal), to: program(fromTerminal))
    let throughEarlyTerminal = early.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: fromTerminal,
      requestedOpenFlags: 0x1)
    XCTAssertTrue(throughEarlyTerminal.isDenied)
    XCTAssertEqual(
      throughEarlyTerminal.policyEvaluations[0].executionOrigin?.origin?.signingIdentifier,
      "com.apple.Terminal")
  }

  /// A service that launchd started before observation began, such as the XProtect plug-in
  /// service, gets a complete history from the kernel's facts, and so do the plug-ins it forks
  /// afterwards: the service is their first program, and the profile admits them through the
  /// complete-history condition instead of the one for processes without a history.
  func testPlugInOfAServiceThatPredatesObservationHasTheServiceAsFirstProgram() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let starter = SystemCompatibilityProfileActor(
      signingIdentifier: Self.daemon, allowedRequests: [], allowedOpenFlags: 0,
      requiredCodeSigningFlags: Self.daemonFlags,
      supportedOSRange: SystemCompatibilityOSRange(
        minimum: SystemCompatibilityOSVersion(major: 26),
        maximumExclusive: SystemCompatibilityOSVersion(major: 28)),
      observedOSBuilds: ["25G83"])
    var plugInActor = actor(Self.helper, requests: [.open])
    plugInActor.allowedEffectiveUsers = .rootOrFolderOwner
    let owner = getuid()

    func evaluate(service: ProcessFacts, seed: Int32, user: UInt32 = 0) throws
      -> EndpointEventCoordinator.AccessEvaluation
    {
      let target = coordinator(
        fixture, profiles: [profile(actors: [starter, plugInActor])],
        observationStart: Self.observationStart)
      let plugIn = try facts(
        seed: seed, signing: Self.helper, effectiveUser: user,
        originalParent: service.processInstance.processID, parent: service,
        startTime: Self.observationStart.addingTimeInterval(5))
      target.observeFork(parent: program(service), child: program(plugIn, as: service))
      target.observeExec(from: program(plugIn, as: service), to: program(plugIn))
      return target.evaluateOpen(
        path: fixture.inside, pathWasTruncated: false, process: plugIn, requestedOpenFlags: 0x1)
    }

    let rootService = try startedByLaunchd(seed: 60, signing: Self.daemon)
    let admitted = try evaluate(service: rootService, seed: 61)
    XCTAssertFalse(admitted.isDenied)
    let evaluation = admitted.policyEvaluations[0]
    XCTAssertEqual(evaluation.match, .systemCompatibilityProfile)
    XCTAssertNil(evaluation.executionOrigin?.uncertainty)
    XCTAssertEqual(evaluation.executionOrigin?.historyEvidence, .kernelLaunchdStart)
    XCTAssertEqual(evaluation.executionOrigin?.origin?.signingIdentifier, Self.daemon)
    // The plug-in's own user is still checked.
    XCTAssertTrue(try evaluate(service: rootService, seed: 62, user: owner &+ 1).isDenied)
    // A first program outside the profile admits nothing.
    let other = try startedByLaunchd(seed: 65, signing: "com.apple.example.other")
    XCTAssertTrue(try evaluate(service: other, seed: 66).isDenied)
    // As after an observed launch, a complete history doesn't check the user the first program
    // runs as, only that it belongs to the profile; without a history the parent's user is
    // checked as well (see testPlugInOfAServiceThatPredatesTheExtension).
    let userService = try startedByLaunchd(seed: 67, signing: Self.daemon, effectiveUser: owner)
    XCTAssertFalse(try evaluate(service: userService, seed: 68, user: owner).isDenied)
  }

  func testRequestKindsAndOpenFlagsAreLimited() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let reader = profile(actors: [
      actor(
        Self.daemon, requests: [.open, .rename],
        openFlags: SystemCompatibilityOpenFlags.readOnly)
    ])
    let target = coordinator(fixture, profiles: [reader])
    let daemon = try facts(signing: Self.daemon)
    let snapshot = EndpointFileSnapshot(path: fixture.inside, pathWasTruncated: false)

    XCTAssertFalse(
      target.evaluate(.open(snapshot, flags: 0x1 | 0x0010_0000), process: daemon).isDenied)
    XCTAssertTrue(target.evaluate(.open(snapshot, flags: 0x1 | 0x2), process: daemon).isDenied)
    XCTAssertFalse(
      target.evaluate(
        .rename(
          source: snapshot,
          destination: CheckedPath(path: fixture.root.appendingPathComponent("new").path)),
        process: daemon
      ).isDenied)
    XCTAssertTrue(target.evaluate(.unlink(target: snapshot), process: daemon).isDenied)
    XCTAssertTrue(target.evaluate(.truncate(target: snapshot), process: daemon).isDenied)
    let root = EndpointFileSnapshot(path: fixture.root.path, pathWasTruncated: false)
    XCTAssertTrue(target.evaluate(.create(in: root, name: "new"), process: daemon).isDenied)
  }

  /// A metadata change is admitted only by an actor that lists that kind of change. The
  /// synthetic reader profile permits opens only; the tagger permits one metadata request.
  func testMetadataChangesNeedTheirOwnRequestKind() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let daemon = try facts(signing: Self.daemon)
    let snapshot = EndpointFileSnapshot(path: fixture.inside, pathWasTruncated: false)
    let reader = coordinator(
      fixture,
      profiles: [profile(actors: [actor(Self.daemon, requests: [.open], openFlags: 0x1)])])
    let tagger = coordinator(
      fixture,
      profiles: [profile(actors: [actor(Self.daemon, requests: [.setExtendedAttribute])])])
    for kind in FileOperationKind.allCases where kind.changesMetadata {
      let request = FileOperationRequest.metadataChange(kind, target: snapshot)
      XCTAssertTrue(reader.evaluate(request, process: daemon).isDenied, kind.rawValue)
      let result = tagger.evaluate(request, process: daemon)
      XCTAssertEqual(result.isDenied, kind != .setExtendedAttribute, kind.rawValue)
      if kind == .setExtendedAttribute {
        XCTAssertEqual(result.policyEvaluations.map(\.match), [.systemCompatibilityProfile])
      }
    }
  }

  func testPartialProfilesDoNotCombine() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let read = profile(
      identifier: "example.read",
      actors: [actor(Self.daemon, requests: [.open], openFlags: 0x1)])
    let write = profile(
      identifier: "example.write",
      actors: [actor(Self.daemon, requests: [.open], openFlags: 0x2)])
    let target = coordinator(fixture, profiles: [read, write])
    let daemon = try facts(signing: Self.daemon)
    let snapshot = EndpointFileSnapshot(path: fixture.inside, pathWasTruncated: false)
    XCTAssertEqual(
      target.evaluate(.open(snapshot, flags: 0x2), process: daemon).policyEvaluations[0]
        .systemCompatibilityProfileIdentifier, "example.write")
    XCTAssertTrue(target.evaluate(.open(snapshot, flags: 0x3), process: daemon).isDenied)
  }

  func testIdentityAndSignatureMustMatch() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let target = coordinator(fixture, profiles: [profile()])
    let cases: [(String, ProcessFacts)] = [
      ("other identifier", try facts(signing: "com.apple.example.other")),
      ("not a platform binary", try facts(signing: Self.daemon, isPlatformBinary: false)),
      ("ad hoc", try facts(signing: Self.daemon, flags: Self.daemonFlags | 0x2)),
      ("without the kill flag", try facts(signing: Self.daemon, flags: Self.daemonFlags & ~0x200)),
      ("debugged", try facts(signing: Self.daemon, flags: Self.daemonFlags | 0x1000_0000)),
    ]
    for (label, process) in cases {
      XCTAssertTrue(
        target.evaluateOpen(
          path: fixture.inside, pathWasTruncated: false, process: process, requestedOpenFlags: 0x1
        ).isDenied, label)
    }
  }

  func testOtherPoliciesAreNotAffected() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let outer = try configuration(
      id: 1, root: fixture.root.path, home: fixture.home.path, profiles: [profile()])
    let inner = try configuration(id: 2, root: fixture.nested.path, home: fixture.home.path)
    let target = EndpointEventCoordinator(
      policySetIdentifier: uuid(100), policies: [outer, inner], policyRevision: 1,
      sink: NoopSink(), decodeFailurePolicy: .failClosed)
    let daemon = try facts(signing: Self.daemon)

    let outside = target.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1)
    XCTAssertFalse(outside.isDenied)

    // Inside the nested folder both policies take part, and the one without the profile denies.
    let both = target.evaluateOpen(
      path: fixture.nestedFile, pathWasTruncated: false, process: daemon, requestedOpenFlags: 0x1)
    XCTAssertTrue(both.isDenied)
    XCTAssertEqual(both.policyEvaluations.map(\.match), [.systemCompatibilityProfile, .none])
    XCTAssertEqual(both.policyEvaluations.map(\.decision), [.allow, .deny])
  }

  func testAuditPolicyRecordsWouldAllow() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let target = coordinator(fixture, mode: .audit, profiles: [profile()])
    let result = target.evaluateOpen(
      path: fixture.inside, pathWasTruncated: false,
      process: try facts(signing: Self.daemon), requestedOpenFlags: 0x1)
    XCTAssertFalse(result.isDenied)
    XCTAssertEqual(result.policyDecision, "audit-only")
    XCTAssertEqual(result.policyEvaluations[0].decision, .wouldAllow)
    XCTAssertEqual(result.policyEvaluations[0].match, .systemCompatibilityProfile)
  }

  func testRecordNamesTheProfileAndAnEnclosingFolder() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let target = coordinator(fixture, profiles: [profile()])
    let parent = EndpointFileSnapshot(path: fixture.home.path, pathWasTruncated: false)
    let removal = target.evaluate(
      .unlink(target: parent), process: try facts(signing: Self.daemon))
    XCTAssertFalse(removal.isDenied)
    let evaluation = removal.policyEvaluations[0]
    XCTAssertEqual(evaluation.match, .systemCompatibilityProfile)
    XCTAssertEqual(
      evaluation.detail, "The request acts on a folder that contains this policy’s folder.")
    let data = try JSONEncoder().encode(evaluation)
    let decoded = try JSONDecoder().decode(PolicyEvaluationRecord.self, from: data)
    XCTAssertEqual(decoded, evaluation)
  }

  func testAProcessNotYetDecodedIsNeverAdmitted() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let result = coordinator(fixture, profiles: [profile()]).evaluateOpen(
      path: fixture.inside, pathWasTruncated: false, process: nil, requestedOpenFlags: 0x1)
    XCTAssertTrue(result.isDenied)
    XCTAssertEqual(result.policyEvaluations[0].match, .decodeError)
  }

  // MARK: - Helpers

  private func actor(
    _ signing: String, requests: [SystemCompatibilityRequestKind],
    openFlags: UInt32 = SystemCompatibilityOpenFlags.any
  ) -> SystemCompatibilityProfileActor {
    SystemCompatibilityProfileActor(
      signingIdentifier: signing, allowedRequests: requests,
      allowedOpenFlags: requests.contains(.open) ? openFlags : 0,
      requiredCodeSigningFlags: Self.daemonFlags,
      supportedOSRange: SystemCompatibilityOSRange(
        minimum: SystemCompatibilityOSVersion(major: 26),
        maximumExclusive: SystemCompatibilityOSVersion(major: 28)),
      observedOSBuilds: ["25G83"])
  }

  private func profile(
    identifier: String = "example.profile",
    actors: [SystemCompatibilityProfileActor]? = nil
  ) -> ResolvedSystemCompatibilityProfile {
    ResolvedSystemCompatibilityProfile(
      profileIdentifier: identifier, authorizationDigest: Self.digest,
      actors: actors ?? [actor(Self.daemon, requests: SystemCompatibilityRequestKind.allCases)])
  }

  private func coordinator(
    _ fixture: Fixture, mode: PolicyMode = .protection, type: PolicyType = .whitelist,
    denyRules: [AllowRule] = [], profiles: [ResolvedSystemCompatibilityProfile],
    observationStart: Date? = nil
  ) -> EndpointEventCoordinator {
    EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        try! configuration(
          id: 1, root: fixture.root.path, home: fixture.home.path, mode: mode, type: type,
          denyRules: denyRules, profiles: profiles)
      ],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed,
      observationStart: observationStart)
  }

  private func configuration(
    id: Int, root: String, home: String, mode: PolicyMode = .protection,
    type: PolicyType = .whitelist, denyRules: [AllowRule] = [],
    profiles: [ResolvedSystemCompatibilityProfile] = []
  ) throws -> EndpointPolicyConfiguration {
    let editor = AllowRule(
      id: "rule.editor",
      identity: .teamSigned(
        SignedProgramIdentity(teamIdentifier: "TEAM123456", signingIdentifier: "com.example.e")),
      allowsDescendants: false)
    let allowRules = type == .whitelist && id == 1 ? [editor] : []
    return EndpointPolicyConfiguration(
      id: uuid(id), name: "Policy \(id)", mode: mode, policyType: type,
      scope: try ProtectedPathScope(root: root, homeDirectory: home),
      rules: PolicySnapshot(rules: type == .whitelist ? allowRules : denyRules),
      executionOriginPolicy: ExecutionOriginPolicySnapshot(
        isBlacklistEnabled: type == .blacklist, allowRules: allowRules, denyRules: denyRules),
      systemCompatibilityProfiles: profiles)
  }

  private func facts(
    seed: Int32 = 10, signing: String, isPlatformBinary: Bool = true,
    flags: UInt32 = daemonFlags, effectiveUser: UInt32? = 0, originalParent: Int32? = 1,
    parent: ProcessFacts? = nil, startTime: Date? = nil
  ) throws -> ProcessFacts {
    ProcessFacts(
      auditToken: try AuditTokenKey(words: Array(repeating: UInt32(seed), count: 8)),
      processInstance: ProcessInstanceKey(processID: seed, processVersion: 1),
      teamIdentifier: nil, signingIdentifier: signing, isPlatformBinary: isPlatformBinary,
      codeSigningFlags: flags, effectiveUserID: effectiveUser,
      originalParentProcessID: originalParent, parentProcessInstance: parent?.processInstance,
      parentEffectiveUserID: parent?.effectiveUserID, startTime: startTime)
  }

  /// When the extension began observing in the tests that use one.
  private static let observationStart = Date(timeIntervalSince1970: 1_800_000_000)

  private func launchdFacts() throws -> ProcessFacts {
    try facts(seed: 1, signing: "com.apple.xpc.launchd", originalParent: 0)
  }

  /// A process that launchd forked a minute before observation began and that is still its
  /// child, as the kernel reports it.
  private func startedByLaunchd(
    seed: Int32 = 10, signing: String, effectiveUser: UInt32? = 0
  ) throws -> ProcessFacts {
    try facts(
      seed: seed, signing: signing, effectiveUser: effectiveUser, parent: launchdFacts(),
      startTime: Self.observationStart.addingTimeInterval(-60))
  }

  private func program(_ facts: ProcessFacts, path: String = "") -> ExecutionProgram {
    ExecutionProgram(facts: facts, executablePath: path)
  }

  /// The image a forked child has before it replaces it: the parent's, under the child's PID.
  private func program(_ child: ProcessFacts, as parent: ProcessFacts) -> ExecutionProgram {
    var image = program(parent)
    image.instance = ProcessInstanceKey(
      processID: child.processInstance.processID, processVersion: 0)
    return image
  }

  /// launchd forks a child that becomes `actor`, all observed.
  private func observeLaunch(_ actor: ProcessFacts, in coordinator: EndpointEventCoordinator)
    throws
  {
    let launchd = ExecutionProgram(
      facts: try facts(seed: 1, signing: "com.apple.xpc.launchd", originalParent: 0),
      executablePath: "/sbin/launchd")
    var child = launchd
    child.instance = ProcessInstanceKey(
      processID: actor.processInstance.processID, processVersion: 0)
    coordinator.observeFork(parent: launchd, child: child)
    coordinator.observeExec(from: child, to: program(actor))
  }

  private func makeFixture() throws -> Fixture {
    let base = PhysicalPath.resolve(
      FileManager.default.temporaryDirectory
        .appendingPathComponent("PasuFSCompatibilityTests-\(UUID().uuidString)"))
    let home = base.appendingPathComponent("home")
    let root = home.appendingPathComponent("Protected")
    let nested = root.appendingPathComponent("Nested")
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    return Fixture(base: base, home: home, root: root, nested: nested)
  }

  private func uuid(_ value: Int) -> UUID {
    UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", value))!
  }
}

private struct NoopSink: EndpointEventSink {
  func record(_: EndpointEventRecord) {}
}
