import Darwin
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest

@testable import PasuFSEndpointCore

/// Finder hands each copy, duplicate and restore from the Time Machine screen to
/// `DesktopServicesHelper`, a service that launchd starts for every operation. The built-in
/// Finder Copy profile lets that helper make the requests it was seen to make, in whichever
/// direction Finder copies, while the program lists still decide everything else.
final class FinderCopyProfileTests: XCTestCase {
  private static let helperIdentifier = "com.apple.DesktopServicesHelper"
  /// The code-signing flags Endpoint Security reported for the helper on macOS 26 and 27.
  private static let helperFlags: UInt32 = 0x2601_4a01
  private static let sourceOpen = UInt32(FREAD | O_EVTONLY)
  private static let folderListing = UInt32(FREAD | O_DIRECTORY | O_CLOEXEC)
  private static let newFolderOpen = UInt32(FREAD | O_NONBLOCK | O_EVTONLY)
  private static let version26 = OperatingSystemVersion(
    majorVersion: 26, minorVersion: 6, patchVersion: 2)
  /// An allow rule for an unrelated program, so the allow list is in use.
  private static let editorRule = AllowRule(
    id: "rule.editor",
    identity: .teamSigned(
      SignedProgramIdentity(teamIdentifier: "TEAM123456", signingIdentifier: "com.example.e")),
    allowsDescendants: false)

  private struct Fixture {
    let base: URL
    let home: URL
    let root: URL
    let outside: URL
    var inside: String { root.appendingPathComponent("report.txt").path }
    var outsideFile: String { outside.appendingPathComponent("report.txt").path }
  }

  // MARK: - Copies the helper makes

  func testCopiesIntoOutOfAndWithinTheFolderNeedTheProfile() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let helper = try facts(signing: Self.helperIdentifier)
    let root = file(fixture.root.path)
    let copies: [(String, [FileOperationRequest])] = [
      (
        "into",
        [
          .clone(source: file(fixture.outsideFile), targetDirectory: root, name: "report.txt"),
          .metadataChange(.setAttributeList, target: file(fixture.inside)),
        ]
      ),
      (
        "out of",
        [
          .open(path: fixture.inside, flags: Self.sourceOpen),
          .clone(
            source: file(fixture.inside), targetDirectory: file(fixture.outside.path),
            name: "report.txt"),
        ]
      ),
      (
        "within",
        [
          .open(path: fixture.inside, flags: Self.sourceOpen),
          .clone(source: file(fixture.inside), targetDirectory: root, name: "report copy.txt"),
          .metadataChange(
            .setAttributeList,
            target: file(fixture.root.appendingPathComponent("report copy.txt").path)),
        ]
      ),
      (
        "restore on macOS 26",
        [
          .create(in: root, name: "report.txt"),
          .open(path: fixture.inside, flags: UInt32(FWRITE)),
          .truncate(target: file(fixture.inside)),
        ]
      ),
      (
        "restore on macOS 27",
        [
          .create(in: root, name: "report.txt"),
          .metadataChange(.deleteExtendedAttribute, target: file(fixture.inside)),
          .metadataChange(.setAttributeList, target: file(fixture.inside)),
        ]
      ),
      (
        "folder into",
        [
          .create(in: root, name: "Folder"),
          .open(path: fixture.root.path + "/Folder", flags: Self.newFolderOpen),
          .metadataChange(.setExtendedAttribute, target: file(fixture.root.path + "/Folder")),
          .clone(
            source: file(fixture.outside.path + "/Folder/a.txt"),
            targetDirectory: file(fixture.root.path + "/Folder"), name: "a.txt"),
          .metadataChange(.deleteExtendedAttribute, target: file(fixture.root.path + "/Folder")),
        ]
      ),
      (
        "whole folder out of",
        [
          .open(path: fixture.root.path, flags: Self.folderListing),
          .open(path: fixture.inside, flags: Self.sourceOpen),
          .clone(
            source: file(fixture.inside), targetDirectory: file(fixture.outside.path + "/Copy"),
            name: "report.txt"),
        ]
      ),
    ]
    let without = coordinator(fixture, profiles: [])
    let with = coordinator(fixture, profiles: [try finderCopy()])
    for (label, requests) in copies {
      for request in requests {
        let denied = without.evaluate(request, process: helper)
        XCTAssertTrue(denied.isInScope, "\(label) \(request.kind)")
        XCTAssertTrue(denied.isDenied, "\(label) \(request.kind)")
        XCTAssertEqual(denied.policyEvaluations[0].executionOrigin?.reason, .incompleteHistory)

        let allowed = with.evaluate(request, process: helper)
        XCTAssertFalse(allowed.isDenied, "\(label) \(request.kind)")
        let evaluation = allowed.policyEvaluations[0]
        XCTAssertEqual(evaluation.match, .systemCompatibilityProfile, "\(label) \(request.kind)")
        XCTAssertEqual(
          evaluation.systemCompatibilityProfileIdentifier,
          BuiltInSystemCompatibilityCatalog.finderCopyIdentifier)
      }
    }
  }

  /// The helper starts as root and writes as the user who asked, after joining that user's
  /// session; both pass, another account does not.
  func testTheHelperRunsAsRootOrAsTheFolderOwner() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let target = coordinator(fixture, profiles: [try finderCopy()])
    let request = FileOperationRequest.clone(
      source: file(fixture.outsideFile), targetDirectory: file(fixture.root.path),
      name: "report.txt")
    let owner = getuid()
    for (user, allowed) in [(owner, true), (0, true), (owner &+ 1, false)] {
      let result = target.evaluate(
        request, process: try facts(signing: Self.helperIdentifier, effectiveUser: user))
      XCTAssertEqual(result.isDenied, !allowed, "\(user)")
    }
  }

  func testRequestsTheHelperWasNotSeenToMakeAreDenied() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let target = coordinator(fixture, profiles: [try finderCopy()])
    let helper = try facts(signing: Self.helperIdentifier)
    let inside = file(fixture.inside)
    let root = file(fixture.root.path)
    var requests: [FileOperationRequest] = [
      .rename(
        source: inside, destination: CheckedPath(path: fixture.root.path + "/renamed.txt")),
      .rename(source: inside, destination: CheckedPath(path: fixture.outsideFile)),
      .unlink(target: inside),
      .link(source: inside, targetDirectory: root, name: "link"),
      .copyFile(source: inside, existingTarget: nil, targetDirectory: root, name: "copy"),
      .exchangeData(inside, file(fixture.outsideFile)),
    ]
    for flags in [O_CREAT, O_TRUNC, O_APPEND, O_EXCL] {
      requests.append(.open(path: fixture.inside, flags: UInt32(FWRITE | flags)))
    }
    let observed: Set<FileOperationKind> = [
      .setAttributeList, .setExtendedAttribute, .deleteExtendedAttribute,
    ]
    for kind in FileOperationKind.allCases where kind.changesMetadata && !observed.contains(kind) {
      requests.append(.metadataChange(kind, target: inside))
    }
    for request in requests {
      let result = target.evaluate(request, process: helper)
      XCTAssertTrue(result.isDenied, "\(request.kind) \(request.requestedOpenFlags ?? 0)")
      XCTAssertNil(result.policyEvaluations[0].systemCompatibilityProfileIdentifier)
    }
    let mount = target.evaluate(
      .mount(mountPoint: fixture.root.path, volumeSource: "/dev/disk9s1"), process: helper)
    XCTAssertTrue(mount.isDenied)
  }

  // MARK: - Finder, the helper and the program lists

  /// The helper's first program is the helper itself, so a rule for Finder never reaches it;
  /// the profile does not reach Finder's own requests either. A copy needs both.
  func testAFinderRuleAndTheProfileAllowDifferentProcesses() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let finderRule = AllowRule(
      id: "rule.finder", identity: .platformBinary(signingIdentifier: "com.apple.finder"),
      allowsDescendants: false)
    let finder = try facts(seed: 30, signing: "com.apple.finder", effectiveUser: getuid())
    let helper = try facts(seed: 31, signing: Self.helperIdentifier, effectiveUser: getuid())
    let listing = FileOperationRequest.open(path: fixture.root.path, flags: UInt32(FREAD))
    let clone = FileOperationRequest.clone(
      source: file(fixture.outsideFile), targetDirectory: file(fixture.root.path),
      name: "report.txt")

    func observed(_ target: EndpointEventCoordinator) throws -> EndpointEventCoordinator {
      try observeLaunch(finder, in: target)
      try observeLaunchThroughXPCProxy(helper, in: target)
      return target
    }
    let ruleOnly = try observed(coordinator(fixture, allowRules: [finderRule], profiles: []))
    XCTAssertFalse(ruleOnly.evaluate(listing, process: finder).isDenied)
    let deniedClone = ruleOnly.evaluate(clone, process: helper)
    XCTAssertTrue(deniedClone.isDenied)
    XCTAssertEqual(deniedClone.policyEvaluations[0].executionOrigin?.reason, .originNotAllowed)
    XCTAssertEqual(
      deniedClone.policyEvaluations[0].executionOrigin?.origin?.signingIdentifier,
      Self.helperIdentifier)

    let profileOnly = try observed(coordinator(fixture, profiles: [try finderCopy()]))
    XCTAssertTrue(profileOnly.evaluate(listing, process: finder).isDenied)
    XCTAssertFalse(profileOnly.evaluate(clone, process: helper).isDenied)

    let both = try observed(
      coordinator(fixture, allowRules: [finderRule], profiles: [try finderCopy()]))
    XCTAssertFalse(both.evaluate(listing, process: finder).isDenied)
    let allowedClone = both.evaluate(clone, process: helper)
    XCTAssertFalse(allowedClone.isDenied)
    XCTAssertEqual(allowedClone.policyEvaluations[0].match, .systemCompatibilityProfile)
  }

  /// Only the helper qualifies, only with its Apple signature, and only when launchd started it.
  func testOtherProgramsAndOtherLaunchesAreNotAdmitted() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let clone = FileOperationRequest.clone(
      source: file(fixture.outsideFile), targetDirectory: file(fixture.root.path),
      name: "report.txt")
    let cases: [(String, ProcessFacts)] = [
      (
        "scripting helper",
        try facts(signing: "com.apple.desktopservices.desktopservicesscriptinghelper")
      ),
      ("Finder", try facts(signing: "com.apple.finder")),
      ("not a platform binary", try facts(signing: Self.helperIdentifier, platform: false)),
      ("ad hoc", try facts(signing: Self.helperIdentifier, flags: Self.helperFlags | 0x2)),
      (
        "debugged", try facts(signing: Self.helperIdentifier, flags: Self.helperFlags | 0x1000_0000)
      ),
      ("not forked by launchd", try facts(signing: Self.helperIdentifier, originalParent: 900)),
    ]
    let target = coordinator(fixture, profiles: [try finderCopy()])
    for (label, process) in cases {
      XCTAssertTrue(target.evaluate(clone, process: process).isDenied, label)
    }

    // Started from Terminal, for example with sudo, the helper has Terminal as its first program.
    let session = coordinator(fixture, profiles: [try finderCopy()])
    let terminal = try facts(seed: 40, signing: "com.apple.Terminal", effectiveUser: getuid())
    try observeLaunch(terminal, in: session)
    let started = try facts(seed: 41, signing: Self.helperIdentifier, originalParent: 40)
    session.observeFork(parent: program(terminal), child: program(started, as: terminal))
    session.observeExec(from: program(started, as: terminal), to: program(started))
    let denied = session.evaluate(clone, process: started)
    XCTAssertTrue(denied.isDenied)
    XCTAssertEqual(
      denied.policyEvaluations[0].executionOrigin?.origin?.signingIdentifier, "com.apple.Terminal")
  }

  func testABlockRuleForTheHelperWins() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let blocked = AllowRule(
      id: "rule.helper", identity: .platformBinary(signingIdentifier: Self.helperIdentifier),
      allowsDescendants: false)
    let target = coordinator(fixture, denyRules: [blocked], profiles: [try finderCopy()])
    let result = target.evaluate(
      .clone(
        source: file(fixture.outsideFile), targetDirectory: file(fixture.root.path),
        name: "report.txt"),
      process: try facts(signing: Self.helperIdentifier))
    XCTAssertTrue(result.isDenied)
    XCTAssertEqual(result.policyEvaluations[0].executionOrigin?.reason, .deniedInHistory)
  }

  // MARK: - Retired paths

  /// At a retired path the profile decides like the program lists do there: the helper's
  /// copies are allowed and recorded with the retired path, and other requests are denied.
  func testAtARetiredPathTheProfileFollowsTheSameRules() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let retired = fixture.home.appendingPathComponent("Former/Protected").path
    let target = coordinator(fixture, profiles: [try finderCopy()], retired: [retired])
    let helper = try facts(signing: Self.helperIdentifier)
    let other = try facts(seed: 50, signing: "com.apple.example.other")

    for request in [
      FileOperationRequest.clone(
        source: file(fixture.outsideFile), targetDirectory: file(retired), name: "report.txt"),
      .clone(
        source: file(retired + "/report.txt"), targetDirectory: file(fixture.outside.path),
        name: "report.txt"),
      .create(in: file(retired), name: "report.txt"),
      .open(path: retired + "/report.txt", flags: Self.sourceOpen),
    ] {
      let allowed = target.evaluate(request, process: helper)
      XCTAssertFalse(allowed.isDenied, "\(request.kind)")
      XCTAssertEqual(allowed.policyEvaluations[0].match, .systemCompatibilityProfile)
      XCTAssertEqual(allowed.policyEvaluations[0].retiredFolderPath, retired)
      let denied = target.evaluate(request, process: other)
      XCTAssertTrue(denied.isDenied, "\(request.kind)")
      XCTAssertEqual(denied.policyEvaluations[0].retiredFolderPath, retired)
    }
    for request in [
      FileOperationRequest.rename(
        source: file(fixture.outsideFile), destination: CheckedPath(path: retired + "/a.txt")),
      .unlink(target: file(retired + "/report.txt")),
      // A copy of a folder above the retired path acts on everything below it.
      .clone(
        source: file(fixture.home.appendingPathComponent("Former").path),
        targetDirectory: file(fixture.outside.path), name: "Former"),
    ] {
      let result = target.evaluate(request, process: helper)
      XCTAssertEqual(result.isDenied, request.kind != .clone, "\(request.kind)")
      XCTAssertEqual(result.policyEvaluations[0].retiredFolderPath, retired)
    }
    let mount = target.evaluate(
      .mount(mountPoint: retired, volumeSource: "/dev/disk9s1"), process: helper)
    XCTAssertTrue(mount.isDenied)
    XCTAssertEqual(mount.policyEvaluations[0].match, .mountPoint)
  }

  // MARK: - Helpers

  /// The Finder Copy profile as the extension activates it from the built-in catalog.
  private func finderCopy() throws -> ResolvedSystemCompatibilityProfile {
    let catalog = BuiltInSystemCompatibilityCatalog.catalog
    let entry = try catalog.policyEntry(
      profileIdentifier: BuiltInSystemCompatibilityCatalog.finderCopyIdentifier)
    let (resolution, resolved) = try SystemCompatibilityResolver.resolve(
      entry, policyIdentifier: uuid(1), catalog: catalog, operatingSystemVersion: Self.version26)
    XCTAssertEqual(resolution.state, .active)
    return try XCTUnwrap(resolved)
  }

  private func coordinator(
    _ fixture: Fixture, allowRules: [AllowRule] = [editorRule], denyRules: [AllowRule] = [],
    profiles: [ResolvedSystemCompatibilityProfile], retired: [String] = []
  ) -> EndpointEventCoordinator {
    let scope = try! ProtectedPathScope(root: fixture.root.path, homeDirectory: fixture.home.path)
    return EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        EndpointPolicyConfiguration(
          id: uuid(1), name: "Policy", mode: .protection, policyType: .whitelist, scope: scope,
          rules: PolicySnapshot(rules: allowRules),
          executionOriginPolicy: ExecutionOriginPolicySnapshot(
            isBlacklistEnabled: !denyRules.isEmpty, allowRules: allowRules, denyRules: denyRules),
          systemCompatibilityProfiles: profiles,
          retiredScopes: retired.map {
            ProtectedPathScope(retired: RetiredFolderPath(path: $0, caseSensitive: false))
          })
      ],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed)
  }

  private func facts(
    seed: Int32 = 10, signing: String, platform: Bool = true, flags: UInt32 = helperFlags,
    effectiveUser: UInt32? = getuid(), originalParent: Int32? = 1
  ) throws -> ProcessFacts {
    ProcessFacts(
      auditToken: try AuditTokenKey(words: Array(repeating: UInt32(seed), count: 8)),
      processInstance: ProcessInstanceKey(processID: seed, processVersion: 1),
      teamIdentifier: nil, signingIdentifier: signing, isPlatformBinary: platform,
      codeSigningFlags: flags, effectiveUserID: effectiveUser,
      originalParentProcessID: originalParent)
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

  private func launchd() throws -> ExecutionProgram {
    ExecutionProgram(
      facts: try facts(
        seed: 1, signing: "com.apple.xpc.launchd", effectiveUser: 0, originalParent: 0),
      executablePath: "/sbin/launchd")
  }

  /// launchd forks a child that becomes `process`, all observed.
  private func observeLaunch(_ process: ProcessFacts, in coordinator: EndpointEventCoordinator)
    throws
  {
    let launchd = try launchd()
    var child = launchd
    child.instance = ProcessInstanceKey(
      processID: process.processInstance.processID, processVersion: 0)
    coordinator.observeFork(parent: launchd, child: child)
    coordinator.observeExec(from: child, to: program(process))
  }

  /// launchd forks a child that runs xpcproxy, which becomes `process`, as for a launchd job.
  private func observeLaunchThroughXPCProxy(
    _ process: ProcessFacts, in coordinator: EndpointEventCoordinator
  ) throws {
    let launchd = try launchd()
    var child = launchd
    child.instance = ProcessInstanceKey(
      processID: process.processInstance.processID, processVersion: 0)
    var proxy = ExecutionProgram(
      facts: try facts(seed: 2, signing: "com.apple.xpc.proxy", effectiveUser: 0),
      executablePath: "/usr/libexec/xpcproxy")
    proxy.instance = ProcessInstanceKey(
      processID: process.processInstance.processID, processVersion: 1)
    coordinator.observeFork(parent: launchd, child: child)
    coordinator.observeExec(from: child, to: proxy)
    coordinator.observeExec(from: proxy, to: program(process))
  }

  private func makeFixture() throws -> Fixture {
    let base = PhysicalPath.resolve(
      FileManager.default.temporaryDirectory
        .appendingPathComponent("PasuFSFinderCopyTests-\(UUID().uuidString)"))
    let home = base.appendingPathComponent("home")
    let root = home.appendingPathComponent("Protected")
    let outside = home.appendingPathComponent("Desktop")
    for folder in [root, outside] {
      try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    }
    return Fixture(base: base, home: home, root: root, outside: outside)
  }

  private func file(_ path: String) -> EndpointFileSnapshot {
    EndpointFileSnapshot(path: path, pathWasTruncated: false)
  }

  private func uuid(_ value: Int) -> UUID {
    UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", value))!
  }
}

private struct NoopSink: EndpointEventSink {
  func record(_: EndpointEventRecord) {}
}
