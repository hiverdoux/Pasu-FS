import Darwin
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest

@testable import PasuFSEndpointCore

/// The XProtect analysis service (`XprotectService`) is an XPC service of which launchd starts
/// one instance for each client: syspolicyd, the Gatekeeper daemon, gets one running as root,
/// and Gatekeeper's agent in the user's session one running as the user. The built-in
/// XProtect Malware Scanning profile lets the root instance open files for reading; the
/// instance running as the user, other request kinds and other programs are still decided by
/// the program lists.
final class XProtectAnalysisServiceProfileTests: XCTestCase {
  private static let serviceIdentifier = "com.apple.XprotectFramework.AnalysisService"
  /// The code-signing flags Endpoint Security reported for the service on macOS 27.0.1 and
  /// 27.2, and that csops reported on macOS 26.6.2.
  private static let serviceFlags: UInt32 = 0x2601_7b01
  /// The opens recorded while the service analyzed an app bundle: the bundle and its folders,
  /// Info.plist, the executable and a file opened without following a symbolic link.
  private static let observedOpens: [UInt32] = [
    UInt32(FREAD | O_DIRECTORY | O_CLOEXEC), UInt32(FREAD | O_NONBLOCK),
    UInt32(FREAD | O_NONBLOCK | O_DIRECTORY | O_CLOEXEC), UInt32(FREAD),
    UInt32(FREAD | O_NOFOLLOW),
  ]
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
    var bundle: String { root.appendingPathComponent("Example.app").path }
    var executable: String {
      root.appendingPathComponent("Example.app/Contents/MacOS/Example").path
    }
  }

  /// The instance syspolicyd uses, started by launchd through xpcproxy while the extension was
  /// observing: its first program is the service itself.
  func testTheRootInstanceReadsWithTheProfile() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let service = try facts(seed: 20, effectiveUser: 0)

    let without = coordinator(fixture, profiles: [])
    try observeLaunchThroughXPCProxy(service, in: without)
    let denied = without.evaluate(
      .open(path: fixture.bundle, flags: Self.observedOpens[0]), process: service)
    XCTAssertTrue(denied.isDenied)
    XCTAssertEqual(denied.policyEvaluations[0].executionOrigin?.reason, .originNotAllowed)
    XCTAssertEqual(
      denied.policyEvaluations[0].executionOrigin?.origin?.signingIdentifier,
      Self.serviceIdentifier)

    let with = coordinator(fixture, profiles: [try xprotect()])
    try observeLaunchThroughXPCProxy(service, in: with)
    for flags in Self.observedOpens {
      for path in [fixture.bundle, fixture.executable] {
        let result = with.evaluate(.open(path: path, flags: flags), process: service)
        XCTAssertFalse(result.isDenied, String(flags, radix: 16))
        XCTAssertEqual(result.policyEvaluations[0].match, .systemCompatibilityProfile)
        XCTAssertEqual(
          result.policyEvaluations[0].systemCompatibilityProfileIdentifier,
          BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier)
      }
    }
  }

  /// An instance that launchd started before the extension: only the kernel's record that
  /// launchd forked it is known.
  func testAnInstanceThatPredatesTheExtension() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let target = coordinator(fixture, profiles: [try xprotect()])
    let unobserved = try facts(seed: 30, effectiveUser: 0)
    let allowed = target.evaluate(
      .open(path: fixture.bundle, flags: Self.observedOpens[0]), process: unobserved)
    XCTAssertFalse(allowed.isDenied)
    XCTAssertEqual(allowed.policyEvaluations[0].executionOrigin?.uncertainty, .beforeObservation)
    let notForkedByLaunchd = try facts(seed: 31, effectiveUser: 0, originalParent: 900)
    XCTAssertTrue(
      target.evaluate(
        .open(path: fixture.bundle, flags: Self.observedOpens[0]), process: notForkedByLaunchd
      ).isDenied)
  }

  /// Gatekeeper's agent in the user's session gets an instance running as the user. The
  /// profile admits the remediator plug-ins as the folder's owner, but not this service.
  func testTheInstanceRunningAsTheUserIsNotAdmitted() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let target = coordinator(fixture, profiles: [try xprotect()])
    let userInstance = try facts(seed: 40, effectiveUser: getuid() == 0 ? 501 : getuid())
    try observeLaunchThroughXPCProxy(userInstance, in: target)
    let result = target.evaluate(
      .open(path: fixture.bundle, flags: Self.observedOpens[0]), process: userInstance)
    XCTAssertTrue(result.isDenied)
    XCTAssertNotEqual(result.policyEvaluations[0].match, .systemCompatibilityProfile)
  }

  func testTheServiceMayOnlyOpenForReading() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let target = coordinator(fixture, profiles: [try xprotect()])
    let service = try facts(seed: 50, effectiveUser: 0)
    for flag in [FWRITE, FWRITE | O_TRUNC, FWRITE | O_APPEND, FREAD | O_CREAT, FREAD | O_EXCL] {
      XCTAssertTrue(
        target.evaluate(.open(path: fixture.executable, flags: UInt32(flag)), process: service)
          .isDenied, String(flag, radix: 16))
    }
    let executable = file(fixture.executable)
    let requests: [FileOperationRequest] = [
      .unlink(target: executable),
      .truncate(target: executable),
      .create(in: file(fixture.root.path), name: "new"),
      .rename(
        source: executable,
        destination: CheckedPath(path: fixture.root.appendingPathComponent("moved").path)),
      .metadataChange(.setExtendedAttribute, target: executable),
      .metadataChange(.deleteExtendedAttribute, target: executable),
      .metadataChange(.setMode, target: executable),
    ]
    for request in requests {
      XCTAssertTrue(target.evaluate(request, process: service).isDenied, "\(request.kind)")
    }
  }

  /// Only the service qualifies, only with its Apple signature, and only when launchd started
  /// it; its clients get nothing from the profile.
  func testOtherProgramsAndOtherLaunchesAreNotAdmitted() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let open = FileOperationRequest.open(path: fixture.bundle, flags: Self.observedOpens[0])
    let cases: [(String, ProcessFacts)] = [
      ("syspolicyd", try facts(signing: "com.apple.syspolicyd", effectiveUser: 0)),
      (
        "Gatekeeper's agent",
        try facts(signing: "com.apple.coreservices.uiagent", effectiveUser: getuid())
      ),
      ("not a platform binary", try facts(effectiveUser: 0, platform: false)),
      ("ad hoc", try facts(effectiveUser: 0, flags: Self.serviceFlags | 0x2)),
      ("debugged", try facts(effectiveUser: 0, flags: Self.serviceFlags | 0x1000_0000)),
      ("without kill", try facts(effectiveUser: 0, flags: Self.serviceFlags & ~UInt32(0x200))),
    ]
    let target = coordinator(fixture, profiles: [try xprotect()])
    for (label, process) in cases {
      XCTAssertTrue(target.evaluate(open, process: process).isDenied, label)
    }

    // Started from Terminal, for example with sudo, the service has Terminal as its first program.
    let session = coordinator(fixture, profiles: [try xprotect()])
    let terminal = try facts(
      seed: 60, signing: "com.apple.Terminal", effectiveUser: getuid())
    try observeLaunch(terminal, in: session)
    let started = try facts(seed: 61, effectiveUser: 0, originalParent: 60)
    session.observeFork(parent: program(terminal), child: program(started, as: terminal))
    session.observeExec(from: program(started, as: terminal), to: program(started))
    let denied = session.evaluate(open, process: started)
    XCTAssertTrue(denied.isDenied)
    XCTAssertEqual(
      denied.policyEvaluations[0].executionOrigin?.origin?.signingIdentifier, "com.apple.Terminal")
  }

  func testABlockRuleForTheServiceWins() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let blocked = AllowRule(
      id: "rule.analysis", identity: .platformBinary(signingIdentifier: Self.serviceIdentifier),
      allowsDescendants: false)
    let target = coordinator(fixture, denyRules: [blocked], profiles: [try xprotect()])
    let result = target.evaluate(
      .open(path: fixture.bundle, flags: Self.observedOpens[0]),
      process: try facts(effectiveUser: 0))
    XCTAssertTrue(result.isDenied)
    XCTAssertEqual(result.policyEvaluations[0].executionOrigin?.reason, .deniedInHistory)
  }

  /// The service is trusted on the macOS versions on which it was observed.
  func testTheServiceIsActiveOnMacOS26And27() throws {
    for (major, minor) in [(26, 6), (27, 0), (27, 2)] {
      let profile = try xprotect(
        OperatingSystemVersion(majorVersion: major, minorVersion: minor, patchVersion: 0))
      XCTAssertTrue(
        profile.actors.contains { $0.signingIdentifier == Self.serviceIdentifier },
        "\(major).\(minor)")
    }
  }

  // MARK: - Helpers

  /// XProtect Malware Scanning as the extension activates it from the built-in catalog.
  private func xprotect(
    _ version: OperatingSystemVersion = OperatingSystemVersion(
      majorVersion: 27, minorVersion: 2, patchVersion: 0)
  ) throws -> ResolvedSystemCompatibilityProfile {
    let catalog = BuiltInSystemCompatibilityCatalog.catalog
    let entry = try catalog.policyEntry(
      profileIdentifier: BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier)
    let (resolution, resolved) = try SystemCompatibilityResolver.resolve(
      entry, policyIdentifier: uuid(1), catalog: catalog, operatingSystemVersion: version)
    XCTAssertEqual(resolution.state, .active)
    return try XCTUnwrap(resolved)
  }

  private func coordinator(
    _ fixture: Fixture, denyRules: [AllowRule] = [],
    profiles: [ResolvedSystemCompatibilityProfile]
  ) -> EndpointEventCoordinator {
    let scope = try! ProtectedPathScope(root: fixture.root.path, homeDirectory: fixture.home.path)
    return EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        EndpointPolicyConfiguration(
          id: uuid(1), name: "Policy", mode: .protection, policyType: .whitelist, scope: scope,
          rules: PolicySnapshot(rules: [Self.editorRule]),
          executionOriginPolicy: ExecutionOriginPolicySnapshot(
            isBlacklistEnabled: !denyRules.isEmpty, allowRules: [Self.editorRule],
            denyRules: denyRules),
          systemCompatibilityProfiles: profiles)
      ],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed)
  }

  private func facts(
    seed: Int32 = 10, signing: String = serviceIdentifier, effectiveUser: UInt32?,
    platform: Bool = true, flags: UInt32 = serviceFlags, originalParent: Int32? = 1
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

  /// launchd forks a child that runs xpcproxy, which becomes `process`, as for an XPC service.
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
        .appendingPathComponent("PasuFSXProtectAnalysisTests-\(UUID().uuidString)"))
    let home = base.appendingPathComponent("home")
    let root = home.appendingPathComponent("Protected")
    try FileManager.default.createDirectory(
      at: root.appendingPathComponent("Example.app/Contents/MacOS"),
      withIntermediateDirectories: true)
    return Fixture(base: base, home: home, root: root)
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
