import Darwin
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest
import os

@testable import PasuFSEndpointCore

/// A policy follows its folder when the folder, or a folder that contains it, is renamed, and
/// renaming a folder that contains a policy folder is allowed for every program.
final class FolderFollowTests: XCTestCase {
  private struct Fixture {
    let base: URL
    let home: URL
    let parent: URL
    let root: URL
    let outside: URL
    var inside: String { root.appendingPathComponent("sample.txt").path }
  }

  private struct Harness {
    let coordinator: EndpointEventCoordinator
    let allowed: ProcessFacts
    let unlisted: ProcessFacts
    let clock: OSAllocatedUnfairLock<UInt64>
    let reports: OSAllocatedUnfairLock<Int>
  }

  // MARK: - Scope arithmetic

  func testRelocatedScopeKeepsThePartBelowTheRenamedFolder() throws {
    let scope = ProtectedPathScope(
      canonicalRoot: "/Users/example/Parent/Secret", caseSensitive: false)
    XCTAssertEqual(
      scope.relocated(from: "/Users/example/Parent", to: "/Users/example/Moved")?.root,
      "/Users/example/Moved/Secret")
    XCTAssertEqual(
      scope.relocated(from: "/Users/example/Parent/Secret", to: "/Users/example/Other")?.root,
      "/Users/example/Other")
    // The source is matched with the volume's case rule; the kept part keeps its spelling.
    XCTAssertEqual(
      scope.relocated(from: "/users/EXAMPLE", to: "/Volumes/Data/example")?.root,
      "/Volumes/Data/example/Parent/Secret")
    XCTAssertEqual(
      scope.relocated(from: "/Users/example/Parent", to: "/Moved")?.root, "/Moved/Secret")
    XCTAssertEqual(
      scope.relocated(from: "/Users/example/./Parent/../Parent", to: "/Users/example/X/")?.root,
      "/Users/example/X/Secret")
    XCTAssertNil(
      scope.relocated(from: "/Users/example/Parent/Secret/Inner", to: "/Users/example/X"))
    XCTAssertNil(scope.relocated(from: "/Users/example/Other", to: "/Users/example/X"))
    XCTAssertNil(scope.relocated(from: "/Users/example/Parent", to: "relative"))
    XCTAssertTrue(scope.isEnclosed(by: "/Users/example/Parent"))
    XCTAssertTrue(scope.isEnclosed(by: "/"))
    XCTAssertFalse(scope.isEnclosed(by: "/Users/example/Parent/Secret"))
    XCTAssertFalse(scope.isEnclosed(by: "/Users/example/Parent/Secret/Inner"))
    let sensitive = ProtectedPathScope(canonicalRoot: "/Volumes/Code/Secret", caseSensitive: true)
    XCTAssertNil(sensitive.relocated(from: "/volumes/code", to: "/Volumes/Other"))
  }

  // MARK: - Parent folder rename

  func testRenamingAParentIsAllowedForEveryProgramInBothModes() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    for mode in [PolicyMode.protection, .audit] {
      let harness = try makeHarness(fixture, mode: mode)
      for process in [harness.unlisted, harness.allowed] as [ProcessFacts?] + [nil] {
        let result = harness.coordinator.evaluate(
          .rename(
            source: file(fixture.parent.path),
            destination: CheckedPath(path: fixture.home.appendingPathComponent("Moved").path)),
          process: process, decodeErrorDescription: "unavailable")
        XCTAssertTrue(result.isInScope)
        XCTAssertFalse(result.isDenied)
        XCTAssertEqual(result.policyDecision, mode == .protection ? "allowed" : "audit-only")
        let evaluation = try XCTUnwrap(result.policyEvaluations.first)
        XCTAssertEqual(evaluation.match, .enclosingFolder)
        XCTAssertEqual(evaluation.decision, mode == .protection ? .allow : .wouldAllow)
        XCTAssertNil(evaluation.executionOrigin)
        XCTAssertNil(result.detail)
      }
    }
  }

  func testRenamingAParentIntoAnotherPolicyFolderKeepsThatFoldersRule() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let destinationFolder = fixture.home.appendingPathComponent("Vault")
    try FileManager.default.createDirectory(
      at: destinationFolder, withIntermediateDirectories: true)
    let harness = try makeHarness(
      fixture,
      extra: [
        (
          "Vault",
          try ProtectedPathScope(root: destinationFolder.path, homeDirectory: fixture.home.path)
        )
      ])
    let request = FileOperationRequest.rename(
      source: file(fixture.parent.path),
      destination: CheckedPath(path: destinationFolder.appendingPathComponent("Parent").path))
    let unlisted = harness.coordinator.evaluate(request, process: harness.unlisted)
    XCTAssertTrue(unlisted.isDenied)
    XCTAssertEqual(
      unlisted.policyEvaluations.first { $0.policyName == "Policy" }?.match, .enclosingFolder)
    XCTAssertEqual(
      unlisted.policyEvaluations.first { $0.policyName == "Policy" }?.decision, .allow)
    let vault = try XCTUnwrap(unlisted.policyEvaluations.first { $0.policyName == "Vault" })
    XCTAssertEqual(vault.decision, .deny)
    XCTAssertEqual(vault.match, .none)
    XCTAssertNotNil(vault.executionOrigin)
    // A denied rename leaves nothing to follow.
    XCTAssertTrue(harness.coordinator.pendingFolderMoves.isEmpty)
  }

  func testOtherRequestsOnAParentAreDecidedByTheListsAndNamedAsEnclosing() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let outside = fixture.outside.path
    let requests: [FileOperationRequest] = [
      .unlink(target: file(fixture.parent.path)),
      .clone(source: file(fixture.parent.path), targetDirectory: file(outside), name: "c"),
      .copyFile(
        source: file(fixture.parent.path), existingTarget: nil, targetDirectory: file(outside),
        name: "c"),
      .exchangeData(file(fixture.parent.path), file(outside)),
    ]
    for request in requests {
      let denied = harness.coordinator.evaluate(request, process: harness.unlisted)
      XCTAssertTrue(denied.isDenied, request.kind.rawValue)
      XCTAssertEqual(
        denied.policyEvaluations.map(\.match), [.enclosingFolder], request.kind.rawValue)
      XCTAssertEqual(
        denied.policyEvaluations.first?.executionOrigin?.reason, .originNotAllowed,
        request.kind.rawValue)
      let allowed = harness.coordinator.evaluate(request, process: harness.allowed)
      XCTAssertFalse(allowed.isDenied, request.kind.rawValue)
      XCTAssertEqual(
        allowed.policyEvaluations.map(\.match), [.enclosingFolder], request.kind.rawValue)
      XCTAssertNotNil(allowed.policyEvaluations.first?.ruleIdentifier, request.kind.rawValue)
    }
    // A request inside the folder keeps the rule match kind.
    let inside = harness.coordinator.evaluate(
      .unlink(target: file(fixture.inside)), process: harness.allowed)
    XCTAssertEqual(inside.policyEvaluations.map(\.match), [.direct])
    // A mount on a parent keeps its own kind.
    let mount = harness.coordinator.evaluate(
      .mount(mountPoint: fixture.parent.path, volumeSource: nil), process: harness.allowed)
    XCTAssertEqual(mount.policyEvaluations.map(\.match), [.mountPoint])
    XCTAssertTrue(mount.isDenied)
    XCTAssertTrue(harness.coordinator.pendingFolderMoves.isEmpty)
  }

  // MARK: - Pending moves

  func testAllowedRenameProtectsTheOldAndTheNewLocation() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    harness.clock.withLock { $0 = 7 }
    let moved = fixture.home.appendingPathComponent("Moved")
    let rename = harness.coordinator.evaluate(
      .rename(source: file(fixture.parent.path), destination: CheckedPath(path: moved.path)),
      process: harness.unlisted)
    XCTAssertFalse(rename.isDenied)
    let pending = harness.coordinator.pendingFolderMoves
    XCTAssertEqual(pending.count, 1)
    XCTAssertEqual(pending.first?.scope.root, moved.appendingPathComponent("Protected").path)
    XCTAssertEqual(pending.first?.source, fixture.parent.path)
    XCTAssertEqual(pending.first?.destination, moved.path)
    XCTAssertEqual(pending.first?.allowedAt, 7)
    XCTAssertEqual(pending.first?.wasNotified, false)
    XCTAssertEqual(pending.first?.policyIdentifier, uuid(1))

    let newInside = moved.appendingPathComponent("Protected/sample.txt").path
    for path in [newInside, fixture.inside] {
      let unlisted = harness.coordinator.evaluate(.open(path: path), process: harness.unlisted)
      XCTAssertTrue(unlisted.isDenied, path)
      XCTAssertEqual(unlisted.policyEvaluations.map(\.match), [.none], path)
      let allowed = harness.coordinator.evaluate(.open(path: path), process: harness.allowed)
      XCTAssertFalse(allowed.isDenied, path)
    }
    // The new location takes part in every check, including mounts.
    let mount = harness.coordinator.evaluate(
      .mount(mountPoint: moved.path, volumeSource: nil), process: nil)
    XCTAssertTrue(mount.isDenied)
    // Renaming the moved folder itself is decided by the lists.
    let again = harness.coordinator.evaluate(
      .rename(
        source: file(moved.appendingPathComponent("Protected").path),
        destination: CheckedPath(path: fixture.outside.appendingPathComponent("P").path)),
      process: harness.unlisted)
    XCTAssertTrue(again.isDenied)
    XCTAssertEqual(again.policyEvaluations.map(\.match), [.none])
    XCTAssertEqual(harness.coordinator.pendingFolderMoves.count, 1)

    harness.coordinator.withdrawPendingFolderMoves([try XCTUnwrap(pending.first?.identifier)])
    XCTAssertTrue(harness.coordinator.pendingFolderMoves.isEmpty)
    XCTAssertFalse(
      harness.coordinator.evaluate(.open(path: newInside), process: harness.unlisted).isInScope)
    XCTAssertTrue(
      harness.coordinator.evaluate(.open(path: fixture.inside), process: harness.unlisted).isDenied)
  }

  func testAllowedProgramRenamingTheFolderItselfIsFollowedAndDeniedRenamesAreNot() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let target = fixture.outside.appendingPathComponent("Renamed").path
    let request = FileOperationRequest.rename(
      source: file(fixture.root.path), destination: CheckedPath(path: target))
    XCTAssertTrue(harness.coordinator.evaluate(request, process: harness.unlisted).isDenied)
    XCTAssertTrue(harness.coordinator.pendingFolderMoves.isEmpty)
    XCTAssertFalse(harness.coordinator.evaluate(request, process: harness.allowed).isDenied)
    XCTAssertEqual(harness.coordinator.pendingFolderMoves.map(\.scope.root), [target])
    // Moving a file inside the folder does not move the folder.
    _ = harness.coordinator.evaluate(
      .rename(
        source: file(fixture.inside),
        destination: CheckedPath(path: fixture.root.appendingPathComponent("b.txt").path)),
      process: harness.allowed)
    XCTAssertEqual(harness.coordinator.pendingFolderMoves.count, 1)
    // A truncated rename is denied and protects nothing new.
    let truncated = harness.coordinator.evaluate(
      .rename(
        source: file(fixture.parent.path),
        destination: CheckedPath(
          path: fixture.home.appendingPathComponent("T").path, wasTruncated: true)),
      process: harness.allowed)
    XCTAssertTrue(truncated.isDenied)
    XCTAssertEqual(harness.coordinator.pendingFolderMoves.count, 1)
  }

  func testRepeatedAndChainedMovesKeepOneEntryPerLocation() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let first = fixture.home.appendingPathComponent("First")
    let second = fixture.home.appendingPathComponent("Second")
    harness.clock.withLock { $0 = 1 }
    _ = harness.coordinator.evaluate(
      .rename(source: file(fixture.parent.path), destination: CheckedPath(path: first.path)),
      process: harness.unlisted)
    // The folder is pending at First; renaming First moves it on to Second.
    harness.clock.withLock { $0 = 2 }
    _ = harness.coordinator.evaluate(
      .rename(source: file(first.path), destination: CheckedPath(path: second.path)),
      process: harness.unlisted)
    XCTAssertEqual(
      Set(harness.coordinator.pendingFolderMoves.map(\.scope.root)),
      [
        first.appendingPathComponent("Protected").path,
        second.appendingPathComponent("Protected").path,
      ])
    // Renaming back to the stored location adds nothing; repeating a move restarts its entry.
    _ = harness.coordinator.evaluate(
      .rename(source: file(second.path), destination: CheckedPath(path: fixture.parent.path)),
      process: harness.unlisted)
    harness.clock.withLock { $0 = 9 }
    _ = harness.coordinator.evaluate(
      .rename(source: file(fixture.parent.path), destination: CheckedPath(path: first.path)),
      process: harness.unlisted)
    let pending = harness.coordinator.pendingFolderMoves
    XCTAssertEqual(pending.count, 2)
    XCTAssertEqual(
      pending.first { $0.scope.root.hasPrefix(first.path) }?.allowedAt, 9)
  }

  func testPendingMovesAreLimitedAndAFullListDeniesTheRename() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    for index in 0..<EndpointEventCoordinator.maximumPendingMovesPerPolicy {
      let result = harness.coordinator.evaluate(
        .rename(
          source: file(fixture.parent.path),
          destination: CheckedPath(path: fixture.home.appendingPathComponent("M\(index)").path)),
        process: harness.unlisted)
      XCTAssertFalse(result.isDenied, "\(index)")
    }
    XCTAssertEqual(
      harness.coordinator.pendingFolderMoves.count,
      EndpointEventCoordinator.maximumPendingMovesPerPolicy)
    let overflow = harness.coordinator.evaluate(
      .rename(
        source: file(fixture.parent.path),
        destination: CheckedPath(path: fixture.home.appendingPathComponent("Last").path)),
      process: harness.allowed)
    XCTAssertTrue(overflow.isDenied)
    XCTAssertEqual(overflow.policyEvaluations.first?.match, .enclosingFolder)
    XCTAssertEqual(
      overflow.policyEvaluations.first?.detail,
      "Too many moves of this policy’s folder are waiting to be confirmed.")
    XCTAssertEqual(
      harness.coordinator.pendingFolderMoves.count,
      EndpointEventCoordinator.maximumPendingMovesPerPolicy)
  }

  func testRenameNotificationMarksItsMoveAndAsksForACheck() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let moved = fixture.home.appendingPathComponent("Moved").path
    _ = harness.coordinator.evaluate(
      .rename(source: file(fixture.parent.path), destination: CheckedPath(path: moved)),
      process: harness.unlisted)
    // An unrelated rename asks for nothing.
    harness.coordinator.noteRename(source: fixture.inside, destination: fixture.outside.path + "/x")
    harness.coordinator.noteRename(
      source: fixture.outside.path, destination: fixture.base.path + "/o")
    XCTAssertEqual(harness.reports.withLock { $0 }, 0)
    XCTAssertEqual(harness.coordinator.pendingFolderMoves.first?.wasNotified, false)
    harness.coordinator.noteRename(source: fixture.parent.path, destination: moved)
    XCTAssertEqual(harness.reports.withLock { $0 }, 1)
    XCTAssertEqual(harness.coordinator.pendingFolderMoves.first?.wasNotified, true)
    // A finished rename of a folder that contains a policy folder asks for a check even when
    // no move is pending, for example after the extension restarted.
    harness.coordinator.withdrawPendingFolderMoves(
      Set(harness.coordinator.pendingFolderMoves.map(\.identifier)))
    harness.coordinator.noteRename(source: fixture.home.path, destination: fixture.base.path + "/h")
    XCTAssertEqual(harness.reports.withLock { $0 }, 2)
  }

  func testUnmountBelowAPendingLocationIsReported() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let reports = OSAllocatedUnfairLock<[String]>(initialState: [])
    let scope = try ProtectedPathScope(root: fixture.root.path, homeDirectory: fixture.home.path)
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [configuration(id: 1, name: "Policy", mode: .protection, scope: scope, rules: [])],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed,
      protectedVolumeUnmounted: { volume, _ in reports.withLock { $0.append(volume.mountPoint) } })
    let actor = try processFacts(seed: 20, team: "OTHERTEAM1", signing: "com.example.Other")
    _ = coordinator.evaluate(
      .rename(source: file(fixture.parent.path), destination: CheckedPath(path: "/Volumes/X/P")),
      process: actor)
    coordinator.noteUnmount(MountedVolume(mountPoint: "/Volumes/X", source: nil))
    XCTAssertEqual(reports.withLock { $0 }, ["/Volumes/X"])
  }

  // MARK: - Helpers

  private func makeHarness(
    _ fixture: Fixture, mode: PolicyMode = .protection,
    extra: [(String, ProtectedPathScope)] = []
  ) throws -> Harness {
    let scope = try ProtectedPathScope(root: fixture.root.path, homeDirectory: fixture.home.path)
    let editorRule = AllowRule(
      id: "rule.editor",
      program: SignedProgramIdentity(
        teamIdentifier: "TEAM123456", signingIdentifier: "com.example.Editor"),
      allowsDescendants: false)
    let clock = OSAllocatedUnfairLock<UInt64>(initialState: 0)
    let reports = OSAllocatedUnfairLock<Int>(initialState: 0)
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        configuration(id: 1, name: "Policy", mode: mode, scope: scope, rules: [editorRule])
      ]
        + extra.enumerated().map { offset, entry in
          configuration(
            id: 50 + offset, name: entry.0, mode: .protection, scope: entry.1, rules: [])
        },
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed,
      folderMoveReported: { reports.withLock { $0 += 1 } },
      uptime: { clock.withLock { $0 } })
    let allowed = try processFacts(seed: 10, team: "TEAM123456", signing: "com.example.Editor")
    let unlisted = try processFacts(seed: 20, team: "OTHERTEAM1", signing: "com.example.Other")
    try observeLaunch(allowed, in: coordinator)
    try observeLaunch(unlisted, in: coordinator)
    return Harness(
      coordinator: coordinator, allowed: allowed, unlisted: unlisted, clock: clock,
      reports: reports)
  }

  private func observeLaunch(_ actor: ProcessFacts, in coordinator: EndpointEventCoordinator) throws
  {
    let launchd = ExecutionProgram(
      facts: try processFacts(
        seed: 1, team: "", signing: "com.apple.xpc.launchd", isPlatformBinary: true),
      executablePath: "/sbin/launchd")
    var child = launchd
    child.instance = ProcessInstanceKey(
      processID: actor.processInstance.processID, processVersion: 0)
    coordinator.observeFork(parent: launchd, child: child)
    coordinator.observeExec(from: child, to: ExecutionProgram(facts: actor, executablePath: ""))
  }

  private func configuration(
    id: Int, name: String, mode: PolicyMode, scope: ProtectedPathScope, rules: [AllowRule]
  ) -> EndpointPolicyConfiguration {
    EndpointPolicyConfiguration(
      id: uuid(id), name: name, mode: mode, policyType: .whitelist, scope: scope,
      rules: PolicySnapshot(rules: rules))
  }

  private func processFacts(
    seed: Int32, team: String, signing: String, isPlatformBinary: Bool = false
  ) throws -> ProcessFacts {
    ProcessFacts(
      auditToken: try AuditTokenKey(words: Array(repeating: UInt32(seed), count: 8)),
      processInstance: ProcessInstanceKey(processID: seed, processVersion: 1),
      teamIdentifier: team, signingIdentifier: signing,
      isPlatformBinary: isPlatformBinary, codeSigningFlags: 1)
  }

  private func file(_ path: String) -> EndpointFileSnapshot {
    EndpointFileSnapshot(path: path, pathWasTruncated: false)
  }

  private func makeFixture() throws -> Fixture {
    let base = PhysicalPath.resolve(
      FileManager.default.temporaryDirectory
        .appendingPathComponent("PasuFSFolderFollowTests-\(UUID().uuidString)"))
    let home = base.appendingPathComponent("home")
    let parent = home.appendingPathComponent("Parent")
    let root = parent.appendingPathComponent("Protected")
    let outside = home.appendingPathComponent("Outside")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    return Fixture(base: base, home: home, parent: parent, root: root, outside: outside)
  }

  private func uuid(_ value: Int) -> UUID {
    UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", value))!
  }
}

private struct NoopSink: EndpointEventSink {
  func record(_: EndpointEventRecord) {}
}
