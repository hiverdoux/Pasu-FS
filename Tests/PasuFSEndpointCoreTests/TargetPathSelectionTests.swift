import EndpointSecurity
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest
import os

@testable import PasuFSEndpointCore

/// The target paths registered while target path muting is inverted: which paths and events
/// the policies need, how the registered set changes without a gap, and what happens when a
/// path can't be registered.
final class TargetPathSelectionTests: XCTestCase {
  private let nfc = "Caf\u{E9}"
  private let nfd = "Cafe\u{301}"

  // MARK: - Events

  func testEveryKindThatCanInvolveAnEnclosingFolderIsMarked() {
    let file = EndpointFileSnapshot(path: "/Users/example/Folder/file", pathWasTruncated: false)
    let folder = EndpointFileSnapshot(path: "/Users/example/Folder", pathWasTruncated: false)
    for kind in FileOperationKind.allCases {
      let request: FileOperationRequest
      switch kind {
      case .open: request = .open(file, flags: 0)
      case .create: request = .create(in: folder, name: "new")
      case .rename: request = .rename(source: file, destination: CheckedPath(path: "/x"))
      case .unlink: request = .unlink(target: file)
      case .link: request = .link(source: file, targetDirectory: folder, name: "link")
      case .clone: request = .clone(source: file, targetDirectory: folder, name: "clone")
      case .copyFile:
        request = .copyFile(
          source: file, existingTarget: nil, targetDirectory: folder, name: "copy")
      case .truncate: request = .truncate(target: file)
      case .exchangeData: request = .exchangeData(file, folder)
      case .mount: request = .mount(mountPoint: folder.path, volumeSource: "/dev/disk9s1")
      default: request = .metadataChange(kind, target: file)
      }
      let reaches =
        request.checkedPaths.contains(where: \.affectsEnclosedFolders)
        || request.newObjectPath != nil
      XCTAssertEqual(kind.reachesEnclosingFolders, reaches, kind.rawValue)
    }
  }

  func testEveryCheckedRequestExceptMountsIsSelectedInsideAFolder() {
    let inside = Set(TargetPathEvents.inside.map(\.rawValue))
    let enclosing = Set(TargetPathEvents.enclosing.map(\.rawValue))
    let subscribed = Set(FileOperationKind.subscribedEventTypes.map(\.rawValue))
    XCTAssertEqual(subscribed.count, 18)
    XCTAssertEqual(
      inside,
      subscribed.subtracting([ES_EVENT_TYPE_AUTH_MOUNT.rawValue]).union([
        ES_EVENT_TYPE_NOTIFY_RENAME.rawValue
      ]))
    XCTAssertTrue(enclosing.isSubset(of: inside))
    XCTAssertEqual(
      enclosing,
      Set(
        [
          ES_EVENT_TYPE_AUTH_CREATE, ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_UNLINK,
          ES_EVENT_TYPE_AUTH_LINK, ES_EVENT_TYPE_AUTH_CLONE, ES_EVENT_TYPE_AUTH_COPYFILE,
          ES_EVENT_TYPE_AUTH_EXCHANGEDATA, ES_EVENT_TYPE_NOTIFY_RENAME,
        ].map(\.rawValue)))
    XCTAssertEqual(TargetPathEvents.execution.map(\.rawValue), [ES_EVENT_TYPE_NOTIFY_EXEC.rawValue])
  }

  // MARK: - Plan

  func testAFolderIsAPrefixAndTheFoldersOnTheWayAreLiteralPaths() {
    let entries = TargetPathPlan.entries(
      for: [scope("/Users/example/Documents/Secret")], resolver: nil)
    XCTAssertEqual(
      paths(entries),
      [
        "prefix /Users/example/Documents/Secret", "literal /Users", "literal /Users/example",
        "literal /Users/example/Documents",
      ])
    XCTAssertEqual(
      events(entries, "/Users/example/Documents/Secret", .prefix), TargetPathEvents.inside)
    XCTAssertEqual(events(entries, "/Users/example", .literal), TargetPathEvents.enclosing)
    // A folder directly below the root has no literal path: `/` itself is never registered.
    XCTAssertEqual(
      paths(TargetPathPlan.entries(for: [scope("/Secret")], resolver: nil)), ["prefix /Secret"])
  }

  func testPathsAreRegisteredByteForByte() {
    XCTAssertEqual("/Users/example/\(nfc)", "/Users/example/\(nfd)")
    XCTAssertNotEqual(
      TargetPathString("/Users/example/\(nfc)"), TargetPathString("/Users/example/\(nfd)"))
    let entries = TargetPathPlan.entries(
      for: [scope("/Users/example/\(nfc)/Secret"), scope("/Users/example/\(nfd)/Secret")],
      resolver: nil)
    let literals = Set(entries.filter { $0.match == .literal }.map(\.path))
    XCTAssertTrue(literals.contains(TargetPathString("/Users/example/\(nfc)")))
    XCTAssertTrue(literals.contains(TargetPathString("/Users/example/\(nfd)")))
    XCTAssertEqual(Set(entries.filter { $0.match == .prefix }.map(\.path)).count, 2)
    XCTAssertEqual(
      TargetPathPlan.ancestors(of: "/Volumes/\(nfd)/Secret").map { Array($0.utf8) },
      [Array("/Volumes".utf8), Array("/Volumes/\(nfd)".utf8)])
  }

  func testAFolderStoredInAnotherSpellingIsRegisteredInThatSpellingToo() {
    let resolver = FakeResolver([
      "/Users/example/Parent/Secret": "/Users/example/PARENT/Secret",
      "/Users/example/\(nfc)": "/Users/example/\(nfd)",
      "/Users/example/Linked": "/Volumes/Other/Linked",
    ])
    let entries = TargetPathPlan.entries(
      for: [
        scope("/Users/example/Parent/Secret"), scope("/Users/example/\(nfc)"),
        scope("/Users/example/Linked"),
      ], resolver: resolver)
    let found = paths(entries)
    XCTAssertTrue(found.contains("prefix /Users/example/PARENT/Secret"))
    XCTAssertTrue(found.contains("literal /Users/example/PARENT"))
    XCTAssertTrue(entries.contains { $0.path == TargetPathString("/Users/example/\(nfd)") })
    // A symbolic link leads elsewhere; the policy doesn't compare paths there.
    XCTAssertFalse(found.contains { $0.contains("/Volumes/Other") })
    // A case-sensitive volume keeps differently cased names apart.
    let sensitive = TargetPathPlan.entries(
      for: [ProtectedPathScope(canonicalRoot: "/Users/example/Parent/Secret", caseSensitive: true)],
      resolver: resolver)
    XCTAssertFalse(paths(sensitive).contains("prefix /Users/example/PARENT/Secret"))
  }

  func testAMissingLocationRegistersTheDeepestExistingFolderForNewEntries() {
    let resolver = FakeResolver([
      "/": "/", "/Volumes": "/Volumes", "/Volumes/Work": "/Volumes/Work",
      "/Volumes/Work/projects": "/Volumes/Work/Projects",
    ])
    let entries = TargetPathPlan.entries(
      for: [scope("/Volumes/Work/projects/Old/Secret")], resolver: resolver)
    let found = paths(entries)
    // Creating `old` or `OLD` there names a new entry in the requester's spelling.
    XCTAssertTrue(found.contains("prefix /Volumes/Work/Projects/"))
    XCTAssertEqual(
      events(entries, "/Volumes/Work/Projects/", .prefix), TargetPathEvents.enclosing)
    XCTAssertTrue(found.contains("literal /Volumes/Work/Projects"))
    XCTAssertTrue(found.contains("literal /Volumes/Work/projects/Old"))
    XCTAssertTrue(found.contains("prefix /Volumes/Work/projects/Old/Secret"))
    // Nothing on the way exists but the root.
    let bare = TargetPathPlan.entries(
      for: [scope("/Volumes/Gone/Secret")], resolver: FakeResolver(["/": "/"]))
    XCTAssertEqual(events(bare, "/", .prefix), TargetPathEvents.enclosing)
    XCTAssertFalse(paths(bare).contains("literal /"))
  }

  func testAPendingMoveIsRegisteredFromTheRequestAlone() {
    let move = PendingFolderMove(
      policyIdentifier: UUID(), scope: scope("/Users/example/Moved/Secret"),
      retiredScopes: [scope("/Users/example/Moved/Old/Secret")], source: "/Users/example/Parent",
      destination: "/Users/example/Moved", allowedAt: 0)
    let found = paths(TargetPathPlan.entries(for: move))
    XCTAssertTrue(found.contains("prefix /Users/example/Moved/Secret"))
    XCTAssertTrue(found.contains("literal /Users/example/Moved"))
    XCTAssertTrue(found.contains("prefix /Users/example/Moved/Old/Secret"))
    XCTAssertTrue(found.contains("prefix /Users/example/Moved/"))
    XCTAssertFalse(found.contains("prefix /Users/example/"))

    // A rename that only changes the letter case reports the old path as an existing
    // destination; the folder that contains it is selected for every request meanwhile.
    let recased = PendingFolderMove(
      policyIdentifier: UUID(), scope: scope("/Users/example/Parent/Secret"),
      source: "/Users/example/Parent", destination: "/Users/example/Parent", allowedAt: 0,
      destinationIsExistingFile: true)
    let widened = TargetPathPlan.entries(for: recased)
    XCTAssertEqual(events(widened, "/Users/example/", .prefix), TargetPathEvents.inside)
  }

  // MARK: - Registry

  func testNewPathsAreRegisteredBeforeOldOnesAreRemoved() throws {
    let muting = FakeMuting()
    let registry = TargetPathRegistry(muting: muting)
    let first = TargetPathPlan.entries(for: [scope("/Users/example/A/Secret")], resolver: nil)
    let second = TargetPathPlan.entries(for: [scope("/Users/example/B/Secret")], resolver: nil)
    XCTAssertTrue(registry.settle(first))
    muting.reset()
    XCTAssertTrue(registry.extend(second))
    XCTAssertTrue(muting.calls.allSatisfy { $0.hasPrefix("add ") })
    XCTAssertTrue(registry.registeredEntries.isSuperset(of: first.union(second)))
    XCTAssertTrue(registry.settle(second))
    let removals = muting.calls.filter { $0.hasPrefix("remove ") }
    XCTAssertEqual(
      Set(removals), ["remove prefix /Users/example/A/Secret", "remove literal /Users/example/A"])
    let lastAddition = try XCTUnwrap(muting.calls.lastIndex { $0.hasPrefix("add ") })
    let firstRemoval = try XCTUnwrap(muting.calls.firstIndex { $0.hasPrefix("remove ") })
    XCTAssertLessThan(lastAddition, firstRemoval)
    XCTAssertEqual(
      registry.registeredEntries, second.union(TargetPathPlan.executionEntries))
    XCTAssertEqual(muting.registered, registry.registeredEntries)
  }

  func testProcessStartsStayRegistered() {
    let muting = FakeMuting()
    let registry = TargetPathRegistry(muting: muting)
    XCTAssertTrue(registry.deliversProcessStarts)
    registry.settle(TargetPathPlan.entries(for: [scope("/Users/example/Secret")], resolver: nil))
    registry.settle([])
    XCTAssertEqual(registry.registeredEntries, TargetPathPlan.executionEntries)
    XCTAssertEqual(
      registry.status(kernelEntries: nil),
      TargetPathMutingStatus(
        isInverted: true, deliversAllRequests: false, prefixCount: 1, literalCount: 0))
  }

  func testAPathThatCantBeRegisteredDeliversEveryRequestUntilItCan() {
    let muting = FakeMuting()
    let date = Date(timeIntervalSince1970: 1_000)
    let registry = TargetPathRegistry(muting: muting, now: { date })
    muting.failing = ["/Users/example/Secret"]
    let entries = TargetPathPlan.entries(for: [scope("/Users/example/Secret")], resolver: nil)
    XCTAssertTrue(registry.extend(entries))
    XCTAssertTrue(registry.deliversAllRequests)
    XCTAssertTrue(registry.registeredEntries.isSuperset(of: TargetPathPlan.allRequestEntries))
    let failed = registry.status(kernelEntries: nil)
    XCTAssertTrue(failed.deliversAllRequests)
    XCTAssertEqual(failed.lastError, "Could not register prefix /Users/example/Secret.")
    XCTAssertEqual(failed.lastErrorAt, date)
    // The fallback stays while the path still fails, and goes once it is registered.
    XCTAssertTrue(registry.settle(entries))
    XCTAssertTrue(registry.deliversAllRequests)
    muting.failing = []
    XCTAssertTrue(registry.settle(entries))
    XCTAssertFalse(registry.deliversAllRequests)
    XCTAssertEqual(registry.registeredEntries, entries.union(TargetPathPlan.executionEntries))
    XCTAssertEqual(muting.registered, registry.registeredEntries)
    // The error stays visible after the recovery.
    XCTAssertEqual(registry.status(kernelEntries: nil).lastErrorAt, date)
  }

  func testAFailedFallbackIsReported() {
    let muting = FakeMuting()
    let registry = TargetPathRegistry(muting: muting)
    muting.failing = ["/Users/example/Secret", "/"]
    XCTAssertFalse(
      registry.extend(TargetPathPlan.entries(for: [scope("/Users/example/Secret")], resolver: nil)))
    XCTAssertFalse(registry.deliversAllRequests)
    XCTAssertEqual(
      registry.status(kernelEntries: nil).lastError, "Could not register / for every request.")
    // A registry whose execution entry failed must not be used inverted.
    let starts = FakeMuting()
    starts.failing = ["/"]
    XCTAssertFalse(TargetPathRegistry(muting: starts).deliversProcessStarts)
  }

  func testPinnedEntriesStayUntilTheirMoveIsWithdrawn() {
    let muting = FakeMuting()
    let registry = TargetPathRegistry(muting: muting)
    let base = TargetPathPlan.entries(for: [scope("/Users/example/Parent/Secret")], resolver: nil)
    registry.settle(base)
    let first = UUID()
    let second = UUID()
    let moved = TargetPathPlan.entries(for: [scope("/Users/example/Moved/Secret")], resolver: nil)
    let again = TargetPathPlan.entries(for: [scope("/Users/example/Again/Secret")], resolver: nil)
    XCTAssertTrue(registry.pin(first, moved))
    XCTAssertTrue(registry.pin(second, again))
    registry.settle(base)
    XCTAssertTrue(registry.registeredEntries.isSuperset(of: moved.union(again)))
    registry.retainPins([second])
    XCTAssertFalse(
      registry.registeredEntries.contains { $0.path.string == "/Users/example/Moved/Secret" })
    XCTAssertTrue(registry.registeredEntries.isSuperset(of: again))
    registry.unpin([second])
    XCTAssertEqual(registry.registeredEntries, base.union(TargetPathPlan.executionEntries))
    // A pin that can't be registered, not even through the fallback, fails.
    muting.failing = ["/Users/example/Third/Secret", "/"]
    XCTAssertFalse(
      registry.pin(
        UUID(), TargetPathPlan.entries(for: [scope("/Users/example/Third/Secret")], resolver: nil)))
  }

  func testARemovalThatFailsKeepsTheEntry() {
    let muting = FakeMuting()
    let registry = TargetPathRegistry(muting: muting)
    let entries = TargetPathPlan.entries(for: [scope("/Users/example/Secret")], resolver: nil)
    registry.settle(entries)
    muting.failing = ["/Users/example/Secret"]
    registry.settle([])
    XCTAssertTrue(
      registry.registeredEntries.isSuperset(
        of: TargetPathEntry.entries("/Users/example/Secret", .prefix, TargetPathEvents.inside)))
    XCTAssertFalse(registry.deliversAllRequests)
    XCTAssertEqual(
      registry.status(kernelEntries: nil).lastError,
      "Could not remove prefix /Users/example/Secret.")
  }

  func testEntriesTheKernelLacksAreRegisteredAgain() {
    let muting = FakeMuting()
    let registry = TargetPathRegistry(muting: muting)
    let entries = TargetPathPlan.entries(for: [scope("/Users/example/Secret")], resolver: nil)
    registry.settle(entries)
    let lacking = muting.registered.filter { $0.path.string != "/Users/example/Secret" }
    muting.registered = lacking
    muting.reset()
    // An entry pinned after the kernel's set was read is not missing.
    let before = registry.registeredEntries
    let moved = TargetPathPlan.entries(for: [scope("/Users/example/Moved")], resolver: nil)
    XCTAssertTrue(registry.pin(UUID(), moved))
    muting.reset()
    registry.verify(kernelEntries: lacking, registeredBefore: before)
    XCTAssertEqual(muting.calls, ["add prefix /Users/example/Secret"])
    XCTAssertEqual(muting.registered, registry.registeredEntries)
    XCTAssertEqual(
      registry.status(kernelEntries: nil).lastError,
      "Endpoint Security lacks \(TargetPathEvents.inside.count) registered target path entries.")
    // Counts come from the kernel's set when it is available.
    let status = registry.status(kernelEntries: muting.registered)
    XCTAssertEqual(status.prefixCount, 3)
    XCTAssertEqual(status.literalCount, 2)
  }

  func testARegistryWithoutInversionRegistersNothing() {
    let registry = TargetPathRegistry(notInvertedBecause: "es_invert_muting failed.")
    XCTAssertTrue(
      registry.extend(TargetPathPlan.entries(for: [scope("/Users/example/Secret")], resolver: nil)))
    XCTAssertTrue(registry.pin(UUID(), []))
    XCTAssertTrue(registry.registeredEntries.isEmpty)
    XCTAssertTrue(registry.deliversProcessStarts)
    let status = registry.status(kernelEntries: nil)
    XCTAssertFalse(status.isInverted)
    XCTAssertTrue(status.deliversAllRequests)
    XCTAssertEqual(status.lastError, "es_invert_muting failed.")
  }

  // MARK: - Coordinator

  func testAnAllowedRenameRegistersTheNewLocationBeforeItIsAnswered() throws {
    let harness = try makeHarness()
    let base = TargetPathPlan.entries(for: [harness.scope], resolver: nil)
    harness.registry.settle(base)
    let result = harness.coordinator.evaluate(
      .rename(
        source: file("/Users/example/Parent"),
        destination: CheckedPath(path: "/Users/example/Moved")),
      process: harness.unlisted)
    XCTAssertFalse(result.isDenied)
    let pending = try XCTUnwrap(harness.coordinator.pendingFolderMoves.first)
    XCTAssertEqual(pending.scope.root, "/Users/example/Moved/Secret")
    XCTAssertTrue(
      paths(harness.registry.registeredEntries).contains("prefix /Users/example/Moved/Secret"))
    // A later settle keeps it; withdrawing the move releases it.
    harness.registry.settle(base)
    XCTAssertTrue(
      paths(harness.registry.registeredEntries).contains("prefix /Users/example/Moved/Secret"))
    harness.coordinator.withdrawPendingFolderMoves([pending.identifier])
    XCTAssertEqual(harness.registry.registeredEntries, base.union(TargetPathPlan.executionEntries))
  }

  func testARenameWhoseNewLocationCantBeRegisteredIsDenied() throws {
    let harness = try makeHarness()
    harness.muting.failing = ["/Users/example/Moved/Secret", "/"]
    let result = harness.coordinator.evaluate(
      .rename(
        source: file("/Users/example/Parent"),
        destination: CheckedPath(path: "/Users/example/Moved")),
      process: harness.allowed)
    XCTAssertTrue(result.isDenied)
    XCTAssertEqual(
      result.policyEvaluations.first?.detail,
      "The folder's new location could not be registered with Endpoint Security.")
    XCTAssertTrue(harness.coordinator.pendingFolderMoves.isEmpty)
    // With the fallback in place the rename is allowed: every request is delivered.
    harness.muting.failing = ["/Users/example/Moved/Secret"]
    XCTAssertFalse(
      harness.coordinator.evaluate(
        .rename(
          source: file("/Users/example/Parent"),
          destination: CheckedPath(path: "/Users/example/Moved")),
        process: harness.allowed
      ).isDenied)
    XCTAssertTrue(harness.registry.deliversAllRequests)
  }

  func testARenameThatOnlyChangesTheSpellingWidensDeliveryUntilConfirmed() throws {
    let harness = try makeHarness()
    // The kernel names the folder's existing entry, in its old spelling, as the destination.
    let result = harness.coordinator.evaluate(
      .rename(
        source: file("/Users/example/Parent"),
        destination: CheckedPath(path: "/Users/example/Parent"),
        destinationIsExistingFile: true),
      process: harness.unlisted)
    XCTAssertFalse(result.isDenied)
    let pending = try XCTUnwrap(harness.coordinator.pendingFolderMoves.first)
    XCTAssertTrue(pending.destinationIsExistingFile)
    XCTAssertEqual(
      events(harness.registry.registeredEntries, "/Users/example/", .prefix),
      TargetPathEvents.inside)
    // An ordinary rename to the folder's own path adds nothing.
    harness.coordinator.withdrawPendingFolderMoves([pending.identifier])
    _ = harness.coordinator.evaluate(
      .rename(
        source: file("/Users/example/Parent"),
        destination: CheckedPath(path: "/Users/example/Parent")),
      process: harness.unlisted)
    XCTAssertTrue(harness.coordinator.pendingFolderMoves.isEmpty)
  }

  func testRemovingAPolicyReleasesItsPendingMoves() throws {
    let harness = try makeHarness()
    _ = harness.coordinator.evaluate(
      .rename(
        source: file("/Users/example/Parent"),
        destination: CheckedPath(path: "/Users/example/Moved")),
      process: harness.unlisted)
    XCTAssertEqual(harness.coordinator.pendingFolderMoves.count, 1)
    harness.coordinator.replacePolicySet(setIdentifier: uuid(100), policies: [], revision: 2)
    XCTAssertFalse(
      paths(harness.registry.registeredEntries).contains("prefix /Users/example/Moved/Secret"))
  }

  func testARenameAroundARetiredPathStartsACheck() throws {
    let harness = try makeHarness(retired: ["/Users/example/Old/Secret"])
    harness.coordinator.noteRename(source: "/Users/example/Old", destination: "/Users/example/old2")
    XCTAssertEqual(harness.reports.withLock { $0 }, 1)
    harness.coordinator.noteRename(source: "/Users/example/X", destination: "/Users/example/OLD")
    XCTAssertEqual(harness.reports.withLock { $0 }, 2)
    harness.coordinator.noteRename(source: "/Users/example/X", destination: "/Users/example/Y")
    XCTAssertEqual(harness.reports.withLock { $0 }, 2)
  }

  // MARK: - Helpers

  private final class FakeMuting: TargetPathMuting, @unchecked Sendable {
    private let lock = OSAllocatedUnfairLock<([String], Set<String>, Set<TargetPathEntry>)>(
      initialState: ([], [], []))
    var calls: [String] { lock.withLock { $0.0 } }
    var failing: Set<String> {
      get { lock.withLock { $0.1 } }
      set { lock.withLock { $0.1 = newValue } }
    }
    var registered: Set<TargetPathEntry> {
      get { lock.withLock { $0.2 } }
      set { lock.withLock { $0.2 = newValue } }
    }
    func reset() { lock.withLock { $0.0 = [] } }

    func add(_ path: TargetPathString, match: TargetPathMatch, events: [UInt32]) -> Bool {
      call("add", path, match, events, insert: true)
    }

    func remove(_ path: TargetPathString, match: TargetPathMatch, events: [UInt32]) -> Bool {
      call("remove", path, match, events, insert: false)
    }

    private func call(
      _ name: String, _ path: TargetPathString, _ match: TargetPathMatch, _ events: [UInt32],
      insert: Bool
    ) -> Bool {
      lock.withLock { state in
        state.0.append("\(name) \(match.rawValue) \(path.string)")
        guard !state.1.contains(path.string) else { return false }
        for event in events {
          let entry = TargetPathEntry(path: path, match: match, eventType: event)
          if insert { state.2.insert(entry) } else { state.2.remove(entry) }
        }
        return true
      }
    }
  }

  private struct FakeResolver: TargetPathResolving {
    let spellings: [String: String]
    init(_ spellings: [String: String]) { self.spellings = spellings }
    func spelling(of path: String) -> String? { spellings[path] }
  }

  private struct Harness {
    let coordinator: EndpointEventCoordinator
    let registry: TargetPathRegistry
    let muting: FakeMuting
    let scope: ProtectedPathScope
    let allowed: ProcessFacts
    let unlisted: ProcessFacts
    let reports: OSAllocatedUnfairLock<Int>
  }

  private func makeHarness(retired: [String] = []) throws -> Harness {
    let muting = FakeMuting()
    let registry = TargetPathRegistry(muting: muting)
    let root = scope("/Users/example/Parent/Secret")
    let rule = AllowRule(
      id: "rule.editor",
      program: SignedProgramIdentity(
        teamIdentifier: "TEAM123456", signingIdentifier: "com.example.Editor"),
      allowsDescendants: false)
    let reports = OSAllocatedUnfairLock<Int>(initialState: 0)
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        EndpointPolicyConfiguration(
          id: uuid(1), name: "Policy", mode: .protection, policyType: .whitelist, scope: root,
          rules: PolicySnapshot(rules: [rule]), retiredScopes: retired.map { scope($0) })
      ],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed,
      folderMoveReported: { reports.withLock { $0 += 1 } }, targetPaths: registry)
    let allowed = try processFacts(seed: 10, team: "TEAM123456", signing: "com.example.Editor")
    let unlisted = try processFacts(seed: 20, team: "OTHERTEAM1", signing: "com.example.Other")
    for actor in [allowed, unlisted] {
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
    return Harness(
      coordinator: coordinator, registry: registry, muting: muting, scope: root,
      allowed: allowed, unlisted: unlisted, reports: reports)
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

  private func scope(_ root: String) -> ProtectedPathScope {
    ProtectedPathScope(canonicalRoot: root, caseSensitive: false)
  }

  private func file(_ path: String) -> EndpointFileSnapshot {
    EndpointFileSnapshot(path: path, pathWasTruncated: false)
  }

  private func uuid(_ value: Int) -> UUID {
    UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", value))!
  }

  /// "prefix <path>" and "literal <path>" for each registered path.
  private func paths(_ entries: Set<TargetPathEntry>) -> Set<String> {
    Set(entries.map { "\($0.match.rawValue) \($0.path.string)" })
  }

  private func events(_ entries: Set<TargetPathEntry>, _ path: String, _ match: TargetPathMatch)
    -> [es_event_type_t]
  {
    let found = Set(
      entries.filter { $0.path == TargetPathString(path) && $0.match == match }.map(\.eventType))
    return TargetPathEvents.inside.filter { found.contains($0.rawValue) }
      + TargetPathEvents.execution.filter { found.contains($0.rawValue) }
  }
}

private struct NoopSink: EndpointEventSink {
  func record(_: EndpointEventRecord) {}
}
