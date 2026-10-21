import Darwin
import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSEndpointCore

/// The periodic and rename-triggered folder check: identities are added, moved folders are
/// followed as a new revision, missing folders are reported and pending moves are withdrawn.
final class PolicyFolderReconcilerTests: XCTestCase {
  private let secretID = FolderIdentity(
    fileSystemID: 0x1_0000_0010, volumeUUID: "VOL-A", objectID: 41)
  private let otherID = FolderIdentity(
    fileSystemID: 0x1_0000_0010, volumeUUID: "VOL-A", objectID: 77)

  func testAnIdentityIsAddedToAScopeStoredWithoutOne() {
    let set = policySet([("Secret", "/Users/example/Secret")])
    let result = reconcile(
      set, scopes: [scope(set, 0, identity: nil)],
      folders: ["/Users/example/Secret": secretID])
    XCTAssertNil(result.policySet)
    XCTAssertTrue(result.scopesChanged)
    XCTAssertEqual(result.scopes.first?.folderIdentity, secretID)
    XCTAssertNil(result.warning)
  }

  func testAPolicyWithoutAStoredScopeGainsOne() {
    let set = policySet([("Secret", "/Users/example/Secret"), ("Notes", "/Users/example/Notes")])
    let result = reconcile(
      set, scopes: [scope(set, 0, identity: secretID)],
      folders: ["/Users/example/Secret": secretID, "/Users/example/Notes": otherID])
    XCTAssertNil(result.policySet)
    XCTAssertTrue(result.scopesChanged)
    XCTAssertEqual(
      result.scopes, [scope(set, 0, identity: secretID), scope(set, 1, identity: otherID)])
  }

  func testAFolderInPlaceChangesNothingAndANewVolumeIDIsRecorded() {
    let set = policySet([("Secret", "/Users/example/Secret")])
    let unchanged = reconcile(
      set, scopes: [scope(set, 0, identity: secretID)],
      folders: ["/Users/example/Secret": secretID])
    XCTAssertNil(unchanged.policySet)
    XCTAssertFalse(unchanged.scopesChanged)
    XCTAssertTrue(unchanged.followed.isEmpty)
    // The volume was mounted again under another ID; its UUID still names it.
    var remounted = secretID
    remounted.fileSystemID = 0x1_0000_0099
    let refreshed = reconcile(
      set, scopes: [scope(set, 0, identity: secretID)],
      folders: ["/Users/example/Secret": remounted])
    XCTAssertNil(refreshed.policySet)
    XCTAssertTrue(refreshed.scopesChanged)
    XCTAssertEqual(refreshed.scopes.first?.folderIdentity, remounted)
  }

  func testAMovedFolderIsFollowedAsTheNextRevision() throws {
    let set = policySet([
      ("Secret", "/Users/example/Parent/Secret"), ("Notes", "/Users/example/Notes"),
    ])
    let notesID = FolderIdentity(fileSystemID: 5, volumeUUID: nil, objectID: 9)
    // Another folder now has the old name; the policy's folder is elsewhere.
    let result = reconcile(
      set,
      scopes: [scope(set, 0, identity: secretID), scope(set, 1, identity: notesID)],
      folders: [
        "/Users/example/Parent/Secret": otherID,
        "/Users/example/Moved/Secret": secretID,
        "/Users/example/Notes": notesID,
      ])
    let followed = try XCTUnwrap(result.policySet)
    XCTAssertEqual(followed.revision, set.revision + 1)
    XCTAssertEqual(followed.setIdentifier, set.setIdentifier)
    XCTAssertEqual(followed.policies[0].protectedRootPath, "/Users/example/Moved/Secret")
    XCTAssertEqual(followed.policies[1], set.policies[1])
    XCTAssertEqual(followed.policies[0].allowRules, set.policies[0].allowRules)
    XCTAssertEqual(followed.policies[0].mode, set.policies[0].mode)
    XCTAssertEqual(result.scopes[0].canonicalRoot, "/Users/example/Moved/Secret")
    XCTAssertEqual(result.scopes[0].folderIdentity, secretID)
    XCTAssertEqual(result.scopes[1], scope(set, 1, identity: notesID))
    XCTAssertTrue(result.scopesChanged)
    XCTAssertEqual(
      result.followed,
      [
        FollowedFolder(
          policyIdentifier: set.policies[0].id, policyName: "Secret",
          previousPath: "/Users/example/Parent/Secret", currentPath: "/Users/example/Moved/Secret")
      ])
    XCTAssertNil(result.warning)
  }

  func testPendingMovesAreSettledWhenReportedExpiredOrNamedByThePolicy() throws {
    let set = policySet([("Secret", "/Users/example/Parent/Secret")])
    let id = set.policies[0].id
    let now: UInt64 = 100_000_000_000
    let toMoved = move(id, "/Users/example/Moved/Secret", at: now - 1)
    let reported = move(id, "/Users/example/Other/Secret", at: now - 1, notified: true)
    let young = move(id, "/Users/example/Young/Secret", at: now - 1_000)
    let expired = move(
      id, "/Users/example/Old/Secret", at: now - PolicyFolderReconciler.confirmationPeriod)
    let orphan = move(UUID(), "/Users/example/Gone/Secret", at: now)
    let result = reconcile(
      set, scopes: [scope(set, 0, identity: secretID)],
      folders: ["/Users/example/Moved/Secret": secretID],
      pending: [toMoved, reported, young, expired, orphan], now: now)
    XCTAssertNotNil(result.policySet)
    XCTAssertEqual(
      result.settledMoves,
      [toMoved.identifier, reported.identifier, expired.identifier, orphan.identifier])
  }

  func testAReportedRenameThatFailedLeavesThePolicyAndSettlesItsMove() {
    let set = policySet([("Secret", "/Users/example/Parent/Secret")])
    let id = set.policies[0].id
    let failed = move(id, "/Users/example/Moved/Secret", at: 10, notified: true)
    let waiting = move(id, "/Users/example/Later/Secret", at: 10)
    let result = reconcile(
      set, scopes: [scope(set, 0, identity: secretID)],
      folders: ["/Users/example/Parent/Secret": secretID], pending: [failed, waiting], now: 20)
    XCTAssertNil(result.policySet)
    XCTAssertFalse(result.scopesChanged)
    XCTAssertEqual(result.settledMoves, [failed.identifier])
  }

  func testAMissingFolderIsReportedAndKeepsItsPath() {
    let set = policySet([("Secret", "/Users/example/Secret"), ("Old", "/Users/example/Old")])
    let result = reconcile(
      set, scopes: [scope(set, 0, identity: secretID), scope(set, 1, identity: nil)],
      folders: [:])
    XCTAssertNil(result.policySet)
    XCTAssertFalse(result.scopesChanged)
    XCTAssertEqual(
      result.scopes, [scope(set, 0, identity: secretID), scope(set, 1, identity: nil)])
    XCTAssertEqual(
      result.warning,
      "Protected folder missing: /Users/example/Secret (Secret)\n"
        + "Protected folder missing: /Users/example/Old (Old)")
  }

  func testAFolderRecreatedAtThePathOfAVanishedFolderIsAdopted() {
    let set = policySet([("Secret", "/Users/example/Secret")])
    let result = reconcile(
      set, scopes: [scope(set, 0, identity: secretID)],
      folders: ["/Users/example/Secret": otherID])
    XCTAssertNil(result.policySet)
    XCTAssertTrue(result.scopesChanged)
    XCTAssertEqual(result.scopes.first?.folderIdentity, otherID)
    XCTAssertEqual(result.scopes.first?.canonicalRoot, "/Users/example/Secret")
    XCTAssertNil(result.warning)
  }

  func testAFolderMovedToALocationThatCantBeProtectedIsReported() {
    let set = policySet([("Secret", "/Users/example/Parent/Secret")])
    let result = reconcile(
      set, scopes: [scope(set, 0, identity: secretID)],
      folders: ["/Volumes": secretID])
    XCTAssertNil(result.policySet)
    XCTAssertEqual(result.unfollowed.first?.foundPath, "/Volumes")
    XCTAssertEqual(result.unfollowed.first?.path, "/Users/example/Parent/Secret")
    XCTAssertTrue(
      result.warning?.hasPrefix("Protected folder moved but not followed: /Volumes (Secret): ")
        ?? false)
  }

  // MARK: - Real folders

  func testSystemLocatorFindsAMovedFolderByIdentity() throws {
    let base = PhysicalPath.resolve(
      FileManager.default.temporaryDirectory
        .appendingPathComponent("PasuFSFolderLocatorTests-\(UUID().uuidString)"))
    defer { try? FileManager.default.removeItem(at: base) }
    let home = base.appendingPathComponent("home")
    let parent = home.appendingPathComponent("Parent")
    let secret = parent.appendingPathComponent("Secret")
    try FileManager.default.createDirectory(at: secret, withIntermediateDirectories: true)
    let file = secret.appendingPathComponent("a.txt")
    try Data("x".utf8).write(to: file)
    let link = home.appendingPathComponent("Link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: secret)

    let locator = SystemFolderLocator()
    let identity = try XCTUnwrap(locator.identity(ofFolderAt: secret.path))
    var info = stat()
    XCTAssertEqual(lstat(secret.path, &info), 0)
    XCTAssertEqual(identity.objectID, UInt64(info.st_ino))
    XCTAssertNil(locator.identity(ofFolderAt: file.path))
    XCTAssertNil(locator.identity(ofFolderAt: link.path))
    XCTAssertNil(locator.identity(ofFolderAt: home.appendingPathComponent("None").path))
    XCTAssertEqual(locator.confirmedIdentity(ofFolderAt: secret.path, expected: identity), identity)
    XCTAssertEqual(locator.path(of: identity), secret.path)

    let moved = home.appendingPathComponent("Moved")
    try FileManager.default.moveItem(at: parent, to: moved)
    let newPath = moved.appendingPathComponent("Secret").path
    XCTAssertNil(locator.confirmedIdentity(ofFolderAt: secret.path, expected: identity))
    XCTAssertEqual(locator.path(of: identity), newPath)
    XCTAssertEqual(locator.confirmedIdentity(ofFolderAt: newPath, expected: identity), identity)

    // The whole check follows the folder with the same path rules as a saved policy.
    var set = policySet([("Secret", secret.path)])
    set.revision = 3
    let result = PolicyFolderReconciler.reconcile(
      policySet: set,
      scopes: [
        PersistedPolicyScope(
          policyIdentifier: set.policies[0].id, canonicalRoot: secret.path, caseSensitive: false,
          folderIdentity: identity)
      ],
      pendingMoves: [], now: 0, locator: locator,
      prepareScope: { try ProtectedPathScope(root: $0, homeDirectory: home.path) })
    XCTAssertEqual(result.policySet?.revision, 4)
    XCTAssertEqual(result.policySet?.policies.first?.protectedRootPath, newPath)

    try FileManager.default.removeItem(at: moved)
    XCTAssertNil(locator.path(of: identity))
  }

  // MARK: - Retired folder paths

  func testFollowingAFolderRetiresItsPreviousPath() throws {
    let set = policySet([("Secret", "/Users/example/Parent/Secret")])
    let result = reconcile(
      set, scopes: [scope(set, 0, identity: secretID)],
      folders: ["/Users/example/Moved/Secret": secretID])
    XCTAssertNotNil(result.policySet)
    XCTAssertEqual(
      result.scopes[0].retiredPaths,
      [RetiredFolderPath(path: "/Users/example/Parent/Secret", caseSensitive: false)])
  }

  func testFollowingAgainKeepsTheOlderRetiredPathsAndAddsTheNewest() throws {
    let set = policySet([("Secret", "/Users/example/Moved/Secret")])
    var stored = scope(set, 0, identity: secretID)
    stored.setRetiredFolderPaths([retired("/Users/example/Parent/Secret")])
    let result = reconcile(
      set, scopes: [stored], folders: ["/Users/example/Archive/Secret": secretID])
    XCTAssertEqual(result.policySet?.policies[0].protectedRootPath, "/Users/example/Archive/Secret")
    XCTAssertEqual(
      result.scopes[0].retiredPaths.map(\.path),
      ["/Users/example/Parent/Secret", "/Users/example/Moved/Secret"])
  }

  func testFollowingTheFolderBackOntoARetiredPathReleasesThatPath() throws {
    let set = policySet([("Secret", "/Users/example/Moved/Secret")])
    var stored = scope(set, 0, identity: secretID)
    stored.setRetiredFolderPaths([
      retired("/Users/example/PARENT/Secret"), retired("/Users/example/Parent/Secret/Inner"),
      retired("/Users/example/Other"),
    ])
    let result = reconcile(
      set, scopes: [stored], folders: ["/Users/example/Parent/Secret": secretID])
    XCTAssertEqual(result.policySet?.policies[0].protectedRootPath, "/Users/example/Parent/Secret")
    // The folder protects its own path again, including what lies inside it.
    XCTAssertEqual(
      result.scopes[0].retiredPaths.map(\.path),
      ["/Users/example/Other", "/Users/example/Moved/Secret"])
  }

  func testARetiredPathNamedAgainMovesToTheEndAndTheOldestIsDroppedBeyondTheLimit() throws {
    let set = policySet([("Secret", "/Users/example/Now")])
    var stored = scope(set, 0, identity: secretID)
    stored.setRetiredFolderPaths((1...8).map { retired("/Users/example/Old\($0)") })
    let result = reconcile(set, scopes: [stored], folders: ["/Users/example/Old5": secretID])
    // Old5 is the folder again; Now joins the end.
    XCTAssertEqual(
      result.scopes[0].retiredPaths.map(\.path),
      [
        "/Users/example/Old1", "/Users/example/Old2", "/Users/example/Old3", "/Users/example/Old4",
        "/Users/example/Old6", "/Users/example/Old7", "/Users/example/Old8", "/Users/example/Now",
      ])
    var full = scope(set, 0, identity: secretID)
    full.setRetiredFolderPaths((1...8).map { retired("/Users/example/Old\($0)") })
    let crowded = reconcile(set, scopes: [full], folders: ["/Users/example/Newer": secretID])
    XCTAssertEqual(crowded.scopes[0].retiredPaths.count, 8)
    XCTAssertEqual(crowded.scopes[0].retiredPaths.first?.path, "/Users/example/Old2")
    XCTAssertEqual(crowded.scopes[0].retiredPaths.last?.path, "/Users/example/Now")
  }

  func testAFolderInPlaceKeepsItsRetiredPathsAndAnExhaustedRevisionRetiresNothing() throws {
    var set = policySet([("Secret", "/Users/example/Moved/Secret")])
    var stored = scope(set, 0, identity: secretID)
    stored.setRetiredFolderPaths([retired("/Users/example/Parent/Secret")])
    let unchanged = reconcile(
      set, scopes: [stored], folders: ["/Users/example/Moved/Secret": secretID])
    XCTAssertFalse(unchanged.scopesChanged)
    XCTAssertEqual(unchanged.scopes, [stored])

    set.revision = UInt64.max
    let exhausted = reconcile(
      set, scopes: [stored], folders: ["/Users/example/Archive/Secret": secretID])
    XCTAssertNil(exhausted.policySet)
    XCTAssertEqual(exhausted.scopes, [stored])
  }

  func testRetiredPathsInsideARenamedFolderMoveWithThePolicyFolder() throws {
    let set = policySet([("Secret", "/Users/example/Base/B/Secret")])
    var stored = scope(set, 0, identity: secretID)
    stored.setRetiredFolderPaths([
      retired("/Users/example/Base/A/Secret"), retired("/Users/example/Elsewhere"),
    ])
    let rename = PendingFolderMove(
      policyIdentifier: set.policies[0].id,
      scope: ProtectedPathScope(
        canonicalRoot: "/Users/example/Base2/B/Secret", caseSensitive: false),
      source: "/Users/example/Base", destination: "/Users/example/Base2", allowedAt: 5)
    let result = reconcile(
      set, scopes: [stored], folders: ["/Users/example/Base2/B/Secret": secretID],
      pending: [rename], now: 6)
    XCTAssertEqual(result.policySet?.policies[0].protectedRootPath, "/Users/example/Base2/B/Secret")
    XCTAssertEqual(
      result.scopes[0].retiredPaths.map(\.path),
      ["/Users/example/Base2/A/Secret", "/Users/example/Elsewhere", "/Users/example/Base/B/Secret"])
  }

  func testRetiredPathsFollowAChainOfRenamesAndStayWhenNoRenameWasSeen() throws {
    let set = policySet([("Secret", "/Users/example/Base/B/Secret")])
    var stored = scope(set, 0, identity: secretID)
    stored.setRetiredFolderPaths([retired("/Users/example/Base/A/Secret")])
    let first = PendingFolderMove(
      policyIdentifier: set.policies[0].id,
      scope: ProtectedPathScope(
        canonicalRoot: "/Users/example/Base2/B/Secret", caseSensitive: false),
      source: "/Users/example/Base", destination: "/Users/example/Base2", allowedAt: 5)
    let second = PendingFolderMove(
      policyIdentifier: set.policies[0].id,
      scope: ProtectedPathScope(
        canonicalRoot: "/Users/example/Base3/B/Secret", caseSensitive: false),
      source: "/Users/example/Base2", destination: "/Users/example/Base3", allowedAt: 7)
    // A rename that was allowed but did not lead to the folder's location is not applied.
    let unrelated = PendingFolderMove(
      policyIdentifier: set.policies[0].id,
      scope: ProtectedPathScope(canonicalRoot: "/Users/example/X/Secret", caseSensitive: false),
      source: "/Users/example/Base/B", destination: "/Users/example/X", allowedAt: 6)
    let chained = reconcile(
      set, scopes: [stored], folders: ["/Users/example/Base3/B/Secret": secretID],
      pending: [second, unrelated, first], now: 8)
    XCTAssertEqual(
      chained.scopes[0].retiredPaths.map(\.path),
      ["/Users/example/Base3/A/Secret", "/Users/example/Base/B/Secret"])

    // A move the extension did not see, for example while it was stopped, moves no retired path.
    let unseen = reconcile(
      set, scopes: [stored], folders: ["/Users/example/Base2/B/Secret": secretID])
    XCTAssertEqual(
      unseen.scopes[0].retiredPaths.map(\.path),
      ["/Users/example/Base/A/Secret", "/Users/example/Base/B/Secret"])
  }

  // MARK: - Spelling

  func testAFolderWhoseNameChangedOnlyInLetterCaseIsFollowed() throws {
    let set = policySet([("Secret", "/Users/example/Parent/Secret")])
    var stored = scope(set, 0, identity: secretID)
    stored.setRetiredFolderPaths([retired("/Users/example/Old/Secret")])
    // The stored path still leads to the folder; the file system spells it differently now.
    let result = reconcile(
      set, scopes: [stored], folders: ["/Users/example/Parent/Secret": secretID],
      spellings: ["/Users/example/Parent/Secret": "/Users/example/PARENT/Secret"])
    let followed = try XCTUnwrap(result.policySet)
    XCTAssertEqual(followed.revision, set.revision + 1)
    XCTAssertEqual(followed.policies[0].protectedRootPath, "/Users/example/PARENT/Secret")
    XCTAssertEqual(
      result.followed.map(\.currentPath), ["/Users/example/PARENT/Secret"])
    XCTAssertEqual(result.scopes[0].canonicalRoot, "/Users/example/PARENT/Secret")
    // The old spelling names the same folder, so it does not become a retired path.
    XCTAssertEqual(result.scopes[0].retiredPaths.map(\.path), ["/Users/example/Old/Secret"])
  }

  func testAChangeOfUnicodeCompositionIsFollowedByBytes() throws {
    let composed = "/Users/example/Caf\u{E9}"
    let decomposed = "/Users/example/Cafe\u{301}"
    XCTAssertEqual(composed, decomposed)
    let set = policySet([("Secret", composed)])
    let result = reconcile(
      set, scopes: [scope(set, 0, identity: secretID)], folders: [composed: secretID],
      spellings: [composed: decomposed])
    let followed = try XCTUnwrap(result.policySet)
    XCTAssertEqual(Array(followed.policies[0].protectedRootPath.utf8), Array(decomposed.utf8))
    XCTAssertTrue(result.scopes[0].retiredPaths.isEmpty)
    // The same bytes change nothing.
    let unchanged = reconcile(
      set, scopes: [scope(set, 0, identity: secretID)], folders: [composed: secretID])
    XCTAssertNil(unchanged.policySet)
  }

  func testAMoveOntoAnExistingNameWaitsForItsNotification() {
    let set = policySet([("Secret", "/Users/example/Parent/Secret")])
    let stored = [scope(set, 0, identity: secretID)]
    let folders = ["/Users/example/Parent/Secret": secretID]
    let respelled = PendingFolderMove(
      policyIdentifier: set.policies[0].id,
      scope: ProtectedPathScope(
        canonicalRoot: "/Users/example/Parent/Secret", caseSensitive: false),
      source: "/Users/example/Parent", destination: "/Users/example/Parent", allowedAt: 100,
      destinationIsExistingFile: true)
    var notified = respelled
    notified.wasNotified = true
    // It names the policy's own folder, yet stays until notified or expired.
    let waiting = reconcile(set, scopes: stored, folders: folders, pending: [respelled], now: 200)
    XCTAssertTrue(waiting.settledMoves.isEmpty)
    let reported = reconcile(set, scopes: stored, folders: folders, pending: [notified], now: 200)
    XCTAssertEqual(reported.settledMoves, [respelled.identifier])
    let expired = reconcile(
      set, scopes: stored, folders: folders, pending: [respelled],
      now: 100 + PolicyFolderReconciler.confirmationPeriod)
    XCTAssertEqual(expired.settledMoves, [respelled.identifier])
  }

  // MARK: - Helpers

  private func retired(_ path: String) -> RetiredFolderPath {
    RetiredFolderPath(path: path, caseSensitive: false)
  }

  private struct FakeLocator: FolderLocating {
    let folders: [String: FolderIdentity]
    var spellings: [String: String] = [:]

    func identity(ofFolderAt path: String) -> FolderIdentity? { folders[path] }

    func spelling(ofFolderAt path: String) -> String? {
      spellings[path] ?? (folders[path] != nil ? path : nil)
    }

    func confirmedIdentity(ofFolderAt path: String, expected: FolderIdentity) -> FolderIdentity? {
      guard let found = folders[path], found.objectID == expected.objectID else { return nil }
      if found.fileSystemID == expected.fileSystemID { return expected }
      return found.volumeUUID != nil && found.volumeUUID == expected.volumeUUID ? found : nil
    }

    func path(of identity: FolderIdentity) -> String? {
      folders.first {
        $0.value.objectID == identity.objectID && $0.value.volumeUUID == identity.volumeUUID
      }?.key
    }
  }

  private func reconcile(
    _ set: PolicySetDocument, scopes: [PersistedPolicyScope], folders: [String: FolderIdentity],
    spellings: [String: String] = [:], pending: [PendingFolderMove] = [], now: UInt64 = 0
  ) -> PolicyFolderReconciliation {
    PolicyFolderReconciler.reconcile(
      policySet: set, scopes: scopes, pendingMoves: pending, now: now,
      locator: FakeLocator(folders: folders, spellings: spellings),
      prepareScope: { path in
        guard path != "/Volumes" else { throw ProtectedPathScopeError.unsafeRoot(path) }
        return ProtectedPathScope(canonicalRoot: path, caseSensitive: false)
      })
  }

  private func move(
    _ policy: UUID, _ root: String, at time: UInt64, notified: Bool = false
  ) -> PendingFolderMove {
    PendingFolderMove(
      policyIdentifier: policy,
      scope: ProtectedPathScope(canonicalRoot: root, caseSensitive: false),
      source: "/source", destination: "/destination", allowedAt: time, wasNotified: notified)
  }

  private func scope(_ set: PolicySetDocument, _ index: Int, identity: FolderIdentity?)
    -> PersistedPolicyScope
  {
    PersistedPolicyScope(
      policyIdentifier: set.policies[index].id,
      canonicalRoot: set.policies[index].protectedRootPath, caseSensitive: false,
      folderIdentity: identity)
  }

  private func policySet(_ policies: [(String, String)]) -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(uuidString: "00000000-0000-0000-0000-000000000100")!, revision: 7,
      policies: policies.enumerated().map { offset, entry in
        DirectoryPolicy(
          id: UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", offset + 1))!,
          name: entry.0, mode: .protection, protectedRootPath: entry.1,
          allowRules: [
            .teamSigned(
              id: "rule.\(offset)", teamIdentifier: "TEAM123456",
              signingIdentifier: "com.example.Editor", allowsDescendants: false)
          ])
      })
  }
}
