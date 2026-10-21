import Darwin
import Foundation
import XCTest

@testable import PasuFSConfiguration

/// Retired folder paths are stored with the committed scopes, survive a restart and are released
/// only for the policy the user saves.
final class RetiredFolderPathStorageTests: XCTestCase {
  private let first = RetiredFolderPath(path: "/Users/example/Parent/Secret", caseSensitive: false)
  private let second = RetiredFolderPath(path: "/Users/example/Moved/Secret", caseSensitive: false)

  func testScopesWithoutRetiredPathsKeepTheirEncoding() throws {
    let fixture = try repository()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let document = policySet()
    try fixture.repository.save(document, scopes: scopes(document))
    let commit = try fixture.store.read(PolicyRepository.commitFilename, maximumSize: 1_048_576)
    XCTAssertFalse(String(decoding: commit, as: UTF8.self).contains("retiredFolderPaths"))
    let loaded = try fixture.repository.load()
    XCTAssertEqual(loaded.state, .ready)
    XCTAssertEqual(loaded.scopes.map(\.retiredPaths), [[], []])
    // An empty list is the same as none.
    XCTAssertNil(
      PersistedPolicyScope(
        policyIdentifier: UUID(), canonicalRoot: "/x", caseSensitive: false,
        retiredFolderPaths: []
      ).retiredFolderPaths)
  }

  func testRetiredPathsAreStoredAndReadBackAfterARestart() throws {
    let fixture = try repository()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let document = policySet()
    var stored = scopes(document)
    stored[0].setRetiredFolderPaths([first, second])
    try fixture.repository.save(document, scopes: stored)
    // A new repository object reads what an earlier extension process stored.
    let reloaded = try PolicyRepository(store: fixture.store).load()
    XCTAssertEqual(reloaded.state, .ready)
    XCTAssertEqual(reloaded.scopes[0].retiredPaths, [first, second])
    XCTAssertEqual(reloaded.scopes[1].retiredPaths, [])

    // Replacing scope metadata, as when identities are added, keeps them.
    var identified = reloaded.scopes
    identified[0].folderIdentity = FolderIdentity(fileSystemID: 1, volumeUUID: nil, objectID: 2)
    try fixture.repository.updateScopes(identified)
    XCTAssertEqual(try fixture.repository.load().scopes[0].retiredPaths, [first, second])

    // Emergency recovery still knows them.
    for backup in [false, true] {
      try fixture.store.write(
        Data("broken".utf8), to: PolicyRepository.filename("a", backup: backup), mode: 0o600)
    }
    let emergency = try fixture.repository.load()
    XCTAssertEqual(emergency.state, .denyAllRecovery)
    XCTAssertEqual(emergency.emergencyScopes[0].retiredPaths, [first, second])
  }

  func testOnlyTheNewestRetiredPathsAreKept() {
    var scope = PersistedPolicyScope(
      policyIdentifier: UUID(), canonicalRoot: "/Users/example/Now", caseSensitive: false)
    let paths = (1...10).map {
      RetiredFolderPath(path: "/Users/example/Old\($0)", caseSensitive: false)
    }
    scope.setRetiredFolderPaths(paths)
    XCTAssertEqual(PersistedPolicyScope.maximumRetiredFolderPathCount, 8)
    XCTAssertEqual(scope.retiredPaths, Array(paths.suffix(8)))
    XCTAssertEqual(scope.retiredPaths.first?.path, "/Users/example/Old3")
  }

  func testUnsafeRetiredPathsAreNotStored() throws {
    let fixture = try repository()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let document = policySet()
    for path in ["relative", "/", "/Users/example/a\0b"] {
      var stored = scopes(document)
      stored[0].setRetiredFolderPaths([RetiredFolderPath(path: path, caseSensitive: false)])
      XCTAssertThrowsError(try fixture.repository.save(document, scopes: stored)) {
        XCTAssertEqual($0 as? PolicyRepositoryError, .invalidScopes)
      }
    }
  }

  func testSavingAPolicyReleasesOnlyItsOwnRetiredPaths() {
    let document = policySet()
    var stored = scopes(document)
    stored[0].setRetiredFolderPaths([first])
    stored[1].setRetiredFolderPaths([second])
    let secret = document.policies[0].id
    let notes = document.policies[1].id

    let afterSavingSecret = PersistedPolicyScope.retiredFolderPaths(
      in: stored, keptBy: document, releasing: secret)
    XCTAssertEqual(afterSavingSecret, [notes: [second]])

    // A set the app sends for another reason, and a revision the extension stores itself
    // after following a folder, release nothing.
    XCTAssertEqual(
      PersistedPolicyScope.retiredFolderPaths(in: stored, keptBy: document, releasing: nil),
      [secret: [first], notes: [second]])

    // A deleted policy takes its retired paths with it.
    var withoutNotes = document
    withoutNotes.policies.removeLast()
    XCTAssertEqual(
      PersistedPolicyScope.retiredFolderPaths(in: stored, keptBy: withoutNotes, releasing: nil),
      [secret: [first]])
  }

  func testTheSavedPolicyTravelsWithTheApplyRequest() throws {
    let policy = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
    let request = PolicyApplyRequest(
      policySetData: Data("{}".utf8), authorization: nil, savedPolicyIdentifier: policy)
    let decoded = try PolicyApplyRequest.decode(JSONEncoder().encode(request))
    XCTAssertEqual(decoded.savedPolicyIdentifier, policy)

    // A request without the field names no saved policy.
    let older = try JSONSerialization.data(withJSONObject: [
      "configurationProtocolVersion": PolicyApplyRequest.currentConfigurationProtocolVersion,
      "policySetData": Data("{}".utf8).base64EncodedString(),
    ])
    XCTAssertNil(try PolicyApplyRequest.decode(older).savedPolicyIdentifier)
  }

  func testTheStatusReportsRetiredPathsAsAnOptionalField() throws {
    let policy = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
    let snapshot = ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(), phase: .enforcing,
      retiredFolderPaths: [PolicyRetiredFolderPaths(policyIdentifier: policy, paths: [first.path])])
    let data = try JSONEncoder().encode(snapshot)
    XCTAssertEqual(
      try JSONDecoder().decode(ExtensionStatusSnapshot.self, from: data).retiredFolderPaths,
      snapshot.retiredFolderPaths)
    var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    object.removeValue(forKey: "retiredFolderPaths")
    let older = try JSONDecoder().decode(
      ExtensionStatusSnapshot.self, from: JSONSerialization.data(withJSONObject: object))
    XCTAssertNil(older.retiredFolderPaths)
  }

  // MARK: - Helpers

  private func policySet() -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(uuidString: "00000000-0000-0000-0000-000000000100")!, revision: 3,
      policies: [
        DirectoryPolicy(
          id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!, name: "Secret",
          mode: .protection, protectedRootPath: "/Users/example/Archive/Secret",
          allowRules: [
            .teamSigned(
              id: "editor", teamIdentifier: "TEAM123456", signingIdentifier: "com.example.Editor",
              allowsDescendants: false)
          ]),
        DirectoryPolicy(
          id: UUID(uuidString: "00000000-0000-0000-0000-000000000002")!, name: "Notes",
          mode: .audit, protectedRootPath: "/Users/example/Notes"),
      ])
  }

  private func scopes(_ document: PolicySetDocument) -> [PersistedPolicyScope] {
    document.policies.map {
      PersistedPolicyScope(
        policyIdentifier: $0.id, canonicalRoot: $0.protectedRootPath, caseSensitive: false)
    }
  }

  private func repository() throws -> (
    directory: URL, store: SecureAtomicFileStore, repository: PolicyRepository
  ) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let store = SecureAtomicFileStore(rootDirectory: directory, requiredOwnerUserID: getuid())
    try store.prepareDirectory(mode: 0o700)
    return (directory, store, PolicyRepository(store: store))
  }
}
