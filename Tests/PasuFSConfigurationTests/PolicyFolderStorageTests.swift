import Darwin
import Foundation
import XCTest

@testable import PasuFSConfiguration

/// Folder identities are stored with the committed scopes, and a followed folder is stored as a
/// new revision that changes nothing but the folder path.
final class PolicyFolderStorageTests: XCTestCase {
  private let identity = FolderIdentity(
    fileSystemID: FolderIdentity.packFileSystemID(16_777_230, 26), volumeUUID: "VOLUME-UUID",
    objectID: 1_234)

  func testFileSystemIDWordsRoundTrip() {
    XCTAssertEqual(identity.fileSystemIDWords.0, 16_777_230)
    XCTAssertEqual(identity.fileSystemIDWords.1, 26)
    let negative = FolderIdentity(
      fileSystemID: FolderIdentity.packFileSystemID(-2, Int32.min), volumeUUID: nil, objectID: 1)
    XCTAssertEqual(negative.fileSystemIDWords.0, -2)
    XCTAssertEqual(negative.fileSystemIDWords.1, Int32.min)
  }

  func testScopesWithoutIdentityKeepTheirEncodingAndGainOneLater() throws {
    let fixture = try repository()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let document = policySet()
    let plain = scopes(document, identity: nil)
    try fixture.repository.save(document, scopes: plain)
    // A scope without an identity is encoded exactly as before the field existed.
    let commit = try fixture.store.read(PolicyRepository.commitFilename, maximumSize: 1_048_576)
    XCTAssertFalse(String(decoding: commit, as: UTF8.self).contains("folderIdentity"))
    let loaded = try fixture.repository.load()
    XCTAssertEqual(loaded.state, .ready)
    XCTAssertEqual(loaded.scopes, plain)

    let identified = scopes(document, identity: identity)
    try fixture.repository.updateScopes(identified)
    let reloaded = try fixture.repository.load()
    XCTAssertEqual(reloaded.state, .ready)
    XCTAssertEqual(reloaded.document, document)
    XCTAssertEqual(reloaded.scopes, identified)

    // Scopes must still name exactly the committed policies.
    XCTAssertThrowsError(try fixture.repository.updateScopes([])) {
      XCTAssertEqual($0 as? PolicyRepositoryError, .invalidScopes)
    }
    var other = identified
    other[0].policyIdentifier = UUID()
    XCTAssertThrowsError(try fixture.repository.updateScopes(other))
    XCTAssertEqual(try fixture.repository.load().scopes, identified)
  }

  func testEmergencyRecoveryKeepsTheStoredIdentity() throws {
    let fixture = try repository()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let document = policySet()
    try fixture.repository.save(document, scopes: scopes(document, identity: identity))
    for backup in [false, true] {
      try fixture.store.write(
        Data("broken".utf8), to: PolicyRepository.filename("a", backup: backup), mode: 0o600)
    }
    let emergency = try fixture.repository.load()
    XCTAssertEqual(emergency.state, .denyAllRecovery)
    XCTAssertEqual(emergency.emergencyScopes.first?.folderIdentity, identity)
    XCTAssertEqual(emergency.scopes.first?.folderIdentity, identity)
  }

  func testMovingFoldersCreatesTheNextRevisionWithOnlyThePathChanged() throws {
    let document = policySet()
    let moved = try document.movingFolders([document.policies[0].id: "/Users/example/Moved"])
    XCTAssertEqual(moved.revision, document.revision + 1)
    XCTAssertEqual(moved.setIdentifier, document.setIdentifier)
    XCTAssertEqual(moved.policies[0].protectedRootPath, "/Users/example/Moved")
    var expected = document.policies[0]
    expected.protectedRootPath = "/Users/example/Moved"
    XCTAssertEqual(moved.policies[0], expected)
    XCTAssertEqual(moved.policies[1], document.policies[1])
    XCTAssertEqual(
      try PolicyUpdateValidator.validate(candidate: moved, against: document), .accepted)
    // Sent by the app, a new folder for a Protection policy needs an administrator; the
    // extension stores this revision itself because the folder is the same one.
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: moved, comparedTo: document))
    var exhausted = document
    exhausted.revision = UInt64.max
    XCTAssertThrowsError(try exhausted.movingFolders([document.policies[0].id: "/x"]))
  }

  func testCompatibilityProfilesStayWithTheMovedFolder() throws {
    var document = policySet()
    let entry = PolicySystemCompatibilityProfile(
      profileIdentifier: "com.example.profile",
      authorizationDigest: String(repeating: "a", count: 64))
    document.policies[0].systemCompatibilityProfiles = [entry]
    let moved = try document.movingFolders([document.policies[0].id: "/Users/example/Moved"])
    XCTAssertEqual(moved.policies[0].systemCompatibilityProfiles, [entry])
    XCTAssertEqual(moved.policies[1].systemCompatibilityProfiles, [])
  }

  // MARK: - Helpers

  private func policySet() -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(uuidString: "00000000-0000-0000-0000-000000000100")!, revision: 3,
      policies: [
        DirectoryPolicy(
          id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!, name: "Secret",
          mode: .protection, protectedRootPath: "/Users/example/Parent/Secret",
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

  private func scopes(_ document: PolicySetDocument, identity: FolderIdentity?)
    -> [PersistedPolicyScope]
  {
    document.policies.map {
      PersistedPolicyScope(
        policyIdentifier: $0.id, canonicalRoot: $0.protectedRootPath, caseSensitive: false,
        folderIdentity: identity)
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
