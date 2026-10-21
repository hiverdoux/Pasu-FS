import Darwin
import Foundation
import XCTest

@testable import PasuFSConfiguration

final class ExecutionOriginConfigurationTests: XCTestCase {
  func testExplicitModeAndBothListsSurviveDraftRoundTripAndToggle() throws {
    let rule = PolicyRule.platformBinary(
      id: "allow", signingIdentifier: "com.apple.TextEdit", allowsDescendants: true)
    var denied = rule
    denied.id = "deny"
    let original = document(allow: [rule], deny: [denied])
    var draft = DirectoryPolicyDraft(policy: original.policies[0])
    draft.isBlacklistEnabled = true
    XCTAssertEqual(draft.allowRules, [rule])
    XCTAssertEqual(draft.denyRules, [denied])
    var saved = original
    saved.policies = [draft.makePolicy()]
    XCTAssertEqual(try PolicySetDocumentCodec.decode(PolicySetDocumentCodec.encode(saved)), saved)
    draft.isBlacklistEnabled = false
    XCTAssertEqual(draft.makePolicy(), original.policies[0])
  }

  func testCurrentSchemaRejectsMissingOrMalformedModeAndEitherList() throws {
    let data = try PolicySetDocumentCodec.encode(document())
    for key in ["isBlacklistEnabled", "allowRules", "denyRules"] {
      var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
      var policies = try XCTUnwrap(object["policies"] as? [[String: Any]])
      policies[0].removeValue(forKey: key)
      object["policies"] = policies
      XCTAssertThrowsError(
        try PolicySetDocumentCodec.decode(
          JSONSerialization.data(withJSONObject: object)))
      policies[0][key] = "invalid"
      object["policies"] = policies
      XCTAssertThrowsError(
        try PolicySetDocumentCodec.decode(
          JSONSerialization.data(withJSONObject: object)))
    }
  }

  func testLegacyMigrationPreservesIDsRevisionAndListMeaningAndRejectsLiveLegacyWrites() throws {
    let rule = PolicyRule.platformBinary(
      id: "sample", signingIdentifier: "com.apple.TextEdit", allowsDescendants: true)
    let original = document(allow: [rule])
    for type in [PolicyType.whitelist, .blacklist] {
      var object = try XCTUnwrap(
        JSONSerialization.jsonObject(
          with: PolicySetDocumentCodec.encode(original)) as? [String: Any])
      var policies = try XCTUnwrap(object["policies"] as? [[String: Any]])
      let rules = policies[0].removeValue(forKey: "allowRules")!
      policies[0].removeValue(forKey: "denyRules")
      policies[0].removeValue(forKey: "isBlacklistEnabled")
      policies[0]["type"] = type.rawValue
      policies[0]["rules"] = rules
      object["schemaVersion"] = 2
      object["policies"] = policies
      let data = try JSONSerialization.data(withJSONObject: object)
      XCTAssertThrowsError(try PolicySetDocumentCodec.decode(data))
      let migrated = try PolicySetDocumentCodec.migrateStoredDocument(data)
      XCTAssertEqual(migrated.setIdentifier, original.setIdentifier)
      XCTAssertEqual(migrated.revision, original.revision)
      XCTAssertEqual(migrated.policies[0].id, original.policies[0].id)
      var reset = rule
      reset.allowsDescendants = false
      XCTAssertEqual(migrated.policies[0].rules, [reset])
      XCTAssertEqual(migrated.policies[0].isBlacklistEnabled, type == .blacklist)
      XCTAssertEqual(migrated.policies[0].denyRules.count, type == .blacklist ? 1 : 0)
    }
  }

  func testRepositoryRecoversOnlyTheLatestCommittedCopyAndThenDeniesKnownScope() throws {
    let fixture = try repository()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let first = document()
    try fixture.repository.save(first, scopes: scopes(first))
    var latest = first
    latest.revision = 2
    latest.policies[0].isBlacklistEnabled = true
    try fixture.repository.save(latest, scopes: scopes(latest))
    try fixture.store.write(
      Data("broken".utf8), to: PolicyRepository.filename("b", backup: false), mode: 0o600)
    let recovered = try fixture.repository.load()
    XCTAssertEqual(recovered.state, .recovered)
    XCTAssertEqual(recovered.document, latest)
    for backup in [false, true] {
      try fixture.store.write(
        Data("broken".utf8), to: PolicyRepository.filename("b", backup: backup), mode: 0o600)
    }
    let emergency = try fixture.repository.load()
    XCTAssertEqual(emergency.state, .denyAllRecovery)
    XCTAssertEqual(emergency.document?.revision, 2)
    XCTAssertEqual(emergency.document?.policies[0].isBlacklistEnabled, false)
    XCTAssertEqual(emergency.document?.policies[0].allowRules, [])
    XCTAssertEqual(emergency.emergencyScopes, scopes(latest))
    // The intact old slot must never resurrect an older policy.
    XCTAssertNotEqual(emergency.document, first)
  }

  func testCommittedSchemaThreeMigratesWithoutRevivingGrantsAndKeepsRecoveryScopes() throws {
    for damagedCopies in 0...2 {
      let fixture = try repository()
      defer { try? FileManager.default.removeItem(at: fixture.directory) }
      let rule = PolicyRule.platformBinary(
        id: "agent", signingIdentifier: "com.apple.example",
        allowsDescendants: true)
      let original = document(allow: [rule])
      try fixture.repository.save(original, scopes: scopes(original))
      var old = original
      old.schemaVersion = 3
      let encoder = JSONEncoder()
      encoder.outputFormatting = [.sortedKeys]
      let oldData = try encoder.encode(old)
      XCTAssertThrowsError(try PolicySetDocumentCodec.decode(oldData))
      var commit = try JSONDecoder().decode(
        PolicyRepository.Commit.self,
        from: fixture.store.read(PolicyRepository.commitFilename, maximumSize: 1_048_576))
      commit.emergencyDocument.schemaVersion = 3
      commit.digest = PolicySetDocumentCodec.digest(of: oldData)
      commit.metadataDigest = nil
      commit.metadataDigest = PolicySetDocumentCodec.digest(of: try encoder.encode(commit))
      try fixture.store.write(
        encoder.encode(commit), to: PolicyRepository.commitFilename,
        mode: 0o600)
      for (index, backup) in [false, true].enumerated() {
        try fixture.store.write(
          index < damagedCopies ? Data("broken".utf8) : oldData,
          to: PolicyRepository.filename(commit.slot, backup: backup), mode: 0o600)
      }
      let loaded = try fixture.repository.load()
      let migrated = try XCTUnwrap(loaded.document)
      XCTAssertEqual(migrated.schemaVersion, PolicySetDocument.currentSchemaVersion)
      XCTAssertEqual(migrated.setIdentifier, original.setIdentifier)
      XCTAssertEqual(migrated.revision, original.revision)
      XCTAssertEqual(migrated.policies.first?.id, original.policies.first?.id)
      if damagedCopies == 2 {
        XCTAssertEqual(loaded.state, .denyAllRecovery)
        XCTAssertEqual(migrated.policies.first?.allowRules, [])
        XCTAssertEqual(loaded.emergencyScopes, scopes(original))
      } else {
        XCTAssertEqual(loaded.state, .migrated)
        XCTAssertFalse(try XCTUnwrap(migrated.policies.first?.allowRules.first).allowsDescendants)
        try fixture.repository.save(migrated, scopes: scopes(migrated))
        XCTAssertEqual(try fixture.repository.load().state, .ready)
        XCTAssertEqual(try fixture.repository.load().document, migrated)
      }
    }
  }

  func testUncommittedSlotAndMismatchedBackupAreNotActivated() throws {
    let fixture = try repository()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let first = document()
    try fixture.repository.save(first, scopes: scopes(first))
    var next = first
    next.revision = 2
    next.policies = []
    try fixture.store.write(
      PolicySetDocumentCodec.encode(next), to: PolicyRepository.filename("b", backup: false),
      mode: 0o600)
    XCTAssertEqual(try fixture.repository.load().document, first)
    try fixture.store.write(
      Data("broken".utf8), to: PolicyRepository.filename("a", backup: false), mode: 0o600)
    try fixture.store.write(
      PolicySetDocumentCodec.encode(next), to: PolicyRepository.filename("a", backup: true),
      mode: 0o600)
    XCTAssertEqual(try fixture.repository.load().state, .denyAllRecovery)
  }

  func testVerifiedCopyRemainsActiveWhenRepairingThePrimaryFails() throws {
    let fixture = try repository()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let original = document()
    try fixture.repository.save(original, scopes: scopes(original))
    let primary = PolicyRepository.filename("a", backup: false)
    try fixture.store.remove(primary)
    try FileManager.default.createDirectory(
      at: fixture.directory.appendingPathComponent(primary), withIntermediateDirectories: false)
    let recovered = try fixture.repository.load()
    XCTAssertEqual(recovered.state, .recovered)
    XCTAssertEqual(recovered.document, original)
    XCTAssertNotNil(recovered.recoveryWarning)
  }

  func testMissingCommitNeverMeansEmptyPolicyAndDeletedPoliciesStayDeleted() throws {
    let fixture = try repository()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    XCTAssertEqual(try fixture.repository.load().state, .notConfigured)
    let first = document()
    try fixture.repository.save(first, scopes: scopes(first))
    var empty = first
    empty.revision += 1
    empty.policies = []
    try fixture.repository.save(empty, scopes: [])
    XCTAssertEqual(try fixture.repository.load().document, empty)
    try fixture.store.remove(PolicyRepository.commitFilename)
    XCTAssertThrowsError(try fixture.repository.load()) { error in
      XCTAssertEqual(error as? PolicyRepositoryError, .missingCommit)
    }
  }

  func testValidJSONDamageToRecoveryScopeIsDetected() throws {
    let fixture = try repository()
    defer { try? FileManager.default.removeItem(at: fixture.directory) }
    let original = document()
    try fixture.repository.save(original, scopes: scopes(original))
    let data = try fixture.store.read(PolicyRepository.commitFilename, maximumSize: 1_048_576)
    var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    var scopes = try XCTUnwrap(object["scopes"] as? [[String: Any]])
    scopes[0]["canonicalRoot"] = "/Users/example/Other"
    object["scopes"] = scopes
    try fixture.store.write(
      JSONSerialization.data(withJSONObject: object), to: PolicyRepository.commitFilename,
      mode: 0o600)
    XCTAssertThrowsError(try fixture.repository.load()) { error in
      XCTAssertEqual(error as? PolicyRepositoryError, .invalidCommit)
    }
  }

  private func document(allow: [PolicyRule] = [], deny: [PolicyRule] = []) -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(), revision: 1,
      policies: [
        DirectoryPolicy(
          name: "Example", mode: .protection, protectedRootPath: "/Users/example/Protected",
          allowRules: allow, denyRules: deny)
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
