import Foundation

public enum PolicyStorageState: String, Codable, Sendable {
  case notConfigured
  case ready
  case migrated
  case recovered
  case denyAllRecovery
  case unavailable
}

/// A path a policy folder had before the policy followed the folder to another path. Until the
/// policy is saved from the app again, the path stays reserved for the programs the policy
/// allows: a program that still uses it can't be redirected elsewhere, and what it saves there
/// can't be read by other programs.
public struct RetiredFolderPath: Codable, Equatable, Hashable, Sendable {
  /// The folder's former path, as its scope stored it.
  public var path: String
  /// The path comparison rule of the volume the folder was on.
  public var caseSensitive: Bool

  public init(path: String, caseSensitive: Bool) {
    self.path = path
    self.caseSensitive = caseSensitive
  }
}

/// A path comparison rule validated when the policy was accepted. It remains
/// usable for emergency denial when both copies of the policy are damaged, for
/// denial at the folder's last known path while the folder cannot be found, and for
/// comparing the stored scope with the found and pending locations of a folder the
/// extension follows after a move.
public struct PersistedPolicyScope: Codable, Equatable, Sendable {
  /// A policy keeps at most this many retired folder paths; the oldest is dropped first.
  public static let maximumRetiredFolderPathCount = 8

  public var policyIdentifier: UUID
  public var canonicalRoot: String
  public var caseSensitive: Bool
  /// The folder at `canonicalRoot` when the scope was stored, used to follow the folder after
  /// it moves. Absent in scopes stored before identities were recorded; the extension adds it
  /// the next time it loads them.
  public var folderIdentity: FolderIdentity?
  /// The paths the folder had before the policy followed it, oldest first. Absent when there
  /// are none, so scopes without retired paths are stored as before.
  public private(set) var retiredFolderPaths: [RetiredFolderPath]?

  public init(
    policyIdentifier: UUID, canonicalRoot: String, caseSensitive: Bool,
    folderIdentity: FolderIdentity? = nil, retiredFolderPaths: [RetiredFolderPath] = []
  ) {
    self.policyIdentifier = policyIdentifier
    self.canonicalRoot = canonicalRoot
    self.caseSensitive = caseSensitive
    self.folderIdentity = folderIdentity
    setRetiredFolderPaths(retiredFolderPaths)
  }

  /// The retired folder paths, oldest first; empty when there are none.
  public var retiredPaths: [RetiredFolderPath] { retiredFolderPaths ?? [] }

  /// Replaces the retired folder paths, keeping the newest
  /// `maximumRetiredFolderPathCount`.
  public mutating func setRetiredFolderPaths(_ paths: [RetiredFolderPath]) {
    let kept = paths.suffix(Self.maximumRetiredFolderPathCount)
    retiredFolderPaths = kept.isEmpty ? nil : Array(kept)
  }

  /// The retired folder paths that the policies of `policySet` keep when the app stores it:
  /// those in `scopes`, except the paths of `released`, the policy whose Save the user chose.
  /// A policy that is not in the set loses its paths with its scope.
  public static func retiredFolderPaths(
    in scopes: [PersistedPolicyScope], keptBy policySet: PolicySetDocument,
    releasing released: UUID?
  ) -> [UUID: [RetiredFolderPath]] {
    let stored = Dictionary(
      scopes.map { ($0.policyIdentifier, $0.retiredPaths) }, uniquingKeysWith: { a, _ in a })
    var kept: [UUID: [RetiredFolderPath]] = [:]
    for policy in policySet.policies where policy.id != released {
      if let paths = stored[policy.id], !paths.isEmpty { kept[policy.id] = paths }
    }
    return kept
  }
}

public struct PolicyRepositoryLoad: Sendable {
  public var document: PolicySetDocument?
  public var state: PolicyStorageState
  public var emergencyScopes: [PersistedPolicyScope]
  public var recoveryWarning: String?
  /// The scopes of the current commit, in every state that read one.
  public var scopes: [PersistedPolicyScope] = []
  /// Whether the document was read from an earlier schema. Storing it again writes the current
  /// schema. Only `migrated` means that reading it changed what it allows.
  public var storedInEarlierSchema = false
}

public enum PolicyRepositoryError: Error, Equatable {
  case invalidCommit
  case missingCommit
  case invalidScopes
}

/// Two bounded slots and an atomic commit record. Both copies of the inactive
/// slot are durable before the commit changes. Recovery never scans old slots
/// for a conveniently readable policy, so deleted policies cannot reappear.
/// Calls must be serialized by the extension's configuration queue.
public final class PolicyRepository: Sendable {
  struct Commit: Codable {
    var schemaVersion: Int = 1
    var slot: String
    var digest: String
    var emergencyDocument: PolicySetDocument
    var scopes: [PersistedPolicyScope]
    var metadataDigest: String?
  }

  static let commitFilename = "policy-commit.json"
  private let store: SecureAtomicFileStore

  public init(store: SecureAtomicFileStore) { self.store = store }

  public func load() throws -> PolicyRepositoryLoad {
    let commit: Commit
    do {
      commit = try readCommit()
    } catch SecureFileStoreError.fileNotFound {
      // Evidence of a committed-store layout forbids falling back to a legacy
      // file if its commit record was lost. An interrupted first migration can
      // be recovered explicitly after inspection, never by guessing a revision.
      for slot in ["a", "b"] {
        for backup in [false, true] {
          do {
            _ = try store.read(Self.filename(slot, backup: backup), maximumSize: 1_048_576)
            throw PolicyRepositoryError.missingCommit
          } catch SecureFileStoreError.fileNotFound { continue }
        }
      }
      do {
        let data = try store.read(
          ExtensionStorageLocations.policySetFilename,
          maximumSize: PolicySetDocumentCodec.maximumDocumentSize)
        let document = try PolicySetDocumentCodec.migrateStoredDocument(data)
        return PolicyRepositoryLoad(
          document: document, state: .migrated, emergencyScopes: [], storedInEarlierSchema: true)
      } catch SecureFileStoreError.fileNotFound {
        return PolicyRepositoryLoad(document: nil, state: .notConfigured, emergencyScopes: [])
      }
    }

    for backup in [false, true] {
      guard
        let data = try? store.read(
          Self.filename(commit.slot, backup: backup),
          maximumSize: PolicySetDocumentCodec.maximumDocumentSize),
        PolicySetDocumentCodec.digest(of: data) == commit.digest,
        let document = try? PolicySetDocumentCodec.migrateStoredDocument(data),
        document.setIdentifier == commit.emergencyDocument.setIdentifier,
        document.revision == commit.emergencyDocument.revision
      else { continue }
      var recoveryWarning: String?
      if backup {
        do {
          try store.write(
            data, to: Self.filename(commit.slot, backup: false), mode: 0o600,
            durability: .storageDevice)
        } catch {
          // A verified current copy is still authoritative when disk repair
          // fails. Losing write access must not discard its valid protection.
          recoveryWarning =
            "The current policy copy is active, but repairing its primary failed: \(error)"
        }
      }
      // Descendant options had no effect before schema 4, so older sets are read with them off
      // (`migrated`). A set stored in schema 4 means the same in the current schema.
      let storedVersion = commit.emergencyDocument.schemaVersion
      return PolicyRepositoryLoad(
        document: document,
        state: storedVersion < PolicySetDocument.firstSchemaVersionWithDescendantAccess
          ? .migrated : (backup ? .recovered : .ready), emergencyScopes: [],
        recoveryWarning: recoveryWarning, scopes: commit.scopes,
        storedInEarlierSchema: storedVersion != PolicySetDocument.currentSchemaVersion)
    }
    return PolicyRepositoryLoad(
      document: try currentEmergencyDocument(commit), state: .denyAllRecovery,
      emergencyScopes: commit.scopes, scopes: commit.scopes)
  }

  public func save(_ document: PolicySetDocument, scopes: [PersistedPolicyScope]) throws {
    let data = try PolicySetDocumentCodec.encode(document)
    let emergency = PolicySetDocument(
      setIdentifier: document.setIdentifier, revision: document.revision,
      policies: document.policies.map {
        DirectoryPolicy(
          id: $0.id, name: $0.name, mode: $0.mode,
          protectedRootPath: $0.protectedRootPath)
      })
    let previous: Commit?
    do { previous = try readCommit() } catch SecureFileStoreError.fileNotFound { previous = nil }
    let slot = previous?.slot == "a" ? "b" : "a"
    var commit = Commit(
      slot: slot, digest: PolicySetDocumentCodec.digest(of: data),
      emergencyDocument: emergency, scopes: scopes)
    commit.metadataDigest = try metadataDigest(commit)
    try validate(commit)
    // Both copies and the commit record are flushed to the storage device before this returns,
    // so a saved revision survives a sudden loss of power; until the commit record is written,
    // the previous commit stays in effect.
    try store.write(
      data, to: Self.filename(slot, backup: false), mode: 0o600, durability: .storageDevice)
    try store.write(
      data, to: Self.filename(slot, backup: true), mode: 0o600, durability: .storageDevice)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    try store.write(
      try encoder.encode(commit), to: Self.commitFilename, mode: 0o600,
      durability: .storageDevice)
    // The old format is no longer authoritative. A failure to remove it must
    // not turn a completed commit into a failed apply receipt.
    try? store.remove(ExtensionStorageLocations.policySetFilename, ifExists: true)
  }

  /// Replaces the scope metadata of the current commit without writing a new copy of the
  /// policy set, for example to add folder identities to scopes stored without them. The
  /// scopes must name the same policies as the committed set.
  public func updateScopes(_ scopes: [PersistedPolicyScope]) throws {
    var commit = try readCommit()
    commit.scopes = scopes
    commit.metadataDigest = nil
    commit.metadataDigest = try metadataDigest(commit)
    try validate(commit)
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    try store.write(
      try encoder.encode(commit), to: Self.commitFilename, mode: 0o600,
      durability: .storageDevice)
  }

  private func readCommit() throws -> Commit {
    let commit = try JSONDecoder().decode(
      Commit.self,
      from: store.read(Self.commitFilename, maximumSize: PolicySetDocumentCodec.maximumDocumentSize)
    )
    try validate(commit)
    return commit
  }

  private func validate(_ commit: Commit) throws {
    guard commit.schemaVersion == 1, ["a", "b"].contains(commit.slot),
      commit.metadataDigest == (try metadataDigest(commit)),
      commit.digest.count == 64,
      commit.digest.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
    else { throw PolicyRepositoryError.invalidCommit }
    _ = try currentEmergencyDocument(commit)
    guard
      commit.emergencyDocument.policies.allSatisfy({
        !$0.isBlacklistEnabled && $0.allowRules.isEmpty && $0.denyRules.isEmpty
      }),
      Set(commit.scopes.map(\.policyIdentifier))
        == Set(commit.emergencyDocument.policies.map(\.id)),
      commit.scopes.count == commit.emergencyDocument.policies.count,
      commit.scopes.allSatisfy({ scope in
        Self.isStorablePath(scope.canonicalRoot)
          && scope.retiredPaths.count <= PersistedPolicyScope.maximumRetiredFolderPathCount
          && scope.retiredPaths.allSatisfy { Self.isStorablePath($0.path) }
      })
    else { throw PolicyRepositoryError.invalidScopes }
  }

  private static func isStorablePath(_ path: String) -> Bool {
    path.hasPrefix("/") && !path.contains("\0") && path != "/"
  }

  private func metadataDigest(_ commit: Commit) throws -> String {
    var payload = commit
    payload.metadataDigest = nil
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    return PolicySetDocumentCodec.digest(of: try encoder.encode(payload))
  }

  /// Verify the original commit digest before normalizing its emergency scope.
  /// This also lets a failed upgrade retain the old store's deny-all boundary.
  private func currentEmergencyDocument(_ commit: Commit) throws -> PolicySetDocument {
    try PolicySetDocumentCodec.migrateStoredDocument(JSONEncoder().encode(commit.emergencyDocument))
  }

  static func filename(_ slot: String, backup: Bool) -> String {
    "policy-slot-\(slot)\(backup ? ".backup" : "").json"
  }
}
