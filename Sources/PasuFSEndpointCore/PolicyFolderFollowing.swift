import Foundation
import PasuFSConfiguration

/// A rename of a policy folder, or of a folder that contains it, that the extension allowed and
/// has not confirmed yet. Until the extension has checked where the folder is, the policy
/// protects both its folder and `scope`, the location the folder has if the rename succeeded,
/// and keeps both its retired paths and `retiredScopes`, where the renamed folder takes the
/// retired paths inside it.
public struct PendingFolderMove: Equatable, Sendable {
  public let identifier: UUID
  public let policyIdentifier: UUID
  public let scope: ProtectedPathScope
  public let retiredScopes: [ProtectedPathScope]
  /// The source and destination of the rename request, as Endpoint Security reported them.
  public let source: String
  public let destination: String
  /// When the rename was allowed, in nanoseconds of system uptime.
  public let allowedAt: UInt64
  /// Whether the kernel reported the destination as an existing file, so that `scope` may not
  /// show how the folder is spelled after the rename (see
  /// `FileOperationRequest.destinationIsExistingFile`). Such a move is withdrawn only after
  /// its rename notification or the confirmation period, once a check has read the spelling.
  public let destinationIsExistingFile: Bool
  /// Whether macOS has reported the rename as finished. The notification is also sent for a
  /// rename that failed, so it only says that the folder's location can be checked now.
  public internal(set) var wasNotified: Bool

  public init(
    identifier: UUID = UUID(), policyIdentifier: UUID, scope: ProtectedPathScope,
    retiredScopes: [ProtectedPathScope] = [], source: String, destination: String,
    allowedAt: UInt64, destinationIsExistingFile: Bool = false, wasNotified: Bool = false
  ) {
    self.identifier = identifier
    self.policyIdentifier = policyIdentifier
    self.scope = scope
    self.retiredScopes = retiredScopes
    self.source = source
    self.destination = destination
    self.allowedAt = allowedAt
    self.destinationIsExistingFile = destinationIsExistingFile
    self.wasNotified = wasNotified
  }
}

/// A policy whose folder was found at another path.
public struct FollowedFolder: Equatable, Sendable {
  public let policyIdentifier: UUID
  public let policyName: String
  public let previousPath: String
  public let currentPath: String
}

/// A policy whose folder could not be found, or was found where it can't be followed.
public struct UnfollowedFolder: Equatable, Sendable {
  public let policyIdentifier: UUID
  public let policyName: String
  /// The path the policy keeps denying.
  public let path: String
  /// The location the folder was found at, when it was found.
  public let foundPath: String?
  public let reason: String?
}

/// What one check of the policy folders found and what to store.
public struct PolicyFolderReconciliation: Sendable {
  /// The next revision of the policy set with the followed folders, or nil when no folder moved.
  public var policySet: PolicySetDocument?
  /// The scopes to store with the policy set, with identities added or brought up to date and
  /// followed folders at their new paths, their previous paths added to the retired paths.
  public var scopes: [PersistedPolicyScope]
  /// Whether `scopes` differ from the stored ones.
  public var scopesChanged: Bool
  public var followed: [FollowedFolder]
  public var unfollowed: [UnfollowedFolder]
  /// Pending moves that can be withdrawn once the result is in effect: those macOS reported as
  /// finished, those older than the confirmation period and those the policy now names anyway.
  public var settledMoves: Set<UUID>

  /// The status warning: one line for each policy whose folder could not be followed.
  public var warning: String? {
    let lines = unfollowed.map { folder in
      if let found = folder.foundPath {
        "Protected folder moved but not followed: \(found) (\(folder.policyName)): "
          + (folder.reason ?? "unknown reason")
      } else {
        "Protected folder missing: \(folder.path) (\(folder.policyName))"
      }
    }
    return lines.isEmpty ? nil : lines.joined(separator: "\n")
  }
}

/// Compares each policy folder with its stored identity and finds where moved folders went.
public enum PolicyFolderReconciler {
  /// How long a pending move protects its new location without a finished notification.
  public static let confirmationPeriod: UInt64 = 10_000_000_000

  /// - Parameters:
  ///   - prepareScope: Validates a found location as a policy folder, as when a policy is saved.
  public static func reconcile(
    policySet: PolicySetDocument,
    scopes: [PersistedPolicyScope],
    pendingMoves: [PendingFolderMove],
    now: UInt64,
    locator: some FolderLocating,
    prepareScope: (String) throws -> ProtectedPathScope
  ) -> PolicyFolderReconciliation {
    let stored = Dictionary(
      scopes.map { ($0.policyIdentifier, $0) }, uniquingKeysWith: { a, _ in a })
    var result = PolicyFolderReconciliation(
      policySet: nil, scopes: [], scopesChanged: false, followed: [], unfollowed: [],
      settledMoves: [])
    var newFolders: [UUID: String] = [:]

    for policy in policySet.policies {
      // Every committed set stores a scope for each policy. Should one be missing, it is made
      // from the policy's folder so that the stored scopes stay complete.
      guard
        var scope = stored[policy.id]
          ?? (try? prepareScope(policy.protectedRootPath)).map({
            PersistedPolicyScope(
              policyIdentifier: policy.id, canonicalRoot: $0.root, caseSensitive: $0.caseSensitive)
          })
      else { continue }
      let original = stored[policy.id]
      // Follows the folder to `found`, where it was located by identity or by its spelling.
      func follow(to found: String, identity: FolderIdentity) {
        do {
          let moved = try prepareScope(found)
          // Compared by bytes: a rename that changed only the Unicode composition of a name
          // gives an equal string in another spelling, which Endpoint Security matches apart.
          if !moved.root.utf8.elementsEqual(scope.canonicalRoot.utf8) {
            result.followed.append(
              FollowedFolder(
                policyIdentifier: policy.id, policyName: policy.name,
                previousPath: scope.canonicalRoot, currentPath: moved.root))
            newFolders[policy.id] = moved.root
            let renames = renameChain(
              from: ProtectedPathScope(recovering: scope), to: moved,
              moves: pendingMoves.filter { $0.policyIdentifier == policy.id })
            scope.setRetiredFolderPaths(
              retiring(
                RetiredFolderPath(path: scope.canonicalRoot, caseSensitive: scope.caseSensitive),
                to: relocating(scope.retiredPaths, along: renames), folder: moved))
            scope.canonicalRoot = moved.root
            scope.caseSensitive = moved.caseSensitive
          }
          scope.folderIdentity = locator.identity(ofFolderAt: moved.root) ?? identity
        } catch {
          result.unfollowed.append(
            UnfollowedFolder(
              policyIdentifier: policy.id, policyName: policy.name,
              path: scope.canonicalRoot, foundPath: found, reason: String(describing: error)))
        }
      }
      if let identity = scope.folderIdentity {
        if let confirmed = locator.confirmedIdentity(
          ofFolderAt: scope.canonicalRoot, expected: identity)
        {
          scope.folderIdentity = confirmed
          // The stored path still leads to the folder, but a rename that changed only the
          // letter case or composition of the folder's name, or of a folder containing it,
          // gives it another spelling, which the kernel reports from then on.
          if let spelled = locator.spelling(ofFolderAt: scope.canonicalRoot),
            !spelled.utf8.elementsEqual(scope.canonicalRoot.utf8)
          {
            follow(to: spelled, identity: confirmed)
          }
        } else if let found = locator.path(of: identity) {
          follow(to: found, identity: identity)
        } else if let replacement = locator.identity(ofFolderAt: scope.canonicalRoot) {
          // The original folder no longer exists anywhere, and another folder now has its
          // path. The policy protected that path all along; it now follows the new folder.
          scope.folderIdentity = replacement
        } else {
          result.unfollowed.append(
            UnfollowedFolder(
              policyIdentifier: policy.id, policyName: policy.name, path: scope.canonicalRoot,
              foundPath: nil, reason: nil))
        }
      } else if let identity = locator.identity(ofFolderAt: scope.canonicalRoot) {
        scope.folderIdentity = identity
      } else {
        result.unfollowed.append(
          UnfollowedFolder(
            policyIdentifier: policy.id, policyName: policy.name, path: scope.canonicalRoot,
            foundPath: nil, reason: nil))
      }
      if scope != original { result.scopesChanged = true }
      result.scopes.append(scope)
    }

    if !newFolders.isEmpty {
      do {
        result.policySet = try policySet.movingFolders(newFolders)
      } catch {
        // The revision counter is exhausted; nothing can be stored, so nothing is followed.
        result.unfollowed += result.followed.map {
          UnfollowedFolder(
            policyIdentifier: $0.policyIdentifier, policyName: $0.policyName,
            path: $0.previousPath, foundPath: $0.currentPath, reason: String(describing: error))
        }
        result.followed = []
        result.scopes = result.scopes.map { stored[$0.policyIdentifier] ?? $0 }
        result.scopesChanged = result.scopes != policySet.policies.compactMap { stored[$0.id] }
      }
    }

    let roots = Dictionary(
      result.scopes.map { ($0.policyIdentifier, ProtectedPathScope(recovering: $0)) },
      uniquingKeysWith: { a, _ in a })
    for move in pendingMoves {
      let expired = now >= move.allowedAt && now - move.allowedAt >= confirmationPeriod
      // A move of a policy that no longer exists, or to the path the policy now names, protects
      // nothing more. A move whose destination was an existing file names the folder's old
      // spelling and waits for its notification or the confirmation period instead.
      let redundant = roots[move.policyIdentifier].map {
        $0.namesSameLocation(as: move.scope) && !move.destinationIsExistingFile
      }
      if move.wasNotified || expired || redundant != false {
        result.settledMoves.insert(move.identifier)
      }
    }
    return result
  }

  /// The allowed renames, oldest first, that take the folder from `old` to `new`, or an empty
  /// list when they can't be traced, for example after a move the extension did not see.
  static func renameChain(
    from old: ProtectedPathScope, to new: ProtectedPathScope, moves: [PendingFolderMove]
  ) -> [PendingFolderMove] {
    var remaining = moves.sorted { $0.allowedAt < $1.allowedAt }
    var location = old
    var chain: [PendingFolderMove] = []
    while !location.namesSameLocation(as: new) {
      guard
        let index = remaining.firstIndex(where: { move in
          location.relocated(from: move.source, to: move.destination).map {
            move.scope.namesSameLocation(as: $0)
          } == true
        })
      else { return [] }
      let move = remaining.remove(at: index)
      location = move.scope
      chain.append(move)
    }
    return chain
  }

  /// `paths` after the renames: a retired path inside a renamed folder moves with it.
  static func relocating(_ paths: [RetiredFolderPath], along renames: [PendingFolderMove])
    -> [RetiredFolderPath]
  {
    paths.map { path in
      var scope = ProtectedPathScope(retired: path)
      for rename in renames {
        scope = scope.relocated(from: rename.source, to: rename.destination) ?? scope
      }
      return RetiredFolderPath(path: scope.root, caseSensitive: path.caseSensitive)
    }
  }

  /// `paths` with `previous` added as the newest retired path. A path that names the same
  /// location again moves to the end, paths that `folder` now contains are dropped because the
  /// folder protects them, and the oldest paths beyond the limit are dropped.
  static func retiring(
    _ previous: RetiredFolderPath, to paths: [RetiredFolderPath], folder: ProtectedPathScope
  ) -> [RetiredFolderPath] {
    let added = ProtectedPathScope(retired: previous)
    let kept = paths.filter { path in
      let scope = ProtectedPathScope(retired: path)
      return !scope.namesSameLocation(as: added) && !added.namesSameLocation(as: scope)
    }
    let result = (kept + [previous]).filter { !folder.contains($0.path) }
    return Array(result.suffix(PersistedPolicyScope.maximumRetiredFolderPathCount))
  }
}
