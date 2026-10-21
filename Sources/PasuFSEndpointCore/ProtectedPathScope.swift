import Darwin
import Foundation
import PasuFSConfiguration

public enum ProtectedPathScopeError: Error, Equatable, CustomStringConvertible {
  case pathMustBeAbsolute
  case pathDoesNotExist(String)
  case pathIsNotDirectory(String)
  case unsafeRoot(String)
  case volumePropertiesUnavailable
  case ownerHomeUnavailable

  public var description: String {
    switch self {
    case .pathMustBeAbsolute:
      "The protected root must be an absolute path."
    case .pathDoesNotExist(let path):
      "The protected root does not exist: \(path)"
    case .pathIsNotDirectory(let path):
      "The protected root is not a directory: \(path)"
    case .unsafeRoot(let path):
      "Choose a folder below the home or system directory: \(path)"
    case .volumePropertiesUnavailable:
      "The volume's path comparison rules could not be determined."
    case .ownerHomeUnavailable:
      "The directory owner's home location could not be determined."
    }
  }
}

public struct ProtectedPathScope: Equatable, Sendable {
  public let root: String
  private let comparisonRoot: String
  public let caseSensitive: Bool
  /// The user ID of the folder's owner when the policy was prepared, or nil for a scope that
  /// was not read from disk.
  public let ownerUserID: UInt32?
  /// That owner's home folder with symbolic links resolved, or nil like `ownerUserID`.
  public let ownerHome: String?

  public init(
    root: String,
    homeDirectory: String? = nil,
    fileManager: FileManager = .default
  ) throws {
    guard root.hasPrefix("/") else {
      throw ProtectedPathScopeError.pathMustBeAbsolute
    }

    // Foundation can rewrite /private/tmp to /tmp after resolving links. ES
    // reports the physical path, so keep realpath's spelling for comparison.
    guard let resolved = realpath(root, nil) else {
      throw ProtectedPathScopeError.pathDoesNotExist(root)
    }
    let standardizedRoot = String(cString: resolved)
    free(resolved)

    var isDirectory: ObjCBool = false
    guard fileManager.fileExists(atPath: standardizedRoot, isDirectory: &isDirectory) else {
      throw ProtectedPathScopeError.pathDoesNotExist(standardizedRoot)
    }
    guard isDirectory.boolValue else {
      throw ProtectedPathScopeError.pathIsNotDirectory(standardizedRoot)
    }

    let properties = try URL(fileURLWithPath: standardizedRoot)
      .resourceValues(forKeys: [.volumeSupportsCaseSensitiveNamesKey])
    guard let caseSensitive = properties.volumeSupportsCaseSensitiveNames else {
      throw ProtectedPathScopeError.volumePropertiesUnavailable
    }
    let (ownerUserID, ownerHome) = try Self.owner(of: standardizedRoot, fileManager: fileManager)
    let homes = [ownerHome, homeDirectory ?? NSHomeDirectory()].map {
      home -> String in
      guard let physical = realpath(home, nil) else { return home }
      defer { free(physical) }
      return String(cString: physical)
    }
    let unsafeRoots =
      [
        "/", "/Applications", "/Library", "/System", "/Users", "/bin", "/private",
        "/sbin", "/usr", "/Volumes",
      ] + homes
    let key = Self.comparisonKey(standardizedRoot, caseSensitive: caseSensitive)
    guard
      !unsafeRoots.contains(where: {
        Self.comparisonKey($0, caseSensitive: caseSensitive) == key
      })
    else { throw ProtectedPathScopeError.unsafeRoot(standardizedRoot) }
    self.init(
      canonicalRoot: standardizedRoot, caseSensitive: caseSensitive, ownerUserID: ownerUserID,
      ownerHome: homes[0])
  }

  init(
    canonicalRoot: String, caseSensitive: Bool, ownerUserID: UInt32? = nil,
    ownerHome: String? = nil
  ) {
    self.root = canonicalRoot
    self.caseSensitive = caseSensitive
    self.comparisonRoot = Self.comparisonKey(canonicalRoot, caseSensitive: caseSensitive)
    self.ownerUserID = ownerUserID
    self.ownerHome = ownerHome
  }

  /// A scope rebuilt from a stored scope record without reading the disk, for string comparison
  /// only. It keeps denying at the path a policy folder was accepted for while that folder
  /// cannot be found or both copies of the policy set are damaged, and it compares stored scopes
  /// with the found and pending locations of a folder the extension follows after a move.
  /// Unlike `init(root:)`, it carries no owner information.
  public init(recovering scope: PasuFSConfiguration.PersistedPolicyScope) {
    self.init(canonicalRoot: scope.canonicalRoot, caseSensitive: scope.caseSensitive)
  }

  /// The former path of a policy folder, kept from the root-owned scope record.
  public init(retired path: RetiredFolderPath) {
    self.init(canonicalRoot: path.path, caseSensitive: path.caseSensitive)
  }

  /// The event supplies the resolved path. This method only compares strings;
  /// filesystem and account lookups are confined to policy preparation above.
  public func contains(_ path: String) -> Bool {
    guard path.hasPrefix("/") else { return false }
    let comparisonPath = Self.comparisonKey(Self.lexicalPath(path), caseSensitive: caseSensitive)
    return comparisonPath == comparisonRoot || comparisonPath.hasPrefix(comparisonRoot + "/")
  }

  /// Whether the policy folder is `path` itself or lies below it, so that an operation on the
  /// object at `path` as a whole (a rename or removal of a parent folder) acts on the policy
  /// folder. Like `contains`, this only compares strings.
  public func rootIsInside(_ path: String) -> Bool {
    guard path.hasPrefix("/") else { return false }
    let comparisonPath = Self.comparisonKey(Self.lexicalPath(path), caseSensitive: caseSensitive)
    return comparisonPath == comparisonRoot
      || comparisonRoot.hasPrefix(comparisonPath == "/" ? "/" : comparisonPath + "/")
  }

  /// Whether `path` is a folder that contains the policy folder without being the folder
  /// itself or lying inside it.
  public func isEnclosed(by path: String) -> Bool {
    rootIsInside(path) && !contains(path)
  }

  /// The scope of this folder after `source`, the folder itself or a folder that contains it,
  /// is renamed to `destination`: the part of the root below `source` is kept and placed below
  /// `destination`. Returns nil when the rename does not move this folder. The new root is
  /// derived from the request's paths; the extension confirms it on disk afterwards.
  public func relocated(from source: String, to destination: String) -> ProtectedPathScope? {
    guard rootIsInside(source), destination.hasPrefix("/") else { return nil }
    let sourceDepth = Self.lexicalPath(source).split(separator: "/").count
    let remainder = root.split(separator: "/").dropFirst(sourceDepth)
    let base = Self.lexicalPath(destination)
    let newRoot =
      remainder.isEmpty
      ? base : (base == "/" ? "" : base) + "/" + remainder.joined(separator: "/")
    guard newRoot != "/" else { return nil }
    return ProtectedPathScope(canonicalRoot: newRoot, caseSensitive: caseSensitive)
  }

  /// Whether both scopes name the same location under this scope's comparison rule.
  func namesSameLocation(as other: ProtectedPathScope) -> Bool {
    comparisonRoot == Self.comparisonKey(other.root, caseSensitive: caseSensitive)
  }

  private static func lexicalPath(_ path: String) -> String {
    var components: [Substring] = []
    for component in path.split(separator: "/") {
      if component == "." { continue }
      if component == ".." {
        if !components.isEmpty { components.removeLast() }
      } else {
        components.append(component)
      }
    }
    return "/" + components.joined(separator: "/")
  }

  private static func comparisonKey(_ path: String, caseSensitive: Bool) -> String {
    caseSensitive
      ? path : path.folding(options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
  }

  private static func owner(of path: String, fileManager: FileManager) throws -> (
    UInt32, String
  ) {
    let attributes = try fileManager.attributesOfItem(atPath: path)
    guard let owner = attributes[.ownerAccountID] as? NSNumber else {
      throw ProtectedPathScopeError.ownerHomeUnavailable
    }
    var capacity = 1024
    while capacity <= 1024 * 1024 {
      var entry = passwd()
      var result: UnsafeMutablePointer<passwd>?
      var buffer = [CChar](repeating: 0, count: capacity)
      let status = getpwuid_r(owner.uint32Value, &entry, &buffer, buffer.count, &result)
      if status == ERANGE {
        capacity *= 2
        continue
      }
      guard status == 0, result != nil, let home = entry.pw_dir else {
        throw ProtectedPathScopeError.ownerHomeUnavailable
      }
      let value = withExtendedLifetime(buffer) { String(cString: home) }
      guard value.hasPrefix("/") else { throw ProtectedPathScopeError.ownerHomeUnavailable }
      return (owner.uint32Value, value)
    }
    throw ProtectedPathScopeError.ownerHomeUnavailable
  }
}
