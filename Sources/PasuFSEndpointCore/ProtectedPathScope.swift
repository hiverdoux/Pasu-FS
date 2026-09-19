import Darwin
import Foundation

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
  private let caseSensitive: Bool

  public init(
    root: String,
    homeDirectory: String? = nil,
    fileManager: FileManager = .default
  ) throws {
    guard root.hasPrefix("/") else {
      throw ProtectedPathScopeError.pathMustBeAbsolute
    }

    let standardizedRoot = URL(fileURLWithPath: root).resolvingSymlinksInPath().path

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
    let ownerHome = try Self.ownerHome(of: standardizedRoot, fileManager: fileManager)
    let homes = [ownerHome, homeDirectory ?? NSHomeDirectory()].map {
      URL(fileURLWithPath: $0).resolvingSymlinksInPath().path
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
    self.init(canonicalRoot: standardizedRoot, caseSensitive: caseSensitive)
  }

  init(canonicalRoot: String, caseSensitive: Bool) {
    self.root = canonicalRoot
    self.caseSensitive = caseSensitive
    self.comparisonRoot = Self.comparisonKey(canonicalRoot, caseSensitive: caseSensitive)
  }

  /// The event supplies the resolved path. This method only compares strings;
  /// filesystem and account lookups are confined to policy preparation above.
  public func contains(_ path: String) -> Bool {
    guard path.hasPrefix("/") else { return false }
    let comparisonPath = Self.comparisonKey(Self.lexicalPath(path), caseSensitive: caseSensitive)
    return comparisonPath == comparisonRoot || comparisonPath.hasPrefix(comparisonRoot + "/")
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

  private static func ownerHome(of path: String, fileManager: FileManager) throws -> String {
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
      return value
    }
    throw ProtectedPathScopeError.ownerHomeUnavailable
  }
}
