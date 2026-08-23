import Foundation

public enum ProtectedPathScopeError: Error, Equatable, CustomStringConvertible {
  case pathMustBeAbsolute
  case pathDoesNotExist(String)
  case pathIsNotDirectory(String)
  case unsafeRoot(String)

  public var description: String {
    switch self {
    case .pathMustBeAbsolute:
      "The protected root must be an absolute path."
    case .pathDoesNotExist(let path):
      "The protected root does not exist: \(path)"
    case .pathIsNotDirectory(let path):
      "The protected root is not a directory: \(path)"
    case .unsafeRoot(let path):
      "The protected root is too broad for the integration harness: \(path)"
    }
  }
}

public struct ProtectedPathScope: Equatable, Sendable {
  public let root: String
  private let comparisonRoot: String

  public init(
    root: String,
    homeDirectory: String = NSHomeDirectory(),
    fileManager: FileManager = .default
  ) throws {
    guard root.hasPrefix("/") else {
      throw ProtectedPathScopeError.pathMustBeAbsolute
    }

    let standardizedRoot = Self.standardize(root)
    let standardizedHome = Self.standardize(homeDirectory)
    let unsafeRoots: Set<String> = [
      "/", "/Applications", "/Library", "/System", "/Users", "/bin", "/private",
      "/sbin", "/usr", standardizedHome,
    ]

    guard !unsafeRoots.contains(standardizedRoot) else {
      throw ProtectedPathScopeError.unsafeRoot(standardizedRoot)
    }

    var isDirectory: ObjCBool = false
    guard fileManager.fileExists(atPath: standardizedRoot, isDirectory: &isDirectory) else {
      throw ProtectedPathScopeError.pathDoesNotExist(standardizedRoot)
    }
    guard isDirectory.boolValue else {
      throw ProtectedPathScopeError.pathIsNotDirectory(standardizedRoot)
    }

    self.root = standardizedRoot
    self.comparisonRoot = Self.comparisonKey(standardizedRoot)
  }

  public func contains(_ path: String) -> Bool {
    let comparisonPath = Self.comparisonKey(Self.standardize(path))
    return comparisonPath == comparisonRoot || comparisonPath.hasPrefix(comparisonRoot + "/")
  }

  private static func standardize(_ path: String) -> String {
    URL(fileURLWithPath: path).standardizedFileURL.path
  }

  private static func comparisonKey(_ path: String) -> String {
    path.folding(options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
  }
}
