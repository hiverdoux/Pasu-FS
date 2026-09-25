import Darwin
import Foundation

/// File URLs whose path names the real location on disk.
///
/// Foundation's standardized paths replace `/private/tmp` with `/tmp`, which is a symbolic
/// link. Code that opens every path component without following links, such as descriptor-
/// relative removal, then refuses a directory that another component created moments before.
/// Resolving the parent directories with `realpath(3)` keeps `/private` and every other real
/// directory name, so writers and removers agree on one path.
public enum PhysicalPath {
  /// Resolves every symbolic link in the parent directories of `url` and keeps the last path
  /// component as written, so a location that is itself a symbolic link is still seen as one
  /// by the checks that refuse it. Components that do not exist yet are appended unchanged. A
  /// relative path is taken from the current directory, and `.` and `..` components are
  /// removed before anything is resolved.
  public static func resolve(_ url: URL) -> URL {
    let components = lexicalComponents(of: url.path)
    guard let last = components.last else {
      return URL(fileURLWithPath: "/", isDirectory: true)
    }
    let parents = components.dropLast()
    var existingCount = parents.count
    while existingCount >= 0 {
      let prefix = "/" + parents.prefix(existingCount).joined(separator: "/")
      // Any failure, including a missing or inaccessible directory, shortens the prefix that
      // is resolved; the root directory itself always resolves.
      if let real = realpath(prefix, nil) {
        defer { free(real) }
        return appending(
          parents.dropFirst(existingCount) + [last], to: String(cString: real),
          isDirectory: url.hasDirectoryPath)
      }
      existingCount -= 1
    }
    return appending(components[...], to: "/", isDirectory: url.hasDirectoryPath)
  }

  private static func appending(
    _ components: ArraySlice<String>, to base: String, isDirectory: Bool
  ) -> URL {
    var result = URL(fileURLWithPath: base, isDirectory: components.isEmpty ? isDirectory : true)
    for (offset, component) in components.enumerated() {
      let isLast = offset == components.count - 1
      result.appendPathComponent(component, isDirectory: isLast ? isDirectory : true)
    }
    return result
  }

  private static func lexicalComponents(of path: String) -> [String] {
    let absolute =
      path.hasPrefix("/") ? path : FileManager.default.currentDirectoryPath + "/" + path
    var result: [String] = []
    for component in absolute.split(separator: "/", omittingEmptySubsequences: true) {
      switch component {
      case ".":
        continue
      case "..":
        if !result.isEmpty { result.removeLast() }
      default:
        result.append(String(component))
      }
    }
    return result
  }
}
