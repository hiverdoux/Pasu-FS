import Foundation

enum ProtectedFolderIssue: Equatable, UserFacingErrorConvertible {
  case notChosen
  case notAbsolute
  case missing
  case notDirectory
  case tooBroad(String)

  var userFacingMessage: String {
    switch self {
    case .notChosen:
      String(localized: "Choose a folder to protect.")
    case .notAbsolute:
      String(localized: "Choose a folder with a full path.")
    case .missing:
      String(localized: "The folder doesn’t exist.")
    case .notDirectory:
      String(localized: "Choose a folder, not a file.")
    case .tooBroad:
      String(
        localized:
          "This folder is too broad. Choose a narrower folder, such as one inside your home folder."
      )
    }
  }
}

/// An early check that mirrors the extension's folder rules. The extension remains the final authority.
enum ProtectedFolderCheck {
  static let tooBroadRoots = [
    "/", "/Applications", "/Library", "/System", "/Users", "/bin", "/private", "/sbin", "/usr",
    "/Volumes",
  ]

  static func issue(
    for path: String,
    homeDirectory: String = NSHomeDirectory(),
    fileManager: FileManager = .default
  ) -> ProtectedFolderIssue? {
    guard !path.isEmpty else { return .notChosen }
    guard path.hasPrefix("/") else { return .notAbsolute }
    let resolved = URL(fileURLWithPath: path).standardizedFileURL.resolvingSymlinksInPath().path
    var isDirectory: ObjCBool = false
    guard fileManager.fileExists(atPath: resolved, isDirectory: &isDirectory) else {
      return .missing
    }
    guard isDirectory.boolValue else { return .notDirectory }
    let home = URL(fileURLWithPath: homeDirectory).resolvingSymlinksInPath().path
    let candidate = resolved.lowercased()
    if (tooBroadRoots + [home]).contains(where: { $0.lowercased() == candidate }) {
      return .tooBroad(resolved)
    }
    return nil
  }

  static func canonicalPath(for url: URL) -> String {
    url.standardizedFileURL.resolvingSymlinksInPath().path
  }

  /// The folder path for text typed into the folder field. A leading `~` means the home folder.
  /// A full path is canonicalized like a chosen folder; other text is kept, trimmed, so that
  /// `issue(for:)` can explain what is wrong with it.
  static func path(fromTypedText text: String, homeDirectory: String = NSHomeDirectory()) -> String
  {
    var path = text.trimmingCharacters(in: .whitespacesAndNewlines)
    if path == "~" || path.hasPrefix("~/") {
      path = homeDirectory + path.dropFirst()
    }
    guard path.hasPrefix("/") else { return path }
    return canonicalPath(for: URL(fileURLWithPath: path))
  }
}
