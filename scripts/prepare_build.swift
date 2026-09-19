import Darwin
import Foundation

struct BuildConfiguration: Decodable {
  let appBundleIdentifier: String
  let hostProfile: String
  let extensionProfile: String
  let identitySHA1: String?
}

struct BuildSequence: Codable {
  let lastIssuedBuildNumber: Int
  let lastIssuedAt: String
}

struct BuildError: Error, CustomStringConvertible {
  let description: String
  init(_ message: String) { description = message }
}

func require(_ condition: Bool, _ message: String) throws {
  if !condition { throw BuildError(message) }
}

func readPlist(_ url: URL) throws -> [String: Any] {
  guard
    let value = try PropertyListSerialization.propertyList(
      from: Data(contentsOf: url), format: nil) as? [String: Any]
  else { throw BuildError("Invalid product property list.") }
  return value
}

do {
  let arguments = CommandLine.arguments
  try require(
    arguments.count == 4 || arguments.count == 5,
    "Usage: swift prepare_build.swift REPO CONFIG STAGE [BUILD_NUMBER]")
  let files = FileManager.default
  let root = URL(fileURLWithPath: arguments[1], isDirectory: true).standardizedFileURL
  let configURL = URL(fileURLWithPath: arguments[2], relativeTo: root).standardizedFileURL
  let stage = URL(fileURLWithPath: arguments[3], isDirectory: true).standardizedFileURL
  try require(
    files.fileExists(atPath: configURL.path),
    "Missing signing configuration. Copy Product/development-signing.example.json to .local/development-signing.json and configure your identifiers and profiles."
  )
  let config = try JSONDecoder().decode(BuildConfiguration.self, from: Data(contentsOf: configURL))
  let identifier = config.appBundleIdentifier
  try require(
    identifier.range(
      of: #"^[A-Za-z0-9][A-Za-z0-9-]*(\.[A-Za-z0-9][A-Za-z0-9-]*){2,}$"#,
      options: .regularExpression) != nil && identifier.count <= 180,
    "appBundleIdentifier must be a reverse-domain identifier, for example com.example.pasu.fs.")
  func profileURL(_ path: String) -> URL {
    URL(fileURLWithPath: path, relativeTo: root).standardizedFileURL
  }
  for path in [config.hostProfile, config.extensionProfile] {
    try require(
      files.isReadableFile(atPath: profileURL(path).path),
      "A configured provisioning profile is missing or unreadable.")
  }

  let source = stage.appendingPathComponent("source", isDirectory: true)
  try files.createDirectory(at: source, withIntermediateDirectories: true)
  for name in ["Package.swift", "Sources", "Tests", "Product"] {
    try files.copyItem(
      at: root.appendingPathComponent(name), to: source.appendingPathComponent(name))
  }
  guard
    let entries = files.enumerator(
      at: source, includingPropertiesForKeys: [.isRegularFileKey, .isSymbolicLinkKey])
  else { throw BuildError("Cannot enumerate build inputs.") }
  for case let file as URL in entries {
    let properties = try file.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey])
    try require(properties.isSymbolicLink != true, "Build inputs must not contain symbolic links.")
    guard properties.isRegularFile == true else { continue }
    if file.lastPathComponent == ".DS_Store" {
      try files.removeItem(at: file)
      continue
    }
    guard let text = try? String(contentsOf: file, encoding: .utf8) else { continue }
    let configured = text.replacingOccurrences(of: "com.example.pasu.fs", with: identifier)
    if configured != text { try configured.write(to: file, atomically: true, encoding: .utf8) }
  }

  // Reserve a number before compilation. Failed attempts do not reuse issued numbers.
  let local = root.appendingPathComponent(".local", isDirectory: true)
  try files.createDirectory(at: local, withIntermediateDirectories: true)
  let lock = open(
    local.appendingPathComponent("build-sequence.lock").path, O_CREAT | O_RDWR | O_NOFOLLOW, 0o600)
  try require(lock >= 0, "Cannot open the build-number lock.")
  defer { close(lock) }
  try require(flock(lock, LOCK_EX) == 0, "Cannot lock the build-number record.")
  defer { flock(lock, LOCK_UN) }
  let record = local.appendingPathComponent("build-sequence.json")
  let previous: Int
  if files.fileExists(atPath: record.path) {
    previous = try JSONDecoder().decode(BuildSequence.self, from: Data(contentsOf: record))
      .lastIssuedBuildNumber
  } else {
    previous = 0
  }
  let hostInfo = source.appendingPathComponent("Product/PasuFSHost-Info.plist")
  let extensionInfo = source.appendingPathComponent("Product/PasuFSSystemExtension-Info.plist")
  let template = try readPlist(hostInfo)
  let extensionTemplate = try readPlist(extensionInfo)
  try require(
    template["CFBundleShortVersionString"] as? String == extensionTemplate[
      "CFBundleShortVersionString"] as? String,
    "App and extension display versions must match.")
  guard let minimumText = template["CFBundleVersion"] as? String, let minimum = Int(minimumText),
    minimum > 0
  else { throw BuildError("The product template must contain a positive numeric build version.") }
  try require(previous >= 0 && previous < Int.max, "Invalid previous build number.")
  let number: Int
  if arguments.count == 5 {
    guard let requested = Int(arguments[4]), requested >= minimum, requested > previous
    else {
      throw BuildError(
        "The requested build number must exceed every previously issued number and meet the product template minimum."
      )
    }
    number = requested
  } else {
    number = max(minimum, previous + 1)
  }
  let date = ISO8601DateFormatter()
  date.timeZone = .current
  let issued = BuildSequence(lastIssuedBuildNumber: number, lastIssuedAt: date.string(from: Date()))
  let encoder = JSONEncoder()
  encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
  try encoder.encode(issued).write(to: record, options: .atomic)
  for file in [hostInfo, extensionInfo] {
    var info = try readPlist(file)
    info["CFBundleVersion"] = String(number)
    try PropertyListSerialization.data(fromPropertyList: info, format: .xml, options: 0).write(
      to: file)
  }
  var signing: [String: String] = [
    "hostProfile": profileURL(config.hostProfile).path,
    "extensionProfile": profileURL(config.extensionProfile).path,
  ]
  signing["identitySHA1"] = config.identitySHA1
  try JSONSerialization.data(withJSONObject: signing, options: [.prettyPrinted, .sortedKeys])
    .write(to: stage.appendingPathComponent("signing.json"))
  try identifier.write(
    to: stage.appendingPathComponent("app-identifier"), atomically: true, encoding: .utf8)
  print("Reserved build \(number). Product identifiers configured for this build.")
} catch {
  FileHandle.standardError.write(Data("Build preparation failed: \(error)\n".utf8))
  exit(1)
}
