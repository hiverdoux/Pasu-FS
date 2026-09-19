import CryptoKit
import Foundation

// Uses only the Swift toolchain and macOS tools already needed to build the product.
struct SigningConfiguration: Decodable {
  let hostProfile: String
  let extensionProfile: String
  let identitySHA1: String?
}

struct SigningError: Error, CustomStringConvertible {
  let description: String
  init(_ description: String) { self.description = description }
}

func require(_ condition: Bool, _ message: String) throws {
  if !condition { throw SigningError(message) }
}

func run(_ executable: String, _ arguments: [String]) throws -> Data {
  let process = Process()
  let output = Pipe()
  process.executableURL = URL(fileURLWithPath: executable)
  process.arguments = arguments
  process.standardOutput = output
  try process.run()
  let data = output.fileHandleForReading.readDataToEndOfFile()
  process.waitUntilExit()
  try require(
    process.terminationStatus == 0, "\(executable) failed (\(process.terminationStatus)).")
  return data
}

func plist(_ data: Data) throws -> [String: Any] {
  guard
    let value = try PropertyListSerialization.propertyList(from: data, format: nil)
      as? [String: Any]
  else { throw SigningError("Expected a property-list dictionary.") }
  return value
}

func writePlist(_ value: [String: Any], to url: URL) throws {
  try PropertyListSerialization.data(fromPropertyList: value, format: .xml, options: 0)
    .write(to: url, options: .atomic)
}

struct Profile {
  let bytes: Data
  let team: String
  let certificates: Set<String>
  let entitlements: [String: Any]

  init(path: URL, info: URL, requested: URL) throws {
    bytes = try Data(contentsOf: path)
    let profile = try plist(run("/usr/bin/security", ["cms", "-D", "-i", path.path]))
    guard let expiry = profile["ExpirationDate"] as? Date, expiry > Date() else {
      throw SigningError("The provisioning profile has expired or has no expiration date.")
    }
    guard let platforms = profile["Platform"] as? [String], platforms.contains("OSX"),
      let devices = profile["ProvisionedDevices"] as? [String], !devices.isEmpty,
      let teams = profile["TeamIdentifier"] as? [String], teams.count == 1,
      let allowed = profile["Entitlements"] as? [String: Any],
      let appID = allowed["com.apple.application-identifier"] as? String,
      let prefixes = profile["ApplicationIdentifierPrefix"] as? [String],
      let certificatesDER = profile["DeveloperCertificates"] as? [Data],
      let bundleID = try plist(Data(contentsOf: info))["CFBundleIdentifier"] as? String
    else { throw SigningError("Expected a device-bound macOS development profile.") }
    team = teams[0]
    try require(
      prefixes.contains { appID == "\($0).\(bundleID)" },
      "Profile App ID does not exactly match \(bundleID).")
    try require(
      allowed["com.apple.developer.team-identifier"] as? String == team,
      "Profile Team ID is inconsistent.")
    var claims = try plist(Data(contentsOf: requested))
    for (key, value) in claims {
      try require(
        allowed[key].map {
          NSDictionary(dictionary: [key: $0])
            .isEqual(to: [key: value])
        } == true,
        "Profile does not authorize the requested entitlement: \(key).")
    }
    claims["com.apple.application-identifier"] = appID
    claims["com.apple.developer.team-identifier"] = team
    entitlements = claims
    certificates = Set(
      certificatesDER.map {
        Insecure.SHA1.hash(data: $0).map { String(format: "%02X", $0) }.joined()
      })
  }
}

do {
  try require(
    CommandLine.arguments.count == 4,
    "Usage: swift prepare_development_signing.swift REPO CONFIG OUTPUT")
  let root = URL(fileURLWithPath: CommandLine.arguments[1], isDirectory: true)
  let configURL = URL(fileURLWithPath: CommandLine.arguments[2])
  let output = URL(fileURLWithPath: CommandLine.arguments[3], isDirectory: true)
  guard FileManager.default.fileExists(atPath: configURL.path) else {
    throw SigningError(
      "Missing signing configuration. Copy Product/development-signing.example.json "
        + "to .local/development-signing.json and set your profile paths. "
    )
  }
  let config = try JSONDecoder().decode(
    SigningConfiguration.self, from: Data(contentsOf: configURL))
  func profilePath(_ path: String) -> URL {
    URL(fileURLWithPath: path, relativeTo: root).standardizedFileURL
  }
  let host = try Profile(
    path: profilePath(config.hostProfile),
    info: root.appendingPathComponent("Product/PasuFSHost-Info.plist"),
    requested: root.appendingPathComponent("Product/PasuFSHost.entitlements"))
  let ext = try Profile(
    path: profilePath(config.extensionProfile),
    info: root.appendingPathComponent("Product/PasuFSSystemExtension-Info.plist"),
    requested: root.appendingPathComponent("Product/PasuFSSystemExtension.entitlements"))
  try require(host.team == ext.team, "Host and extension profiles use different teams.")
  let identities = String(
    decoding: try run(
      "/usr/bin/security",
      ["find-identity", "-v", "-p", "codesigning"]), as: UTF8.self)
  let available = Set(
    identities.split(separator: "\n").compactMap { line -> String? in
      let fields = line.split(separator: " ", omittingEmptySubsequences: true)
      guard fields.count >= 3, fields[1].count == 40,
        line.contains("\"Apple Development:")
      else { return nil }
      return String(fields[1]).uppercased()
    })
  var candidates = host.certificates.intersection(ext.certificates).intersection(available)
  if let requested = config.identitySHA1 {
    candidates = candidates.intersection([requested.uppercased()])
  }
  try require(
    candidates.count == 1,
    "Expected one matching Apple Development identity with a private key; found \(candidates.count). "
      + "For multiple matches, set identitySHA1 in your local configuration.")
  let identity = candidates.first!
  try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
  try host.bytes.write(to: output.appendingPathComponent("host.provisionprofile"), options: .atomic)
  try ext.bytes.write(
    to: output.appendingPathComponent("extension.provisionprofile"), options: .atomic)
  try writePlist(host.entitlements, to: output.appendingPathComponent("host.entitlements"))
  try writePlist(ext.entitlements, to: output.appendingPathComponent("extension.entitlements"))
  try identity.write(
    to: output.appendingPathComponent("identity"), atomically: true, encoding: .utf8)
  print("Development profiles and matching signing identity validated.")
} catch {
  FileHandle.standardError.write(Data("Signing preparation failed: \(error)\n".utf8))
  exit(1)
}
