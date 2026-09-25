import Foundation

public struct ExtensionStorageLocations: Equatable, Sendable {
  public static let legacyPolicyFilename = "policy.json"
  public static let policySetFilename = "policy-set.json"
  public static let systemCompatibilitySettingsFilename =
    "system-compatibility-settings.json"

  public let rootDirectory: URL
  public let legacyPolicyFile: URL
  public let policySetFile: URL
  public let systemCompatibilitySettingsFile: URL
  public let statusFile: URL
  public let auditDirectory: URL
  public let auditFile: URL

  public init(rootDirectory: URL) {
    let standardizedRoot = PhysicalPath.resolve(rootDirectory)
    self.rootDirectory = standardizedRoot
    self.legacyPolicyFile = standardizedRoot.appendingPathComponent(
      Self.legacyPolicyFilename, isDirectory: false)
    self.policySetFile = standardizedRoot.appendingPathComponent(
      Self.policySetFilename, isDirectory: false)
    self.systemCompatibilitySettingsFile = standardizedRoot.appendingPathComponent(
      Self.systemCompatibilitySettingsFilename, isDirectory: false)
    self.statusFile = standardizedRoot.appendingPathComponent("status.json", isDirectory: false)
    self.auditDirectory = standardizedRoot.appendingPathComponent("logs", isDirectory: true)
    self.auditFile = auditDirectory.appendingPathComponent(
      "endpoint-events.jsonl", isDirectory: false)
  }

  public static func localSystemDefault(fileManager: FileManager = .default) throws -> Self {
    guard
      let applicationSupport = fileManager.urls(
        for: .applicationSupportDirectory,
        in: .localDomainMask
      ).first
    else {
      throw ExtensionStorageLocationError.localApplicationSupportUnavailable
    }
    return Self(
      rootDirectory: applicationSupport.appendingPathComponent("PasuFS", isDirectory: true))
  }
}

public enum ExtensionStorageLocationError: Error, CustomStringConvertible, Sendable {
  case localApplicationSupportUnavailable

  public var description: String {
    "The local Application Support directory is unavailable."
  }
}
