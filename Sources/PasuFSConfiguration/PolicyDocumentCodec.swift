import CryptoKit
import Foundation

public enum PolicySetDocumentCodecError: Error, Equatable, CustomStringConvertible, Sendable {
  case documentTooLarge(Int)
  case topLevelObjectRequired
  case policiesArrayRequired
  case policyObjectRequired(Int)
  case rulesArrayRequired(Int)
  case ruleObjectRequired(policy: Int, rule: Int)
  case unknownTopLevelKeys([String])
  case unknownPolicyKeys(index: Int, keys: [String])
  case unknownRuleKeys(policy: Int, rule: Int, keys: [String])
  case compatibilityProfilesArrayRequired(Int)
  case compatibilityProfileObjectRequired(policy: Int, profile: Int)
  case unknownCompatibilityProfileKeys(policy: Int, profile: Int, keys: [String])

  public var description: String {
    switch self {
    case .documentTooLarge(let size):
      "Policy-set document exceeds the 1 MiB limit: \(size) bytes."
    case .topLevelObjectRequired:
      "Policy-set JSON must contain one top-level object."
    case .policiesArrayRequired:
      "Policy-set JSON must contain a policies array."
    case .policyObjectRequired(let index):
      "Policy at index \(index) must be an object."
    case .rulesArrayRequired(let index):
      "Policy at index \(index) must contain a rules array."
    case .ruleObjectRequired(let policy, let rule):
      "Rule \(rule) in policy \(policy) must be an object."
    case .unknownTopLevelKeys(let keys):
      "Unknown top-level policy-set keys: \(keys.joined(separator: ", "))."
    case .unknownPolicyKeys(let index, let keys):
      "Unknown keys in policy \(index): \(keys.joined(separator: ", "))."
    case .unknownRuleKeys(let policy, let rule, let keys):
      "Unknown keys in rule \(rule) of policy \(policy): \(keys.joined(separator: ", "))."
    case .compatibilityProfilesArrayRequired(let index):
      "The compatibility profiles of policy \(index) must be an array."
    case .compatibilityProfileObjectRequired(let policy, let profile):
      "Compatibility profile \(profile) in policy \(policy) must be an object."
    case .unknownCompatibilityProfileKeys(let policy, let profile, let keys):
      "Unknown keys in compatibility profile \(profile) of policy \(policy): \(keys.joined(separator: ", "))."
    }
  }
}

public enum PolicySetDocumentCodec {
  public static let maximumDocumentSize = 1_048_576

  private static let topLevelKeys: Set<String> = [
    "schemaVersion", "setIdentifier", "revision", "policies",
  ]
  private static let policyKeys: Set<String> = [
    "id", "name", "mode", "isBlacklistEnabled", "protectedRootPath", "allowRules", "denyRules",
    "systemCompatibilityProfiles",
  ]
  private static let compatibilityProfileKeys: Set<String> = [
    "profileIdentifier", "authorizationDigest",
  ]
  private static let ruleKeys: Set<String> = [
    "id", "kind", "teamIdentifier", "signingIdentifier", "isEnabled",
    "allowsDescendants",
  ]
  private static let legacyV1RequiredKeys: Set<String> = [
    "schemaVersion", "revision", "mode", "protectedRootPath", "rules",
  ]

  public static func decode(_ data: Data) throws -> PolicySetDocument {
    guard data.count <= maximumDocumentSize else {
      throw PolicySetDocumentCodecError.documentTooLarge(data.count)
    }
    try validateKeys(in: data)
    let document = try JSONDecoder().decode(PolicySetDocument.self, from: data)
    try document.validate()
    return document
  }

  /// The schema of a stored set, read before the set is decoded.
  public static func storedSchemaVersion(of data: Data) throws -> Int {
    struct Header: Decodable { var schemaVersion: Int }
    return try JSONDecoder().decode(Header.self, from: data).schemaVersion
  }

  /// Disk-only migration. Authenticated writes must use the current schema;
  /// an old client must not overwrite a list it cannot represent.
  ///
  /// Schema 4 sets are read as they are, descendant options and compatibility profiles
  /// included. Schemas 2 and 3 turn descendant options off. A newer schema is rejected, so a set
  /// written by a later version is never read with rules this version doesn't know.
  public static func migrateStoredDocument(_ data: Data) throws -> PolicySetDocument {
    guard data.count <= maximumDocumentSize else {
      throw PolicySetDocumentCodecError.documentTooLarge(data.count)
    }
    let version = try storedSchemaVersion(of: data)
    guard (2..<PolicySetDocument.currentSchemaVersion).contains(version) else {
      return try decode(data)
    }
    try validateKeys(in: data, legacy: version == 2)
    var document = try JSONSerialization.jsonObject(with: data) as! [String: Any]
    var policies = document["policies"] as! [[String: Any]]
    for index in policies.indices where version == 2 {
      // Decode the required legacy shape before translating it. Missing or
      // malformed mode/list fields never become an unrestricted policy.
      struct LegacyPolicy: Decodable {
        var id: UUID
        var name: String
        var mode: PolicyMode
        var type: PolicyType
        var protectedRootPath: String
        var rules: [PolicyRule]
      }
      let old = try JSONDecoder().decode(
        LegacyPolicy.self, from: JSONSerialization.data(withJSONObject: policies[index]))
      policies[index].removeValue(forKey: "type")
      let rules = policies[index].removeValue(forKey: "rules")!
      policies[index]["isBlacklistEnabled"] = old.type == .blacklist
      policies[index]["allowRules"] = old.type == .whitelist ? rules : []
      policies[index]["denyRules"] = old.type == .blacklist ? rules : []
    }
    document["schemaVersion"] = PolicySetDocument.currentSchemaVersion
    document["policies"] = policies
    var migrated = try decode(JSONSerialization.data(withJSONObject: document))
    guard version < PolicySetDocument.firstSchemaVersionWithDescendantAccess else {
      return migrated
    }
    // Earlier schemas could retain this bit without enforcing it. Never turn
    // that stale metadata into a new grant just by updating the extension.
    for index in migrated.policies.indices {
      for rule in migrated.policies[index].allowRules.indices {
        migrated.policies[index].allowRules[rule].allowsDescendants = false
      }
      for rule in migrated.policies[index].denyRules.indices {
        migrated.policies[index].denyRules[rule].allowsDescendants = false
      }
    }
    return migrated
  }

  public static func encode(
    _ document: PolicySetDocument,
    prettyPrinted: Bool = true
  ) throws -> Data {
    try document.validate()
    let encoder = JSONEncoder()
    encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
    let data = try encoder.encode(document)
    guard data.count <= maximumDocumentSize else {
      throw PolicySetDocumentCodecError.documentTooLarge(data.count)
    }
    return data
  }

  public static func digest(of data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  public static func digest(of document: PolicySetDocument) throws -> String {
    digest(of: try encode(document, prettyPrinted: false))
  }

  /// Identifies the exact top-level shape used by the retired single-policy
  /// schema. The extension uses this only to remove a confirmed v1 file; it
  /// never activates or migrates the contents.
  public static func isLegacyV1Document(_ data: Data) -> Bool {
    struct SchemaHeader: Decodable {
      let schemaVersion: Int
    }
    guard data.count <= maximumDocumentSize,
      let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
      let header = try? JSONDecoder().decode(SchemaHeader.self, from: data),
      header.schemaVersion == 1
    else {
      return false
    }
    return legacyV1RequiredKeys.isSubset(of: Set(object.keys))
  }

  private static func validateKeys(in data: Data, legacy: Bool = false) throws {
    let json = try JSONSerialization.jsonObject(with: data)
    guard let object = json as? [String: Any] else {
      throw PolicySetDocumentCodecError.topLevelObjectRequired
    }

    let unknownTopLevelKeys = Set(object.keys).subtracting(topLevelKeys).sorted()
    guard unknownTopLevelKeys.isEmpty else {
      throw PolicySetDocumentCodecError.unknownTopLevelKeys(unknownTopLevelKeys)
    }
    guard let policies = object["policies"] as? [Any] else {
      throw PolicySetDocumentCodecError.policiesArrayRequired
    }

    for (policyIndex, value) in policies.enumerated() {
      guard let policy = value as? [String: Any] else {
        throw PolicySetDocumentCodecError.policyObjectRequired(policyIndex)
      }
      let permitted =
        legacy
        ? Set(["id", "name", "mode", "type", "protectedRootPath", "rules"]) : policyKeys
      let unknownPolicyKeys = Set(policy.keys).subtracting(permitted).sorted()
      guard unknownPolicyKeys.isEmpty else {
        throw PolicySetDocumentCodecError.unknownPolicyKeys(
          index: policyIndex,
          keys: unknownPolicyKeys
        )
      }
      for listKey in legacy ? ["rules"] : ["allowRules", "denyRules"] {
        guard let rules = policy[listKey] as? [Any] else {
          throw PolicySetDocumentCodecError.rulesArrayRequired(policyIndex)
        }
        for (ruleIndex, ruleValue) in rules.enumerated() {
          guard let rule = ruleValue as? [String: Any] else {
            throw PolicySetDocumentCodecError.ruleObjectRequired(
              policy: policyIndex,
              rule: ruleIndex
            )
          }
          let unknownRuleKeys = Set(rule.keys).subtracting(ruleKeys).sorted()
          guard unknownRuleKeys.isEmpty else {
            throw PolicySetDocumentCodecError.unknownRuleKeys(
              policy: policyIndex,
              rule: ruleIndex,
              keys: unknownRuleKeys
            )
          }
        }
      }
      guard let profilesValue = policy["systemCompatibilityProfiles"] else { continue }
      guard let profiles = profilesValue as? [Any] else {
        throw PolicySetDocumentCodecError.compatibilityProfilesArrayRequired(policyIndex)
      }
      for (profileIndex, profileValue) in profiles.enumerated() {
        guard let profile = profileValue as? [String: Any] else {
          throw PolicySetDocumentCodecError.compatibilityProfileObjectRequired(
            policy: policyIndex, profile: profileIndex)
        }
        let unknownKeys = Set(profile.keys).subtracting(compatibilityProfileKeys).sorted()
        guard unknownKeys.isEmpty else {
          throw PolicySetDocumentCodecError.unknownCompatibilityProfileKeys(
            policy: policyIndex, profile: profileIndex, keys: unknownKeys)
        }
      }
    }
  }
}
