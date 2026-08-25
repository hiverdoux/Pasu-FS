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
    }
  }
}

public enum PolicySetDocumentCodec {
  public static let maximumDocumentSize = 1_048_576

  private static let topLevelKeys: Set<String> = [
    "schemaVersion", "setIdentifier", "revision", "policies",
  ]
  private static let policyKeys: Set<String> = [
    "id", "name", "mode", "type", "protectedRootPath", "rules",
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

  private static func validateKeys(in data: Data) throws {
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
      let unknownPolicyKeys = Set(policy.keys).subtracting(policyKeys).sorted()
      guard unknownPolicyKeys.isEmpty else {
        throw PolicySetDocumentCodecError.unknownPolicyKeys(
          index: policyIndex,
          keys: unknownPolicyKeys
        )
      }
      guard let rules = policy["rules"] as? [Any] else {
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
  }
}
