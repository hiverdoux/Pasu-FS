import Foundation
import PasuFSPolicy

public enum PolicyMode: String, Codable, CaseIterable, Sendable {
  case protection
  case audit
}

public enum PolicyType: String, Codable, CaseIterable, Sendable {
  case whitelist
  case blacklist
}

public enum PolicyRuleKind: String, Codable, CaseIterable, Sendable {
  case teamSigned
  case platformBinary
}

public struct PolicyRule: Codable, Equatable, Hashable, Identifiable, Sendable {
  public var id: String
  public var kind: PolicyRuleKind
  public var teamIdentifier: String?
  public var signingIdentifier: String
  public var isEnabled: Bool
  public var allowsDescendants: Bool

  public init(
    id: String,
    kind: PolicyRuleKind,
    teamIdentifier: String? = nil,
    signingIdentifier: String,
    isEnabled: Bool = true,
    allowsDescendants: Bool
  ) {
    self.id = id
    self.kind = kind
    self.teamIdentifier = teamIdentifier
    self.signingIdentifier = signingIdentifier
    self.isEnabled = isEnabled
    self.allowsDescendants = allowsDescendants
  }

  public static func teamSigned(
    id: String,
    teamIdentifier: String,
    signingIdentifier: String,
    isEnabled: Bool = true,
    allowsDescendants: Bool
  ) -> Self {
    Self(
      id: id,
      kind: .teamSigned,
      teamIdentifier: teamIdentifier,
      signingIdentifier: signingIdentifier,
      isEnabled: isEnabled,
      allowsDescendants: allowsDescendants
    )
  }

  public static func platformBinary(
    id: String,
    signingIdentifier: String,
    isEnabled: Bool = true,
    allowsDescendants: Bool
  ) -> Self {
    Self(
      id: id,
      kind: .platformBinary,
      signingIdentifier: signingIdentifier,
      isEnabled: isEnabled,
      allowsDescendants: allowsDescendants
    )
  }

  public func matcherRule() throws -> AllowRule {
    switch kind {
    case .teamSigned:
      guard let teamIdentifier else {
        throw PolicyValidationError.teamIdentifierRequired(id)
      }
      return AllowRule(
        id: id,
        identity: .teamSigned(
          SignedProgramIdentity(
            teamIdentifier: teamIdentifier.uppercased(),
            signingIdentifier: signingIdentifier
          )
        ),
        allowsDescendants: allowsDescendants
      )
    case .platformBinary:
      return AllowRule(
        id: id,
        identity: .platformBinary(signingIdentifier: signingIdentifier),
        allowsDescendants: allowsDescendants
      )
    }
  }

  fileprivate var identityKey: String {
    switch kind {
    case .teamSigned:
      "team:\((teamIdentifier ?? "").uppercased()):\(signingIdentifier)"
    case .platformBinary:
      "platform:\(signingIdentifier)"
    }
  }
}

public struct DirectoryPolicy: Codable, Equatable, Identifiable, Sendable {
  public var id: UUID
  public var name: String
  public var mode: PolicyMode
  public var policyType: PolicyType
  public var protectedRootPath: String
  public var rules: [PolicyRule]

  public init(
    id: UUID = UUID(),
    name: String,
    mode: PolicyMode,
    policyType: PolicyType,
    protectedRootPath: String,
    rules: [PolicyRule]
  ) {
    self.id = id
    self.name = name
    self.mode = mode
    self.policyType = policyType
    self.protectedRootPath = protectedRootPath
    self.rules = rules
  }

  public var activeRuleCount: Int {
    rules.lazy.filter(\.isEnabled).count
  }

  public func policySnapshot() throws -> PolicySnapshot {
    PolicySnapshot(rules: try rules.filter(\.isEnabled).map { try $0.matcherRule() })
  }

  private enum CodingKeys: String, CodingKey {
    case id
    case name
    case mode
    case policyType = "type"
    case protectedRootPath
    case rules
  }
}

public struct PolicySetDocument: Codable, Equatable, Sendable {
  public static let currentSchemaVersion = 2
  public static let maximumPolicyCount = 64
  public static let maximumRuleCount = 1_024
  public static let maximumPolicyNameLength = 80

  public var schemaVersion: Int
  public var setIdentifier: UUID
  public var revision: UInt64
  public var policies: [DirectoryPolicy]

  public init(
    schemaVersion: Int = Self.currentSchemaVersion,
    setIdentifier: UUID,
    revision: UInt64,
    policies: [DirectoryPolicy]
  ) {
    self.schemaVersion = schemaVersion
    self.setIdentifier = setIdentifier
    self.revision = revision
    self.policies = policies
  }

  public func validate() throws {
    guard schemaVersion == Self.currentSchemaVersion else {
      throw PolicyValidationError.unsupportedSchemaVersion(schemaVersion)
    }
    guard revision > 0 else {
      throw PolicyValidationError.invalidRevision
    }
    guard policies.count <= Self.maximumPolicyCount else {
      throw PolicyValidationError.tooManyPolicies(policies.count)
    }

    let totalRuleCount = policies.reduce(into: 0) { $0 += $1.rules.count }
    guard totalRuleCount <= Self.maximumRuleCount else {
      throw PolicyValidationError.tooManyRules(totalRuleCount)
    }

    var policyIDs = Set<UUID>()
    var policyNames = Set<String>()
    var modeAndDirectories = Set<String>()

    for policy in policies {
      guard policyIDs.insert(policy.id).inserted else {
        throw PolicyValidationError.duplicatePolicyID(policy.id)
      }

      let trimmedName = policy.name.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !trimmedName.isEmpty, trimmedName == policy.name,
        trimmedName.count <= Self.maximumPolicyNameLength,
        trimmedName.unicodeScalars.allSatisfy({
          !CharacterSet.controlCharacters.contains($0)
        })
      else {
        throw PolicyValidationError.invalidPolicyName(policy.name)
      }
      let nameKey = trimmedName.folding(
        options: [.caseInsensitive, .diacriticInsensitive],
        locale: Locale(identifier: "en_US_POSIX")
      )
      guard policyNames.insert(nameKey).inserted else {
        throw PolicyValidationError.duplicatePolicyName(policy.name)
      }

      guard policy.protectedRootPath.hasPrefix("/"),
        !policy.protectedRootPath.contains("\0")
      else {
        throw PolicyValidationError.protectedRootMustBeAbsolute(policy.name)
      }
      let modeAndDirectory =
        "\(policy.mode.rawValue):\(Self.canonicalPathComparisonKey(policy.protectedRootPath))"
      guard modeAndDirectories.insert(modeAndDirectory).inserted else {
        throw PolicyValidationError.duplicateModeAndDirectory(
          mode: policy.mode,
          path: policy.protectedRootPath
        )
      }

      if policy.mode == .protection, policy.policyType == .whitelist,
        policy.activeRuleCount == 0
      {
        throw PolicyValidationError.protectionWhitelistRequiresEnabledRule(policy.name)
      }

      try Self.validateRules(in: policy)
    }
  }

  public static func canonicalPathComparisonKey(_ path: String) -> String {
    URL(fileURLWithPath: path)
      .standardizedFileURL
      .resolvingSymlinksInPath()
      .path
      .folding(options: [.caseInsensitive], locale: Locale(identifier: "en_US_POSIX"))
  }

  private static func validateRules(in policy: DirectoryPolicy) throws {
    var ruleIDs = Set<String>()
    var identities = Set<String>()

    for rule in policy.rules {
      try validateIdentifier(rule.id, field: "rule id")
      try validateIdentifier(rule.signingIdentifier, field: "signing identifier")

      switch rule.kind {
      case .teamSigned:
        guard let teamIdentifier = rule.teamIdentifier else {
          throw PolicyValidationError.teamIdentifierRequired(rule.id)
        }
        try validateIdentifier(teamIdentifier, field: "team identifier")
      case .platformBinary:
        guard rule.teamIdentifier == nil else {
          throw PolicyValidationError.teamIdentifierForbidden(rule.id)
        }
      }

      guard ruleIDs.insert(rule.id).inserted else {
        throw PolicyValidationError.duplicateRuleID(
          policy: policy.name,
          ruleID: rule.id
        )
      }
      guard identities.insert(rule.identityKey).inserted else {
        throw PolicyValidationError.duplicateIdentity(
          policy: policy.name,
          identity: rule.identityKey
        )
      }
    }
  }

  private static func validateIdentifier(_ value: String, field: String) throws {
    guard !value.isEmpty, value.count <= 512,
      value == value.trimmingCharacters(in: .whitespacesAndNewlines),
      value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) })
    else {
      throw PolicyValidationError.invalidIdentifier(field)
    }
  }
}

public enum PolicyValidationError: Error, Equatable, CustomStringConvertible, Sendable {
  case unsupportedSchemaVersion(Int)
  case invalidRevision
  case tooManyPolicies(Int)
  case tooManyRules(Int)
  case duplicatePolicyID(UUID)
  case invalidPolicyName(String)
  case duplicatePolicyName(String)
  case protectedRootMustBeAbsolute(String)
  case duplicateModeAndDirectory(mode: PolicyMode, path: String)
  case protectionWhitelistRequiresEnabledRule(String)
  case invalidIdentifier(String)
  case teamIdentifierRequired(String)
  case teamIdentifierForbidden(String)
  case duplicateRuleID(policy: String, ruleID: String)
  case duplicateIdentity(policy: String, identity: String)

  public var description: String {
    switch self {
    case .unsupportedSchemaVersion(let version):
      "Unsupported policy-set schema version: \(version)."
    case .invalidRevision:
      "Policy-set revision must be greater than zero."
    case .tooManyPolicies(let count):
      "Policy set contains too many policies: \(count)."
    case .tooManyRules(let count):
      "Policy set contains too many rules: \(count)."
    case .duplicatePolicyID(let id):
      "Duplicate policy ID: \(id.uuidString)."
    case .invalidPolicyName(let name):
      "Policy name is empty, too long, padded, or contains a control character: \(name)."
    case .duplicatePolicyName(let name):
      "Duplicate policy name: \(name)."
    case .protectedRootMustBeAbsolute(let name):
      "The protected root for \(name) must be an absolute path."
    case .duplicateModeAndDirectory(let mode, let path):
      "Another \(mode.rawValue) policy already uses this directory: \(path)."
    case .protectionWhitelistRequiresEnabledRule(let name):
      "Protection whitelist \(name) requires at least one enabled rule."
    case .invalidIdentifier(let field):
      "The \(field) is empty, too long, padded, or contains a control character."
    case .teamIdentifierRequired(let id):
      "Team-signed rule \(id) requires a Team ID."
    case .teamIdentifierForbidden(let id):
      "Platform-binary rule \(id) must not contain a Team ID."
    case .duplicateRuleID(let policy, let ruleID):
      "Policy \(policy) contains duplicate rule ID: \(ruleID)."
    case .duplicateIdentity(let policy, let identity):
      "Policy \(policy) contains duplicate program identity: \(identity)."
    }
  }
}

public enum PolicyUpdateDisposition: Equatable, Sendable {
  case accepted
  case unchanged
}

public enum PolicyUpdateError: Error, Equatable, CustomStringConvertible, Sendable {
  case setIdentifierMismatch(candidate: UUID, active: UUID)
  case revisionDowngrade(candidate: UInt64, active: UInt64)
  case revisionCollision(UInt64)

  public var description: String {
    switch self {
    case .setIdentifierMismatch(let candidate, let active):
      "Policy-set identifier \(candidate.uuidString) does not match active set \(active.uuidString)."
    case .revisionDowngrade(let candidate, let active):
      "Policy-set revision \(candidate) is older than active revision \(active)."
    case .revisionCollision(let revision):
      "Policy-set revision \(revision) has different contents from the active policy set."
    }
  }
}

public enum PolicyUpdateValidator {
  public static func validate(
    candidate: PolicySetDocument,
    against active: PolicySetDocument?
  ) throws -> PolicyUpdateDisposition {
    try candidate.validate()
    guard let active else { return .accepted }
    guard candidate.setIdentifier == active.setIdentifier else {
      throw PolicyUpdateError.setIdentifierMismatch(
        candidate: candidate.setIdentifier,
        active: active.setIdentifier
      )
    }
    if candidate.revision < active.revision {
      throw PolicyUpdateError.revisionDowngrade(
        candidate: candidate.revision,
        active: active.revision
      )
    }
    if candidate.revision == active.revision {
      guard candidate == active else {
        throw PolicyUpdateError.revisionCollision(candidate.revision)
      }
      return .unchanged
    }
    return .accepted
  }
}
