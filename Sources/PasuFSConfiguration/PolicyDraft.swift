import Foundation

public struct DirectoryPolicyDraft: Equatable, Identifiable, Sendable {
  public var id: UUID
  public var name: String
  public var mode: PolicyMode
  public var policyType: PolicyType
  public var protectedRootPath: String
  public var rules: [PolicyRule]

  public init(
    id: UUID = UUID(),
    name: String,
    mode: PolicyMode = .protection,
    policyType: PolicyType = .whitelist,
    protectedRootPath: String = "",
    rules: [PolicyRule] = []
  ) {
    self.id = id
    self.name = name
    self.mode = mode
    self.policyType = policyType
    self.protectedRootPath = protectedRootPath
    self.rules = rules
  }

  public init(policy: DirectoryPolicy) {
    self.init(
      id: policy.id,
      name: policy.name,
      mode: policy.mode,
      policyType: policy.policyType,
      protectedRootPath: policy.protectedRootPath,
      rules: policy.rules
    )
  }

  public func makePolicy() -> DirectoryPolicy {
    DirectoryPolicy(
      id: id,
      name: name,
      mode: mode,
      policyType: policyType,
      protectedRootPath: protectedRootPath,
      rules: rules
    )
  }

  public mutating func addRule(kind: PolicyRuleKind = .teamSigned) {
    rules.append(
      PolicyRule(
        id: "rule.\(UUID().uuidString.lowercased())",
        kind: kind,
        teamIdentifier: kind == .teamSigned ? "" : nil,
        signingIdentifier: "",
        isEnabled: true,
        allowsDescendants: false
      )
    )
  }
}

public struct PolicySetDraft: Equatable, Sendable {
  public var setIdentifier: UUID
  public var policies: [DirectoryPolicyDraft]

  public init(
    setIdentifier: UUID = UUID(),
    policies: [DirectoryPolicyDraft] = []
  ) {
    self.setIdentifier = setIdentifier
    self.policies = policies
  }

  public init(document: PolicySetDocument) {
    self.init(
      setIdentifier: document.setIdentifier,
      policies: document.policies.map(DirectoryPolicyDraft.init)
    )
  }

  public func makeDocument(revision: UInt64) throws -> PolicySetDocument {
    let document = PolicySetDocument(
      setIdentifier: setIdentifier,
      revision: revision,
      policies: policies.map { $0.makePolicy() }
    )
    try document.validate()
    return document
  }
}
