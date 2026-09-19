import Foundation

public struct PolicyAuditLogKey: Codable, Hashable, Sendable {
  public let setIdentifier: UUID
  public let policyIdentifier: UUID

  public init(setIdentifier: UUID, policyIdentifier: UUID) {
    self.setIdentifier = setIdentifier
    self.policyIdentifier = policyIdentifier
  }

  public var filename: String {
    "policy-\(setIdentifier.uuidString)_\(policyIdentifier.uuidString).jsonl"
  }

  public init?(filename: String) {
    let current = filename.hasSuffix(".1") ? String(filename.dropLast(2)) : filename
    guard current.hasPrefix("policy-"), current.hasSuffix(".jsonl") else { return nil }
    let identifiers = current.dropFirst(7).dropLast(6).split(separator: "_")
    guard identifiers.count == 2,
      let set = UUID(uuidString: String(identifiers[0])),
      let policy = UUID(uuidString: String(identifiers[1]))
    else { return nil }
    self.init(setIdentifier: set, policyIdentifier: policy)
    guard current == self.filename else { return nil }
  }
}

public struct PolicyAuditLogRequest: Codable, Equatable, Sendable {
  public let key: PolicyAuditLogKey
  public let maximumLineCount: Int

  public init(key: PolicyAuditLogKey, maximumLineCount: Int = 500) {
    self.key = key
    self.maximumLineCount = maximumLineCount
  }
}
