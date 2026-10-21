import Foundation

/// Machine-readable backend contract. It does not prescribe a presentation.
public struct ExecutionOriginCapabilities: Codable, Equatable, Sendable {
  /// Version 3 decides compatibility profiles, metadata changes and mounts, and follows moved
  /// policy folders.
  public static let currentVersion = 3

  public var version: Int = Self.currentVersion
  public var policySchemaVersion: Int = PolicySetDocument.currentSchemaVersion
  public var authorizationEvents: [String] = AuthorizationEventCatalog.supportedEventNames
  public var blocksProgramLaunch: Bool = false
  public var usesCommonAllowListForOriginAndActor: Bool = true
  public var preservesInactiveAllowList: Bool = true
  public var supportsDescendantAccessGrants: Bool = true
  public var supportsSystemCompatibilityBypass: Bool = true
  public var requiresObservedHistory: Bool = true
  public var maximumPolicyCount: Int = PolicySetDocument.maximumPolicyCount
  public var maximumCombinedRuleCount: Int = PolicySetDocument.maximumRuleCount
  public var intermediaryCatalogVersion: Int = 1

  public init() {}
}
