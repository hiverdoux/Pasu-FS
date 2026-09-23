import Foundation

public struct ReclamationMetrics: Codable, Equatable, Sendable {
  public var passes: UInt64 = 0
  public var suppressed: UInt64 = 0
  public var reclaimedBytes: UInt64 = 0
  public var elapsedNanoseconds: UInt64 = 0
  public var supersededExecutions: UInt64 = 0
  public init() {}
}

public struct AuditDeliveryMetrics: Codable, Equatable, Sendable {
  public var minimalRecordsStored: UInt64 = 0
  public var admissionDrops: UInt64 = 0
  public var storageFailures: UInt64 = 0
  public init() {}
}

public struct AuthorizationMetrics: Codable, Equatable, Sendable {
  public var responses: UInt64 = 0
  public var failures: UInt64 = 0
  public var deadlineExceeded: UInt64 = 0
  public var minimumRemainingTicks: UInt64?
  public init() {}
}
