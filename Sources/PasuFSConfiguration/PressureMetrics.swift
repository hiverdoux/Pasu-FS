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
  /// Every record that could not enter the save queue, whatever its lane.
  public var admissionDrops: UInt64 = 0
  public var storageFailures: UInt64 = 0
  /// Records of denied requests that could not enter the save queue because the lane reserved
  /// for them was full. Each one is a request that no saved record counts.
  public var deniedLaneDrops: UInt64?
  /// Other records, of allowed requests and process events, that could not enter the shared lanes.
  public var sharedLaneDrops: UInt64?
  /// Repeated denied requests counted in an earlier record instead of being saved as new records.
  public var combinedDeniedRequests: UInt64?
  /// Allowed requests counted in an earlier record instead of being saved as new records.
  public var combinedAllowedRequests: UInt64?
  public init() {}
}

/// Requests that the extension could not check because macOS dropped their messages when the
/// client's queue was full. macOS denies a dropped authorization request in fail-closed mode
/// and allows it in the default kill mode. This count does not distinguish those outcomes.
///
/// Endpoint Security numbers every message it sends to the extension, and separately every
/// message of each event type. A gap in the overall numbering shows how many messages were
/// dropped but not which kinds they were. Gaps within one second of the first one form a stretch.
/// From each stretch's dropped messages the extension subtracts the process starts, forks and
/// exits that their own numbering shows missing during the stretch, and counts the rest as
/// unchecked requests. The count is an upper-bound estimate: the rest can also hold other
/// notifications, and process notifications whose loss shows only after the stretch, when the
/// next notification of that kind arrives.
public struct UncheckedRequestMetrics: Codable, Equatable, Sendable {
  /// The estimated unchecked requests of every finished stretch since the extension connected to
  /// Endpoint Security.
  public var estimatedCount: UInt64 = 0
  /// The time of the last gap in the latest stretch with unchecked requests.
  public var lastObservedAt: Date?
  /// The estimated unchecked requests of that stretch.
  public var lastEstimatedCount: UInt64?
  /// Messages missing from the overall numbering, of every kind, including the current stretch.
  public var missedMessages: UInt64 = 0
  /// Process starts, forks and exits missing from their own numbering. Each loss resets the
  /// execution history.
  public var missedProcessEvents: UInt64 = 0
  public init() {}
}

public struct AuthorizationMetrics: Codable, Equatable, Sendable {
  public var responses: UInt64 = 0
  public var failures: UInt64 = 0
  public var deadlineExceeded: UInt64 = 0
  public var minimumRemainingTicks: UInt64?
  public var evaluatedOpenCount: UInt64?
  public var totalEvaluationTicks: UInt64?
  public var maximumEvaluationTicks: UInt64?
  public init() {}
}
