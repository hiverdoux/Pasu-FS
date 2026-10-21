import Foundation
import PasuFSConfiguration

/// Finds the messages that Endpoint Security numbered for this client but dropped.
///
/// Each message carries an overall number that counts every message sent to the client (message
/// version 4 and later) and a number of its own event type (version 2 and later). macOS drops
/// messages when the client's queue is full, which leaves a gap in both.
///
/// Only a gap in the numbering of process starts, forks and exits means the execution history
/// missed a change, because only those notifications build it. Any other gap is counted as
/// unchecked requests. macOS decides a dropped authorization request according to its deadline
/// miss mode; this accounting does not imply that the request was allowed.
/// The overall number does not tell which kinds of messages a gap held, so the count is an
/// upper-bound estimate (see `UncheckedRequestMetrics`). Gaps within one second of the first form
/// one stretch, the same window that combines repeated log records, and each finished stretch is
/// logged once.
struct DeliveryGapAccounting: Sendable {
  /// Consecutive gaps logged as one record.
  struct Stretch: Equatable, Sendable {
    var firstGapAt: Date
    var lastGapAt: Date
    /// System uptime in nanoseconds when the first gap was found.
    var openedUptime: UInt64
    /// The overall number, or else the event type's number, of the message that showed the first
    /// gap.
    var firstSequence: UInt64
    var gapCount: UInt64 = 0
    var missedMessages: UInt64 = 0
    /// Process starts, forks and exits found missing while the stretch was open.
    var missedProcessEvents: UInt64 = 0

    /// The dropped messages that were not process notifications, at most.
    var estimatedUncheckedRequests: UInt64 {
      missedMessages > missedProcessEvents ? missedMessages - missedProcessEvents : 0
    }
  }

  /// What one message's numbers show.
  struct Observation: Equatable, Sendable {
    /// The message has no numbers, so a missed process change could not be noticed.
    var lacksNumbering = false
    /// The numbering of this kind of process notification skipped or restarted.
    var lostProcessEvents = false
    /// A stretch whose window ended before this message, to be logged.
    var finished: Stretch?
  }

  static let window = UInt64(PolicyAuditLogStore.groupingWindow * 1_000_000_000)

  private var lastGlobalSequence: UInt64?
  private var lastSequences: [UInt32: UInt64] = [:]
  private var open: Stretch?
  /// Totals since the client connected. Unchecked requests are added when a stretch finishes.
  private(set) var metrics = UncheckedRequestMetrics()

  /// Accounts for one delivered message. Call for every message, in delivery order. The first
  /// message, and the first one of each event type, sets the numbering and shows no gap.
  mutating func observe(
    eventType: UInt32, isProcessEvent: Bool, sequence: UInt64?, globalSequence: UInt64?,
    at time: Date, uptime: UInt64
  ) -> Observation {
    var result = Observation(finished: finish(uptime: uptime, force: false))
    guard let sequence else {
      result.lacksNumbering = true
      return result
    }
    var missedOfType: UInt64 = 0
    if let previous = lastSequences[eventType] {
      if sequence > previous {
        missedOfType = sequence - previous - 1
      } else if isProcessEvent {
        // A number that does not advance gives no count, but process changes may be missing.
        result.lostProcessEvents = true
      }
    }
    lastSequences[eventType] = sequence

    var missedMessages: UInt64 = 0
    if let globalSequence {
      if let previous = lastGlobalSequence, globalSequence > previous {
        missedMessages = globalSequence - previous - 1
      }
      lastGlobalSequence = globalSequence
    } else {
      // Before message version 4 only the numbering of each event type shows drops.
      missedMessages = missedOfType
    }

    if missedMessages > 0 {
      var stretch =
        open
        ?? Stretch(
          firstGapAt: time, lastGapAt: time, openedUptime: uptime,
          firstSequence: globalSequence ?? sequence)
      stretch.gapCount &+= 1
      stretch.missedMessages &+= missedMessages
      stretch.lastGapAt = max(stretch.lastGapAt, time)
      open = stretch
      metrics.missedMessages &+= missedMessages
    }
    if isProcessEvent, missedOfType > 0 {
      result.lostProcessEvents = true
      metrics.missedProcessEvents &+= missedOfType
      open?.missedProcessEvents &+= missedOfType
    }
    return result
  }

  /// Ends the open stretch when its window has passed, or now when `force` is set, and adds its
  /// unchecked requests to the totals. Returns the stretch to log.
  mutating func finish(uptime: UInt64, force: Bool) -> Stretch? {
    guard let stretch = open,
      force || uptime >= stretch.openedUptime &+ Self.window
    else { return nil }
    open = nil
    let estimate = stretch.estimatedUncheckedRequests
    if estimate > 0 {
      metrics.estimatedCount &+= estimate
      metrics.lastObservedAt = stretch.lastGapAt
      metrics.lastEstimatedCount = estimate
    }
    return stretch
  }
}
