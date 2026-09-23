import Foundation
import os

/// Accounts for retained payload estimates, not resident memory. Dedicated lanes
/// cannot be borrowed by ordinary work. A reservation survives queue handoff.
public final class AuditWorkBudget: Sendable {
  enum Lane: Hashable, Sendable { case general, lifecycle, audit }
  struct Limit: Sendable {
    var entries: Int
    var bytes: Int
  }
  struct Usage: Equatable, Sendable {
    var entries = 0
    var bytes = 0
  }
  private struct Allocation {
    var lane: Lane
    var bytes: Int
  }
  private struct State {
    var usage: [Lane: Usage] = [:]
    var allocations: [UUID: Allocation] = [:]
  }
  private let state = OSAllocatedUnfairLock(initialState: State())
  private let limits: [Lane: Limit]

  public init(maximumEntries: Int = 1_024, maximumBytes: Int = 32 * 1_024 * 1_024) {
    precondition(maximumEntries > 0 && maximumBytes > 0)
    limits = [.general: Limit(entries: maximumEntries, bytes: maximumBytes)]
  }

  init(limits: [Lane: Limit]) {
    precondition(limits.values.allSatisfy { $0.entries > 0 && $0.bytes > 0 })
    self.limits = limits
  }

  public static func partitioned() -> AuditWorkBudget {
    AuditWorkBudget(limits: [
      .general: Limit(entries: 896, bytes: 28 * 1_024 * 1_024),
      .lifecycle: Limit(entries: 64, bytes: 1_024 * 1_024),
      .audit: Limit(entries: 64, bytes: 3 * 1_024 * 1_024),
    ])
  }

  private func acquire(_ bytes: Int, lane: Lane, state: inout State) -> Bool {
    guard bytes >= 0, let limit = limits[lane] else { return false }
    var use = state.usage[lane, default: Usage()]
    guard use.entries < limit.entries, bytes <= limit.bytes - use.bytes else { return false }
    use.entries += 1
    use.bytes += bytes
    state.usage[lane] = use
    return true
  }

  // Kept for simple synchronous callers and explicit saturation fixtures.
  func acquire(bytes: Int) -> Bool {
    state.withLock { acquire(bytes, lane: .general, state: &$0) }
  }
  func release(bytes: Int) {
    state.withLock {
      precondition($0.usage[.general, default: Usage()].entries > 0)
      $0.usage[.general, default: Usage()].entries -= 1
      $0.usage[.general, default: Usage()].bytes -= bytes
    }
  }

  func reserve(bytes: Int, lane: Lane = .general) -> Reservation? {
    let id = UUID()
    let accepted = state.withLock {
      guard acquire(bytes, lane: lane, state: &$0) else { return false }
      $0.allocations[id] = Allocation(lane: lane, bytes: bytes)
      return true
    }
    return accepted ? Reservation(budget: self, id: id) : nil
  }

  var usage: Usage {
    state.withLock { state in
      state.usage.values.reduce(into: Usage()) {
        $0.entries += $1.entries
        $0.bytes += $1.bytes
      }
    }
  }

  final class Reservation: Sendable {
    private let budget: AuditWorkBudget
    private let id: UUID
    fileprivate init(budget: AuditWorkBudget, id: UUID) {
      self.budget = budget
      self.id = id
    }
    deinit { release() }

    var bytes: Int { budget.state.withLock { $0.allocations[id]?.bytes ?? 0 } }

    func belongs(to budget: AuditWorkBudget) -> Bool { self.budget === budget }

    /// Replaces the accounted size without releasing the slot to another producer.
    @discardableResult
    func resize(to bytes: Int) -> Bool {
      budget.state.withLock { state in
        guard bytes >= 0, var allocation = state.allocations[id],
          let limit = budget.limits[allocation.lane]
        else { return false }
        let delta = bytes - allocation.bytes
        guard delta <= limit.bytes - state.usage[allocation.lane, default: Usage()].bytes else {
          return false
        }
        state.usage[allocation.lane, default: Usage()].bytes += delta
        allocation.bytes = bytes
        state.allocations[id] = allocation
        return true
      }
    }

    func release() {
      budget.state.withLock { state in
        guard let allocation = state.allocations.removeValue(forKey: id) else { return }
        state.usage[allocation.lane, default: Usage()].entries -= 1
        state.usage[allocation.lane, default: Usage()].bytes -= allocation.bytes
      }
    }
  }
}

protocol ReservedEndpointEventSink: EndpointEventSink {
  func record(_ event: EndpointEventRecord, reservation: AuditWorkBudget.Reservation)
  func recordAdmissionDrop(_ event: EndpointEventRecord)
}
