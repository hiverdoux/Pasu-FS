import Darwin
import Dispatch
import Foundation
import PasuFSConfiguration
import os

/// Shared admission budget for both observation and audit-write queues. Counts
/// retained payload estimates, not the process's total resident memory.
public final class AuditWorkBudget: Sendable {
  private struct State {
    var entries = 0
    var bytes = 0
  }
  private let state = OSAllocatedUnfairLock(initialState: State())
  private let maximumEntries: Int
  private let maximumBytes: Int

  public init(maximumEntries: Int = 1_024, maximumBytes: Int = 32 * 1_024 * 1_024) {
    precondition(maximumEntries > 0 && maximumBytes > 0)
    self.maximumEntries = maximumEntries
    self.maximumBytes = maximumBytes
  }

  func acquire(bytes: Int) -> Bool {
    state.withLock {
      guard $0.entries < maximumEntries, bytes <= maximumBytes - $0.bytes else { return false }
      $0.entries += 1
      $0.bytes += bytes
      return true
    }
  }

  func release(bytes: Int) {
    state.withLock {
      $0.entries -= 1
      $0.bytes -= bytes
    }
  }
}

public struct LineageObservation: Sendable {
  public var eventType: String
  public var timestamp: Date
  public var sequence: UInt64?
  public var globalSequence: UInt64?
  public var source: LineageProcess?
  public var target: LineageProcess?
  public var issues: [String]

  public init(
    eventType: String, timestamp: Date, sequence: UInt64? = nil,
    globalSequence: UInt64? = nil, source: LineageProcess? = nil,
    target: LineageProcess? = nil, issues: [String] = []
  ) {
    self.eventType = eventType
    self.timestamp = timestamp
    self.sequence = sequence
    self.globalSequence = globalSequence
    self.source = source
    self.target = target
    self.issues = issues
  }

  var actor: LineageProcess? {
    eventType == "NOTIFY_FORK" || eventType == "NOTIFY_EXEC" ? target : source
  }
  var estimatedByteCount: Int {
    512 + (source?.estimatedByteCount ?? 0) + (target?.estimatedByteCount ?? 0)
  }
}

/// Value-only graph owned by the collector queue. It never reads the process
/// table, resolves a PID against current state, or participates in authorization.
struct ProcessLineageGraph {
  private struct Entry {
    var process: LineageProcess
    var incoming: [LineageRelation] = []
    var ordinal: UInt64
    var bytes: Int { process.estimatedByteCount + incoming.count * 160 }
  }

  let bootIdentifier: String
  let collectionIdentifier: UUID
  let startedAt: Date
  private let maximumBytes: Int
  private var entries: [LineageProcessKey: Entry] = [:]
  private var problems: [String: LineageIssue] = [:]
  private(set) var byteCount = 0
  private(set) var observationCount: UInt64 = 0

  init(
    bootIdentifier: String, collectionIdentifier: UUID = UUID(),
    startedAt: Date = Date(), maximumBytes: Int = 128 * 1_024 * 1_024
  ) {
    self.bootIdentifier = bootIdentifier
    self.collectionIdentifier = collectionIdentifier
    self.startedAt = startedAt
    self.maximumBytes = maximumBytes
  }

  var status: ProcessLineageStatus {
    ProcessLineageStatus(
      isTracking: true, collectionStartedAt: startedAt, observedEventCount: observationCount,
      retainedProcessCount: entries.count, retainedDataBytes: byteCount,
      issues: problems.values.sorted { $0.reason < $1.reason }
    )
  }

  mutating func note(_ reason: String, count: UInt64 = 1, at: Date) {
    if var problem = problems[reason] {
      problem.count &+= count
      problem.lastObservedAt = at
      problems[reason] = problem
    } else {
      problems[reason] = LineageIssue(reason: reason, count: count, at: at)
    }
  }

  mutating func mergeDeliveryIssues(_ issues: [LineageIssue]) {
    for issue in issues {
      if issue.count >= (problems[issue.reason]?.count ?? 0) {
        problems[issue.reason] = issue
      }
    }
  }

  mutating func observe(_ event: LineageObservation) {
    observationCount &+= 1
    for issue in event.issues { note(issue, at: event.timestamp) }

    let protected = Set([event.source?.key, event.target?.key].compactMap { $0 })
    if let source = event.source { observe(source, at: event.timestamp, protected: protected) }
    if let target = event.target { observe(target, at: event.timestamp, protected: protected) }
    if let source = event.source, let target = event.target {
      if event.eventType == "NOTIFY_FORK" {
        add(.fork, from: source.key, to: target.key, at: event.timestamp, protected: protected)
      } else if event.eventType == "NOTIFY_EXEC" {
        if source.key.pid == target.key.pid, source.key != target.key {
          add(.exec, from: source.key, to: target.key, at: event.timestamp, protected: protected)
          entries[source.key]?.process.exitedAt = event.timestamp
        } else {
          note("executionMismatch", at: event.timestamp)
        }
      }
    }
    if event.eventType == "NOTIFY_EXIT", let source = event.source {
      entries[source.key]?.process.exitedAt = event.timestamp
    }
  }

  private mutating func observe(
    _ process: LineageProcess, at: Date, protected: Set<LineageProcessKey>
  ) {
    let previous = entries[process.key]
    var next = previous ?? Entry(process: process, ordinal: observationCount)
    next.process = process
    next.process.observedAt = at
    next.ordinal = observationCount
    let delta = next.bytes - (previous?.bytes ?? 0)
    guard makeRoom(for: delta, protected: protected) else {
      note("resourceLimit", at: at)
      return
    }
    entries[process.key] = next
    byteCount += delta
    if let parent = process.parent, parent.pid > 0,
      previous == nil || previous?.process.parent != parent
    {
      add(.parent, from: parent, to: process.key, at: at, protected: protected)
    }
    if let responsible = process.responsible, responsible != process.key,
      previous == nil || previous?.process.responsible != responsible
    {
      add(.responsible, from: responsible, to: process.key, at: at, protected: protected)
    }
  }

  private mutating func add(
    _ kind: LineageRelationKind, from: LineageProcessKey, to: LineageProcessKey,
    at: Date, protected: Set<LineageProcessKey>
  ) {
    guard entries[to] != nil else { return }
    guard makeRoom(for: 160, protected: protected) else {
      note("resourceLimit", at: at)
      return
    }
    entries[to]?.incoming.append(
      LineageRelation(
        source: from, target: to, kind: kind, observedAt: at,
        observation: observationCount))
    byteCount += 160
  }

  private mutating func makeRoom(for bytes: Int, protected: Set<LineageProcessKey>) -> Bool {
    guard bytes > maximumBytes - byteCount else { return true }
    var reachable = protected
    var stack = Array(protected)
    for (key, entry) in entries where entry.process.exitedAt == nil {
      if reachable.insert(key).inserted { stack.append(key) }
    }
    while let key = stack.popLast() {
      for relation in entries[key]?.incoming ?? [] {
        if reachable.insert(relation.source).inserted { stack.append(relation.source) }
      }
    }
    let disposable = entries.filter { !reachable.contains($0.key) }
      .sorted { $0.value.ordinal < $1.value.ordinal }
    for (key, entry) in disposable {
      entries.removeValue(forKey: key)
      byteCount -= entry.bytes
      if bytes <= maximumBytes - byteCount { return true }
    }
    return bytes <= maximumBytes - byteCount
  }

  func snapshot(for event: LineageObservation) -> ProcessLineageSnapshot {
    var snapshot = ProcessLineageSnapshot(
      bootIdentifier: bootIdentifier, collectionIdentifier: collectionIdentifier,
      collectionStartedAt: startedAt, capturedAt: event.timestamp, actor: event.actor?.key,
      responsible: event.actor?.responsible, issues: status.issues
    )
    var visited = Set<LineageProcessKey>()
    var visiting = Set<LineageProcessKey>()
    var roots = [event.actor?.key, event.actor?.responsible].compactMap { $0 }
    // Iterative traversal: no recursion or depth cap, even for long exec histories.
    var rootIndex = 0
    while rootIndex < roots.count {
      let root = roots[rootIndex]
      rootIndex += 1
      var stack: [(LineageProcessKey, Bool)] = [(root, false)]
      while let (key, finish) = stack.popLast() {
        if finish {
          visiting.remove(key)
          guard visited.insert(key).inserted else { continue }
          if let entry = entries[key] {
            snapshot.processes.append(entry.process)
            snapshot.relations.append(contentsOf: entry.incoming)
            for relation in entry.incoming where relation.kind == .responsible {
              if !visited.contains(relation.source) { roots.append(relation.source) }
            }
            let hasParent = entry.incoming.contains {
              $0.kind == .fork || $0.kind == .parent || $0.kind == .exec
            }
            if !hasParent && !(key.pid == 1 && entry.process.originalParentPID == 0) {
              snapshot.issues.append(
                LineageIssue(reason: "parentUnavailable", process: key, at: event.timestamp))
            }
          } else {
            snapshot.processes.append(LineageProcess(key: key))
            snapshot.issues.append(
              LineageIssue(reason: "unobserved", process: key, at: event.timestamp))
          }
          continue
        }
        guard !visited.contains(key) else { continue }
        guard visiting.insert(key).inserted else {
          snapshot.issues.append(LineageIssue(reason: "cycle", process: key, at: event.timestamp))
          continue
        }
        stack.append((key, true))
        for relation in (entries[key]?.incoming ?? []).reversed()
        where relation.kind != .responsible {
          stack.append((relation.source, false))
        }
      }
    }
    return snapshot
  }
}

/// Serial asynchronous collector. Submissions occur in ES delivery order after
/// authorization has responded, including events that do not produce a log row.
public final class ProcessLineageTracker: @unchecked Sendable {
  public static func currentBootIdentifier() -> String {
    var size = 0
    guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 0 else {
      return "collection-\(UUID().uuidString)"
    }
    var buffer = [CChar](repeating: 0, count: size)
    guard sysctlbyname("kern.bootsessionuuid", &buffer, &size, nil, 0) == 0 else {
      return "collection-\(UUID().uuidString)"
    }
    return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
  }

  private struct State {
    var closed = false
    var status: ProcessLineageStatus
    var sequences: [String: UInt64] = [:]
    var lastGlobalSequence: UInt64?
    var deliveryIssues: [String: LineageIssue] = [:]

    mutating func note(_ reason: String, count: UInt64 = 1, at: Date) {
      if var issue = deliveryIssues[reason] {
        issue.count &+= count
        issue.lastObservedAt = at
        deliveryIssues[reason] = issue
      } else {
        deliveryIssues[reason] = LineageIssue(reason: reason, count: count, at: at)
      }
    }

    // Account for EVERY delivered ES message before admission. A sequence gap
    // after our own queue drops is not evidence of a kernel delivery loss.
    mutating func observeDelivery(_ event: LineageObservation) {
      if let current = event.globalSequence {
        if let previous = lastGlobalSequence, current > previous, current - previous > 1 {
          note("kernelEventLoss", count: current - previous - 1, at: event.timestamp)
        } else if let previous = lastGlobalSequence, current <= previous {
          note("Event sequence restarted within this collection.", at: event.timestamp)
        }
        lastGlobalSequence = current
      } else if let current = event.sequence, let previous = sequences[event.eventType],
        current > previous, current - previous > 1
      {
        note("kernelEventLoss", count: current - previous - 1, at: event.timestamp)
      }
      if let current = event.sequence { sequences[event.eventType] = current }
    }
  }
  private let state: OSAllocatedUnfairLock<State>
  private let queue = DispatchQueue(label: "com.example.pasu.fs.process-history")
  private let sink: any EndpointEventSink
  private let budget: AuditWorkBudget
  private var graph: ProcessLineageGraph

  public init(
    bootIdentifier: String, sink: any EndpointEventSink,
    budget: AuditWorkBudget = AuditWorkBudget(),
    maximumDataBytes: Int = 128 * 1_024 * 1_024
  ) {
    self.sink = sink
    self.budget = budget
    self.graph = ProcessLineageGraph(bootIdentifier: bootIdentifier, maximumBytes: maximumDataBytes)
    self.state = OSAllocatedUnfairLock(initialState: State(status: graph.status))
  }

  public var status: ProcessLineageStatus {
    state.withLock {
      var result = $0.status
      result.isTracking = !$0.closed
      let reasons = Set($0.deliveryIssues.keys)
      result.issues.removeAll { reasons.contains($0.reason) }
      result.issues.append(contentsOf: $0.deliveryIssues.values)
      result.issues.sort { $0.reason < $1.reason }
      return result
    }
  }

  public func submit(_ observation: LineageObservation, record: EndpointEventRecord?) {
    let bytes = observation.estimatedByteCount + (record?.estimatedByteCount ?? 0)
    state.withLock { state in
      guard !state.closed else { return }
      state.observeDelivery(observation)
      guard budget.acquire(bytes: bytes) else {
        state.note("queueOverflow", at: observation.timestamp)
        return
      }
      let deliveryIssues = Array(state.deliveryIssues.values)
      queue.async { [self] in
        defer { budget.release(bytes: bytes) }
        graph.mergeDeliveryIssues(deliveryIssues)
        graph.observe(observation)
        if var record {
          record.timestamp = observation.timestamp
          record.processLineage = graph.snapshot(for: observation)
          sink.record(record)
        }
        self.state.withLock { $0.status = graph.status }
      }
    }
  }

  public func note(_ reason: String) {
    state.withLock { state in
      guard !state.closed else { return }
      queue.async { [self] in
        graph.note(reason, at: Date())
        self.state.withLock { $0.status = graph.status }
      }
    }
  }

  public func flush() { queue.sync {} }

  public func close() {
    let close = state.withLock { state in
      guard !state.closed else { return false }
      state.closed = true
      return true
    }
    if close { flush() }
  }
}
