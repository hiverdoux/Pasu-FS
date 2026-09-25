import Darwin
import Dispatch
import Foundation
import PasuFSConfiguration
import os

public struct LineageObservation: Sendable {
  public var eventType: String
  public var timestamp: Date
  public var sequence: UInt64?
  public var globalSequence: UInt64?
  public var machTime: UInt64?
  public var source: LineageProcess?
  public var target: LineageProcess?
  public var issues: [String]

  public init(
    eventType: String, timestamp: Date, sequence: UInt64? = nil,
    globalSequence: UInt64? = nil, source: LineageProcess? = nil,
    target: LineageProcess? = nil, issues: [String] = [], machTime: UInt64? = nil
  ) {
    self.eventType = eventType
    self.timestamp = timestamp
    self.sequence = sequence
    self.globalSequence = globalSequence
    self.machTime = machTime
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
          note("sequenceRestarted", at: event.timestamp)
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
    state.withLock { state in
      var item = observation
      var minimal = false
      var omittedLifecycleRecord: EndpointEventRecord?
      var acceptedRecord = record
      guard !state.closed else { return }
      state.observeDelivery(observation)
      let bytes = observation.estimatedByteCount + (record?.estimatedByteCount ?? 0) + 1_024
      var reservation = budget.reserve(bytes: bytes)
      if reservation == nil {
        state.note("queueOverflow", at: observation.timestamp)
        minimal = true
        if observation.eventType == "AUTH_OPEN", let record {
          item.source = observation.source.map(Self.compact)
          item.target = nil
          reservation = budget.reserve(
            bytes: item.estimatedByteCount + record.estimatedByteCount + 1_024, lane: .audit)
        } else if ["NOTIFY_EXEC", "NOTIFY_FORK", "NOTIFY_EXIT"].contains(observation.eventType) {
          item.source = observation.source.map(Self.compact)
          item.target = observation.target.map(Self.compact)
          reservation = budget.reserve(
            bytes: item.estimatedByteCount + (record?.estimatedByteCount ?? 0) + 1_024,
            lane: .lifecycle)
          if reservation == nil {
            acceptedRecord = nil
            omittedLifecycleRecord = record
            reservation = budget.reserve(bytes: item.estimatedByteCount + 1_024, lane: .lifecycle)
          }
        }
      }
      guard let reservation else {
        if let record { (sink as? any ReservedEndpointEventSink)?.recordAdmissionDrop(record) }
        return
      }
      if let omittedLifecycleRecord {
        (sink as? any ReservedEndpointEventSink)?.recordAdmissionDrop(omittedLifecycleRecord)
      }
      let deliveryIssues = Array(state.deliveryIssues.values)
      let queuedObservation = item
      let queuedRecord = acceptedRecord
      let isMinimal = minimal
      queue.async { [self] in
        var transferred = false
        defer { if !transferred { reservation.release() } }
        graph.mergeDeliveryIssues(deliveryIssues)
        if !isMinimal || queuedObservation.eventType != "AUTH_OPEN" {
          graph.observe(queuedObservation, preserveMetadata: isMinimal)
        }
        if var record = queuedRecord {
          record.timestamp = queuedObservation.timestamp
          let baseBytes = queuedObservation.estimatedByteCount + record.estimatedByteCount + 1_024
          record.processLineage =
            isMinimal
            ? graph.omittedSnapshot(for: queuedObservation, reason: "historyOmitted")
            : graph.snapshot(for: queuedObservation) { reservation.resize(to: baseBytes + $0) }
          // The original observation remains alive through this synchronous handoff.
          // Keep its estimate until the writer consumes the reservation.
          if !reservation.resize(
            to: queuedObservation.estimatedByteCount + record.estimatedByteCount)
          {
            record.processLineage = graph.omittedSnapshot(
              for: queuedObservation, reason: "historyBudgetExceeded")
          }
          if let reservedSink = sink as? any ReservedEndpointEventSink {
            reservedSink.record(record, reservation: reservation)
            transferred = true
          } else {
            sink.record(record)
          }
        }
        self.state.withLock { $0.status = graph.status }
      }
    }
  }

  private static func compact(_ process: LineageProcess) -> LineageProcess {
    LineageProcess(
      key: process.key, startTime: process.startTime, parent: process.parent,
      responsible: process.responsible, originalParentPID: process.originalParentPID,
      observedAt: process.observedAt)
  }

  // Internal deterministic pressure fixture: never used by the extension runtime.
  func enqueueBarrier(_ work: @escaping @Sendable () -> Void) { queue.async(execute: work) }

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
