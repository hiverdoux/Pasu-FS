import Dispatch
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import os

public enum PolicyAuditLogStoreError: Error, CustomStringConvertible {
  case unknownPolicy

  public var description: String { "The requested policy is not in the stored policy set." }
}

/// What makes a later record of the same process instance count as one more request of an open
/// record instead of a record of its own. Only answered file requests inside a policy folder are
/// combined; process events, response errors and records without a known process never are.
struct RecordGroupKey: Hashable, Sendable {
  struct Decision: Hashable, Sendable {
    var policyIdentifier: UUID
    var mode: PolicyMode
    var decision: PolicyEvaluationDecision
    var retiredFolderPath: String?
  }

  struct Request: Hashable, Sendable {
    var eventType: String
    var targetPath: String
    var destinationPath: String?
    var pathWasTruncated: Bool?
    var requestedFlags: Int32?
  }

  var policySetIdentifier: UUID?
  var policyRevision: UInt64?
  var policyDecision: String
  var kernelResponse: String
  /// Each policy that took part and its decision, so every policy log receives the combined
  /// record of the requests it covered.
  var decisions: [Decision]
  /// The exact request, or nil for allowed requests, which combine whatever their target.
  var request: Request?

  init?(_ record: EndpointEventRecord) {
    guard AuthorizationEventCatalog.isAuthorizationEvent(record.eventType),
      record.kernelResponse == "allow" || record.kernelResponse == "deny",
      record.requestCount == nil,
      let target = record.targetPath, !target.isEmpty,
      let evaluations = record.policyEvaluations, !evaluations.isEmpty
    else { return nil }
    policySetIdentifier = record.policySetIdentifier
    policyRevision = record.policyRevision
    policyDecision = record.policyDecision
    kernelResponse = record.kernelResponse
    decisions = evaluations.map {
      Decision(
        policyIdentifier: $0.policyIdentifier, mode: $0.mode, decision: $0.decision,
        retiredFolderPath: $0.retiredFolderPath)
    }
    request =
      record.combinesAnyTarget
      ? nil
      : Request(
        eventType: record.eventType, targetPath: target, destinationPath: record.destinationPath,
        pathWasTruncated: record.pathWasTruncated, requestedFlags: record.requestedFlags)
  }
}

/// A bounded, nonblocking event sink. All file operations and policy retirement
/// are serialized on its worker queue; the kernel response never waits for disk.
///
/// A record of an answered file request waits up to `groupingWindow` for later requests of the
/// same process instance that it can stand for: allowed requests under the same decisions
/// whatever their target, and otherwise identical repeats. Each process instance has at most one
/// waiting record, so a different record from it saves the waiting one first and the order of
/// one process's records is kept. Waiting records are bounded separately from the queue budget.
public final class PolicyAuditLogStore: ReservedEndpointEventSink, @unchecked Sendable {
  /// How long after its first request a record can still count later requests.
  static let groupingWindow: TimeInterval = 1
  static let maximumOpenGroups = 256
  static let maximumHeldBytes = 8 * 1_024 * 1_024

  private struct RecordGroup {
    var key: RecordGroupKey
    var head: EndpointEventRecord
    var count: UInt64 = 1
    var last: Date
    var serial: UInt64
    var bytes: Int
    /// System uptime when the record started waiting. Bounds the wait even if the clock changes.
    var openedUptime: TimeInterval

    var windowEnd: Date { head.timestamp.addingTimeInterval(PolicyAuditLogStore.groupingWindow) }

    /// The seconds left before the record is saved.
    func remainingWait(now: Date, uptime: TimeInterval) -> TimeInterval {
      min(
        windowEnd.timeIntervalSince(now),
        openedUptime + PolicyAuditLogStore.groupingWindow - uptime)
    }

    var record: EndpointEventRecord {
      guard count > 1 else { return head }
      var record = head
      record.requestCount = count
      record.lastTimestamp = last
      return record
    }
  }

  private struct State {
    var isClosed = false
    var allowedKeys: Set<PolicyAuditLogKey> = []
    var droppedEventCount: UInt64 = 0
    var delivery: AuditDeliveryMetrics = {
      var metrics = AuditDeliveryMetrics()
      metrics.deniedLaneDrops = 0
      metrics.sharedLaneDrops = 0
      metrics.combinedDeniedRequests = 0
      metrics.combinedAllowedRequests = 0
      return metrics
    }()
    var policyDrops: [PolicyAuditLogKey: UInt64] = [:]
    var groups: [LineageProcessKey: RecordGroup] = [:]
    var heldBytes = 0
    var nextGroupSerial: UInt64 = 0
    var isFlushScheduled = false

    mutating func countDrop(_ event: EndpointEventRecord, admission: Bool) {
      let requests = event.representedRequestCount
      if admission {
        delivery.admissionDrops &+= requests
        if event.isDeniedRequest {
          delivery.deniedLaneDrops = (delivery.deniedLaneDrops ?? 0) &+ requests
        } else {
          delivery.sharedLaneDrops = (delivery.sharedLaneDrops ?? 0) &+ requests
        }
      } else {
        delivery.storageFailures &+= requests
      }
      droppedEventCount &+= requests
      for key in PolicyAuditLogStore.keys(for: event) where allowedKeys.contains(key) {
        policyDrops[key, default: 0] &+= requests
      }
    }

    /// Counts `event` in the open record of `actor` when it is one more request of it.
    mutating func absorb(
      _ event: EndpointEventRecord, key: RecordGroupKey, actor: LineageProcessKey
    ) -> Bool {
      guard !isClosed, var group = groups[actor], group.key == key,
        event.timestamp < group.windowEnd
      else { return false }
      group.count &+= 1
      group.last = max(group.last, event.timestamp)
      groups[actor] = group
      if event.isDeniedRequest {
        delivery.combinedDeniedRequests = (delivery.combinedDeniedRequests ?? 0) &+ 1
      } else {
        delivery.combinedAllowedRequests = (delivery.combinedAllowedRequests ?? 0) &+ 1
      }
      return true
    }

    mutating func removeGroup(of actor: LineageProcessKey) -> RecordGroup? {
      guard let group = groups.removeValue(forKey: actor) else { return nil }
      heldBytes -= group.bytes
      return group
    }

    mutating func removeGroups(where shouldRemove: (RecordGroup) -> Bool) -> [RecordGroup] {
      let actors = groups.filter { shouldRemove($0.value) }.map(\.key)
      return actors.compactMap { removeGroup(of: $0) }.sorted { $0.serial < $1.serial }
    }
  }

  private let state = OSAllocatedUnfairLock(initialState: State())
  private let queue = DispatchQueue(label: "com.example.pasu.fs.audit-router")
  private let queueKey = DispatchSpecificKey<UInt8>()
  private let budget: AuditWorkBudget
  private let store: SecureAtomicFileStore
  private let global: JSONLineEventLogger
  private let maximumFileSize: Int64
  private var allowedKeys: Set<PolicyAuditLogKey> = []
  private var writers: [PolicyAuditLogKey: JSONLineEventLogger] = [:]
  private var creationErrors: [PolicyAuditLogKey: String] = [:]
  private var cleanupWarning: String?

  public init(
    directoryURL: URL,
    requiredOwnerUserID: UInt32? = nil,
    maximumPendingRecords: Int = 1_024,
    maximumFileSize: Int64 = 10 * 1_024 * 1_024,
    budget: AuditWorkBudget? = nil
  ) throws {
    precondition(maximumPendingRecords > 0 && maximumFileSize > 0)
    // Without a shared budget, denied requests get half as many pending records as the rest.
    self.budget =
      budget
      ?? AuditWorkBudget(
        maximumEntries: maximumPendingRecords, deniedEntries: max(maximumPendingRecords / 2, 1))
    self.maximumFileSize = maximumFileSize
    self.store = SecureAtomicFileStore(
      rootDirectory: directoryURL, requiredOwnerUserID: requiredOwnerUserID)
    self.global = try JSONLineEventLogger(
      directoryURL: directoryURL,
      requiredOwnerUserID: requiredOwnerUserID,
      maximumFileSize: maximumFileSize
    )
    queue.setSpecific(key: queueKey, value: 1)
  }

  deinit { flushAndClose() }

  public var droppedEventCount: UInt64 {
    state.withLock { $0.droppedEventCount }
  }

  public var lastErrorDescription: String? {
    queue.sync { combinedWarning }
  }

  /// Call only after successfully loading or persisting a validated policy set.
  /// Never call with an inferred empty set following a policy-store read failure.
  public func updatePolicySet(_ document: PolicySetDocument) {
    queue.sync {
      // Records waiting for repeats belong to the policies they were decided under.
      flushAllGroups()
      allowedKeys = Set(
        document.policies.map {
          PolicyAuditLogKey(setIdentifier: document.setIdentifier, policyIdentifier: $0.id)
        })
      state.withLock {
        $0.allowedKeys = allowedKeys
        $0.policyDrops = $0.policyDrops.filter { allowedKeys.contains($0.key) }
      }
      for key in Array(writers.keys) where !allowedKeys.contains(key) {
        writers.removeValue(forKey: key)?.flushAndClose()
      }
      creationErrors = creationErrors.filter { allowedKeys.contains($0.key) }
      var failures: [String] = []
      do {
        let names = try FileManager.default.contentsOfDirectory(atPath: store.rootDirectory.path)
        for name in names {
          guard let key = PolicyAuditLogKey(filename: name), !allowedKeys.contains(key) else {
            continue
          }
          do { try store.remove(name, ifExists: true) } catch {
            failures.append("Could not remove retired policy log \(name): \(error)")
          }
        }
      } catch {
        failures.append("Could not inspect retired policy logs: \(error)")
      }
      cleanupWarning = failures.isEmpty ? nil : failures.sorted().joined(separator: "\n")
    }
  }

  public var deliveryMetrics: AuditDeliveryMetrics { state.withLock { $0.delivery } }

  public func record(_ original: EndpointEventRecord) {
    let event: EndpointEventRecord
    do {
      event =
        original.estimatedByteCount > maximumFileSize
        ? try JSONLineEventLogger.recordWithinLimit(original, maximumBytes: maximumFileSize)
        : original
    } catch {
      recordStorageDrop(original)
      return
    }
    guard let reservation = budget.reserve(bytes: event.estimatedByteCount, lane: event.auditLane)
    else {
      recordAdmissionDrop(event, actor: event.processLineage?.actor)
      return
    }
    record(event, reservation: reservation)
  }

  private func recordStorageDrop(_ event: EndpointEventRecord) {
    state.withLock { $0.countDrop(event, admission: false) }
  }

  func recordAdmissionDrop(_ event: EndpointEventRecord) {
    recordAdmissionDrop(event, actor: nil)
  }

  /// A record that found no room in its lane still counts when it repeats an open record, which
  /// needs no further space. Only otherwise is it lost.
  func recordAdmissionDrop(_ event: EndpointEventRecord, actor: LineageProcessKey?) {
    let key = actor == nil ? nil : RecordGroupKey(event)
    state.withLock { state in
      if let actor, let key, state.absorb(event, key: key, actor: actor) { return }
      state.countDrop(event, admission: true)
    }
  }

  func absorbRepeat(_ event: EndpointEventRecord, actor: LineageProcessKey?) -> Bool {
    guard let actor, let key = RecordGroupKey(event) else { return false }
    return state.withLock { $0.absorb(event, key: key, actor: actor) }
  }

  func record(_ original: EndpointEventRecord, reservation: AuditWorkBudget.Reservation) {
    guard reservation.belongs(to: budget) else {
      recordAdmissionDrop(original)
      return
    }
    let event: EndpointEventRecord
    do {
      event =
        original.estimatedByteCount > maximumFileSize
        ? try JSONLineEventLogger.recordWithinLimit(original, maximumBytes: maximumFileSize)
        : original
    } catch {
      recordStorageDrop(original)
      return
    }
    // Keep accounting for the producer's transient observation until this
    // reservation reaches the writer. Do not shrink it during handoff.
    guard reservation.resize(to: max(reservation.bytes, event.estimatedByteCount)) else {
      recordAdmissionDrop(event)
      return
    }
    let actor = event.processLineage?.actor
    let key = actor == nil ? nil : RecordGroupKey(event)
    let bytes = event.estimatedByteCount
    state.withLock { state in
      guard !state.isClosed else {
        state.countDrop(event, admission: true)
        return
      }
      if let actor, let key, state.absorb(event, key: key, actor: actor) { return }
      // A different record from the same process saves the one waiting for repeats first.
      var writes = actor.flatMap { state.removeGroup(of: $0) }.map { [$0.record] } ?? []
      var held = false
      if let actor, let key, bytes <= Self.maximumHeldBytes {
        while state.groups.count >= Self.maximumOpenGroups
          || bytes > Self.maximumHeldBytes - state.heldBytes,
          let oldest = state.groups.min(by: { $0.value.serial < $1.value.serial })?.key,
          let evicted = state.removeGroup(of: oldest)
        {
          writes.append(evicted.record)
        }
        state.nextGroupSerial &+= 1
        state.groups[actor] = RecordGroup(
          key: key, head: event, last: event.timestamp, serial: state.nextGroupSerial,
          bytes: bytes, openedUptime: ProcessInfo.processInfo.systemUptime)
        state.heldBytes += bytes
        held = true
        scheduleFlush(&state)
      } else {
        writes.append(event)
      }
      // A waiting record is bounded by the grouping limits, not by its queue reservation.
      let retained = held ? nil : reservation
      if held { reservation.release() }
      guard !writes.isEmpty else { return }
      queue.async { [self] in
        // The last owner releases the reservation, including an overlapping
        // producer still returning from handoff.
        defer { withExtendedLifetime(retained) {} }
        for record in writes { write(record) }
      }
    }
  }

  /// Saves one record to the global log and to the log of each policy that took part. Runs on
  /// the worker queue.
  private func write(_ event: EndpointEventRecord) {
    var failed = !global.recordSynchronously(event)
    let globalStored = !failed
    let requests = event.representedRequestCount
    for key in Self.keys(for: event) where allowedKeys.contains(key) {
      guard
        let evaluation = event.policyEvaluations?.first(where: {
          $0.policyIdentifier == key.policyIdentifier
        })
      else { continue }
      var scoped = event
      scoped.policyEvaluations = [evaluation]
      var stored = false
      do {
        let writer: JSONLineEventLogger
        if let existing = writers[key] {
          writer = existing
        } else {
          writer = try JSONLineEventLogger(
            directoryURL: store.rootDirectory,
            filename: key.filename, requiredOwnerUserID: store.requiredOwnerUserID,
            maximumFileSize: maximumFileSize)
          writers[key] = writer
          creationErrors.removeValue(forKey: key)
        }
        stored = writer.recordSynchronously(scoped)
      } catch { creationErrors[key] = "Policy log \(key.filename): \(error)" }
      if !stored {
        failed = true
        state.withLock { $0.policyDrops[key, default: 0] &+= requests }
      }
    }
    let minimal =
      event.processLineage?.issues.contains {
        ["historyOmitted", "historyBudgetExceeded", "oversizedRecord"].contains($0.reason)
      } == true
    let storageFailed = failed
    state.withLock {
      if storageFailed {
        $0.delivery.storageFailures &+= requests
        $0.droppedEventCount &+= requests
      }
      if globalStored && minimal { $0.delivery.minimalRecordsStored &+= 1 }
    }
  }

  /// Schedules saving the waiting records once the earliest of their windows ends. Call while
  /// holding the state lock.
  private func scheduleFlush(_ state: inout State) {
    let now = Date()
    let uptime = ProcessInfo.processInfo.systemUptime
    guard !state.isFlushScheduled,
      let next = state.groups.values.map({ $0.remainingWait(now: now, uptime: uptime) }).min()
    else { return }
    state.isFlushScheduled = true
    let delay = max(next, 0) + 0.01
    queue.asyncAfter(deadline: .now() + delay, qos: .utility) { [weak self] in
      self?.flushExpiredGroups()
    }
  }

  /// Saves the records whose wait has ended. Runs on the worker queue.
  private func flushExpiredGroups() {
    let now = Date()
    let uptime = ProcessInfo.processInfo.systemUptime
    let expired = state.withLock { state in
      state.isFlushScheduled = false
      let expired = state.removeGroups { $0.remainingWait(now: now, uptime: uptime) <= 0 }
      scheduleFlush(&state)
      return expired
    }
    for group in expired { write(group.record) }
  }

  /// Saves every record still waiting for repeats. Runs on the worker queue.
  private func flushAllGroups() {
    let open = state.withLock { $0.removeGroups { _ in true } }
    for group in open { write(group.record) }
  }

  /// Saves the records waiting for repeats now instead of when their window ends.
  func flushOpenRecords() {
    if DispatchQueue.getSpecific(key: queueKey) != nil {
      flushAllGroups()
    } else {
      queue.sync { flushAllGroups() }
    }
  }

  /// Reading saves the records still waiting for repeats first, so it returns every answered
  /// request; later repeats start a new record.
  public func readAuditLog(maximumLineCount: Int) throws -> AuditLogBatch {
    try queue.sync {
      flushAllGroups()
      return try read(
        filenames: ["endpoint-events.jsonl"], maximumLineCount: maximumLineCount,
        key: nil, dropped: droppedEventCount, warning: combinedWarning)
    }
  }

  public func readPolicyAuditLog(_ request: PolicyAuditLogRequest) throws -> AuditLogBatch {
    try queue.sync {
      guard allowedKeys.contains(request.key) else { throw PolicyAuditLogStoreError.unknownPolicy }
      flushAllGroups()
      let key = request.key
      let dropped = state.withLock { $0.policyDrops[key, default: 0] }
      return try read(
        filenames: [key.filename + ".1", key.filename],
        maximumLineCount: request.maximumLineCount, key: key, dropped: dropped,
        warning: creationErrors[key] ?? writers[key]?.lastErrorDescription)
    }
  }

  public func flushAndClose() {
    let open: [RecordGroup]? = state.withLock {
      guard !$0.isClosed else { return nil }
      $0.isClosed = true
      return $0.removeGroups { _ in true }
    }
    guard let open else { return }
    let closeFiles = { [self] in
      for group in open { write(group.record) }
      global.flushAndClose()
      for writer in writers.values { writer.flushAndClose() }
    }
    if DispatchQueue.getSpecific(key: queueKey) != nil {
      closeFiles()
    } else {
      queue.sync(execute: closeFiles)
    }
  }

  private var combinedWarning: String? {
    let warnings =
      [cleanupWarning, global.lastErrorDescription]
      + creationErrors.values.map(Optional.some)
      + writers.values.map(\.lastErrorDescription)
    let values = Set(warnings.compactMap { $0 }).sorted()
    return values.isEmpty ? nil : values.joined(separator: "\n")
  }

  fileprivate static func keys(for event: EndpointEventRecord) -> Set<PolicyAuditLogKey> {
    guard AuthorizationEventCatalog.isAuthorizationEvent(event.eventType),
      let set = event.policySetIdentifier,
      let target = event.targetPath, !target.isEmpty
    else { return [] }
    return Set(
      (event.policyEvaluations ?? []).map {
        PolicyAuditLogKey(setIdentifier: set, policyIdentifier: $0.policyIdentifier)
      })
  }

  private func read(
    filenames: [String], maximumLineCount: Int, key: PolicyAuditLogKey?,
    dropped: UInt64, warning: String?
  ) throws -> AuditLogBatch {
    var lines: [Data] = []
    for filename in filenames {
      do {
        let data = try store.read(filename, maximumSize: Int(maximumFileSize))
        lines.append(contentsOf: data.split(separator: 0x0A).map { Data($0) })
      } catch SecureFileStoreError.fileNotFound {
        continue
      }
    }
    let maximum = min(max(maximumLineCount, 1), 500)
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    var records: [AuditEventRecord] = []
    var skipped = 0
    for line in lines.suffix(maximum) {
      do {
        let record = try decoder.decode(AuditEventRecord.self, from: line)
        if let key {
          guard Self.keys(for: record) == [key], record.policyEvaluations?.count == 1 else {
            skipped += 1
            continue
          }
        }
        records.append(record)
      } catch { skipped += 1 }
    }
    return AuditLogBatch(
      records: records, skippedLineCount: skipped, droppedEventCount: dropped,
      isTruncated: lines.count > maximum, warning: warning)
  }
}
