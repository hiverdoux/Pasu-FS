import Dispatch
import Foundation
import PasuFSConfiguration

/// Value-only graph owned by the collector queue. It never reads the process
/// table, resolves a PID against current state, or participates in authorization.
struct ProcessLineageGraph {
  private struct Entry {
    var process: LineageProcess
    var incoming: [LineageRelation] = []
    var ordinal: UInt64
    var machTime: UInt64?
    // Includes per-entry timing and the bounded PID index estimate.
    var bytes: Int { 96 + process.estimatedByteCount + incoming.count * 160 }
  }

  let bootIdentifier: String
  let collectionIdentifier: UUID
  let startedAt: Date
  private let maximumBytes: Int
  private let targetBytes: Int
  private let clock: @Sendable () -> UInt64
  private var latestByPID: [Int32: LineageProcessKey] = [:]
  private var lastAttempt: (time: UInt64, observations: UInt64, changes: UInt64)?
  private var recoveryChanges: UInt64 = 0
  private(set) var reclamation = ReclamationMetrics()
  private var entries: [LineageProcessKey: Entry] = [:]
  private var problems: [String: LineageIssue] = [:]
  private(set) var byteCount = 0
  private(set) var observationCount: UInt64 = 0

  init(
    bootIdentifier: String, collectionIdentifier: UUID = UUID(),
    startedAt: Date = Date(), maximumBytes: Int = 128 * 1_024 * 1_024,
    targetFraction: Double = 0.875,
    clock: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
  ) {
    self.bootIdentifier = bootIdentifier
    self.collectionIdentifier = collectionIdentifier
    self.startedAt = startedAt
    precondition(maximumBytes > 0 && targetFraction > 0 && targetFraction < 1)
    self.maximumBytes = maximumBytes
    self.targetBytes = Int(Double(maximumBytes) * targetFraction)
    self.clock = clock
  }

  var status: ProcessLineageStatus {
    ProcessLineageStatus(
      isTracking: true, collectionStartedAt: startedAt, observedEventCount: observationCount,
      retainedProcessCount: entries.count, retainedDataBytes: byteCount,
      issues: problems.values.sorted { $0.reason < $1.reason }, reclamation: reclamation
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

  mutating func observe(_ event: LineageObservation, preserveMetadata: Bool = false) {
    observationCount &+= 1
    for issue in event.issues { note(issue, at: event.timestamp) }

    let explicitExec =
      event.eventType == "NOTIFY_EXEC"
      && event.source?.key.pid == event.target?.key.pid
      && event.source?.key != event.target?.key
    if explicitExec, let source = event.source {
      markExited(source.key, at: event.timestamp)
    }
    // Recognize directly observed replacements before estimating admission;
    // this can make an old execution reclaimable even when the graph is full.
    if let source = event.source, event.eventType != "NOTIFY_EXIT" {
      observeCurrent(source.key, at: event.timestamp, machTime: event.machTime)
    }
    if let target = event.target {
      observeCurrent(target.key, at: event.timestamp, machTime: event.machTime)
    }
    let protected = Set(
      [
        event.source?.key, event.target?.key, event.source?.parent, event.target?.parent,
        event.source?.responsible, event.target?.responsible,
      ].compactMap { $0 })
    // Reserve headroom for the whole event, including relationships, rather
    // than stopping a batch at the size of its first individual mutation.
    let anticipatedGrowth = growthEstimate(for: event, preserveMetadata: preserveMetadata)
    if anticipatedGrowth > maximumBytes - byteCount {
      _ = makeRoom(for: anticipatedGrowth, protected: protected)
    }
    if let source = event.source {
      observe(
        source, at: event.timestamp, machTime: event.machTime, protected: protected,
        preserveMetadata: preserveMetadata)
      if explicitExec { markExited(source.key, at: event.timestamp) }
      if event.eventType != "NOTIFY_EXIT" {
        observeCurrent(source.key, at: event.timestamp, machTime: event.machTime)
      }
    }
    if let target = event.target {
      observe(
        target, at: event.timestamp, machTime: event.machTime, protected: protected,
        preserveMetadata: preserveMetadata)
      observeCurrent(target.key, at: event.timestamp, machTime: event.machTime)
    }
    if let source = event.source, let target = event.target {
      if event.eventType == "NOTIFY_FORK" {
        add(.fork, from: source.key, to: target.key, at: event.timestamp, protected: protected)
      } else if event.eventType == "NOTIFY_EXEC" {
        if source.key.pid == target.key.pid, source.key != target.key {
          add(.exec, from: source.key, to: target.key, at: event.timestamp, protected: protected)
          markExited(source.key, at: event.timestamp)
          observeCurrent(target.key, at: event.timestamp, machTime: event.machTime)
        } else {
          note("executionMismatch", at: event.timestamp)
        }
      }
    }
    if event.eventType == "NOTIFY_EXIT", let source = event.source {
      markExited(source.key, at: event.timestamp)
    }
  }

  private func growthEstimate(for event: LineageObservation, preserveMetadata: Bool) -> Int {
    var growth = 0
    var seen = Set<LineageProcessKey>()
    for process in [event.source, event.target].compactMap({ $0 }) {
      guard seen.insert(process.key).inserted else { continue }
      let previous = entries[process.key]
      if let oldTime = previous?.machTime, let time = event.machTime, time < oldTime { continue }
      let metadata =
        preserveMetadata && previous != nil
        ? previous!.process.estimatedByteCount : process.estimatedByteCount
      growth += max(
        0,
        96 + metadata + (previous?.incoming.count ?? 0) * 160
          - (previous?.bytes ?? 0))
      if let parent = process.parent, parent.pid > 0,
        previous == nil || previous?.process.parent != parent
      {
        growth += 160
      }
      if let responsible = process.responsible, responsible != process.key,
        previous == nil || previous?.process.responsible != responsible
      {
        growth += 160
      }
    }
    if let source = event.source, let target = event.target,
      event.eventType == "NOTIFY_FORK"
        || (event.eventType == "NOTIFY_EXEC" && source.key.pid == target.key.pid
          && source.key != target.key)
    {
      growth += 160
    }
    return growth
  }

  private mutating func observe(
    _ process: LineageProcess, at: Date, machTime: UInt64?, protected: Set<LineageProcessKey>,
    preserveMetadata: Bool
  ) {
    let previous = entries[process.key]
    var next = previous ?? Entry(process: process, ordinal: observationCount)
    if let old = previous?.machTime, let machTime, machTime < old { return }
    next.process = process
    if preserveMetadata, let old = previous?.process {
      next.process.executablePath = old.executablePath
      next.process.pathWasTruncated = old.pathWasTruncated
      next.process.signingIdentifier = old.signingIdentifier
      next.process.teamIdentifier = old.teamIdentifier
      next.process.codeSigningFlags = old.codeSigningFlags
      next.process.isPlatformBinary = old.isPlatformBinary
    }
    next.process.exitedAt = previous?.process.exitedAt ?? process.exitedAt
    next.process.supersededObservedAt =
      previous?.process.supersededObservedAt
      ?? process.supersededObservedAt
    next.process.supersededBy = previous?.process.supersededBy ?? process.supersededBy
    next.machTime = machTime ?? previous?.machTime
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

  private mutating func markExited(_ key: LineageProcessKey, at: Date) {
    guard entries[key] != nil, entries[key]?.process.exitedAt == nil else { return }
    entries[key]?.process.exitedAt = at
    recoveryChanges &+= 1
  }

  private mutating func observeCurrent(
    _ key: LineageProcessKey, at: Date, machTime: UInt64?
  ) {
    guard let machTime else { return }
    if let entry = entries[key] {
      guard entry.process.exitedAt == nil, entry.process.supersededBy == nil else { return }
      if let previousTime = entry.machTime, machTime < previousTime { return }
    }
    if let previous = latestByPID[key.pid], previous != key,
      let old = entries[previous], let oldTime = old.machTime
    {
      guard machTime > oldTime || (machTime == oldTime && old.process.exitedAt != nil) else {
        return
      }
      if old.process.exitedAt == nil && old.process.supersededBy == nil {
        entries[previous]?.process.supersededObservedAt = at
        entries[previous]?.process.supersededBy = key
        recoveryChanges &+= 1
        reclamation.supersededExecutions &+= 1
      }
    }
    if entries[key] != nil { latestByPID[key.pid] = key }
  }

  private mutating func makeRoom(for bytes: Int, protected: Set<LineageProcessKey>) -> Bool {
    if byteCount + max(bytes, 0) <= targetBytes { lastAttempt = nil }
    guard bytes > maximumBytes - byteCount else { return true }
    // Impossible requests must not repeatedly evict useful records.
    guard bytes <= maximumBytes else { return false }
    let now = clock()
    if let attempt = lastAttempt {
      let elapsed = now >= attempt.time ? now - attempt.time : 0
      guard elapsed >= 1_000_000_000,
        recoveryChanges - attempt.changes >= 64
          || observationCount - attempt.observations >= 4_096
          || elapsed >= 5_000_000_000
      else {
        reclamation.suppressed &+= 1
        return false
      }
    }
    reclamation.passes &+= 1
    let before = byteCount
    var reachable = protected
    var stack = Array(protected)
    for (key, entry) in entries
    where entry.process.exitedAt == nil && entry.process.supersededBy == nil {
      if reachable.insert(key).inserted { stack.append(key) }
    }
    while let key = stack.popLast() {
      for relation in entries[key]?.incoming ?? [] {
        if reachable.insert(relation.source).inserted { stack.append(relation.source) }
      }
    }
    var disposable: [(ordinal: UInt64, key: LineageProcessKey, bytes: Int)] = []
    for (key, entry) in entries where !reachable.contains(key) {
      disposable.append((entry.ordinal, key, entry.bytes))
    }
    disposable.sort {
      if $0.ordinal != $1.ordinal { return $0.ordinal < $1.ordinal }
      if $0.key.pid != $1.key.pid { return $0.key.pid < $1.key.pid }
      return $0.key.version < $1.key.version
    }
    for candidate in disposable {
      entries.removeValue(forKey: candidate.key)
      if latestByPID[candidate.key.pid] == candidate.key {
        latestByPID.removeValue(forKey: candidate.key.pid)
      }
      byteCount -= candidate.bytes
      if byteCount + bytes <= targetBytes { break }
    }
    reclamation.reclaimedBytes &+= UInt64(before - byteCount)
    let finished = clock()
    reclamation.elapsedNanoseconds &+= finished >= now ? finished - now : 0
    lastAttempt =
      byteCount + bytes <= targetBytes
      ? nil
      : (finished, observationCount, recoveryChanges)
    return bytes <= maximumBytes - byteCount
  }

  func omittedSnapshot(for event: LineageObservation, reason: String) -> ProcessLineageSnapshot {
    ProcessLineageSnapshot(
      bootIdentifier: bootIdentifier, collectionIdentifier: collectionIdentifier,
      collectionStartedAt: startedAt, capturedAt: event.timestamp, actor: event.actor?.key,
      responsible: event.actor?.responsible,
      issues: [LineageIssue(reason: reason, at: event.timestamp)])
  }

  func snapshot(
    for event: LineageObservation, reserve: (Int) -> Bool = { _ in true }
  ) -> ProcessLineageSnapshot {
    var snapshot = ProcessLineageSnapshot(
      bootIdentifier: bootIdentifier, collectionIdentifier: collectionIdentifier,
      collectionStartedAt: startedAt, capturedAt: event.timestamp, actor: event.actor?.key,
      responsible: event.actor?.responsible, issues: status.issues
    )
    var accounted = snapshot.estimatedByteCount
    func grow(_ bytes: Int) -> Bool {
      accounted += bytes
      return accounted <= 10 * 1_024 * 1_024 && reserve(accounted)
    }
    guard grow(256) else { return omittedSnapshot(for: event, reason: "historyBudgetExceeded") }
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
            guard grow(entry.process.estimatedByteCount + entry.incoming.count * 160 + 256) else {
              return omittedSnapshot(for: event, reason: "historyBudgetExceeded")
            }
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
            guard grow(800) else {
              return omittedSnapshot(for: event, reason: "historyBudgetExceeded")
            }
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
        // Charge traversal scratch before pushing, including duplicate edges.
        guard grow(128 + (entries[key]?.incoming.count ?? 0) * 64) else {
          return omittedSnapshot(for: event, reason: "historyBudgetExceeded")
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
