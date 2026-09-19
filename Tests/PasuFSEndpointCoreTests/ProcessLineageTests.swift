import Foundation
import PasuFSConfiguration
import XCTest
import os

@testable import PasuFSEndpointCore

final class ProcessLineageTests: XCTestCase {
  private let time = Date(timeIntervalSince1970: 1_800_000_000)

  private func process(
    _ pid: Int32, version: Int32 = 1, parent: LineageProcessKey? = nil,
    responsible: LineageProcessKey? = nil, path: String? = nil
  ) -> LineageProcess {
    let key = LineageProcessKey(pid: pid, version: version)
    return LineageProcess(
      key: key, executablePath: path ?? "/example/tool\(pid)",
      signingIdentifier: "example.tool\(pid)",
      teamIdentifier: "EXAMPLE", startTime: time, parent: parent, responsible: responsible ?? key,
      originalParentPID: parent?.pid ?? (pid == 1 ? 0 : nil), observedAt: time)
  }

  private func event(
    _ type: String = "AUTH_OPEN", _ source: LineageProcess,
    target: LineageProcess? = nil, sequence: UInt64? = nil
  ) -> LineageObservation {
    LineageObservation(
      eventType: type, timestamp: time, globalSequence: sequence, source: source, target: target)
  }

  private func graph(maximumBytes: Int = 128 * 1_024 * 1_024) -> ProcessLineageGraph {
    ProcessLineageGraph(bootIdentifier: "example-boot", startedAt: time, maximumBytes: maximumBytes)
  }

  func testFull256GenerationAncestryAnd1024ExecutableReplacements() throws {
    var graph = graph()
    let root = process(1)
    var parent = root
    for pid: Int32 in 2...257 {
      let child = process(pid, parent: parent.key, responsible: root.key)
      graph.observe(event("NOTIFY_FORK", parent, target: child))
      parent = child
    }
    for version: Int32 in 2...1_025 {
      let next = process(
        parent.key.pid, version: version, parent: parent.parent, responsible: root.key)
      graph.observe(event("NOTIFY_EXEC", parent, target: next))
      parent = next
    }
    let snapshot = graph.snapshot(for: event("AUTH_OPEN", parent))
    XCTAssertEqual(snapshot.processes.count, 1_281)
    XCTAssertEqual(snapshot.actorAncestryKeys.count, 1_281)
    XCTAssertEqual(snapshot.relations.filter { $0.kind == .exec }.count, 1_024)
    XCTAssertEqual(snapshot.relations.filter { $0.kind == .fork }.count, 256)
    XCTAssertFalse(snapshot.issues.contains { $0.reason == "cycle" || $0.reason == "unobserved" })
    XCTAssertEqual(snapshot.processes.first?.key, root.key)
    XCTAssertEqual(snapshot.processes.last?.key, parent.key)
    let encoded = try JSONEncoder().encode(snapshot)
    XCTAssertEqual(try JSONDecoder().decode(ProcessLineageSnapshot.self, from: encoded), snapshot)
  }

  func testResponsibilityIsNotInjectedIntoParentAncestry() {
    var graph = graph()
    let launch = process(1)
    let app = process(
      20, parent: launch.key, path: "/Applications/Example.app/Contents/MacOS/Example")
    let service = process(30, parent: launch.key, responsible: app.key)
    graph.observe(event("NOTIFY_FORK", launch, target: app))
    graph.observe(event("NOTIFY_FORK", launch, target: service))
    let snapshot = graph.snapshot(for: event("AUTH_OPEN", service))
    XCTAssertEqual(snapshot.responsible, app.key)
    XCTAssertFalse(snapshot.actorAncestryKeys.contains(app.key))
    XCTAssertTrue(snapshot.processes.contains { $0.key == app.key })
    let record = EndpointEventRecord(
      processLineage: snapshot, eventType: "AUTH_OPEN",
      executablePath: service.executablePath, policyDecision: "allow", kernelResponse: "allow")
    XCTAssertEqual(record.processPreview, "Example > tool30")
  }

  func testUnknownIdentityNeverUsesReusedPID() {
    var graph = graph()
    let original = process(40, version: 2)
    let reused = process(40, version: 9, path: "/example/unrelated")
    let child = process(50, parent: original.key, responsible: original.key)
    graph.observe(event("AUTH_OPEN", reused))
    graph.observe(event("AUTH_OPEN", child))
    let snapshot = graph.snapshot(for: event("AUTH_OPEN", child))
    XCTAssertEqual(snapshot.processes.first { $0.key == original.key }?.executablePath, nil)
    XCTAssertFalse(snapshot.processes.contains { $0.key == reused.key })
    XCTAssertTrue(
      snapshot.issues.contains { $0.reason == "unobserved" && $0.process == original.key })
  }

  func testParentExitReparentingAndHistoricalSnapshotArePreserved() {
    var graph = graph()
    let launch = process(1)
    let parent = process(2, parent: launch.key)
    var child = process(3, parent: parent.key, responsible: parent.key)
    graph.observe(event("NOTIFY_FORK", launch, target: parent))
    graph.observe(event("NOTIFY_FORK", parent, target: child))
    let earlier = graph.snapshot(for: event("AUTH_OPEN", child))
    graph.observe(event("NOTIFY_EXIT", parent))
    child.parent = launch.key
    child.responsible = child.key
    graph.observe(event("AUTH_OPEN", child))
    let later = graph.snapshot(for: event("AUTH_OPEN", child))
    XCTAssertEqual(earlier.responsible, parent.key)
    XCTAssertNil(earlier.processes.first { $0.key == parent.key }?.exitedAt)
    XCTAssertEqual(later.responsible, child.key)
    XCTAssertEqual(later.processes.first { $0.key == parent.key }?.exitedAt, time)
    XCTAssertTrue(
      later.relations.contains {
        $0.kind == .fork && $0.source == parent.key && $0.target == child.key
      })
    XCTAssertTrue(
      later.relations.contains {
        $0.kind == .parent && $0.source == launch.key && $0.target == child.key
      })
    XCTAssertEqual(earlier.processes.first { $0.key == child.key }?.parent, parent.key)
  }

  func testSequenceGapsCountOnceAcrossEventTypes() {
    let sink = LineageTestSink()
    let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: sink)
    var first = event("AUTH_OPEN", process(1), sequence: 1)
    first.sequence = 1
    tracker.submit(first, record: nil)
    var next = event("NOTIFY_EXIT", process(2), sequence: 5)
    next.sequence = 4
    tracker.submit(next, record: record())
    tracker.close()
    XCTAssertEqual(tracker.status.issues.first { $0.reason == "kernelEventLoss" }?.count, 3)
    XCTAssertEqual(
      sink.records[0].processLineage?.issues.first { $0.reason == "kernelEventLoss" }?.count, 3)
  }

  func testPerTypeSequencesDoNotCrossCompareAndVersionGapsStayVisible() {
    let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: LineageTestSink())
    tracker.submit(
      LineageObservation(eventType: "NOTIFY_FORK", timestamp: time, sequence: 20), record: nil)
    tracker.submit(
      LineageObservation(eventType: "NOTIFY_EXEC", timestamp: time, sequence: 100), record: nil)
    tracker.submit(
      LineageObservation(
        eventType: "NOTIFY_FORK", timestamp: time, sequence: 23,
        issues: ["versionUnavailable", "decodeError"]), record: nil)
    tracker.close()
    XCTAssertEqual(tracker.status.issues.first { $0.reason == "kernelEventLoss" }?.count, 2)
    XCTAssertTrue(tracker.status.issues.contains { $0.reason == "decodeError" })
    XCTAssertTrue(tracker.status.issues.contains { $0.reason == "versionUnavailable" })
  }

  func testASecondCollectionDoesNotReuseTheFirstCollectionsGraph() {
    var first = graph()
    let child = process(2, parent: process(1).key)
    first.observe(event("NOTIFY_FORK", process(1), target: child))
    var second = graph()
    second.observe(event("AUTH_OPEN", child))
    let snapshot = second.snapshot(for: event("AUTH_OPEN", child))
    XCTAssertNotEqual(first.collectionIdentifier, snapshot.collectionIdentifier)
    XCTAssertTrue(snapshot.issues.contains { $0.reason == "unobserved" })
  }

  func testResourceBudgetPreservesLiveAncestryAndRejectsAdditionalData() {
    var graph = graph(maximumBytes: 2_000)
    let parent = process(1)
    let child = process(2, parent: parent.key)
    graph.observe(event("NOTIFY_FORK", parent, target: child))
    graph.observe(event("NOTIFY_EXIT", parent))
    for pid: Int32 in 3...30 { graph.observe(event("AUTH_OPEN", process(pid))) }
    let snapshot = graph.snapshot(for: event("AUTH_OPEN", child))
    XCTAssertLessThanOrEqual(graph.byteCount, 2_000)
    XCTAssertEqual(
      snapshot.processes.first { $0.key == parent.key }?.executablePath, parent.executablePath)
    XCTAssertTrue(snapshot.issues.contains { $0.reason == "resourceLimit" })
  }

  func testUnreferencedEndedExecutionsCanBeReclaimed() {
    var graph = graph(maximumBytes: 2_000)
    for pid: Int32 in 1...50 {
      graph.observe(event("NOTIFY_EXIT", process(pid)))
    }
    XCTAssertLessThanOrEqual(graph.byteCount, 2_000)
    XCTAssertFalse(graph.status.issues.contains { $0.reason == "resourceLimit" })
    XCTAssertLessThan(graph.status.retainedProcessCount, 10)
  }

  func testCyclesAndInvalidExecAreExplicitAndDoNotLoop() {
    var graph = graph()
    let a = process(2, parent: LineageProcessKey(pid: 3, version: 1))
    let b = process(3, parent: a.key)
    graph.observe(event("AUTH_OPEN", a))
    graph.observe(event("AUTH_OPEN", b))
    graph.observe(event("NOTIFY_EXEC", a, target: b))
    let snapshot = graph.snapshot(for: event("AUTH_OPEN", b))
    XCTAssertEqual(snapshot.processes.count, 2)
    XCTAssertTrue(snapshot.issues.contains { $0.reason == "cycle" })
    XCTAssertTrue(snapshot.issues.contains { $0.reason == "executionMismatch" })
    XCTAssertFalse(snapshot.relations.contains { $0.kind == .exec })
  }

  func testQueueOverflowAndRecoveredRecordExplainTheGap() {
    let sink = LineageTestSink()
    let budget = AuditWorkBudget(maximumEntries: 4, maximumBytes: 8_192)
    let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: sink, budget: budget)
    XCTAssertTrue(budget.acquire(bytes: 8_192))
    tracker.submit(event("AUTH_OPEN", process(1)), record: nil)
    XCTAssertEqual(tracker.status.issues.first { $0.reason == "queueOverflow" }?.count, 1)
    budget.release(bytes: 8_192)
    tracker.submit(event("AUTH_OPEN", process(1)), record: record())
    tracker.close()
    XCTAssertFalse(tracker.status.isTracking)
    XCTAssertEqual(sink.records.count, 1)
    XCTAssertTrue(
      sink.records[0].processLineage?.issues.contains { $0.reason == "queueOverflow" } == true)
  }

  func testInternalQueueLossIsNotReportedAsKernelLoss() {
    let sink = LineageTestSink()
    let budget = AuditWorkBudget(maximumEntries: 4, maximumBytes: 8_192)
    let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: sink, budget: budget)
    tracker.submit(event("AUTH_OPEN", process(1), sequence: 1), record: nil)
    tracker.flush()
    XCTAssertTrue(budget.acquire(bytes: 8_192))
    tracker.submit(event("AUTH_OPEN", process(1), sequence: 2), record: nil)
    budget.release(bytes: 8_192)
    tracker.submit(event("AUTH_OPEN", process(1), sequence: 3), record: record())
    tracker.close()
    XCTAssertEqual(tracker.status.issues.first { $0.reason == "queueOverflow" }?.count, 1)
    XCTAssertFalse(tracker.status.issues.contains { $0.reason == "kernelEventLoss" })
    XCTAssertFalse(
      sink.records[0].processLineage!.issues.contains { $0.reason == "kernelEventLoss" })
    XCTAssertEqual(
      tracker.status.issues.first { $0.reason == "queueOverflow" }?.firstObservedAt, time)
  }

  func testKernelLossOnRejectedSubmissionIsRetainedSeparately() {
    let sink = LineageTestSink()
    let budget = AuditWorkBudget(maximumEntries: 4, maximumBytes: 8_192)
    let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: sink, budget: budget)
    tracker.submit(event("AUTH_OPEN", process(1), sequence: 1), record: nil)
    tracker.flush()
    XCTAssertTrue(budget.acquire(bytes: 8_192))
    tracker.submit(event("AUTH_OPEN", process(1), sequence: 5), record: nil)
    budget.release(bytes: 8_192)
    tracker.submit(event("AUTH_OPEN", process(1), sequence: 6), record: record())
    tracker.close()
    XCTAssertEqual(tracker.status.issues.first { $0.reason == "kernelEventLoss" }?.count, 3)
    XCTAssertEqual(tracker.status.issues.first { $0.reason == "queueOverflow" }?.count, 1)
    XCTAssertEqual(
      sink.records[0].processLineage?.issues.first { $0.reason == "kernelEventLoss" }?.count, 3)
  }

  func testLegacyLossCountsStayReadableAndAreMarkedAsPossiblyOverlapping() throws {
    var snapshot = graph().snapshot(for: event("AUTH_OPEN", process(1)))
    snapshot.issues = [
      LineageIssue(reason: "kernelEventLoss", count: 3, at: time),
      LineageIssue(reason: "queueOverflow", count: 3, at: time),
    ]
    let data = try JSONEncoder().encode(snapshot)
    var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    object.removeValue(forKey: "deliveryAccountingVersion")
    let old = try JSONDecoder().decode(
      ProcessLineageSnapshot.self, from: JSONSerialization.data(withJSONObject: object))
    XCTAssertNil(old.deliveryAccountingVersion)
    XCTAssertNotNil(
      LineageIssue.lossAccountingWarning(version: old.deliveryAccountingVersion, issues: old.issues)
    )
    XCTAssertNil(
      LineageIssue.lossAccountingWarning(
        version: snapshot.deliveryAccountingVersion, issues: snapshot.issues))
    XCTAssertEqual(old.issues, snapshot.issues)
  }

  func testCollectorRetainsOrderingAndImmutableSnapshotsWithoutPolicies() {
    let sink = LineageTestSink()
    let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: sink)
    let first = process(2, parent: process(1).key)
    let second = process(2, version: 2, parent: process(1).key)
    tracker.submit(event("NOTIFY_FORK", process(1), target: first), record: nil)
    tracker.submit(event("AUTH_OPEN", first), record: record())
    tracker.submit(event("NOTIFY_EXEC", first, target: second), record: nil)
    tracker.submit(event("AUTH_OPEN", second), record: record())
    tracker.close()
    XCTAssertEqual(sink.records.count, 2)
    XCTAssertEqual(sink.records[0].processLineage?.processes.count, 2)
    XCTAssertEqual(sink.records[1].processLineage?.processes.count, 3)
    XCTAssertEqual(sink.records[0].processLineage?.actor, first.key)
  }

  func testOversizedHistoryProducesReadableExplicitFailureWithinFileLimit() throws {
    var graph = graph()
    let huge = process(2, path: "/example/" + String(repeating: "x", count: 10_000))
    graph.observe(event("AUTH_OPEN", huge))
    var original = record()
    original.processLineage = graph.snapshot(for: event("AUTH_OPEN", huge))
    let bounded = try JSONLineEventLogger.recordWithinLimit(original, maximumBytes: 2_000)
    XCTAssertEqual(bounded.processLineage?.processes, [])
    XCTAssertEqual(bounded.processLineage?.issues.first?.reason, "oversizedRecord")
    XCTAssertEqual(bounded.eventIdentifier, original.eventIdentifier)
    XCTAssertEqual(bounded.targetPath, original.targetPath)
    XCTAssertLessThan(try JSONEncoder().encode(bounded).count, 2_000)
  }

  func testMissingResponsibilityDoesNotReuseHistoricalResponsible() {
    var graph = graph()
    var actor = process(2, responsible: process(1).key)
    graph.observe(event("AUTH_OPEN", actor))
    actor.responsible = nil
    graph.observe(event("AUTH_OPEN", actor))
    let snapshot = graph.snapshot(for: event("AUTH_OPEN", actor))
    XCTAssertNil(snapshot.responsible)
    var record = record()
    record.processLineage = snapshot
    XCTAssertTrue(record.processPreview.hasPrefix("Unknown >"))
  }

  private func record() -> EndpointEventRecord {
    EndpointEventRecord(
      timestamp: time, eventType: "AUTH_OPEN", processID: 2,
      executablePath: "/example/tool2", targetPath: "/example/file",
      policyDecision: "allowed", kernelResponse: "allow")
  }
}

private final class LineageTestSink: EndpointEventSink, Sendable {
  private let storage = OSAllocatedUnfairLock(initialState: [EndpointEventRecord]())
  var records: [EndpointEventRecord] { storage.withLock { $0 } }
  func record(_ event: EndpointEventRecord) { storage.withLock { $0.append(event) } }
}
