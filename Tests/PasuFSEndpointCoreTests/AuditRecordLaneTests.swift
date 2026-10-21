import Dispatch
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest

@testable import PasuFSEndpointCore

/// The denied-request lane and the combining of repeated requests into one record.
final class AuditRecordLaneTests: XCTestCase {
  private let start = Date(timeIntervalSince1970: 1_800_000_000)
  private let setIdentifier = UUID(uuidString: "00000000-0000-0000-0000-000000000099")!
  private let protectedID = UUID(uuidString: "00000000-0000-0000-0000-000000000001")!
  private let auditID = UUID(uuidString: "00000000-0000-0000-0000-000000000002")!

  private var document: PolicySetDocument {
    PolicySetDocument(
      setIdentifier: setIdentifier, revision: 3,
      policies: [
        DirectoryPolicy(
          id: protectedID, name: "Protected", mode: .protection, policyType: .whitelist,
          protectedRootPath: "/Users/example/Protected", rules: []),
        DirectoryPolicy(
          id: auditID, name: "Audit", mode: .audit, policyType: .whitelist,
          protectedRootPath: "/Users/example/Audit", rules: []),
      ])
  }

  // MARK: - Fixtures

  private func process(_ pid: Int32, version: Int32 = 1) -> LineageProcess {
    LineageProcess(key: .init(pid: pid, version: version), executablePath: "/example/tool")
  }

  private func observation(_ pid: Int32, version: Int32 = 1, at offset: TimeInterval = 0)
    -> LineageObservation
  {
    LineageObservation(
      eventType: "AUTH_OPEN", timestamp: start.addingTimeInterval(offset),
      source: process(pid, version: version))
  }

  /// A file request inside the Protection policy, or inside the Audit policy with `audit`, where
  /// macOS is always told to allow and "deny" is a prediction.
  private func request(
    _ response: String, pid: Int32 = 7, version: Int32 = 1, at offset: TimeInterval = 0,
    target: String = "/Users/example/Protected/a.txt", flags: Int32 = 1, audit: Bool = false,
    eventType: String = "AUTH_OPEN", lineage: Bool = true
  ) -> EndpointEventRecord {
    let time = start.addingTimeInterval(offset)
    let evaluation: PolicyEvaluationRecord
    if audit {
      evaluation = PolicyEvaluationRecord(
        policyIdentifier: auditID, policyName: "Audit", mode: .audit, policyType: .whitelist,
        match: .none, decision: response == "deny" ? .wouldDeny : .wouldAllow)
    } else {
      evaluation = PolicyEvaluationRecord(
        policyIdentifier: protectedID, policyName: "Protected", mode: .protection,
        policyType: .whitelist, match: .none, decision: response == "deny" ? .deny : .allow)
    }
    let key = LineageProcessKey(pid: pid, version: version)
    return EndpointEventRecord(
      processLineage: lineage
        ? ProcessLineageSnapshot(
          bootIdentifier: "example", collectionIdentifier: UUID(), collectionStartedAt: start,
          capturedAt: time, actor: key, responsible: key,
          processes: [LineageProcess(key: key, executablePath: "/example/tool")])
        : nil,
      timestamp: time, policySetIdentifier: setIdentifier, policyRevision: 3,
      eventType: eventType, processID: pid, executablePath: "/example/tool",
      targetPath: target, requestedFlags: flags,
      policyDecision: audit ? "audit-only" : (response == "deny" ? "denied" : "allowed"),
      kernelResponse: audit ? "allow" : response, policyEvaluations: [evaluation])
  }

  private func withStore(
    budget: AuditWorkBudget? = nil,
    _ body: (PolicyAuditLogStore, URL) throws -> Void
  ) throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try PolicyAuditLogStore(directoryURL: directory, budget: budget)
    defer { store.flushAndClose() }
    store.updatePolicySet(document)
    try body(store, directory)
  }

  /// Log times are saved to the second.
  private func saved(_ offset: TimeInterval) -> Date {
    Date(timeIntervalSince1970: (start.timeIntervalSince1970 + offset).rounded(.down))
  }

  private func isMinimal(_ record: AuditEventRecord) -> Bool {
    record.processLineage?.issues.contains {
      ["historyOmitted", "historyBudgetExceeded"].contains($0.reason)
    } != false
  }

  /// Every saved line of the global log, read from disk without saving waiting records.
  private func savedRecords(_ directory: URL) throws -> [AuditEventRecord] {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    let url = directory.appendingPathComponent("endpoint-events.jsonl")
    guard FileManager.default.fileExists(atPath: url.path) else { return [] }
    return try Data(contentsOf: url).split(separator: 0x0A).map {
      try decoder.decode(AuditEventRecord.self, from: Data($0))
    }
  }

  private func blockedTracker(_ store: PolicyAuditLogStore, budget: AuditWorkBudget)
    -> (ProcessLineageTracker, DispatchSemaphore)
  {
    let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: store, budget: budget)
    let entered = DispatchSemaphore(value: 0)
    let proceed = DispatchSemaphore(value: 0)
    tracker.enqueueBarrier {
      entered.signal()
      proceed.wait()
    }
    XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
    return (tracker, proceed)
  }

  // MARK: - Lanes

  func testDeniedLaneIsUsedOnlyByDeniedRequests() throws {
    let budget = AuditWorkBudget(limits: [
      .general: .init(entries: 2, bytes: 1_000_000),
      .denied: .init(entries: 2, bytes: 1_000_000),
    ])
    let general = try XCTUnwrap(budget.reserve(bytes: 10))
    let second = try XCTUnwrap(budget.reserve(bytes: 10))
    XCTAssertNil(budget.reserve(bytes: 10))
    let denied = try XCTUnwrap(budget.reserve(bytes: 10, lane: .denied))
    XCTAssertEqual(budget.usage(of: .denied).entries, 1)
    XCTAssertEqual(budget.usage(of: .general).entries, 2)
    // No lifecycle or minimal-record lane exists here, and the denied lane is not one of them.
    XCTAssertNil(budget.reserve(bytes: 10, lane: .lifecycle))
    XCTAssertNil(budget.reserve(bytes: 10, lane: .audit))
    for item in [general, second, denied] { item.release() }
    XCTAssertEqual(budget.usage, .init())

    XCTAssertEqual(request("deny").auditLane, .denied)
    XCTAssertEqual(request("allow").auditLane, .general)
    XCTAssertEqual(request("deny", audit: true).auditLane, .general)
    var failed = request("deny")
    failed.kernelResponse = "response-error"
    XCTAssertEqual(failed.auditLane, .denied)

    let partitioned = AuditWorkBudget.partitioned()
    let lane = (0..<AuditWorkBudget.deniedLaneEntries).compactMap { _ in
      partitioned.reserve(bytes: 1, lane: .denied)
    }
    XCTAssertEqual(lane.count, 512)
    XCTAssertNil(partitioned.reserve(bytes: 1, lane: .denied))
    XCTAssertNotNil(partitioned.reserve(bytes: 1))
  }

  func testLanesStayIsolatedInBothDirections() throws {
    let budget = AuditWorkBudget(limits: [
      .general: .init(entries: 3, bytes: 1_000_000),
      .lifecycle: .init(entries: 1, bytes: 1_000_000),
      .audit: .init(entries: 1, bytes: 1_000_000),
      .denied: .init(entries: 3, bytes: 1_000_000),
    ])
    try withStore(budget: budget) { store, directory in
      let (tracker, proceed) = blockedTracker(store, budget: budget)
      // Denied requests for different files fill only their own lane.
      for index in 0..<5 {
        tracker.submit(
          observation(10),
          record: request("deny", pid: 10, target: "/Users/example/Protected/d\(index)"))
      }
      // Allowed requests of different processes still find the shared lanes.
      for pid: Int32 in 20..<26 {
        tracker.submit(observation(pid), record: request("allow", pid: pid))
      }
      tracker.submit(
        LineageObservation(eventType: "NOTIFY_EXIT", timestamp: start, source: process(30)),
        record: nil)
      XCTAssertEqual(budget.usage(of: .denied).entries, 3)
      XCTAssertEqual(budget.usage(of: .general).entries, 3)
      XCTAssertEqual(budget.usage(of: .audit).entries, 1)
      XCTAssertEqual(budget.usage(of: .lifecycle).entries, 1)
      proceed.signal()
      tracker.close()
      store.flushOpenRecords()
      let rows = try savedRecords(directory)
      XCTAssertEqual(
        rows.filter { $0.kernelResponse == "deny" }.map(\.targetPath),
        [
          "/Users/example/Protected/d0", "/Users/example/Protected/d1",
          "/Users/example/Protected/d2",
        ])
      XCTAssertEqual(rows.filter { $0.kernelResponse == "allow" }.count, 4)
      let metrics = store.deliveryMetrics
      XCTAssertEqual(metrics.deniedLaneDrops, 2)
      XCTAssertEqual(metrics.sharedLaneDrops, 2)
      XCTAssertEqual(metrics.admissionDrops, 4)
      XCTAssertEqual(store.droppedEventCount, 4)
    }
    XCTAssertEqual(budget.usage, .init())
  }

  func testAllowedFloodCannotDisplaceDeniedRecords() throws {
    let budget = AuditWorkBudget.partitioned()
    try withStore(budget: budget) { store, directory in
      let (tracker, proceed) = blockedTracker(store, budget: budget)
      for index in 0..<2_000 {
        // Allowed requests from many processes, so none of them combine.
        let pid = Int32(1_000 + index)
        tracker.submit(observation(pid), record: request("allow", pid: pid))
        if index % 20 == 0 {
          tracker.submit(
            observation(9),
            record: request("deny", pid: 9, target: "/Users/example/Protected/f\(index)"))
        }
      }
      proceed.signal()
      tracker.close()
      store.flushOpenRecords()
      let rows = try savedRecords(directory)
      let denied = rows.filter { $0.kernelResponse == "deny" }
      XCTAssertEqual(denied.count, 100)
      XCTAssertFalse(denied.contains(where: isMinimal))
      let metrics = store.deliveryMetrics
      XCTAssertEqual(metrics.deniedLaneDrops, 0)
      // The partitioned budget holds 896 records in the general lane and 64 in the audit lane:
      // 896 allowed records are kept in full, 64 more without history, and the rest are dropped.
      XCTAssertEqual(metrics.sharedLaneDrops, 2_000 - 896 - 64)
      XCTAssertEqual(rows.filter { $0.kernelResponse == "allow" }.count, 896 + 64)
    }
    XCTAssertEqual(budget.usage, .init())
  }

  // MARK: - Combining

  func testAllowedRequestsOfOneProcessCombineWhateverTheirTarget() throws {
    try withStore { store, directory in
      store.record(request("allow", at: 0, target: "/Users/example/Protected/a.txt"))
      store.record(request("allow", at: 0.2, target: "/Users/example/Protected/b.txt"))
      store.record(
        request(
          "allow", at: 0.5, target: "/Users/example/Protected/c.txt", eventType: "AUTH_CREATE")
      )
      XCTAssertTrue(try savedRecords(directory).isEmpty)
      let rows = try store.readAuditLog(maximumLineCount: 10).records
      XCTAssertEqual(rows.count, 1)
      let row = try XCTUnwrap(rows.first)
      XCTAssertEqual(row.requestCount, 3)
      XCTAssertEqual(row.representedRequestCount, 3)
      XCTAssertEqual(row.timestamp, start)
      XCTAssertEqual(row.lastTimestamp, saved(0.5))
      XCTAssertEqual(row.targetPath, "/Users/example/Protected/a.txt")
      XCTAssertTrue(row.combinesAnyTarget)
      let policy = try store.readPolicyAuditLog(
        PolicyAuditLogRequest(
          key: PolicyAuditLogKey(setIdentifier: setIdentifier, policyIdentifier: protectedID)))
      XCTAssertEqual(policy.records.map(\.requestCount), [3])
      XCTAssertEqual(store.deliveryMetrics.combinedAllowedRequests, 2)
      XCTAssertEqual(store.deliveryMetrics.combinedDeniedRequests, 0)
    }
  }

  func testIdenticalDeniedRepeatsCombineAndKeepTheFirstHistory() throws {
    let budget = AuditWorkBudget.partitioned()
    try withStore(budget: budget) { store, directory in
      let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: store, budget: budget)
      var parent = process(1)
      parent.executablePath = "/example/launcher"
      var child = process(7)
      child.parent = parent.key
      tracker.submit(
        LineageObservation(
          eventType: "NOTIFY_FORK", timestamp: start, source: parent, target: child),
        record: nil)
      for index in 0..<1_000 {
        let offset = Double(index) / 2_000
        tracker.submit(
          LineageObservation(
            eventType: "AUTH_OPEN", timestamp: start.addingTimeInterval(offset), source: child),
          record: request("deny", at: offset, lineage: false))
      }
      tracker.close()
      let rows = try store.readAuditLog(maximumLineCount: 10).records
      XCTAssertEqual(rows.count, 1)
      let row = try XCTUnwrap(rows.first)
      XCTAssertEqual(row.requestCount, 1_000)
      XCTAssertEqual(row.timestamp, start)
      XCTAssertEqual(row.lastTimestamp, saved(999.0 / 2_000))
      XCTAssertFalse(row.combinesAnyTarget)
      // The first request's history is kept whole.
      XCTAssertEqual(row.processLineage?.actor, LineageProcessKey(pid: 7, version: 1))
      XCTAssertEqual(
        Set(row.processLineage?.processes.map(\.key) ?? []),
        [LineageProcessKey(pid: 1, version: 1), LineageProcessKey(pid: 7, version: 1)])
      XCTAssertFalse(isMinimal(row))
      XCTAssertEqual(store.deliveryMetrics.combinedDeniedRequests, 999)
      XCTAssertEqual(store.deliveryMetrics.deniedLaneDrops, 0)
      XCTAssertEqual(try savedRecords(directory).count, 1)
    }
    XCTAssertEqual(budget.usage, .init())
  }

  func testDeniedRequestsThatDifferStaySeparateInOrder() throws {
    try withStore { store, _ in
      store.record(request("deny", at: 0, target: "/Users/example/Protected/a.txt"))
      store.record(request("deny", at: 0.1, target: "/Users/example/Protected/a.txt"))
      store.record(request("deny", at: 0.2, target: "/Users/example/Protected/b.txt"))
      store.record(request("deny", at: 0.3, target: "/Users/example/Protected/a.txt"))
      store.record(request("deny", at: 0.4, target: "/Users/example/Protected/a.txt", flags: 3))
      store.record(
        request("deny", at: 0.5, target: "/Users/example/Protected/a.txt", eventType: "AUTH_UNLINK")
      )
      // An Audit prediction to deny keeps its target too.
      store.record(request("deny", at: 0.6, target: "/Users/example/Audit/x", audit: true))
      store.record(request("deny", at: 0.7, target: "/Users/example/Audit/y", audit: true))
      let rows = try store.readAuditLog(maximumLineCount: 20).records
      XCTAssertEqual(
        rows.map(\.targetPath),
        [
          "/Users/example/Protected/a.txt", "/Users/example/Protected/b.txt",
          "/Users/example/Protected/a.txt", "/Users/example/Protected/a.txt",
          "/Users/example/Protected/a.txt", "/Users/example/Audit/x", "/Users/example/Audit/y",
        ])
      XCTAssertEqual(rows.map(\.representedRequestCount), [2, 1, 1, 1, 1, 1, 1])
      XCTAssertEqual(rows.map(\.kernelResponse).last, "allow")
      XCTAssertFalse(try XCTUnwrap(rows.last).combinesAnyTarget)
    }
  }

  /// Denied metadata changes go to the denied lane and are combined only with repeats of the
  /// same kind on the same target, like other denied requests.
  func testDeniedMetadataChangesKeepTheirKind() throws {
    try withStore { store, _ in
      let target = "/Users/example/Protected/a.txt"
      for (offset, eventType) in [
        "AUTH_SETMODE", "AUTH_SETMODE", "AUTH_SETEXTATTR", "AUTH_DELETEEXTATTR", "AUTH_UTIMES",
        "AUTH_UTIMES", "AUTH_SETMODE",
      ].enumerated() {
        let record = request(
          "deny", at: Double(offset) / 10, target: target, eventType: eventType)
        XCTAssertTrue(record.isDeniedRequest)
        store.record(record)
      }
      let rows = try store.readAuditLog(maximumLineCount: 20).records
      XCTAssertEqual(
        rows.map(\.eventType),
        ["AUTH_SETMODE", "AUTH_SETEXTATTR", "AUTH_DELETEEXTATTR", "AUTH_UTIMES", "AUTH_SETMODE"])
      XCTAssertEqual(rows.map(\.representedRequestCount), [2, 1, 1, 2, 1])
    }
  }

  func testOneSecondWindowBoundary() throws {
    try withStore { store, _ in
      store.record(request("deny", at: 0))
      store.record(request("deny", at: 0.999))
      store.record(request("deny", at: 1.0))
      store.record(request("deny", at: 1.5))
      store.record(request("allow", at: 3))
      store.record(request("allow", at: 3.999, target: "/Users/example/Protected/b"))
      store.record(request("allow", at: 4.0, target: "/Users/example/Protected/c"))
      let rows = try store.readAuditLog(maximumLineCount: 20).records
      XCTAssertEqual(rows.map(\.representedRequestCount), [2, 2, 2, 1])
      XCTAssertEqual(rows.map(\.timestamp), [0, 1.0, 3, 4.0].map(saved))
      XCTAssertEqual(rows.map(\.lastRequestTimestamp), [0.999, 1.5, 3.999, 4.0].map(saved))
      XCTAssertNil(rows.last?.requestCount)
      XCTAssertNil(rows.last?.lastTimestamp)
    }
  }

  func testOtherRecordsOfTheSameProcessCloseTheOpenRecord() throws {
    try withStore { store, _ in
      store.record(request("allow", at: 0))
      store.record(request("allow", at: 0.1, target: "/Users/example/Protected/b"))
      store.record(request("deny", at: 0.2))
      store.record(request("allow", at: 0.3))
      store.record(request("allow", at: 0.4))
      // Another execution of the same PID and a policy revision change are separate.
      store.record(request("allow", version: 2, at: 0.5))
      var revised = request("allow", version: 2, at: 0.6)
      revised.policyRevision = 4
      store.record(revised)
      // Records without a known process, and process events, are never combined.
      store.record(request("deny", pid: 8, at: 0.7, lineage: false))
      store.record(request("deny", pid: 8, at: 0.8, lineage: false))
      // Each process's records keep their order. A waiting record is saved after records that
      // other processes made meanwhile.
      let rows = try store.readAuditLog(maximumLineCount: 20).records
      func sequence(pid: Int32, version: Int32? = nil) -> [String] {
        rows.filter {
          $0.processID == pid && (version == nil || $0.processLineage?.actor?.version == version)
        }.map { "\($0.kernelResponse)×\($0.representedRequestCount)" }
      }
      XCTAssertEqual(sequence(pid: 7, version: 1), ["allow×2", "deny×1", "allow×2"])
      XCTAssertEqual(sequence(pid: 7, version: 2), ["allow×1", "allow×1"])
      XCTAssertEqual(sequence(pid: 8), ["deny×1", "deny×1"])
    }
  }

  func testWaitingRecordIsSavedWhenItsWindowEnds() throws {
    try withStore { store, directory in
      let now = Date()
      var first = request("deny")
      first.timestamp = now
      var again = first
      again.timestamp = now.addingTimeInterval(0.1)
      store.record(first)
      store.record(again)
      XCTAssertTrue(try savedRecords(directory).isEmpty)
      let deadline = Date().addingTimeInterval(5)
      var rows: [AuditEventRecord] = []
      while rows.isEmpty, Date() < deadline {
        Thread.sleep(forTimeInterval: 0.1)
        rows = try savedRecords(directory)
      }
      XCTAssertEqual(rows.map(\.requestCount), [2])
      XCTAssertGreaterThanOrEqual(Date().timeIntervalSince(now), PolicyAuditLogStore.groupingWindow)
    }
  }

  func testRepeatWithoutRoomStillCountsInTheOpenRecord() throws {
    let budget = AuditWorkBudget(limits: [
      .general: .init(entries: 4, bytes: 1_000_000),
      .denied: .init(entries: 1, bytes: 1_000_000),
    ])
    try withStore(budget: budget) { store, _ in
      let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: store, budget: budget)
      tracker.submit(observation(7), record: request("deny", lineage: false))
      tracker.flush()
      let entered = DispatchSemaphore(value: 0)
      let proceed = DispatchSemaphore(value: 0)
      tracker.enqueueBarrier {
        entered.signal()
        proceed.wait()
      }
      XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
      // The first repeat takes the only slot; the rest find the lane full.
      for index in 1...50 {
        let offset = Double(index) / 100
        tracker.submit(
          observation(7, at: offset), record: request("deny", at: offset, lineage: false))
      }
      // A different denied request without room is lost and counted.
      tracker.submit(
        observation(7, at: 0.6),
        record: request("deny", at: 0.6, target: "/Users/example/Protected/z", lineage: false))
      proceed.signal()
      tracker.close()
      let rows = try store.readAuditLog(maximumLineCount: 10).records
      XCTAssertEqual(rows.map(\.representedRequestCount), [51])
      let metrics = store.deliveryMetrics
      XCTAssertEqual(metrics.combinedDeniedRequests, 50)
      XCTAssertEqual(metrics.deniedLaneDrops, 1)
      XCTAssertEqual(metrics.admissionDrops, 1)
      // Saved requests and lost requests together are every request answered.
      XCTAssertEqual(
        rows.map(\.representedRequestCount).reduce(0, +) + store.droppedEventCount, 52)
    }
    XCTAssertEqual(budget.usage, .init())
  }

  func testPolicyChangeAndCloseSaveWaitingRecords() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try PolicyAuditLogStore(directoryURL: directory)
    store.updatePolicySet(document)
    store.record(request("allow", at: 0))
    store.record(request("allow", at: 0.1))
    var revised = document
    revised.revision = 4
    store.updatePolicySet(revised)
    XCTAssertEqual(try savedRecords(directory).map(\.requestCount), [2])
    store.record(request("deny", at: 0.2))
    store.flushAndClose()
    store.record(request("deny", at: 0.3))
    XCTAssertEqual(try savedRecords(directory).map(\.representedRequestCount), [2, 1])
    XCTAssertEqual(store.deliveryMetrics.deniedLaneDrops, 1)
  }

  // MARK: - Formats

  func testNewFieldsAreOptionalInRecordsAndStatus() throws {
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    let single = request("deny")
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: encoder.encode(single)) as? [String: Any])
    XCTAssertNil(object["requestCount"])
    XCTAssertNil(object["lastTimestamp"])
    var combined = single
    combined.requestCount = 5
    combined.lastTimestamp = start.addingTimeInterval(1)
    XCTAssertEqual(
      try decoder.decode(AuditEventRecord.self, from: encoder.encode(combined)), combined)
    XCTAssertEqual(combined.lastRequestTimestamp, start.addingTimeInterval(1))

    var metrics = AuditDeliveryMetrics()
    let older = try XCTUnwrap(
      JSONSerialization.jsonObject(with: JSONEncoder().encode(metrics)) as? [String: Any])
    XCTAssertEqual(Set(older.keys), ["minimalRecordsStored", "admissionDrops", "storageFailures"])
    XCTAssertNil(
      try JSONDecoder().decode(AuditDeliveryMetrics.self, from: JSONEncoder().encode(metrics))
        .deniedLaneDrops)
    metrics.deniedLaneDrops = 1
    metrics.sharedLaneDrops = 2
    metrics.combinedDeniedRequests = 3
    metrics.combinedAllowedRequests = 4
    var status = ExtensionStatusSnapshot(runtimeInstanceIdentifier: UUID(), phase: .enforcing)
    status.auditDelivery = metrics
    XCTAssertEqual(
      try JSONDecoder().decode(ExtensionStatusSnapshot.self, from: JSONEncoder().encode(status)),
      status)
    XCTAssertEqual(ExtensionStatusSnapshot.currentSchemaVersion, 7)

    try withStore { store, _ in
      let reported = store.deliveryMetrics
      XCTAssertEqual(reported.deniedLaneDrops, 0)
      XCTAssertEqual(reported.sharedLaneDrops, 0)
      XCTAssertEqual(reported.combinedDeniedRequests, 0)
      XCTAssertEqual(reported.combinedAllowedRequests, 0)
    }
  }
}
