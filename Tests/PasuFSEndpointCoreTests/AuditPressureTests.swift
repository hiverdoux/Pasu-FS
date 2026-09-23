import Dispatch
import Foundation
import PasuFSConfiguration
import XCTest
import os

@testable import PasuFSEndpointCore

final class AuditPressureTests: XCTestCase {
  private func budget() -> AuditWorkBudget {
    AuditWorkBudget(limits: [
      .general: .init(entries: 1, bytes: 32_768),
      .lifecycle: .init(entries: 1, bytes: 8_192),
      .audit: .init(entries: 1, bytes: 8_192),
    ])
  }

  private func event(_ sequence: UInt64, type: String = "AUTH_OPEN") -> LineageObservation {
    LineageObservation(
      eventType: type, timestamp: Date(timeIntervalSince1970: Double(sequence)),
      globalSequence: sequence, source: LineageProcess(key: .init(pid: 7, version: 1)),
      machTime: sequence)
  }

  private func record(_ sequence: UInt64) -> EndpointEventRecord {
    EndpointEventRecord(
      eventSequence: sequence, eventType: "AUTH_OPEN", processID: 7,
      executablePath: "/example/tool", targetPath: "/example/protected/file",
      policyDecision: "deny", kernelResponse: "deny")
  }

  func testAtomicResizeKeepsSlotAndDedicatedLanesRemainSeparate() throws {
    let budget = budget()
    let token = try XCTUnwrap(budget.reserve(bytes: 10_000))
    XCTAssertTrue(token.resize(to: 32_768))
    XCTAssertFalse(token.resize(to: 32_769))
    XCTAssertNil(budget.reserve(bytes: 1))
    let audit = try XCTUnwrap(budget.reserve(bytes: 8_192, lane: .audit))
    let lifecycle = try XCTUnwrap(budget.reserve(bytes: 8_192, lane: .lifecycle))
    XCTAssertNil(budget.reserve(bytes: 1, lane: .audit))
    DispatchQueue.concurrentPerform(iterations: 1_000) { _ in
      XCTAssertNil(budget.reserve(bytes: 1))
      XCTAssertTrue(token.resize(to: 16_384))
    }
    token.release()
    token.release()
    audit.release()
    lifecycle.release()
    XCTAssertEqual(budget.usage, .init())
  }

  func testReservedMinimalRecordsKeepOrderAndCountAdmissionFailure() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let budget = budget()
    let store = try PolicyAuditLogStore(directoryURL: directory, budget: budget)
    let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: store, budget: budget)
    let entered = DispatchSemaphore(value: 0)
    let proceed = DispatchSemaphore(value: 0)
    tracker.enqueueBarrier {
      entered.signal()
      proceed.wait()
    }
    XCTAssertEqual(entered.wait(timeout: .now() + 3), .success)
    tracker.submit(event(1), record: record(1))
    tracker.submit(event(2), record: record(2))
    tracker.submit(event(3), record: record(3))
    tracker.submit(event(4, type: "NOTIFY_EXIT"), record: nil)
    XCTAssertEqual(budget.usage.entries, 3)
    proceed.signal()
    tracker.close()
    store.flushAndClose()
    let rows = try store.readAuditLog(maximumLineCount: 10).records
    XCTAssertEqual(rows.map(\.eventSequence), [1, 2])
    XCTAssertEqual(rows.map(\.kernelResponse), ["deny", "deny"])
    XCTAssertEqual(rows.last?.timestamp, Date(timeIntervalSince1970: 2))
    XCTAssertEqual(rows.last?.processLineage?.issues.first?.reason, "historyOmitted")
    XCTAssertEqual(store.deliveryMetrics.minimalRecordsStored, 1)
    XCTAssertEqual(store.deliveryMetrics.admissionDrops, 1)
    XCTAssertEqual(store.droppedEventCount, 1)
    XCTAssertEqual(budget.usage, .init())
    XCTAssertFalse(tracker.status.issues.contains { $0.reason == "kernelEventLoss" })
  }

  func testSnapshotGrowthFallsBackWithoutLeakingReservation() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let budget = AuditWorkBudget(maximumEntries: 8, maximumBytes: 5_000)
    let store = try PolicyAuditLogStore(directoryURL: directory, budget: budget)
    let tracker = ProcessLineageTracker(bootIdentifier: "example", sink: store, budget: budget)
    var parent: LineageProcessKey?
    for pid: Int32 in 1...20 {
      let process = LineageProcess(key: .init(pid: pid, version: 1), parent: parent)
      tracker.submit(
        LineageObservation(
          eventType: "AUTH_OPEN", timestamp: Date(),
          source: process), record: nil)
      tracker.flush()
      parent = process.key
    }
    tracker.submit(
      LineageObservation(
        eventType: "AUTH_OPEN", timestamp: Date(),
        source: LineageProcess(key: parent!, parent: .init(pid: 19, version: 1))), record: record(1)
    )
    tracker.close()
    store.flushAndClose()
    let rows = try store.readAuditLog(maximumLineCount: 10).records
    XCTAssertEqual(rows.count, 1)
    XCTAssertEqual(rows.first?.processLineage?.issues.first?.reason, "historyBudgetExceeded")
    XCTAssertEqual(rows.first?.processLineage?.processes.count, 0)
    XCTAssertEqual(budget.usage, .init())
  }

  func testRotationWriteFailureIsCountedOnceAndReleasesReservation() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer {
      try? FileManager.default.setAttributes(
        [.posixPermissions: 0o700], ofItemAtPath: directory.path)
      try? FileManager.default.removeItem(at: directory)
    }
    let budget = budget()
    let store = try PolicyAuditLogStore(
      directoryURL: directory, maximumFileSize: 800, budget: budget)
    store.record(record(1))
    _ = try store.readAuditLog(maximumLineCount: 10)
    try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: directory.path)
    for index: UInt64 in 2...4 {
      store.record(record(index))
      _ = try store.readAuditLog(maximumLineCount: 10)
    }
    store.flushAndClose()
    XCTAssertGreaterThan(store.deliveryMetrics.storageFailures, 0)
    XCTAssertEqual(store.droppedEventCount, store.deliveryMetrics.storageFailures)
    XCTAssertEqual(budget.usage, .init())
  }

  func testClosedWriterCountsFailureAndReturnsReservation() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let budget = budget()
    let store = try PolicyAuditLogStore(directoryURL: directory, budget: budget)
    store.flushAndClose()
    store.record(record(1))
    XCTAssertEqual(store.deliveryMetrics.admissionDrops, 1)
    XCTAssertEqual(budget.usage, .init())
  }
}
