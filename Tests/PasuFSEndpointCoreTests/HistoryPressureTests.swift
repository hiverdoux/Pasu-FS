import Foundation
import PasuFSConfiguration
import XCTest
import os

@testable import PasuFSEndpointCore

final class HistoryPressureTests: XCTestCase {
  private let date = Date(timeIntervalSince1970: 1_800_000_000)

  private func process(_ pid: Int32, version: Int32 = 1) -> LineageProcess {
    LineageProcess(key: .init(pid: pid, version: version), executablePath: "/example/tool")
  }

  private func event(_ process: LineageProcess, type: String = "AUTH_OPEN", time: UInt64 = 1)
    -> LineageObservation
  {
    LineageObservation(eventType: type, timestamp: date, source: process, machTime: time)
  }

  func testBatchReclaimsHeadroomAndPreservesNewResponsibleReference() {
    var graph = ProcessLineageGraph(bootIdentifier: "example", maximumBytes: 12_000)
    for pid: Int32 in 1...15 { graph.observe(event(process(pid), type: "NOTIFY_EXIT")) }
    var actor = process(100)
    actor.responsible = process(1).key
    graph.observe(event(actor, time: 20))
    for pid: Int32 in 101...104 { graph.observe(event(process(pid), type: "NOTIFY_EXIT")) }
    XCTAssertGreaterThan(graph.reclamation.passes, 0)
    XCTAssertGreaterThan(graph.reclamation.reclaimedBytes, 1_000)
    XCTAssertLessThanOrEqual(graph.byteCount, 12_000)
    let snapshot = graph.snapshot(for: event(actor))
    XCTAssertEqual(
      snapshot.processes.first { $0.key == process(1).key }?.executablePath,
      "/example/tool")
  }

  func testUnproductivePassHasTimeAndObservationGates() {
    let clock = OSAllocatedUnfairLock(initialState: UInt64(0))
    var graph = ProcessLineageGraph(
      bootIdentifier: "example", maximumBytes: 1_000,
      clock: { clock.withLock { $0 } })
    graph.observe(event(process(1)))
    graph.observe(event(process(2)))
    XCTAssertEqual(graph.reclamation.passes, 1)
    for pid: Int32 in 3...5_000 { graph.observe(event(process(pid))) }
    XCTAssertEqual(graph.reclamation.passes, 1)
    clock.withLock { $0 = 1_000_000_000 }
    graph.observe(event(process(5_001)))
    XCTAssertEqual(graph.reclamation.passes, 2)
    clock.withLock { $0 = 5_999_999_999 }
    graph.observe(event(process(5_002)))
    XCTAssertEqual(graph.reclamation.passes, 2)
    clock.withLock { $0 = 6_000_000_000 }
    graph.observe(event(process(5_003)))
    XCTAssertEqual(graph.reclamation.passes, 3)
    graph.observe(event(process(1), type: "NOTIFY_EXIT", time: 2))
    XCTAssertEqual(graph.snapshot(for: event(process(1))).processes.first?.exitedAt, date)
  }

  func testReplacementEvidenceDoesNotInventExitAndLateExitCannotEndNewExecution() {
    var graph = ProcessLineageGraph(bootIdentifier: "example")
    let old = process(20)
    let new = process(20, version: 2)
    var child = process(21)
    child.parent = old.key
    graph.observe(event(old, time: 10))
    graph.observe(event(child, time: 11))
    graph.observe(event(new, time: 12))
    let snapshot = graph.snapshot(for: event(child))
    let retained = snapshot.processes.first { $0.key == old.key }
    XCTAssertEqual(retained?.supersededBy, new.key)
    XCTAssertEqual(retained?.supersededObservedAt, date)
    XCTAssertNil(retained?.exitedAt)
    graph.observe(event(old, type: "NOTIFY_EXIT", time: 11))
    graph.observe(event(old, time: 9))
    XCTAssertNil(graph.snapshot(for: event(new)).processes.first { $0.key == new.key }?.exitedAt)
    XCTAssertEqual(
      graph.snapshot(for: event(child)).processes.first { $0.key == old.key }?.supersededBy, new.key
    )
  }

  func testNewExecutionCanRetireMissingExitWhenStorageIsAlreadyFull() {
    let clock = OSAllocatedUnfairLock(initialState: UInt64(0))
    var graph = ProcessLineageGraph(
      bootIdentifier: "example", maximumBytes: 1_000,
      clock: { clock.withLock { $0 } })
    let old = process(20)
    let new = process(20, version: 2)
    graph.observe(event(old, time: 10))
    graph.observe(event(new, time: 20))
    let snapshot = graph.snapshot(for: event(new))
    XCTAssertEqual(snapshot.processes.first?.executablePath, "/example/tool")
    XCTAssertEqual(graph.reclamation.supersededExecutions, 1)
    XCTAssertLessThanOrEqual(graph.byteCount, 1_000)
  }

  func testExplicitExecUsesObservedEndInsteadOfInferredSupersession() {
    var graph = ProcessLineageGraph(bootIdentifier: "example")
    let old = process(20)
    let replacement = process(20, version: 2)
    graph.observe(event(old, time: 10))
    graph.observe(
      LineageObservation(
        eventType: "NOTIFY_EXEC", timestamp: date,
        source: old, target: replacement, machTime: 20))
    let snapshot = graph.snapshot(for: event(replacement))
    let ended = snapshot.processes.first { $0.key == old.key }
    XCTAssertEqual(ended?.exitedAt, date)
    XCTAssertNil(ended?.supersededObservedAt)
    XCTAssertEqual(graph.reclamation.supersededExecutions, 0)
  }

  func testSixtyFourObservedExitsPermitRetryAfterMinimumInterval() {
    let clock = OSAllocatedUnfairLock(initialState: UInt64(0))
    var graph = ProcessLineageGraph(
      bootIdentifier: "example", maximumBytes: 100_000, targetFraction: 0.75,
      clock: { clock.withLock { $0 } })
    for pid: Int32 in 1...150 { graph.observe(event(process(pid))) }
    graph.observe(event(process(1_000)))
    graph.observe(event(process(1_001)))
    graph.observe(event(process(1_002)))
    graph.observe(event(process(1_003)))
    let before = graph.reclamation.passes
    XCTAssertGreaterThan(before, 0)
    for pid: Int32 in 1...64 { graph.observe(event(process(pid), type: "NOTIFY_EXIT", time: 2)) }
    clock.withLock { $0 = 999_999_999 }
    graph.observe(event(process(1_004)))
    XCTAssertEqual(graph.reclamation.passes, before)
    clock.withLock { $0 = 1_000_000_000 }
    graph.observe(event(process(1_005)))
    XCTAssertEqual(graph.reclamation.passes, before + 1)
    XCTAssertLessThanOrEqual(graph.byteCount, 75_000)
  }

  func testNewOptionalFieldsDecodeFromOlderHistoryAndStatus() throws {
    var graph = ProcessLineageGraph(bootIdentifier: "example")
    graph.observe(event(process(7)))
    let encoder = JSONEncoder()
    let decoder = JSONDecoder()
    let processData = try encoder.encode(process(7))
    let oldProcess = try decoder.decode(LineageProcess.self, from: processData)
    XCTAssertNil(oldProcess.supersededBy)
    XCTAssertNil(oldProcess.supersededObservedAt)
    var status = ExtensionStatusSnapshot(runtimeInstanceIdentifier: UUID(), phase: .enforcing)
    let oldStatus = try decoder.decode(ExtensionStatusSnapshot.self, from: encoder.encode(status))
    XCTAssertNil(oldStatus.auditDelivery)
    XCTAssertNil(oldStatus.authorization)
    status.auditDelivery = AuditDeliveryMetrics()
    XCTAssertEqual(
      try decoder.decode(ExtensionStatusSnapshot.self, from: encoder.encode(status)), status)
  }

  func testAmbiguousTimeAndHistoricalReferencesDoNotSupersede() {
    var graph = ProcessLineageGraph(bootIdentifier: "example")
    let old = process(20)
    let new = process(20, version: 2)
    graph.observe(event(old, time: 10))
    graph.observe(event(new, time: 10))
    var actor = process(21)
    actor.parent = new.key
    graph.observe(event(actor, time: 20))
    XCTAssertNil(graph.snapshot(for: event(old)).processes.first?.supersededBy)
    var missingTime = event(new, time: 30)
    missingTime.machTime = nil
    graph.observe(missingTime)
    XCTAssertNil(graph.snapshot(for: event(old)).processes.first?.supersededBy)
  }
}
