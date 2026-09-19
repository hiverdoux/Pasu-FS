import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSApp

@MainActor
final class ProcessLineagePresentationTests: XCTestCase {
  func testPreviewKeepsTwoRolesAndSearchFindsHiddenMiddleProcess() {
    let owner = LineageProcessKey(pid: 10, version: 1)
    let middle = LineageProcessKey(pid: 20, version: 1)
    let actor = LineageProcessKey(pid: 30, version: 1)
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    let lineage = ProcessLineageSnapshot(
      bootIdentifier: "example", collectionIdentifier: UUID(), collectionStartedAt: now,
      capturedAt: now, actor: actor, responsible: owner,
      processes: [
        LineageProcess(key: owner, executablePath: "/example/Terminal"),
        LineageProcess(
          key: middle, executablePath: "/example/middle-tool", signingIdentifier: "example.middle"),
        LineageProcess(key: actor, executablePath: "/example/cat"),
      ])
    var record = AuditEventRecord(
      processLineage: lineage, timestamp: now, eventType: "AUTH_OPEN",
      processID: actor.pid, executablePath: "/example/cat", policyDecision: "allowed",
      kernelResponse: "allow")
    XCTAssertEqual(record.processPreview, "Terminal > cat")
    let log = PolicyLogState(
      key: PolicyAuditLogKey(setIdentifier: UUID(), policyIdentifier: UUID()))
    log.batch = AuditLogBatch(records: [record])
    log.filterText = "example.middle"
    XCTAssertEqual(log.rows.count, 1)
    XCTAssertEqual(log.rows.first?.process, "Terminal > cat")
    let model = AppModel()
    model.auditBatch = AuditLogBatch(records: [record])
    model.auditFilterText = "middle-tool"
    XCTAssertEqual(model.filteredAuditRecords.count, 1)
    record.processLineage?.responsible = actor
    XCTAssertEqual(record.processPreview, "cat > cat")
    record.processLineage?.responsible = LineageProcessKey(pid: 99, version: 2)
    XCTAssertEqual(record.processPreview, "PID 99 > cat")
    record.processLineage?.responsible = nil
    XCTAssertEqual(record.processPreview, "Unknown > cat")
  }

  func testLegacyRecordRemainsReadableWithoutFabricatedLineage() throws {
    let data = Data(
      """
      {"schemaVersion":4,"timestamp":"2026-09-13T00:00:00Z","eventType":"AUTH_OPEN",
       "processID":2,"executablePath":"/example/cat","policyDecision":"allowed","kernelResponse":"allow"}
      """.utf8)
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    let record = try decoder.decode(AuditEventRecord.self, from: data)
    XCTAssertNil(record.processLineage)
    XCTAssertNil(record.eventIdentifier)
    XCTAssertEqual(record.processPreview, "Unknown > cat")
    XCTAssertFalse(record.id.isEmpty)
  }
}
