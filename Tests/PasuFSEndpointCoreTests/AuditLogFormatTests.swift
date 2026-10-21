import Darwin
import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSEndpointCore

/// Logs written by earlier versions stay readable next to the records of this version.
final class AuditLogFormatTests: XCTestCase {
  func testSchemaEightRecordsAreReadWithNewRecordsAfterAnUpdate() throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    let setIdentifier = UUID()
    let policyIdentifier = UUID()
    let key = PolicyAuditLogKey(setIdentifier: setIdentifier, policyIdentifier: policyIdentifier)
    // Lines as versions 0.9.0 through 0.12.4 wrote them (schema 8): a combined denial at a mount
    // point, and a record of messages macOS dropped, which names no policy.
    let denial = """
      {"eventIdentifier":"\(UUID().uuidString)","eventSequence":41,"eventType":"AUTH_MOUNT",\
      "kernelResponse":"deny","lastTimestamp":"2027-01-15T08:00:03Z","policyDecision":"denied",\
      "policyEvaluations":[{"decision":"deny","match":"mountPoint","mode":"protection",\
      "policyIdentifier":"\(policyIdentifier.uuidString)","policyName":"Example",\
      "policyType":"whitelist"}],"policyRevision":3,\
      "policySetIdentifier":"\(setIdentifier.uuidString)","processID":120,"requestCount":2,\
      "schemaVersion":8,"targetPath":"/Users/example/Protected",\
      "timestamp":"2027-01-15T08:00:02Z"}
      """
    let gap = """
      {"detail":"missedMessages=3 missedProcessEvents=1 estimatedUncheckedRequests=2 gaps=1",\
      "eventIdentifier":"\(UUID().uuidString)","eventSequence":90,"eventType":"DELIVERY_GAP",\
      "kernelResponse":"not-delivered","policyDecision":"unchecked","schemaVersion":8,\
      "timestamp":"2027-01-15T08:00:04Z"}
      """
    try Data((denial + "\n" + gap + "\n").utf8).write(
      to: directory.appendingPathComponent("endpoint-events.jsonl"))
    try Data((denial + "\n").utf8).write(to: directory.appendingPathComponent(key.filename))
    for filename in ["endpoint-events.jsonl", key.filename] {
      XCTAssertEqual(
        chmod(directory.appendingPathComponent(filename).path, 0o600), 0, String(errno))
    }

    let store = try PolicyAuditLogStore(directoryURL: directory, requiredOwnerUserID: getuid())
    defer { store.flushAndClose() }
    let document = PolicySetDocument(
      setIdentifier: setIdentifier, revision: 3,
      policies: [
        DirectoryPolicy(
          id: policyIdentifier, name: "Example", mode: .protection,
          protectedRootPath: "/Users/example/Protected")
      ])
    store.updatePolicySet(document)
    store.record(
      AuditEventRecord(
        policySetIdentifier: setIdentifier, policyRevision: 3, eventSequence: 120,
        eventType: "AUTH_OPEN", processID: 121, targetPath: "/Users/example/Protected/a.txt",
        policyDecision: "denied", kernelResponse: "deny",
        policyEvaluations: [
          PolicyEvaluationRecord(
            policyIdentifier: policyIdentifier, policyName: "Example", mode: .protection,
            policyType: .whitelist, match: .none, decision: .deny)
        ]))

    let global = try store.readAuditLog(maximumLineCount: 500)
    XCTAssertEqual(global.skippedLineCount, 0)
    XCTAssertEqual(global.records.map(\.schemaVersion), [8, 8, 9])
    XCTAssertEqual(global.records[0].representedRequestCount, 2)
    XCTAssertEqual(global.records[0].policyEvaluations?.first?.match, .mountPoint)
    XCTAssertEqual(global.records[1].eventType, "DELIVERY_GAP")
    let policy = try store.readPolicyAuditLog(PolicyAuditLogRequest(key: key))
    XCTAssertEqual(policy.skippedLineCount, 0)
    XCTAssertEqual(policy.records.map(\.schemaVersion), [8, 9])
  }

  /// Version 0.12.4 wrote schema 8, whose execution-origin evidence has no history evidence
  /// and whose programs have no current parent or start time.
  func testSchemaEightEvidenceIsReadWithoutTheHistoryEvidence() throws {
    let line = """
      {"eventIdentifier":"\(UUID().uuidString)","eventSequence":7,"eventType":"AUTH_OPEN",\
      "kernelResponse":"deny","policyDecision":"denied","policyEvaluations":[{"decision":"deny",\
      "executionOrigin":{"actor":{"codeSigningFlags":1,"executablePath":"/example/daemon",\
      "instance":{"processID":40,"processVersion":1},"isPlatformBinary":true,\
      "originalParentProcessID":1,"pathWasTruncated":false,\
      "signingIdentifier":"com.example.daemon"},"bootIdentifier":"example-boot",\
      "isAllowed":false,"isBlacklistEnabled":true,"reason":"incompleteHistory",\
      "uncertainty":"beforeObservation"},"match":"none","mode":"protection",\
      "policyIdentifier":"\(UUID().uuidString)","policyName":"Example",\
      "policyType":"blacklist"}],"schemaVersion":8,"targetPath":"/Users/example/Protected/a.txt",\
      "timestamp":"2027-01-15T08:00:02Z"}
      """
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    let record = try decoder.decode(AuditEventRecord.self, from: Data(line.utf8))
    XCTAssertEqual(record.schemaVersion, 8)
    let origin = try XCTUnwrap(record.policyEvaluations?.first?.executionOrigin)
    XCTAssertEqual(origin.uncertainty, .beforeObservation)
    XCTAssertNil(origin.historyEvidence)
    XCTAssertNil(origin.actor.parentProcessID)
    XCTAssertNil(origin.actor.startTime)
    XCTAssertEqual(origin.actor.originalParentProcessID, 1)
  }
}
