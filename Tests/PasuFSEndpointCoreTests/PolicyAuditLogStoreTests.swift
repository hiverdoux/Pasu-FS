import Darwin
import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSEndpointCore

final class PolicyAuditLogStoreTests: XCTestCase {
  func testEmbeddedHistorySurvivesOtherLogRotationAndRestart() throws {
    try withStore(maximumFileSize: 5_000) { store, directory, document in
      let key = LineageProcessKey(pid: 123, version: 7)
      let time = Date(timeIntervalSince1970: 1_800_000_000)
      let snapshot = ProcessLineageSnapshot(
        bootIdentifier: "example", collectionIdentifier: UUID(), collectionStartedAt: time,
        capturedAt: time, actor: key, responsible: key,
        processes: [LineageProcess(key: key, executablePath: "/example/actor", observedAt: time)])
      var quiet = record(document, sequence: 1, policies: [document.policies[0].id])
      quiet.processLineage = snapshot
      store.record(quiet)
      for sequence: UInt64 in 2...30 {
        store.record(record(document, sequence: sequence, policies: [document.policies[1].id]))
      }
      XCTAssertEqual(
        try read(store, document, document.policies[0].id).records.first?.processLineage, snapshot)
      store.flushAndClose()
      let restarted = try PolicyAuditLogStore(directoryURL: directory, maximumFileSize: 5_000)
      defer { restarted.flushAndClose() }
      restarted.updatePolicySet(document)
      XCTAssertEqual(
        try read(restarted, document, document.policies[0].id).records.first?.processLineage,
        snapshot)
      var edited = document
      edited.policies.removeLast()
      restarted.updatePolicySet(edited)
      XCTAssertEqual(
        try read(restarted, edited, edited.policies[0].id).records.first?.processLineage, snapshot)
    }
  }

  func testRoutesOpenEventsToEachEvaluatedPolicyAndPreservesFinalResponse() throws {
    try withStore { store, _, document in
      let first = document.policies[0].id
      let second = document.policies[1].id
      let event = record(document, sequence: 1, policies: [first, second])
      store.record(event)
      var lifecycle = event
      lifecycle.eventType = "NOTIFY_EXEC"
      store.record(lifecycle)
      var noTarget = event
      noTarget.targetPath = nil
      store.record(noTarget)
      var outside = event
      outside.policyEvaluations = []
      store.record(outside)

      let a = try read(store, document, first)
      let b = try read(store, document, second)
      XCTAssertEqual(a.records.count, 1)
      XCTAssertEqual(b.records.count, 1)
      XCTAssertEqual(a.records[0].policyEvaluations?.map(\.policyIdentifier), [first])
      XCTAssertEqual(a.records[0].policyEvaluations?.first?.decision, .allow)
      XCTAssertEqual(b.records[0].policyEvaluations?.first?.decision, .wouldDeny)
      XCTAssertEqual(a.records[0].kernelResponse, "deny")
      XCTAssertEqual(b.records[0].kernelResponse, "deny")
      let global = try store.readAuditLog(maximumLineCount: 500)
      XCTAssertEqual(global.records.count, 4)
      XCTAssertEqual(global.records[0].policyEvaluations?.count, 2)
    }
  }

  func testBusyPolicyDoesNotPushQuietPolicyOutOfItsTail() throws {
    try withStore { store, _, document in
      store.record(record(document, sequence: 0, policies: [document.policies[0].id]))
      for index in 1...610 {
        store.record(record(document, sequence: UInt64(index), policies: [document.policies[1].id]))
      }
      let quiet = try read(store, document, document.policies[0].id)
      let busy = try read(store, document, document.policies[1].id)
      XCTAssertEqual(quiet.records.map(\.eventSequence), [0])
      XCTAssertFalse(quiet.isTruncated)
      XCTAssertEqual(busy.records.count, 500)
      XCTAssertEqual(busy.records.first?.eventSequence, 111)
      XCTAssertEqual(busy.records.last?.eventSequence, 610)
      XCTAssertTrue(busy.isTruncated)
      XCTAssertEqual(busy.droppedEventCount, 0)
      XCTAssertEqual(try store.readAuditLog(maximumLineCount: 500).records.count, 500)
    }
  }

  func testReadsPreviousFileAndRotatesEachPolicyIndependently() throws {
    try withStore(maximumFileSize: 3_000) { store, directory, document in
      let quietID = document.policies[0].id
      let busyID = document.policies[1].id
      store.record(record(document, sequence: 0, policies: [quietID]))
      for index in 1...12 {
        store.record(record(document, sequence: UInt64(index), policies: [busyID]))
      }
      let batch = try read(store, document, busyID)
      let busyKey = key(document, busyID)
      let current = try decodeFile(directory.appendingPathComponent(busyKey.filename))
      let previous = try decodeFile(directory.appendingPathComponent(busyKey.filename + ".1"))
      XCTAssertFalse(previous.isEmpty)
      XCTAssertEqual(batch.records, previous + current)
      XCTAssertEqual(batch.records.last?.eventSequence, 12)
      XCTAssertEqual(try read(store, document, quietID).records.map(\.eventSequence), [0])
      XCTAssertFalse(
        FileManager.default.fileExists(
          atPath: directory.appendingPathComponent(key(document, quietID).filename + ".1").path))
      let single = try store.readPolicyAuditLog(
        PolicyAuditLogRequest(key: busyKey, maximumLineCount: 0))
      XCTAssertEqual(single.records.map(\.eventSequence), [12])
      XCTAssertTrue(single.isTruncated)
    }
  }

  func testHistorySurvivesEditsAndRestartWithoutBackfillingGlobalRecords() throws {
    try withStore { store, directory, document in
      let id = document.policies[0].id
      store.record(record(document, sequence: 1, policies: [id]))
      var edited = document
      edited.revision += 1
      edited.policies[0].name = "Renamed"
      edited.policies[0].protectedRootPath = "/Users/example/NewFolder"
      store.updatePolicySet(edited)
      var new = record(edited, sequence: 2, policies: [id])
      new.targetPath = "/Users/example/NewFolder/file.txt"
      store.record(new)
      store.flushAndClose()

      let reopened = try PolicyAuditLogStore(directoryURL: directory, requiredOwnerUserID: getuid())
      defer { reopened.flushAndClose() }
      reopened.updatePolicySet(edited)
      XCTAssertEqual(try read(reopened, edited, id).records.map(\.eventSequence), [1, 2])
      // A pre-existing global-only record must never be imported into a policy file.
      let legacy = record(edited, sequence: 3, policies: [edited.policies[1].id])
      let globalOnly = try JSONLineEventLogger(directoryURL: directory)
      globalOnly.record(legacy)
      globalOnly.flushAndClose()
      XCTAssertTrue(try read(reopened, edited, edited.policies[1].id).records.isEmpty)
    }
  }

  func testDeletionRemovesOnlyRetiredFilesAndLateEventsCannotRecreateThem() throws {
    try withStore { store, directory, document in
      let removedID = document.policies[0].id
      let keptID = document.policies[1].id
      let event = record(document, sequence: 1, policies: [removedID, keptID])
      store.record(event)
      _ = try read(store, document, removedID)
      let removedKey = key(document, removedID)
      let old = directory.appendingPathComponent(removedKey.filename + ".1")
      try Data("previous".utf8).write(to: old)
      let unrelated = directory.appendingPathComponent("unrelated.jsonl")
      try Data("keep".utf8).write(to: unrelated)
      var remaining = document
      remaining.revision += 1
      remaining.policies.removeFirst()
      store.updatePolicySet(remaining)
      store.record(event)
      let global = try store.readAuditLog(maximumLineCount: 500)
      XCTAssertEqual(global.records.count, 2)
      XCTAssertEqual(try read(store, remaining, keptID).records.count, 2)
      XCTAssertFalse(FileManager.default.fileExists(atPath: old.path))
      XCTAssertFalse(
        FileManager.default.fileExists(
          atPath: directory.appendingPathComponent(removedKey.filename).path))
      XCTAssertEqual(try String(contentsOf: unrelated, encoding: .utf8), "keep")
      XCTAssertThrowsError(try read(store, document, removedID))
      var replacement = remaining
      replacement.policies.append(
        DirectoryPolicy(
          name: document.policies[0].name, mode: .audit, policyType: .whitelist,
          protectedRootPath: document.policies[0].protectedRootPath, rules: []))
      store.updatePolicySet(replacement)
      XCTAssertTrue(try read(store, replacement, replacement.policies.last!.id).records.isEmpty)
    }
  }

  func testCleanupFailureIsVisibleAndRetriedAfterValidPolicyLoad() throws {
    try withStore { store, directory, document in
      let retired = key(document, document.policies[0].id)
      let blocked = directory.appendingPathComponent(retired.filename + ".1")
      try FileManager.default.createDirectory(at: blocked, withIntermediateDirectories: false)
      var remaining = document
      remaining.policies.removeFirst()
      remaining.revision += 1
      store.updatePolicySet(remaining)
      XCTAssertNotNil(store.lastErrorDescription)
      XCTAssertNotNil(try store.readAuditLog(maximumLineCount: 500).warning)
      store.flushAndClose()
      try FileManager.default.removeItem(at: blocked)
      try Data("retired".utf8).write(to: blocked)
      let reopened = try PolicyAuditLogStore(directoryURL: directory, requiredOwnerUserID: getuid())
      defer { reopened.flushAndClose() }
      // Opening the store alone must not infer deletion from an unavailable policy set.
      XCTAssertTrue(FileManager.default.fileExists(atPath: blocked.path))
      reopened.updatePolicySet(remaining)
      XCTAssertFalse(FileManager.default.fileExists(atPath: blocked.path))
      XCTAssertNil(reopened.lastErrorDescription)
    }
  }

  func testPolicyWriteFailureDoesNotStopGlobalLogAndReportsLostRecords() throws {
    try withStore { store, directory, document in
      let id = document.policies[0].id
      let blocked = directory.appendingPathComponent(key(document, id).filename)
      try FileManager.default.createDirectory(at: blocked, withIntermediateDirectories: false)
      store.record(record(document, sequence: 1, policies: [id]))
      XCTAssertEqual(try store.readAuditLog(maximumLineCount: 500).records.count, 1)
      XCTAssertNotNil(store.lastErrorDescription)
      XCTAssertThrowsError(try read(store, document, id))
      try FileManager.default.removeItem(at: blocked)
      let failed = try read(store, document, id)
      XCTAssertEqual(failed.droppedEventCount, 1)
      XCTAssertNotNil(failed.warning)
      store.record(record(document, sequence: 2, policies: [id]))
      let recovered = try read(store, document, id)
      XCTAssertEqual(recovered.records.map(\.eventSequence), [2])
      XCTAssertEqual(recovered.droppedEventCount, 1)
      XCTAssertNil(recovered.warning)
    }
  }

  func testSkipsMalformedAndWrongPolicyRowsWithoutReturningAnotherPolicy() throws {
    try withStore { store, directory, document in
      let id = document.policies[0].id
      let encoder = JSONEncoder()
      encoder.dateEncodingStrategy = .iso8601
      var data = Data("malformed\n".utf8)
      data.append(
        try encoder.encode(record(document, sequence: 1, policies: [document.policies[1].id])))
      data.append(0x0A)
      data.append(try encoder.encode(record(document, sequence: 2, policies: [id])))
      data.append(0x0A)
      try data.write(to: directory.appendingPathComponent(key(document, id).filename))
      let batch = try read(store, document, id)
      XCTAssertEqual(batch.records.map(\.eventSequence), [2])
      XCTAssertEqual(batch.skippedLineCount, 2)
      XCTAssertThrowsError(
        try store.readPolicyAuditLog(
          PolicyAuditLogRequest(
            key: PolicyAuditLogKey(setIdentifier: UUID(), policyIdentifier: id))))
    }
  }

  func testAdmissionDropCountsOneEventAndEachAffectedPolicyOnce() throws {
    try withStore { store, _, document in
      let ids = document.policies.map(\.id)
      store.recordAdmissionDrop(record(document, sequence: 1, policies: ids))
      XCTAssertEqual(store.droppedEventCount, 1)
      XCTAssertEqual(store.deliveryMetrics.admissionDrops, 1)
      for id in ids { XCTAssertEqual(try read(store, document, id).droppedEventCount, 1) }
    }
  }

  private func withStore(
    maximumFileSize: Int64 = 10 * 1_024 * 1_024,
    _ body: (PolicyAuditLogStore, URL, PolicySetDocument) throws -> Void
  ) throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try PolicyAuditLogStore(
      directoryURL: directory, requiredOwnerUserID: getuid(), maximumPendingRecords: 2_048,
      maximumFileSize: maximumFileSize)
    defer { store.flushAndClose() }
    let document = PolicySetDocument(
      setIdentifier: UUID(), revision: 1,
      policies: [
        DirectoryPolicy(
          name: "First", mode: .protection, policyType: .whitelist,
          protectedRootPath: "/Users/example/Protected", rules: []),
        DirectoryPolicy(
          name: "Second", mode: .audit, policyType: .whitelist,
          protectedRootPath: "/Users/example/Protected/Child", rules: []),
      ])
    store.updatePolicySet(document)
    try body(store, directory, document)
  }

  private func key(_ document: PolicySetDocument, _ id: UUID) -> PolicyAuditLogKey {
    PolicyAuditLogKey(setIdentifier: document.setIdentifier, policyIdentifier: id)
  }

  private func read(_ store: PolicyAuditLogStore, _ document: PolicySetDocument, _ id: UUID) throws
    -> AuditLogBatch
  {
    try store.readPolicyAuditLog(PolicyAuditLogRequest(key: key(document, id)))
  }

  private func record(_ document: PolicySetDocument, sequence: UInt64, policies: [UUID])
    -> AuditEventRecord
  {
    AuditEventRecord(
      timestamp: Date(timeIntervalSince1970: Double(sequence)),
      policySetIdentifier: document.setIdentifier, policyRevision: document.revision,
      eventSequence: sequence, eventType: "AUTH_OPEN", processID: 123,
      executablePath: "/Applications/Example.app/Contents/MacOS/example",
      signingIdentifier: "com.example.app", targetPath: "/Users/example/Protected/Child/file.txt",
      policyDecision: "denied", kernelResponse: "deny",
      policyEvaluations: policies.map { id in
        let policy = document.policies.first { $0.id == id }!
        return PolicyEvaluationRecord(
          policyIdentifier: id, policyName: policy.name, mode: policy.mode,
          policyType: policy.policyType, match: .none,
          decision: policy.mode == .audit ? .wouldDeny : .allow)
      })
  }

  private func decodeFile(_ url: URL) throws -> [AuditEventRecord] {
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    return try Data(contentsOf: url).split(separator: 0x0A).map {
      try decoder.decode(AuditEventRecord.self, from: Data($0))
    }
  }
}
