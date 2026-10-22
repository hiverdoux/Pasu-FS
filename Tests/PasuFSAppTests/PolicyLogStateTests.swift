import Foundation
import PasuFSConfiguration
import PasuFSHostCore
import XCTest

@testable import PasuFSApp

@MainActor
final class PolicyLogStateTests: XCTestCase {
  func testRowsKeepAllRecordsForBlankSearchAndRespectSortOrder() {
    let state = PolicyLogState(key: .init(setIdentifier: UUID(), policyIdentifier: UUID()))
    let first = AuditEventRecord(
      timestamp: Date(timeIntervalSince1970: 1), eventType: "AUTH_OPEN",
      policyDecision: "allowed", kernelResponse: "allow")
    let second = AuditEventRecord(
      timestamp: first.timestamp, eventType: "AUTH_OPEN",
      policyDecision: "allowed", kernelResponse: "allow")
    let newest = AuditEventRecord(
      timestamp: Date(timeIntervalSince1970: 2), eventType: "AUTH_OPEN",
      policyDecision: "allowed", kernelResponse: "allow")
    state.batch = AuditLogBatch(records: [first, second, newest])

    for query in ["", " \n\t "] {
      state.filterText = query
      XCTAssertEqual(state.rows.map(\.id), [newest.id, second.id, first.id])
    }
    state.sortOrder = [KeyPathComparator(\PolicyLogRow.timestamp, order: .forward)]
    XCTAssertEqual(state.rows.map(\.id), [second.id, first.id, newest.id])
  }

  func testRowsSearchSelectedPolicyFieldsWithWhitespaceAndCaseFolding() {
    let policyID = UUID()
    let state = PolicyLogState(key: .init(setIdentifier: UUID(), policyIdentifier: policyID))
    let selected = PolicyEvaluationRecord(
      policyIdentifier: policyID, policyName: "Sample Policy", mode: .protection,
      policyType: .whitelist, match: .direct, ruleIdentifier: "sample-rule", decision: .allow)
    let other = PolicyEvaluationRecord(
      policyIdentifier: UUID(), policyName: "Other Policy", mode: .protection,
      policyType: .whitelist, match: .direct, ruleIdentifier: "other-rule", decision: .allow)
    let record = AuditEventRecord(
      eventType: "AUTH_OPEN", teamIdentifier: "SAMPLETEAM",
      signingIdentifier: "com.example.reader", targetPath: "/example/sample.txt",
      policyDecision: "allowed", kernelResponse: "allow", policyEvaluations: [other, selected])
    let missingFields = AuditEventRecord(
      eventType: "AUTH_OPEN", policyDecision: "allowed", kernelResponse: "allow")
    state.batch = AuditLogBatch(records: [record, missingFields])

    for query in [
      " SAMPLE-RULE \n", "sample policy", "sampleteam", "COM.EXAMPLE.READER", "sample.txt",
    ] {
      state.filterText = query
      XCTAssertEqual(state.rows.map(\.id), [record.id], query)
    }
    for query in ["other-rule", "Other Policy", "no-match"] {
      state.filterText = query
      XCTAssertTrue(state.rows.isEmpty, query)
    }
  }

  func testNoticesKeepEachCurrentIssueAndPrioritizeRefreshFailure() {
    let state = PolicyLogState(key: .init(setIdentifier: UUID(), policyIdentifier: UUID()))
    state.hasLoaded = true
    state.error = "Connection lost"
    state.batch = AuditLogBatch(
      records: [], skippedLineCount: 7, droppedEventCount: 12, isTruncated: true,
      warning: "Storage warning")

    XCTAssertEqual(state.notices.map(\.id), ["load", "runtime", "dropped", "unreadable"])
    XCTAssertEqual(state.notices.first?.severity, .error)
    XCTAssertTrue(state.notices.first?.message.contains("records loaded earlier") == true)
    XCTAssertEqual(state.notices.filter { $0.severity == .warning }.count, 3)

    state.error = nil
    XCTAssertEqual(state.notices.map(\.id), ["runtime", "dropped", "unreadable"])
    state.batch = AuditLogBatch(records: [], isTruncated: true)
    XCTAssertTrue(state.notices.isEmpty)
  }

  func testInitialFailureAndEmptyMessagesDoNotInventWarnings() {
    let state = PolicyLogState(key: .init(setIdentifier: UUID(), policyIdentifier: UUID()))
    state.error = "Unavailable"
    XCTAssertTrue(state.notices.first?.message.contains("could not be loaded") == true)
    XCTAssertFalse(state.notices.first?.message.contains("records loaded earlier") == true)
    state.error = "  "
    state.batch.warning = "\n"
    XCTAssertTrue(state.notices.isEmpty)
  }

  func testQueriesAndUIStateStayWithTheirPolicyDuringNavigation() async throws {
    let document = policies()
    let runtime = PolicyLogRuntime()
    let model = AppModel(initialPolicySet: document, runtimeController: runtime)
    let a = document.policies[0].id
    let b = document.policies[1].id
    let first = Task { await model.refreshPolicyAuditLog(policyID: a) }
    await runtime.waitForRequests(1)
    model.selectedSection = .policy(b)
    let second = Task { await model.refreshPolicyAuditLog(policyID: b) }
    await runtime.waitForRequests(2)
    await runtime.complete(1, result: .success(batch(2)))
    await second.value
    await runtime.complete(0, result: .success(batch(1)))
    await first.value
    let stateA = try XCTUnwrap(model.policyLogState(policyID: a))
    let stateB = try XCTUnwrap(model.policyLogState(policyID: b))
    XCTAssertEqual(stateA.batch.records.first?.eventSequence, 1)
    XCTAssertEqual(stateB.batch.records.first?.eventSequence, 2)
    stateA.filterText = "first only"
    stateA.selectedEventIDs = ["first selection"]
    XCTAssertTrue(stateB.filterText.isEmpty)
    XCTAssertTrue(stateB.selectedEventIDs.isEmpty)
    let keys = await runtime.requestKeys
    XCTAssertEqual(
      keys,
      [
        PolicyAuditLogKey(setIdentifier: document.setIdentifier, policyIdentifier: a),
        PolicyAuditLogKey(setIdentifier: document.setIdentifier, policyIdentifier: b),
      ])
  }

  func testOlderReplyCannotOverwriteMoreRecentRefresh() async throws {
    let document = policies()
    let runtime = PolicyLogRuntime()
    let model = AppModel(initialPolicySet: document, runtimeController: runtime)
    let id = document.policies[0].id
    let first = Task { await model.refreshPolicyAuditLog(policyID: id) }
    await runtime.waitForRequests(1)
    let second = Task { await model.refreshPolicyAuditLog(policyID: id) }
    await runtime.waitForRequests(2)
    await runtime.complete(1, result: .success(batch(2)))
    await second.value
    await runtime.complete(0, result: .success(batch(1)))
    await first.value
    XCTAssertEqual(model.policyLogState(policyID: id)?.batch.records.first?.eventSequence, 2)
    XCTAssertFalse(try XCTUnwrap(model.policyLogState(policyID: id)).isLoading)
  }

  func testDeletedOrReplacedPolicyStateCannotBeRecreatedByLateReply() async throws {
    var document = policies()
    let runtime = PolicyLogRuntime()
    let model = AppModel(initialPolicySet: document, runtimeController: runtime)
    let id = document.policies[0].id
    let oldState = try XCTUnwrap(model.policyLogState(policyID: id))
    let request = Task { await model.refreshPolicyAuditLog(policyID: id) }
    await runtime.waitForRequests(1)
    document.policies.removeFirst()
    document.revision += 1
    model.installActivePolicySet(document)
    await runtime.complete(0, result: .success(batch(1)))
    await request.value
    XCTAssertNil(model.policyLogState(policyID: id))
    XCTAssertTrue(oldState.batch.records.isEmpty)
  }

  func testDraftAndSavedFolderEditsRetainHistoryButNewSetHasSeparateState() throws {
    var document = policies()
    let model = AppModel(initialPolicySet: document)
    let id = document.policies[0].id
    let original = try XCTUnwrap(model.policyLogState(policyID: id))
    original.batch = batch(1)
    model.updatePolicyDraft(id: id) { $0.protectedRootPath = "/Users/example/Unsaved" }
    XCTAssertEqual(model.activePolicy(id: id)?.protectedRootPath, "/Users/example/First")
    XCTAssertTrue(model.policyLogState(policyID: id) === original)
    document.policies[0].protectedRootPath = "/Users/example/Saved"
    document.revision += 1
    model.installActivePolicySet(document, markingClean: id)
    XCTAssertTrue(model.policyLogState(policyID: id) === original)
    document.setIdentifier = UUID()
    model.installActivePolicySet(document)
    XCTAssertFalse(model.policyLogState(policyID: id) === original)
    XCTAssertTrue(try XCTUnwrap(model.policyLogState(policyID: id)).batch.records.isEmpty)
  }

  func testFailedRefreshPreservesLoadedRecordsAndDisplaysUnsupportedError() async throws {
    let document = policies()
    let runtime = PolicyLogRuntime()
    let model = AppModel(initialPolicySet: document, runtimeController: runtime)
    let id = document.policies[0].id
    let state = try XCTUnwrap(model.policyLogState(policyID: id))
    state.batch = batch(1)
    state.hasLoaded = true
    let request = Task { await model.refreshPolicyAuditLog(policyID: id) }
    await runtime.waitForRequests(1)
    await runtime.complete(
      0, result: .failure(ExtensionControlClientError.policyAuditLogUnsupported))
    await request.value
    XCTAssertEqual(state.batch.records.first?.eventSequence, 1)
    XCTAssertTrue(state.error?.contains("Update the extension") == true)
    XCTAssertTrue(state.hasLoaded)
    XCTAssertFalse(state.isLoading)
  }

  func testUnsavedPolicyDoesNotRequestLogsAndAuditDecisionIsNotKernelResponse() async throws {
    let runtime = PolicyLogRuntime()
    let model = AppModel(initialPolicySet: policies(), runtimeController: runtime)
    model.createNewPolicy()
    let id = try XCTUnwrap(model.selectedPolicyID)
    await model.refreshPolicyAuditLog(policyID: id)
    XCTAssertNil(model.policyLogState(policyID: id))
    let requested = await runtime.requestKeys
    XCTAssertTrue(requested.isEmpty)
    var record = batch(1).records[0]
    record.kernelResponse = "allow"
    record.policyEvaluations = [
      PolicyEvaluationRecord(
        policyIdentifier: id, policyName: "Audit", mode: .audit, policyType: .whitelist,
        match: .none, decision: .wouldDeny)
    ]
    let row = PolicyLogRow(record: record)
    XCTAssertEqual(row.decision, "Would deny")
    XCTAssertEqual(row.response, "allow")
  }

  private func policies() -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(), revision: 1,
      policies: [
        DirectoryPolicy(
          name: "First", mode: .audit, policyType: .whitelist,
          protectedRootPath: "/Users/example/First", rules: []),
        DirectoryPolicy(
          name: "Second", mode: .audit, policyType: .whitelist,
          protectedRootPath: "/Users/example/Second", rules: []),
      ])
  }

  private func batch(_ sequence: UInt64) -> AuditLogBatch {
    AuditLogBatch(records: [
      AuditEventRecord(
        eventSequence: sequence, eventType: "AUTH_OPEN", policyDecision: "audit-only",
        kernelResponse: "allow")
    ])
  }
}

private actor PolicyLogRuntime: ExtensionRuntimeControlling {
  private var replies: [CheckedContinuation<AuditLogBatch, any Error>?] = []
  private var waiters: [(Int, CheckedContinuation<Void, Never>)] = []
  private(set) var requestKeys: [PolicyAuditLogKey] = []

  func readPolicyAuditLog(setIdentifier: UUID, policyIdentifier: UUID, maximumLineCount: Int)
    async throws
    -> AuditLogBatch
  {
    requestKeys.append(
      PolicyAuditLogKey(setIdentifier: setIdentifier, policyIdentifier: policyIdentifier))
    return try await withCheckedThrowingContinuation { continuation in
      replies.append(continuation)
      let ready = waiters.filter { replies.count >= $0.0 }
      waiters.removeAll { replies.count >= $0.0 }
      for waiter in ready { waiter.1.resume() }
    }
  }

  func waitForRequests(_ count: Int) async {
    if replies.count >= count { return }
    await withCheckedContinuation { waiters.append((count, $0)) }
  }

  func complete(_ index: Int, result: Result<AuditLogBatch, any Error>) {
    replies[index]?.resume(with: result)
    replies[index] = nil
  }

  func applyPolicySet(
    _ document: PolicySetDocument, authorization: Data?, savedPolicyIdentifier: UUID?
  ) async throws -> PolicyApplyReceipt {
    throw Failure.unused
  }
  func queryStatus() async throws -> ExtensionStatusSnapshot { throw Failure.unused }
  func queryPolicySet() async throws -> PolicySetDocument { throw Failure.unused }
  func readAuditLog(maximumLineCount: Int) async throws -> AuditLogBatch { throw Failure.unused }
  func invalidate() {}
  private enum Failure: Error { case unused }
}
