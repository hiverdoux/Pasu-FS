import Darwin
import EndpointSecurity
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest
import os

@testable import PasuFSEndpointCore

/// Messages macOS dropped: only lost process starts, forks and exits reset the execution history;
/// any other gap counts toward unchecked requests and is logged once per stretch.
final class DeliveryGapTests: XCTestCase {
  private let forkEvent = ES_EVENT_TYPE_NOTIFY_FORK.rawValue
  private let exitEvent = ES_EVENT_TYPE_NOTIFY_EXIT.rawValue
  private let openEvent = ES_EVENT_TYPE_AUTH_OPEN.rawValue
  private let renameEvent = ES_EVENT_TYPE_AUTH_RENAME.rawValue
  private let second: UInt64 = 1_000_000_000
  private let start = Date(timeIntervalSince1970: 1_800_000_000)

  // MARK: - Numbering

  func testFirstMessagesShowNoGap() {
    var gaps = DeliveryGapAccounting()
    // Numbers that start high are where the client's numbering stands, not drops.
    XCTAssertEqual(observe(&gaps, forkEvent, sequence: 40, global: 900), .init())
    XCTAssertEqual(observe(&gaps, openEvent, sequence: 7, global: 901), .init())
    XCTAssertEqual(observe(&gaps, exitEvent, sequence: 12, global: 902), .init())
    XCTAssertNil(gaps.finish(uptime: 10 * second, force: true))
    XCTAssertEqual(gaps.metrics, UncheckedRequestMetrics())
  }

  func testOnlyProcessEventGapsLoseHistory() {
    var gaps = DeliveryGapAccounting()
    _ = observe(&gaps, forkEvent, sequence: 1, global: 1)
    _ = observe(&gaps, openEvent, sequence: 1, global: 2)
    // Three messages dropped; the open's own numbering shows two of them were opens.
    let request = observe(&gaps, openEvent, sequence: 4, global: 6)
    XCTAssertFalse(request.lostProcessEvents)
    XCTAssertFalse(request.lacksNumbering)
    // The next fork follows the last one, so no fork was among the dropped messages.
    XCTAssertFalse(observe(&gaps, forkEvent, sequence: 2, global: 7).lostProcessEvents)
    let skippedFork = observe(&gaps, forkEvent, sequence: 4, global: 9)
    XCTAssertTrue(skippedFork.lostProcessEvents)
    XCTAssertEqual(gaps.metrics.missedMessages, 4)
    XCTAssertEqual(gaps.metrics.missedProcessEvents, 1)
  }

  func testProcessEventsMissedInTheSameStretchAreNotCountedAsRequests() throws {
    var gaps = DeliveryGapAccounting()
    _ = observe(&gaps, forkEvent, sequence: 1, global: 1)
    _ = observe(&gaps, exitEvent, sequence: 1, global: 2)
    _ = observe(&gaps, openEvent, sequence: 1, global: 3)
    // Ten messages dropped: two forks and three exits among them, found within the second.
    XCTAssertFalse(observe(&gaps, openEvent, sequence: 3, global: 14).lostProcessEvents)
    XCTAssertTrue(observe(&gaps, forkEvent, sequence: 4, global: 15, at: 0.3).lostProcessEvents)
    XCTAssertTrue(observe(&gaps, exitEvent, sequence: 5, global: 16, at: 0.6).lostProcessEvents)
    // Nothing counts until the stretch ends.
    XCTAssertEqual(gaps.metrics.estimatedCount, 0)
    let stretch = try XCTUnwrap(gaps.finish(uptime: second, force: false))
    XCTAssertEqual(stretch.missedMessages, 10)
    XCTAssertEqual(stretch.missedProcessEvents, 5)
    XCTAssertEqual(stretch.estimatedUncheckedRequests, 5)
    XCTAssertEqual(stretch.gapCount, 1)
    XCTAssertEqual(stretch.firstSequence, 14)
    XCTAssertEqual(gaps.metrics.estimatedCount, 5)
    XCTAssertEqual(gaps.metrics.lastEstimatedCount, 5)
    XCTAssertEqual(gaps.metrics.lastObservedAt, start)
  }

  func testGapsWithinOneSecondFormOneStretch() throws {
    var gaps = DeliveryGapAccounting()
    _ = observe(&gaps, openEvent, sequence: 1, global: 1)
    _ = observe(&gaps, openEvent, sequence: 3, global: 3)
    _ = observe(&gaps, openEvent, sequence: 6, global: 6, at: 0.5)
    XCTAssertNil(observe(&gaps, openEvent, sequence: 7, global: 7, at: 0.9).finished)
    // The first message after the window ends the stretch; its own gap starts the next one.
    let ended = observe(&gaps, openEvent, sequence: 9, global: 9, at: 1.2)
    let first = try XCTUnwrap(ended.finished)
    XCTAssertEqual(first.gapCount, 2)
    XCTAssertEqual(first.missedMessages, 3)
    XCTAssertEqual(first.firstGapAt, start)
    XCTAssertEqual(first.lastGapAt, start.addingTimeInterval(0.5))
    XCTAssertEqual(gaps.metrics.estimatedCount, 3)
    XCTAssertEqual(gaps.metrics.missedMessages, 4)
    // A stretch still open counts only once it is finished.
    XCTAssertNil(gaps.finish(uptime: 2 * second, force: false))
    let next = try XCTUnwrap(gaps.finish(uptime: 2 * second + second / 5, force: false))
    XCTAssertEqual(next.missedMessages, 1)
    XCTAssertEqual(next.firstGapAt, start.addingTimeInterval(1.2))
    XCTAssertEqual(gaps.metrics.estimatedCount, 4)
    XCTAssertEqual(gaps.metrics.lastEstimatedCount, 1)
    XCTAssertEqual(gaps.metrics.lastObservedAt, start.addingTimeInterval(1.2))
  }

  func testStretchOfOnlyProcessEventsLeavesTheLastUncheckedRequestsAlone() throws {
    var gaps = DeliveryGapAccounting()
    _ = observe(&gaps, openEvent, sequence: 1, global: 1)
    _ = observe(&gaps, forkEvent, sequence: 1, global: 2)
    _ = observe(&gaps, openEvent, sequence: 3, global: 4)
    _ = try XCTUnwrap(gaps.finish(uptime: 5 * second, force: true))
    XCTAssertEqual(gaps.metrics.lastEstimatedCount, 1)
    _ = observe(&gaps, forkEvent, sequence: 3, global: 6, at: 10)
    let stretch = try XCTUnwrap(gaps.finish(uptime: 20 * second, force: false))
    XCTAssertEqual(stretch.estimatedUncheckedRequests, 0)
    XCTAssertEqual(gaps.metrics.estimatedCount, 1)
    XCTAssertEqual(gaps.metrics.lastEstimatedCount, 1)
    XCTAssertEqual(gaps.metrics.lastObservedAt, start)
    XCTAssertEqual(gaps.metrics.missedProcessEvents, 1)
  }

  func testProcessNumberingThatGoesBackLosesHistory() {
    var gaps = DeliveryGapAccounting()
    _ = observe(&gaps, exitEvent, sequence: 50, global: 1)
    XCTAssertTrue(observe(&gaps, exitEvent, sequence: 2, global: 2).lostProcessEvents)
    // An overall number that goes back gives no count.
    XCTAssertFalse(observe(&gaps, openEvent, sequence: 1, global: 1).lostProcessEvents)
    XCTAssertEqual(gaps.metrics.missedMessages, 0)
  }

  func testEventTypeNumberingAloneBeforeMessageVersion4() throws {
    var gaps = DeliveryGapAccounting()
    _ = observe(&gaps, openEvent, sequence: 1, global: nil)
    _ = observe(&gaps, renameEvent, sequence: 1, global: nil)
    _ = observe(&gaps, exitEvent, sequence: 1, global: nil)
    XCTAssertFalse(observe(&gaps, openEvent, sequence: 4, global: nil).lostProcessEvents)
    XCTAssertFalse(observe(&gaps, renameEvent, sequence: 2, global: nil).lostProcessEvents)
    XCTAssertTrue(observe(&gaps, exitEvent, sequence: 3, global: nil).lostProcessEvents)
    let stretch = try XCTUnwrap(gaps.finish(uptime: 0, force: true))
    XCTAssertEqual(stretch.missedMessages, 3)
    XCTAssertEqual(stretch.missedProcessEvents, 1)
    XCTAssertEqual(stretch.estimatedUncheckedRequests, 2)
    XCTAssertEqual(stretch.firstSequence, 4)
  }

  func testMessagesWithoutNumberingAreReported() {
    var gaps = DeliveryGapAccounting()
    XCTAssertTrue(observe(&gaps, forkEvent, sequence: nil, global: nil).lacksNumbering)
    XCTAssertTrue(observe(&gaps, openEvent, sequence: nil, global: nil).lacksNumbering)
    XCTAssertEqual(gaps.metrics, UncheckedRequestMetrics())
  }

  // MARK: - Execution history and log

  func testOverallGapKeepsAllowedProgramsAllowedAndIsLoggedOnce() throws {
    let fixture = try Fixture()
    defer { fixture.remove() }
    try fixture.launchAllowedProgram()
    fixture.deliver(forkEvent, sequence: 1, global: 1)
    fixture.deliver(openEvent, sequence: 1, global: 2)
    fixture.deliver(openEvent, sequence: 2, global: 9)
    fixture.deliver(openEvent, sequence: 5, global: 12, at: 0.4)
    fixture.deliver(forkEvent, sequence: 2, global: 13, at: 0.8)

    XCTAssertEqual(fixture.coordinator.executionOriginStatus.invalidationCount, 0)
    XCTAssertEqual(fixture.allowedOpen().authorizedFlags, UInt32.max)
    XCTAssertTrue(fixture.sink.records.isEmpty)

    fixture.advance(to: 1.1)
    fixture.deliver(exitEvent, sequence: 1, global: 14, at: 1.1)
    let record = try XCTUnwrap(fixture.sink.records.first)
    XCTAssertEqual(fixture.sink.records.count, 1)
    XCTAssertEqual(record.eventType, EndpointEventCoordinator.deliveryGapEventType)
    XCTAssertEqual(record.kernelResponse, "not-delivered")
    XCTAssertEqual(record.policyDecision, "unchecked")
    XCTAssertEqual(record.eventSequence, 9)
    XCTAssertEqual(record.timestamp, start)
    XCTAssertEqual(record.lastTimestamp, start.addingTimeInterval(0.4))
    XCTAssertNil(record.requestCount)
    XCTAssertNil(record.processID)
    XCTAssertNil(record.policyEvaluations)
    XCTAssertEqual(
      record.detail,
      "missedMessages=8 missedProcessEvents=0 estimatedUncheckedRequests=8 gaps=2")
    var expected = UncheckedRequestMetrics()
    expected.estimatedCount = 8
    expected.lastEstimatedCount = 8
    expected.lastObservedAt = start.addingTimeInterval(0.4)
    expected.missedMessages = 8
    XCTAssertEqual(fixture.coordinator.uncheckedRequestMetrics, expected)
  }

  func testProcessEventGapDeniesUntilTheProgramIsStartedAgain() throws {
    let fixture = try Fixture()
    defer { fixture.remove() }
    try fixture.launchAllowedProgram()
    fixture.deliver(forkEvent, sequence: 1, global: 1)
    fixture.deliver(forkEvent, sequence: 3, global: 3)

    let status = fixture.coordinator.executionOriginStatus
    XCTAssertEqual(status.invalidationCount, 1)
    XCTAssertEqual(status.lastInvalidation, .eventLoss)
    let denied = fixture.allowedOpen()
    XCTAssertEqual(denied.authorizedFlags, 0)
    XCTAssertEqual(denied.policyEvaluations[0].executionOrigin?.reason, .incompleteHistory)
    XCTAssertEqual(denied.policyEvaluations[0].executionOrigin?.uncertainty, .eventLoss)

    try fixture.launchAllowedProgram()
    XCTAssertEqual(fixture.allowedOpen().authorizedFlags, UInt32.max)
    // The dropped message was a fork, so no request went unchecked.
    fixture.coordinator.finishDeliveryGaps(force: true)
    XCTAssertEqual(fixture.coordinator.uncheckedRequestMetrics.estimatedCount, 0)
    XCTAssertEqual(fixture.coordinator.uncheckedRequestMetrics.missedProcessEvents, 1)
    XCTAssertEqual(
      fixture.sink.records.map(\.detail),
      ["missedMessages=1 missedProcessEvents=1 estimatedUncheckedRequests=0 gaps=1"])
  }

  func testMixedGapResetsHistoryAndCountsTheRest() throws {
    let fixture = try Fixture()
    defer { fixture.remove() }
    try fixture.launchAllowedProgram()
    fixture.deliver(exitEvent, sequence: 1, global: 1)
    fixture.deliver(openEvent, sequence: 1, global: 2)
    fixture.deliver(exitEvent, sequence: 3, global: 8)
    XCTAssertEqual(fixture.coordinator.executionOriginStatus.lastInvalidation, .eventLoss)
    XCTAssertEqual(fixture.allowedOpen().authorizedFlags, 0)
    fixture.coordinator.finishDeliveryGaps(force: true)
    XCTAssertEqual(fixture.coordinator.uncheckedRequestMetrics.estimatedCount, 4)
    XCTAssertEqual(fixture.coordinator.executionOriginStatus.invalidationCount, 1)
  }

  func testMessagesWithoutNumberingResetHistoryAsBefore() throws {
    let fixture = try Fixture()
    defer { fixture.remove() }
    try fixture.launchAllowedProgram()
    fixture.deliver(openEvent, sequence: nil, global: nil)
    XCTAssertEqual(
      fixture.coordinator.executionOriginStatus.lastInvalidation, .unavailableEventVersion)
    XCTAssertEqual(fixture.allowedOpen().authorizedFlags, 0)
    XCTAssertTrue(fixture.sink.records.isEmpty)
  }

  func testWaitingStretchIsLoggedWhenTheStatusIsReadOrTheExtensionStops() throws {
    let fixture = try Fixture()
    defer { fixture.remove() }
    fixture.deliver(openEvent, sequence: 1, global: 1)
    fixture.deliver(openEvent, sequence: 2, global: 3)
    fixture.coordinator.finishDeliveryGaps()
    XCTAssertTrue(fixture.sink.records.isEmpty)
    fixture.advance(to: 1)
    fixture.coordinator.finishDeliveryGaps()
    XCTAssertEqual(fixture.sink.records.count, 1)
    fixture.deliver(openEvent, sequence: 3, global: 5, at: 1.5)
    fixture.coordinator.finishDeliveryGaps(force: true)
    XCTAssertEqual(fixture.sink.records.count, 2)
    XCTAssertEqual(fixture.coordinator.uncheckedRequestMetrics.estimatedCount, 2)
  }

  func testGapRecordIsSavedOnlyInTheGlobalLog() throws {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("pasu-fs-delivery-gap-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = try PolicyAuditLogStore(directoryURL: directory, requiredOwnerUserID: getuid())
    defer { store.flushAndClose() }
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: UUID(), policies: [], policyRevision: 1, sink: store)
    for (sequence, global): (UInt64, UInt64) in [(1, 1), (2, 4)] {
      if let stretch = coordinator.observeDelivery(
        eventType: ES_EVENT_TYPE_AUTH_OPEN, sequence: sequence, globalSequence: global, at: start)
      {
        coordinator.recordDeliveryGaps(stretch)
      }
    }
    coordinator.finishDeliveryGaps(force: true)
    let records = try store.readAuditLog(maximumLineCount: 10).records
    XCTAssertEqual(records.map(\.eventType), [EndpointEventCoordinator.deliveryGapEventType])
    XCTAssertEqual(
      records.first?.detail,
      "missedMessages=2 missedProcessEvents=0 estimatedUncheckedRequests=2 gaps=1")
    let names = try FileManager.default.contentsOfDirectory(atPath: directory.path)
    XCTAssertFalse(names.contains { $0.hasPrefix("policy-") })
  }

  func testStatusWithoutUncheckedRequestsStillDecodes() throws {
    var snapshot = ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(), phase: .idle, timestamp: start)
    snapshot.uncheckedRequests = UncheckedRequestMetrics()
    snapshot.uncheckedRequests?.estimatedCount = 3
    let encoder = JSONEncoder()
    let decoder = JSONDecoder()
    let data = try encoder.encode(snapshot)
    XCTAssertEqual(try decoder.decode(ExtensionStatusSnapshot.self, from: data), snapshot)
    var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    object.removeValue(forKey: "uncheckedRequests")
    let older = try decoder.decode(
      ExtensionStatusSnapshot.self, from: JSONSerialization.data(withJSONObject: object))
    XCTAssertNil(older.uncheckedRequests)
  }

  // MARK: - Helpers

  private func observe(
    _ gaps: inout DeliveryGapAccounting, _ type: UInt32, sequence: UInt64?, global: UInt64?,
    at seconds: Double = 0
  ) -> DeliveryGapAccounting.Observation {
    gaps.observe(
      eventType: type, isProcessEvent: type == forkEvent || type == exitEvent,
      sequence: sequence, globalSequence: global, at: start.addingTimeInterval(seconds),
      uptime: UInt64(seconds * Double(second)))
  }

  /// A Protection policy that allows one program, with a clock the test moves.
  private final class Fixture {
    let sink = GapTestSink()
    let base: URL
    let coordinator: EndpointEventCoordinator
    private let clock = OSAllocatedUnfairLock(initialState: UInt64(0))
    private let folder: URL
    private let start = Date(timeIntervalSince1970: 1_800_000_000)
    private let editor: ProcessFacts

    init() throws {
      base = PhysicalPath.resolve(
        FileManager.default.temporaryDirectory
          .appendingPathComponent("PasuFSDeliveryGapTests-\(UUID().uuidString)"))
      let home = base.appendingPathComponent("home")
      folder = home.appendingPathComponent("Protected")
      try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
      let rule = AllowRule(
        id: "rule.editor",
        program: SignedProgramIdentity(
          teamIdentifier: "TEAM123456", signingIdentifier: "com.example.Editor"),
        allowsDescendants: false)
      editor = try Self.facts(seed: 10, team: "TEAM123456", signing: "com.example.Editor")
      let clock = clock
      coordinator = EndpointEventCoordinator(
        policySetIdentifier: UUID(),
        policies: [
          EndpointPolicyConfiguration(
            id: UUID(), name: "Example", mode: .protection, policyType: .whitelist,
            scope: try ProtectedPathScope(root: folder.path, homeDirectory: home.path),
            rules: PolicySnapshot(rules: [rule]))
        ],
        policyRevision: 1, sink: sink, decodeFailurePolicy: .failClosed,
        uptime: { clock.withLock { $0 } })
    }

    func remove() { try? FileManager.default.removeItem(at: base) }

    func advance(to seconds: Double) {
      clock.withLock { $0 = UInt64(seconds * 1_000_000_000) }
    }

    /// Mirrors `handle(client:message:)`: the numbering is checked first and a finished
    /// stretch is logged after the message.
    func deliver(_ type: UInt32, sequence: UInt64?, global: UInt64?, at seconds: Double = 0) {
      if let stretch = coordinator.observeDelivery(
        eventType: es_event_type_t(rawValue: type), sequence: sequence, globalSequence: global,
        at: start.addingTimeInterval(seconds))
      {
        coordinator.recordDeliveryGaps(stretch)
      }
    }

    /// launchd forks a child that starts the allowed program, all observed.
    func launchAllowedProgram() throws {
      let launchd = ExecutionProgram(
        facts: try Self.facts(
          seed: 1, team: "", signing: "com.apple.xpc.launchd", isPlatformBinary: true),
        executablePath: "/sbin/launchd")
      var child = launchd
      child.instance = ProcessInstanceKey(
        processID: editor.processInstance.processID, processVersion: 0)
      coordinator.observeFork(parent: launchd, child: child)
      coordinator.observeExec(from: child, to: ExecutionProgram(facts: editor, executablePath: ""))
    }

    func allowedOpen() -> EndpointEventCoordinator.AccessEvaluation {
      coordinator.evaluateOpen(
        path: folder.appendingPathComponent("sample.txt").path, pathWasTruncated: false,
        process: editor)
    }

    private static func facts(
      seed: Int32, team: String, signing: String, isPlatformBinary: Bool = false
    ) throws -> ProcessFacts {
      ProcessFacts(
        auditToken: try AuditTokenKey(words: Array(repeating: UInt32(seed), count: 8)),
        processInstance: ProcessInstanceKey(processID: seed, processVersion: 1),
        teamIdentifier: team, signingIdentifier: signing,
        isPlatformBinary: isPlatformBinary, codeSigningFlags: 1)
    }
  }
}

private final class GapTestSink: EndpointEventSink, Sendable {
  private let storage = OSAllocatedUnfairLock(initialState: [EndpointEventRecord]())
  var records: [EndpointEventRecord] { storage.withLock { $0 } }
  func record(_ event: EndpointEventRecord) { storage.withLock { $0.append(event) } }
}
