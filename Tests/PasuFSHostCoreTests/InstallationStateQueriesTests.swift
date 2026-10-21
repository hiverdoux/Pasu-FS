import Foundation
import XCTest

@testable import PasuFSHostCore

final class InstallationStateQueriesTests: XCTestCase {
  private let start = Date(timeIntervalSince1970: 1_800_000_000)

  private func at(_ seconds: TimeInterval) -> Date {
    start.addingTimeInterval(seconds)
  }

  /// A record whose latest query started at `seconds` and was answered.
  private func answered(at seconds: TimeInterval) -> InstallationStateRecord {
    var record = InstallationStateRecord()
    record.record(
      .reported([]), startedAt: at(seconds), endedAt: at(seconds + 0.1), retryPolicy: .standard)
    return record
  }

  /// One check at launch, then one a minute after the latest query started.
  func testBackgroundChecksAreAMinuteApart() {
    let queries = InstallationStateQueries()
    XCTAssertTrue(queries.isDue(at: start, interests: []))

    let record = answered(at: 0)
    for seconds in [2.0, 4, 30, 59.9] {
      XCTAssertFalse(queries.isDue(at: at(seconds), interests: [], record: record), "\(seconds)")
    }
    XCTAssertTrue(queries.isDue(at: at(60), interests: [], record: record))
    XCTAssertEqual(queries.interval(for: []), InstallationStateQueries.backgroundInterval)
  }

  func testScreensThatShowTheStatesShortenTheInterval() {
    let queries = InstallationStateQueries()
    let record = answered(at: 0)

    XCTAssertEqual(queries.interval(for: [.extensionSettings]), 15)
    XCTAssertFalse(queries.isDue(at: at(14), interests: [.extensionSettings], record: record))
    XCTAssertTrue(queries.isDue(at: at(15), interests: [.extensionSettings], record: record))

    XCTAssertEqual(queries.interval(for: [.approval]), 5)
    XCTAssertFalse(queries.isDue(at: at(4.9), interests: [.approval], record: record))
    XCTAssertTrue(queries.isDue(at: at(5), interests: [.approval], record: record))
    XCTAssertEqual(queries.interval(for: [.approval, .extensionSettings]), 5)
  }

  /// An extension that starts or stops answering, or restarts, may have been approved, replaced
  /// or removed; the next check comes sooner, and only once.
  func testRuntimeChangeAsksSoonerOnce() {
    var queries = InstallationStateQueries()
    queries.recordRuntimeChange()
    XCTAssertEqual(queries.interval(for: []), InstallationStateQueries.runtimeChangeInterval)
    let record = answered(at: 0)
    XCTAssertFalse(queries.isDue(at: at(4), interests: [], record: record))
    XCTAssertTrue(queries.isDue(at: at(5), interests: [], record: record))

    let submission = queries.recordSubmission()
    queries.recordCompletion(submission, queried: true)
    XCTAssertFalse(queries.runtimeChanged)
    XCTAssertEqual(queries.interval(for: []), InstallationStateQueries.backgroundInterval)
    XCTAssertFalse(queries.isDue(at: at(20), interests: [], record: answered(at: 5)))
  }

  /// A call that was held back or cancelled started no query, so the change waits for the next
  /// one; a change during a call is left for the next one too.
  func testOnlyACallThatQueriedCoversTheRuntimeChange() {
    var queries = InstallationStateQueries()
    queries.recordRuntimeChange()
    let held = queries.recordSubmission()
    queries.recordCompletion(held, queried: false)
    XCTAssertTrue(queries.runtimeChanged)

    let queried = queries.recordSubmission()
    queries.recordRuntimeChange()
    queries.recordCompletion(queried, queried: true)
    XCTAssertTrue(queries.runtimeChanged, "the change came after the call")
    let next = queries.recordSubmission()
    queries.recordCompletion(next, queried: true)
    XCTAssertFalse(queries.runtimeChanged)
  }

  /// Only one background check waits for an answer at a time.
  func testNoBackgroundCheckWhileOneIsPending() {
    var queries = InstallationStateQueries()
    let submission = queries.recordSubmission()
    XCTAssertEqual(queries.pendingCount, 1)
    XCTAssertFalse(queries.isDue(at: at(600), interests: [.approval]))

    queries.recordCompletion(submission, queried: true)
    XCTAssertEqual(queries.pendingCount, 0)
    XCTAssertTrue(queries.isDue(at: at(600), interests: [], record: answered(at: 0)))
    queries.recordCompletion(submission, queried: true)
    XCTAssertEqual(queries.pendingCount, 0, "never below zero")
  }

  func testCheckIsDueAfterTheClockMovedBack() {
    let queries = InstallationStateQueries()
    XCTAssertTrue(queries.isDue(at: at(-1), interests: [], record: answered(at: 0)))
  }

  /// While macOS doesn't answer, background checks wait for the record's automatic retry time,
  /// whatever the interval. A Refresh that was held back meanwhile doesn't move the schedule.
  func testUnansweredQueriesHoldBackgroundChecks() {
    var record = InstallationStateRecord()
    record.record(
      .unanswered, startedAt: start, endedAt: at(20), retryPolicy: .standard)
    var queries = InstallationStateQueries()
    let refresh = queries.recordSubmission()
    queries.recordCompletion(refresh, queried: false)

    XCTAssertFalse(queries.isDue(at: at(30), interests: [.approval], record: record))
    XCTAssertFalse(queries.isDue(at: at(59), interests: [.approval], record: record))
    XCTAssertTrue(queries.isDue(at: at(60), interests: [.approval], record: record))
  }
}
