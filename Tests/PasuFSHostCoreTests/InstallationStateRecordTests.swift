import Foundation
import XCTest

@testable import PasuFSHostCore

final class InstallationStateRecordTests: XCTestCase {
  private let start = Date(timeIntervalSince1970: 1_800_000_000)
  private let installed = [
    ExtensionInstallationProperties(
      bundleIdentifier: ActivationController.extensionIdentifier, bundleVersion: "123",
      bundleShortVersion: "1.2.3", isEnabled: true, isAwaitingUserApproval: false,
      isUninstalling: false)
  ]

  private func at(_ seconds: TimeInterval) -> Date {
    start.addingTimeInterval(seconds)
  }

  private func record(
    _ result: InstallationStateQueryResult, startedAt: TimeInterval,
    in record: inout InstallationStateRecord
  ) {
    record.record(
      result, startedAt: at(startedAt), endedAt: at(startedAt + 0.1), retryPolicy: .standard)
  }

  /// Reported installations describe the Mac for 90 seconds, then count as unknown.
  func testReportIsCurrentWithinTheMaximumAge() {
    var states = InstallationStateRecord()
    XCTAssertNil(states.currentInstallations(at: start), "no report yet")
    record(.reported(installed), startedAt: 0, in: &states)

    XCTAssertEqual(states.currentInstallations(at: at(0.1)), installed)
    XCTAssertTrue(states.isCurrent(at: at(InstallationStateQueries.maximumAge)))
    XCTAssertFalse(states.isCurrent(at: at(InstallationStateQueries.maximumAge + 1)))
    XCTAssertTrue(states.isCurrent(at: at(2), maximumAge: 2))
    XCTAssertFalse(states.isCurrent(at: at(3), maximumAge: 2))
    XCTAssertFalse(states.isCurrent(at: at(-1)), "a report from the future")

    // An empty report is current too: macOS reports that nothing is installed.
    record(.reported([]), startedAt: 10, in: &states)
    XCTAssertEqual(states.currentInstallations(at: at(11)), [])
  }

  /// A later failure or unanswered query makes earlier installations unknown, not absent.
  func testFailureOrTimeoutMakesTheReportUnknown() {
    var states = InstallationStateRecord()
    record(.reported(installed), startedAt: 0, in: &states)
    record(.failed(.invalidOutput), startedAt: 10, in: &states)
    XCTAssertNil(states.currentInstallations(at: at(11)))
    XCTAssertEqual(states.installations, installed, "the last report is kept")
    XCTAssertEqual(states.failure, .invalidOutput)
    XCTAssertNil(states.unansweredSince, "a local failure doesn't say whether macOS answers")

    record(.reported(installed), startedAt: 20, in: &states)
    XCTAssertNotNil(states.currentInstallations(at: at(21)))
    record(.unanswered, startedAt: 30, in: &states)
    XCTAssertNil(states.currentInstallations(at: at(51)))
    XCTAssertEqual(states.unansweredSince, at(30))
  }

  func testUnansweredQueriesKeepTheFirstStartUntilMacOSAnswers() {
    var states = InstallationStateRecord()
    record(.reported(installed), startedAt: 0, in: &states)
    record(.unanswered, startedAt: 60, in: &states)
    record(.unanswered, startedAt: 120, in: &states)
    XCTAssertEqual(states.unansweredSince, at(60))
    XCTAssertEqual(states.unansweredCount, 2)

    // A local failure meanwhile doesn't show that macOS answers again.
    record(.failed(.launchFailed("sample")), startedAt: 240, in: &states)
    XCTAssertEqual(states.unansweredSince, at(60))

    // An error from macOS does.
    record(
      .failed(.requestFailed(domain: "OSSystemExtensionErrorDomain", code: 1, description: "x")),
      startedAt: 300, in: &states)
    XCTAssertNil(states.unansweredSince)
    XCTAssertEqual(states.unansweredCount, 0)
    XCTAssertNil(states.nextQueryNotBefore(automatic: true, at: at(301)))
    XCTAssertEqual(states.reportedAt, at(0.1), "an error reports no states")
  }

  /// While macOS doesn't answer, any query waits a minute from the start of the unanswered one,
  /// and automatic checks wait twice as long after each further one, up to 10 minutes.
  func testRetryTimesWhileMacOSDoesNotAnswer() {
    var states = InstallationStateRecord()
    record(.unanswered, startedAt: 0, in: &states)
    XCTAssertEqual(states.nextQueryNotBefore(automatic: false, at: at(20)), at(60))
    XCTAssertEqual(states.nextQueryNotBefore(automatic: true, at: at(20)), at(60))
    XCTAssertNil(states.nextQueryNotBefore(automatic: false, at: at(60)))

    record(.unanswered, startedAt: 60, in: &states)
    XCTAssertEqual(states.nextQueryNotBefore(automatic: false, at: at(80)), at(120))
    XCTAssertEqual(states.nextQueryNotBefore(automatic: true, at: at(80)), at(180))
    record(.unanswered, startedAt: 180, in: &states)
    XCTAssertEqual(states.nextQueryNotBefore(automatic: true, at: at(200)), at(420))
    for _ in 0..<10 { record(.unanswered, startedAt: 1_000, in: &states) }
    XCTAssertEqual(states.nextQueryNotBefore(automatic: true, at: at(1_001)), at(1_600))
    XCTAssertEqual(states.nextQueryNotBefore(automatic: false, at: at(1_001)), at(1_060))
    // After the clock moved back, a query may start.
    XCTAssertNil(states.nextQueryNotBefore(automatic: true, at: at(999)))

    record(.reported([]), startedAt: 1_100, in: &states)
    XCTAssertNil(states.nextQueryNotBefore(automatic: true, at: at(1_101)))
  }

  func testAutomaticDelayDoublesUpToTheMaximum() {
    let policy = InstallationStateRetryPolicy.standard
    XCTAssertEqual(policy.automaticDelay(afterUnansweredQueries: 0), 0)
    XCTAssertEqual(
      (1...7).map { policy.automaticDelay(afterUnansweredQueries: $0) },
      [60, 120, 240, 480, 600, 600, 600])
    XCTAssertEqual(policy.automaticDelay(afterUnansweredQueries: 10_000), 600)
    let none = InstallationStateRetryPolicy(minimumInterval: 0, maximumAutomaticDelay: 0)
    XCTAssertEqual(none.automaticDelay(afterUnansweredQueries: 3), 0)
  }

  func testEveryChangeRaisesTheRevision() {
    var states = InstallationStateRecord()
    record(.reported([]), startedAt: 0, in: &states)
    record(.unanswered, startedAt: 1, in: &states)
    record(.failed(.invalidOutput), startedAt: 2, in: &states)
    XCTAssertEqual(states.revision, 3)
    XCTAssertEqual(states.lastQueryStartedAt, at(2), "the schedule counts from it")
  }
}
