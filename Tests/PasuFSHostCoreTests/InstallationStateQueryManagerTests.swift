import Darwin
import Foundation
import XCTest

@testable import PasuFSHostCore

/// The manager that runs the installation state queries in child processes, with children whose
/// end the test decides.
final class InstallationStateQueryManagerTests: XCTestCase {
  private let installed = ExtensionInstallationProperties(
    bundleIdentifier: ActivationController.extensionIdentifier, bundleVersion: "123",
    bundleShortVersion: "1.2.3", isEnabled: true, isAwaitingUserApproval: false,
    isUninstalling: false)

  func testReportedInstallationsAreRecorded() async {
    let launcher = ScriptedChildLauncher(endings: [.report(.reported([installed]))])
    let manager = InstallationStateQueryManager(launcher: launcher, timeout: 5)

    let outcome = await manager.query(.automatic)

    XCTAssertEqual(outcome.answer, .reported([installed]))
    XCTAssertEqual(outcome.record.installations, [installed])
    XCTAssertNotNil(outcome.record.reportedAt)
    XCTAssertEqual(launcher.launchCount, 1)
    XCTAssertEqual(launcher.killCount, 0)
  }

  /// macOS's error, an unreadable output, a process that exits or crashes without an answer and
  /// one that can't start are failures, each named.
  func testFailuresAreNamed() async {
    let cases: [(ScriptedChildLauncher.Ending, InstallationStateQueryFailure)] = [
      (
        .report(.requestFailed(domain: "D", code: 4, description: "E")),
        .requestFailed(domain: "D", code: 4, description: "E")
      ),
      (.report(.endedWithoutAnswer), .endedWithoutAnswer),
      (.output("not json\n", status: 0), .invalidOutput),
      (
        .output(#"{"formatVersion":1,"outcome":"timedOut","timeoutSeconds":30}"#, status: 0),
        .invalidOutput
      ),
      (.output("", status: 0), .invalidOutput),
      (.output("", status: 1), .exited(1)),
      (.signal(SIGSEGV), .signaled(SIGSEGV)),
      (.truncated, .invalidOutput),
      (.launchFailure, .launchFailed("sample launch failure")),
    ]
    for (ending, failure) in cases {
      let manager = InstallationStateQueryManager(
        launcher: ScriptedChildLauncher(endings: [ending]), timeout: 5)
      let outcome = await manager.query(.refresh)
      XCTAssertEqual(outcome.answer, .failed(failure), "\(ending)")
      XCTAssertEqual(outcome.record.failure, failure)
      XCTAssertNil(outcome.record.unansweredSince)
    }
  }

  /// A child that doesn't end within the timeout is killed, and the query counts as unanswered
  /// only after the child has ended.
  func testChildIsKilledAtTheTimeoutAndItsEndConfirmed() async {
    let launcher = ScriptedChildLauncher(endings: [.never])
    let manager = InstallationStateQueryManager(launcher: launcher, timeout: 0.1)

    let started = Date()
    let outcome = await manager.query(.automatic)

    XCTAssertEqual(outcome.answer, .unanswered)
    XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    XCTAssertEqual(launcher.killCount, 1)
    XCTAssertTrue(launcher.everyChildEnded, "the answer comes only after the child ended")
    XCTAssertNotNil(outcome.record.unansweredSince)
  }

  /// A child that ends only well after it was killed keeps the query waiting until then: the
  /// manager doesn't start another while one may still run.
  func testNextQueryWaitsForTheKilledChildToEnd() async {
    let launcher = ScriptedChildLauncher(
      endings: [.endsAfterKill(delay: .milliseconds(300)), .report(.reported([]))])
    let manager = InstallationStateQueryManager(
      launcher: launcher, timeout: 0.05, retryPolicy: noRetryLimit)

    let first = Task { await manager.query(.refresh) }
    try? await Task.sleep(for: .milliseconds(150))
    let second = Task { await manager.query(.afterChange) }

    let firstOutcome = await first.value
    XCTAssertEqual(firstOutcome.answer, .unanswered)
    XCTAssertEqual(launcher.maximumRunningChildren, 1)
    let secondOutcome = await second.value
    XCTAssertEqual(secondOutcome.answer, .reported([]))
    XCTAssertEqual(launcher.maximumRunningChildren, 1)
    XCTAssertEqual(launcher.launchCount, 2)
  }

  /// A child that exits on its own just as the timeout passes keeps its answer: only a child the
  /// manager ended left none.
  func testAnswerThatArrivesAtTheTimeoutIsKept() async {
    let launcher = ScriptedChildLauncher(
      endings: [.report(.reported([installed]), delay: .milliseconds(100), ignoresKill: true)])
    let manager = InstallationStateQueryManager(launcher: launcher, timeout: 0.05)

    let outcome = await manager.query(.refresh)

    XCTAssertEqual(launcher.killCount, 1)
    XCTAssertEqual(outcome.answer, .reported([installed]))
    XCTAssertNil(outcome.record.unansweredSince)
  }

  /// The child's own timeout, which protects against a parent that is gone, also counts as
  /// unanswered.
  func testChildTimeoutCountsAsUnanswered() async {
    let manager = InstallationStateQueryManager(
      launcher: ScriptedChildLauncher(endings: [.report(.timedOut(seconds: 30))]), timeout: 5)
    let outcome = await manager.query(.automatic)
    XCTAssertEqual(outcome.answer, .unanswered)
  }

  /// Refreshes and automatic checks while a query runs share its answer: one child.
  func testConcurrentQueriesShareOneChild() async {
    let launcher = ScriptedChildLauncher(
      endings: [.report(.reported([installed]), delay: .milliseconds(200))])
    let manager = InstallationStateQueryManager(launcher: launcher, timeout: 5)

    let outcomes = await withTaskGroup(of: InstallationStateQueryOutcome.self) { group in
      for index in 0..<8 {
        group.addTask { await manager.query(index.isMultiple(of: 2) ? .refresh : .automatic) }
      }
      return await group.reduce(into: []) { $0.append($1) }
    }

    XCTAssertEqual(launcher.launchCount, 1)
    XCTAssertEqual(outcomes.map(\.answer), Array(repeating: .reported([installed]), count: 8))
    XCTAssertEqual(Set(outcomes.map(\.record.revision)), [1])
  }

  /// A check after a change doesn't take the answer of a query that started before it: it waits
  /// for a new one, and checks after the same change share that one.
  func testCheckAfterAChangeWaitsForANewQuery() async {
    let removing = ExtensionInstallationProperties(
      bundleIdentifier: installed.bundleIdentifier, bundleVersion: "123",
      bundleShortVersion: "1.2.3", isEnabled: false, isAwaitingUserApproval: false,
      isUninstalling: true)
    let launcher = ScriptedChildLauncher(endings: [
      .report(.reported([installed]), delay: .milliseconds(200)),
      .report(.reported([removing]), delay: .milliseconds(50)),
    ])
    let manager = InstallationStateQueryManager(launcher: launcher, timeout: 5)

    let before = Task { await manager.query(.automatic) }
    while launcher.launchCount == 0 { try? await Task.sleep(for: .milliseconds(5)) }
    // The change happens here, while the first query runs.
    let after = Task { await manager.query(.afterChange) }
    let alsoAfter = Task { await manager.query(.afterChange) }
    let refresh = Task { await manager.query(.refresh) }

    let beforeOutcome = await before.value
    let afterOutcome = await after.value
    let alsoAfterOutcome = await alsoAfter.value
    let refreshOutcome = await refresh.value

    XCTAssertEqual(beforeOutcome.answer, .reported([installed]))
    XCTAssertEqual(refreshOutcome.answer, .reported([installed]), "a refresh may share it")
    XCTAssertEqual(afterOutcome.answer, .reported([removing]))
    XCTAssertEqual(alsoAfterOutcome.answer, .reported([removing]))
    XCTAssertGreaterThan(afterOutcome.record.revision, beforeOutcome.record.revision)
    XCTAssertEqual(launcher.launchCount, 2)
    XCTAssertEqual(launcher.maximumRunningChildren, 1)
    let record = await manager.record
    XCTAssertEqual(record.installations, [removing])
  }

  /// While macOS doesn't answer, a minute passes between queries, and repeated Refresh commands
  /// start no more; automatic checks wait longer after each unanswered one.
  func testRetryLimitWhileMacOSDoesNotAnswer() async {
    let clock = TestClock()
    let launcher = ScriptedChildLauncher(endings: [
      .never, .never, .never, .report(.reported([])), .report(.reported([])),
    ])
    let manager = InstallationStateQueryManager(
      launcher: launcher, timeout: 0.05, now: { clock.now })

    let first = await manager.query(.automatic)
    XCTAssertEqual(first.answer, .unanswered)
    let start = clock.now

    for _ in 0..<20 {
      let refresh = await manager.query(.refresh)
      XCTAssertEqual(refresh.answer, .held(notBefore: start.addingTimeInterval(60)))
    }
    let afterChange = await manager.query(.afterChange)
    XCTAssertEqual(afterChange.answer, .held(notBefore: start.addingTimeInterval(60)))
    XCTAssertEqual(launcher.launchCount, 1)

    clock.advance(by: 60)
    let second = await manager.query(.refresh)
    XCTAssertEqual(second.answer, .unanswered)
    XCTAssertEqual(launcher.launchCount, 2)
    let secondStart = clock.now

    // The automatic check now waits two minutes; Refresh still a minute.
    clock.advance(by: 60)
    let automatic = await manager.query(.automatic)
    XCTAssertEqual(automatic.answer, .held(notBefore: secondStart.addingTimeInterval(120)))
    let third = await manager.query(.refresh)
    XCTAssertEqual(third.answer, .unanswered)
    XCTAssertEqual(launcher.launchCount, 3)

    // Once macOS answers, queries start at once again.
    clock.advance(by: 60)
    let answered = await manager.query(.refresh)
    XCTAssertEqual(answered.answer, .reported([]))
    XCTAssertNil(answered.record.unansweredSince)
    let after = await manager.query(.automatic)
    XCTAssertEqual(after.answer, .reported([]))
    XCTAssertEqual(launcher.launchCount, 5)
  }

  /// A check after a change that waited for a query that then went unanswered isn't started
  /// within the minute either.
  func testQueuedCheckAfterAnUnansweredQueryIsHeld() async {
    let clock = TestClock()
    let launcher = ScriptedChildLauncher(endings: [.never])
    let manager = InstallationStateQueryManager(
      launcher: launcher, timeout: 0.1, now: { clock.now })

    let running = Task { await manager.query(.refresh) }
    while launcher.launchCount == 0 { try? await Task.sleep(for: .milliseconds(5)) }
    let queued = await manager.query(.afterChange)
    _ = await running.value

    guard case .held = queued.answer else { return XCTFail("\(queued.answer)") }
    XCTAssertEqual(launcher.launchCount, 1)
  }

  /// A cancelled call returns at once; the query goes on for the others.
  func testCancelledCallReturnsAtOnce() async {
    let launcher = ScriptedChildLauncher(
      endings: [.report(.reported([installed]), delay: .milliseconds(300))])
    let manager = InstallationStateQueryManager(launcher: launcher, timeout: 5)

    let cancelled = Task { await manager.query(.refresh) }
    let other = Task { await manager.query(.refresh) }
    while launcher.launchCount == 0 { try? await Task.sleep(for: .milliseconds(5)) }
    let started = Date()
    cancelled.cancel()
    let cancelledOutcome = await cancelled.value
    XCTAssertEqual(cancelledOutcome.answer, .cancelled)
    XCTAssertLessThan(Date().timeIntervalSince(started), 0.25)
    let otherOutcome = await other.value
    XCTAssertEqual(otherOutcome.answer, .reported([installed]))
  }

  /// The launcher refuses an executable outside an app bundle: only the app's main executable
  /// has the entitlements the request needs.
  func testLauncherRequiresTheAppExecutable() {
    for url in [
      nil, URL(fileURLWithPath: "/usr/bin/true"), URL(string: "https://example.com/pasu-fs-app"),
    ] {
      XCTAssertThrowsError(try InstallationStateChildProcessLauncher(executableURL: url).launch())
    }
    XCTAssertEqual(
      InstallationStateChildProcessLauncher.arguments,
      ["--pasu-fs-host", "--installation-states", "--json"])
  }

  private let noRetryLimit = InstallationStateRetryPolicy(
    minimumInterval: 0, maximumAutomaticDelay: 0)
}

private final class TestClock: @unchecked Sendable {
  private let lock = NSLock()
  private var current = Date(timeIntervalSince1970: 1_800_000_000)

  var now: Date { lock.withLock { current } }

  func advance(by seconds: TimeInterval) {
    lock.withLock { current = current.addingTimeInterval(seconds) }
  }
}

/// Starts children that end as the test scripted, one ending per launch in order.
private final class ScriptedChildLauncher: InstallationStateChildLaunching, @unchecked Sendable {
  enum Ending {
    /// Exits with the report's output and status, after the delay. With `ignoresKill`, it
    /// exits on its own even when killed meanwhile.
    case report(InstallationStateReport, delay: Duration = .zero, ignoresKill: Bool = false)
    case output(String, status: Int32)
    case signal(Int32)
    case truncated
    /// Runs until killed.
    case never
    /// Ends this long after it is killed.
    case endsAfterKill(delay: Duration)
    case launchFailure
  }

  private let lock = NSLock()
  private var endings: [Ending]
  private var launches = 0
  private var kills = 0
  private var running = 0
  private var maximumRunning = 0

  init(endings: [Ending]) {
    self.endings = endings
  }

  var launchCount: Int { lock.withLock { launches } }
  var killCount: Int { lock.withLock { kills } }
  var maximumRunningChildren: Int { lock.withLock { maximumRunning } }
  var everyChildEnded: Bool { lock.withLock { running == 0 } }

  func launch() throws -> any InstallationStateChild {
    let ending = try lock.withLock { () throws -> Ending in
      let ending = endings.isEmpty ? .never : endings.removeFirst()
      if case .launchFailure = ending {
        throw InstallationStateLaunchError("sample launch failure")
      }
      launches += 1
      running += 1
      maximumRunning = max(maximumRunning, running)
      return ending
    }
    return ScriptedChild(ending: ending, launcher: self)
  }

  fileprivate func childKilled() { lock.withLock { kills += 1 } }
  fileprivate func childEnded() { lock.withLock { running -= 1 } }
}

private final class ScriptedChild: InstallationStateChild, @unchecked Sendable {
  private let lock = NSLock()
  private var termination: InstallationStateChildTermination?
  private var waiters: [CheckedContinuation<InstallationStateChildTermination, Never>] = []
  private let ending: ScriptedChildLauncher.Ending
  private weak var launcher: ScriptedChildLauncher?

  init(ending: ScriptedChildLauncher.Ending, launcher: ScriptedChildLauncher) {
    self.ending = ending
    self.launcher = launcher
    switch ending {
    case .report(let report, let delay, _):
      endLater(
        after: delay,
        InstallationStateChildTermination(
          reason: .exited(report.exitStatus), standardOutput: report.encoded()))
    case .output(let text, let status):
      end(
        InstallationStateChildTermination(reason: .exited(status), standardOutput: Data(text.utf8)))
    case .signal(let signal):
      end(InstallationStateChildTermination(reason: .signaled(signal), standardOutput: Data()))
    case .truncated:
      end(
        InstallationStateChildTermination(
          reason: .exited(0), standardOutput: InstallationStateReport.reported([]).encoded(),
          outputWasTruncated: true))
    case .never, .endsAfterKill, .launchFailure:
      break
    }
  }

  func waitForTermination() async -> InstallationStateChildTermination {
    await withCheckedContinuation { continuation in
      let termination = lock.withLock { () -> InstallationStateChildTermination? in
        if let termination { return termination }
        waiters.append(continuation)
        return nil
      }
      if let termination { continuation.resume(returning: termination) }
    }
  }

  func kill() {
    let hasEnded = lock.withLock { termination != nil }
    guard !hasEnded else { return }
    launcher?.childKilled()
    let killed = InstallationStateChildTermination(
      reason: .signaled(SIGKILL), standardOutput: Data())
    switch ending {
    case .report(_, _, ignoresKill: true):
      break
    case .endsAfterKill(let delay):
      endLater(after: delay, killed)
    default:
      end(killed)
    }
  }

  private func endLater(after delay: Duration, _ termination: InstallationStateChildTermination) {
    Task {
      if delay > .zero { try? await Task.sleep(for: delay) }
      self.end(termination)
    }
  }

  private func end(_ ending: InstallationStateChildTermination) {
    let waiters = lock.withLock {
      () -> [CheckedContinuation<InstallationStateChildTermination, Never>]? in
      guard termination == nil else { return nil }
      termination = ending
      defer { self.waiters = [] }
      return self.waiters
    }
    guard let waiters else { return }
    launcher?.childEnded()
    for waiter in waiters { waiter.resume(returning: ending) }
  }
}
