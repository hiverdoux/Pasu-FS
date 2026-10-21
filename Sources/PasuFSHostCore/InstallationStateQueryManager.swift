import Darwin
import Foundation

/// Why a query for the installation states produced no installations.
public enum InstallationStateQueryFailure: Equatable, Sendable {
  /// macOS answered the request with an error.
  case requestFailed(domain: String, code: Int, description: String)
  /// macOS ended the request without installations or an error.
  case endedWithoutAnswer
  /// The process that sends the request could not be started.
  case launchFailed(String)
  /// The process exited with this status without a readable answer.
  case exited(Int32)
  /// A signal that Pasu FS didn't send ended the process.
  case signaled(Int32)
  /// The process wrote an answer that isn't in the expected format or doesn't match its exit
  /// status.
  case invalidOutput

  /// Whether macOS answered, so that it no longer counts as not answering.
  public var isAnswerFromMacOS: Bool {
    switch self {
    case .requestFailed, .endedWithoutAnswer: true
    case .launchFailed, .exited, .signaled, .invalidOutput: false
    }
  }
}

/// What one process that queried the installation states produced.
public enum InstallationStateQueryResult: Equatable, Sendable {
  case reported([ExtensionInstallationProperties])
  case failed(InstallationStateQueryFailure)
  /// macOS didn't answer within the timeout.
  case unanswered

  /// Reads how the process ended. A process that Pasu FS ended after the timeout left no answer;
  /// one that exited on its own just before is read as usual.
  public init(_ termination: InstallationStateChildTermination, endedAfterTimeout: Bool) {
    switch termination.reason {
    case .signaled(let signal):
      self = endedAfterTimeout && signal == SIGKILL ? .unanswered : .failed(.signaled(signal))
    case .exited(let status):
      guard !termination.outputWasTruncated,
        let report = InstallationStateReport(
          decoding: termination.standardOutput, exitStatus: status)
      else {
        self =
          termination.standardOutput.isEmpty && status != InstallationStateReport.reportedExitStatus
          ? .failed(.exited(status)) : .failed(.invalidOutput)
        return
      }
      switch report {
      case .reported(let installations):
        self = .reported(installations)
      case .requestFailed(let domain, let code, let description):
        self = .failed(.requestFailed(domain: domain, code: code, description: description))
      case .endedWithoutAnswer:
        self = .failed(.endedWithoutAnswer)
      case .timedOut:
        self = .unanswered
      }
    }
  }
}

/// How often queries may start while macOS doesn't answer them.
public struct InstallationStateRetryPolicy: Equatable, Sendable {
  /// The shortest time from the start of an unanswered query to the start of the next one, for
  /// every reason to ask, Refresh commands included.
  public var minimumInterval: TimeInterval
  /// The longest time automatic checks wait after an unanswered query.
  public var maximumAutomaticDelay: TimeInterval

  public static let standard = InstallationStateRetryPolicy(
    minimumInterval: 60, maximumAutomaticDelay: 600)

  public init(minimumInterval: TimeInterval, maximumAutomaticDelay: TimeInterval) {
    self.minimumInterval = minimumInterval
    self.maximumAutomaticDelay = maximumAutomaticDelay
  }

  /// How long automatic checks wait after `count` unanswered queries in a row: the minimum
  /// interval, doubled after each further one, up to the maximum.
  public func automaticDelay(afterUnansweredQueries count: Int) -> TimeInterval {
    guard count > 0 else { return 0 }
    let doubled = minimumInterval * pow(2, Double(min(count - 1, 32)))
    return max(minimumInterval, min(doubled, maximumAutomaticDelay))
  }
}

/// What the app knows about the installation states from the queries that have ended.
public struct InstallationStateRecord: Equatable, Sendable {
  /// Counts the changes. A copy with a higher revision is newer.
  public private(set) var revision: UInt64 = 0
  /// When the latest query that ended started.
  public private(set) var lastQueryStartedAt: Date?
  /// The installations macOS reported last, or nil before it has reported any.
  public private(set) var installations: [ExtensionInstallationProperties]?
  /// When macOS reported `installations`.
  public private(set) var reportedAt: Date?
  /// Why the latest query that ended produced no installations, while no later one answered.
  public private(set) var failure: InstallationStateQueryFailure?
  /// When the first query that macOS didn't answer since it last answered started, or nil while
  /// macOS answers.
  public private(set) var unansweredSince: Date?
  /// How many queries in a row macOS didn't answer.
  public private(set) var unansweredCount = 0
  /// When the latest unanswered query started.
  public private(set) var lastUnansweredStartedAt: Date?
  /// While macOS doesn't answer, when the next query may start.
  public private(set) var retryNotBefore: Date?
  /// While macOS doesn't answer, when the next automatic check may start.
  public private(set) var automaticRetryNotBefore: Date?

  public init() {}

  /// The reported installations while they describe the Mac at `now`: no later query failed or
  /// went unanswered, and they are at most `maximumAge` seconds old. Otherwise nil, which means
  /// unknown rather than not installed.
  public func currentInstallations(
    at now: Date, maximumAge: TimeInterval = InstallationStateQueries.maximumAge
  ) -> [ExtensionInstallationProperties]? {
    guard let installations, let reportedAt, failure == nil, unansweredSince == nil,
      (0...maximumAge).contains(now.timeIntervalSince(reportedAt))
    else { return nil }
    return installations
  }

  public func isCurrent(
    at now: Date, maximumAge: TimeInterval = InstallationStateQueries.maximumAge
  ) -> Bool {
    currentInstallations(at: now, maximumAge: maximumAge) != nil
  }

  /// While macOS doesn't answer, when the next query (or the next automatic one) may start, or
  /// nil when one may start now. After the clock moved back, one may.
  public func nextQueryNotBefore(automatic: Bool, at now: Date) -> Date? {
    guard let notBefore = automatic ? automaticRetryNotBefore : retryNotBefore,
      let lastUnansweredStartedAt, now >= lastUnansweredStartedAt, now < notBefore
    else { return nil }
    return notBefore
  }

  /// Records the end of the query that started at `startedAt`.
  public mutating func record(
    _ result: InstallationStateQueryResult, startedAt: Date, endedAt: Date,
    retryPolicy: InstallationStateRetryPolicy
  ) {
    revision += 1
    lastQueryStartedAt = startedAt
    switch result {
    case .reported(let installations):
      self.installations = installations
      reportedAt = endedAt
      failure = nil
      clearUnanswered()
    case .failed(let failure):
      self.failure = failure
      if failure.isAnswerFromMacOS { clearUnanswered() }
    case .unanswered:
      failure = nil
      unansweredSince = min(unansweredSince ?? startedAt, startedAt)
      unansweredCount += 1
      lastUnansweredStartedAt = startedAt
      retryNotBefore = startedAt.addingTimeInterval(retryPolicy.minimumInterval)
      automaticRetryNotBefore = startedAt.addingTimeInterval(
        retryPolicy.automaticDelay(afterUnansweredQueries: unansweredCount))
    }
  }

  private mutating func clearUnanswered() {
    unansweredSince = nil
    unansweredCount = 0
    lastUnansweredStartedAt = nil
    retryNotBefore = nil
    automaticRetryNotBefore = nil
  }
}

/// Why the app asks for the installation states.
public enum InstallationStateQueryKind: Equatable, Sendable {
  /// A check on the app's own schedule. While macOS doesn't answer, it waits longer after each
  /// unanswered query.
  case automatic
  /// A Refresh command, or a check before a lifecycle request. The answer of a query that is
  /// already running will do.
  case refresh
  /// A check after the app changed the installation: only a query that starts after the call
  /// will do, so that the answer isn't from before the change.
  case afterChange
}

/// The answer to one call of `InstallationStateQuerying.query`.
public struct InstallationStateQueryOutcome: Equatable, Sendable {
  public enum Answer: Equatable, Sendable {
    case reported([ExtensionInstallationProperties])
    case failed(InstallationStateQueryFailure)
    case unanswered
    /// No query started: macOS hasn't answered lately, and the next one may start at this time.
    case held(notBefore: Date)
    /// The calling task was cancelled before a query ended.
    case cancelled
  }

  public var answer: Answer
  /// What the manager knew when it answered.
  public var record: InstallationStateRecord

  public init(answer: Answer, record: InstallationStateRecord) {
    self.answer = answer
    self.record = record
  }
}

public protocol InstallationStateQuerying: Sendable {
  func query(_ kind: InstallationStateQueryKind) async -> InstallationStateQueryOutcome
}

/// Reads the installation states in short-lived child processes, one at a time.
///
/// On macOS 27.2 the SystemExtensions framework tears a properties request down only when it fails,
/// so each answered request leaves its connection to the system extension daemon (`sysextd`) open
/// until the process that sent it exits, and `sysextd` holds a transaction for each. A long-running
/// app therefore doesn't send the request itself: a child process (the app's own executable with
/// `--pasu-fs-host --installation-states --json`) sends one, writes the answer and exits, and its
/// connection closes with it.
///
/// Every reason to ask goes through one manager. Calls while a query runs share its answer, except
/// for checks after a change, which wait for the next query. A query that doesn't end within the
/// timeout is ended with SIGKILL, and counts as unanswered once the process has ended. While macOS
/// doesn't answer, `InstallationStateRetryPolicy` limits how often queries start.
public actor InstallationStateQueryManager: InstallationStateQuerying {
  private struct Waiter {
    let identifier: UInt64
    let continuation: CheckedContinuation<InstallationStateQueryOutcome, Never>
  }

  private let launcher: any InstallationStateChildLaunching
  private let timeout: TimeInterval
  private let retryPolicy: InstallationStateRetryPolicy
  private let now: @Sendable () -> Date
  public private(set) var record = InstallationStateRecord()
  /// How many queries have started.
  public private(set) var launchCount = 0
  private var isRunning = false
  /// The calls that the running query answers.
  private var runningWaiters: [Waiter] = []
  /// The calls that wait for the next query.
  private var nextWaiters: [Waiter] = []
  private var nextWaiterIdentifier: UInt64 = 0

  public init(
    launcher: any InstallationStateChildLaunching,
    timeout: TimeInterval = InstallationStateQueries.answerTimeout,
    retryPolicy: InstallationStateRetryPolicy = .standard,
    now: @escaping @Sendable () -> Date = { Date() }
  ) {
    self.launcher = launcher
    self.timeout = timeout
    self.retryPolicy = retryPolicy
    self.now = now
  }

  public func query(_ kind: InstallationStateQueryKind) async -> InstallationStateQueryOutcome {
    let identifier = nextWaiterIdentifier
    nextWaiterIdentifier += 1
    return await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        let waiter = Waiter(identifier: identifier, continuation: continuation)
        if Task.isCancelled {
          continuation.resume(returning: outcome(.cancelled))
        } else if isRunning, kind != .afterChange {
          runningWaiters.append(waiter)
        } else if isRunning {
          nextWaiters.append(waiter)
        } else if let notBefore = record.nextQueryNotBefore(
          automatic: kind == .automatic, at: now())
        {
          continuation.resume(returning: outcome(.held(notBefore: notBefore)))
        } else {
          runningWaiters.append(waiter)
          launch()
        }
      }
    } onCancel: {
      Task { await self.cancelWaiter(identifier) }
    }
  }

  private func outcome(_ answer: InstallationStateQueryOutcome.Answer)
    -> InstallationStateQueryOutcome
  {
    InstallationStateQueryOutcome(answer: answer, record: record)
  }

  private func launch() {
    isRunning = true
    launchCount += 1
    let startedAt = now()
    Task { [launcher, timeout] in
      let result = await Self.run(launcher: launcher, timeout: timeout)
      self.finish(result, startedAt: startedAt)
    }
  }

  private func finish(_ result: InstallationStateQueryResult, startedAt: Date) {
    record.record(result, startedAt: startedAt, endedAt: now(), retryPolicy: retryPolicy)
    let answer: InstallationStateQueryOutcome.Answer =
      switch result {
      case .reported(let installations): .reported(installations)
      case .failed(let failure): .failed(failure)
      case .unanswered: .unanswered
      }
    let answered = runningWaiters
    runningWaiters = []
    isRunning = false
    for waiter in answered { waiter.continuation.resume(returning: outcome(answer)) }

    guard !nextWaiters.isEmpty else { return }
    let queued = nextWaiters
    nextWaiters = []
    if let notBefore = record.nextQueryNotBefore(automatic: false, at: now()) {
      for waiter in queued {
        waiter.continuation.resume(returning: outcome(.held(notBefore: notBefore)))
      }
    } else {
      runningWaiters = queued
      launch()
    }
  }

  private func cancelWaiter(_ identifier: UInt64) {
    if let index = runningWaiters.firstIndex(where: { $0.identifier == identifier }) {
      runningWaiters.remove(at: index).continuation.resume(returning: outcome(.cancelled))
    } else if let index = nextWaiters.firstIndex(where: { $0.identifier == identifier }) {
      nextWaiters.remove(at: index).continuation.resume(returning: outcome(.cancelled))
    }
  }

  /// Starts one process and waits until it has ended: on its own, or after the timeout, when it is
  /// ended with SIGKILL.
  private static func run(
    launcher: any InstallationStateChildLaunching, timeout: TimeInterval
  ) async -> InstallationStateQueryResult {
    let child: any InstallationStateChild
    do {
      child = try launcher.launch()
    } catch {
      return .failed(.launchFailed(String(describing: error)))
    }
    let termination = Task { await child.waitForTermination() }
    let endedAfterTimeout = await withTaskGroup(of: Bool.self) { group in
      group.addTask {
        _ = await termination.value
        return false
      }
      group.addTask {
        do {
          try await Task.sleep(for: .seconds(timeout))
          return true
        } catch {
          return false
        }
      }
      let timedOut = await group.next() ?? false
      if timedOut { child.kill() }
      group.cancelAll()
      return timedOut
    }
    // After a kill, this waits until the process has ended.
    return InstallationStateQueryResult(
      await termination.value, endedAfterTimeout: endedAfterTimeout)
  }
}
