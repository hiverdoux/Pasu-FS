import Foundation

/// What makes the app read macOS's installation states sooner than in the background.
public enum InstallationStateInterest: Hashable, Sendable {
  /// The setup assistant waits for the extension to be approved in System Settings.
  case approval
  /// Settings → Extension is on screen.
  case extensionSettings
}

/// When the app checks the extension's installation states on its own.
///
/// Each check starts a short-lived process (see `InstallationStateQueryManager`), so the app checks
/// only when the states can matter: at launch, around its own lifecycle requests, on a Refresh
/// command, while a screen that shows them is open, after the extension's own status changed, and
/// otherwise at the background interval. The extension's status over the authenticated connection
/// is read separately and more often.
public struct InstallationStateQueries: Equatable, Sendable {
  /// The interval without a reason to ask sooner.
  public static let backgroundInterval: TimeInterval = 60
  /// The interval while the setup assistant waits for approval.
  public static let approvalInterval: TimeInterval = 5
  /// The interval while Settings → Extension is on screen.
  public static let extensionSettingsInterval: TimeInterval = 15
  /// The interval after the extension started or stopped answering, or restarted.
  public static let runtimeChangeInterval: TimeInterval = 5
  /// How long a query may go unanswered before macOS counts as not reporting the states.
  public static let answerTimeout: TimeInterval = 20
  /// How long the query process itself waits, in case nothing ends it: longer than the app waits,
  /// so that the app's timeout decides.
  public static let processTimeout: TimeInterval = 30
  /// How old reported states can be and still describe the installation: the background interval
  /// plus the timeout, with room for a status check that delays the next query.
  public static let maximumAge: TimeInterval = 90

  /// Calls that have neither been answered nor ended.
  public private(set) var pendingCount = 0
  /// Counts the extension's changes, and the changes that a query made since then has covered.
  private var runtimeChangeCount = 0
  private var coveredRuntimeChangeCount = 0

  /// Whether the extension started or stopped answering, or restarted, after the latest call that
  /// queried was made.
  public var runtimeChanged: Bool { runtimeChangeCount > coveredRuntimeChangeCount }

  public init() {}

  /// The interval between background checks for the given interests.
  public func interval(for interests: Set<InstallationStateInterest>) -> TimeInterval {
    var interval = Self.backgroundInterval
    if interests.contains(.approval) { interval = min(interval, Self.approvalInterval) }
    if interests.contains(.extensionSettings) {
      interval = min(interval, Self.extensionSettingsInterval)
    }
    if runtimeChanged { interval = min(interval, Self.runtimeChangeInterval) }
    return interval
  }

  /// Whether a background check is due: the interval has passed since the latest query in
  /// `record` started. None is while another call waits for its answer, or while `record` holds
  /// automatic checks back because macOS doesn't answer. A call that started no query, because
  /// it was held back, doesn't count. After the clock moved back, the latest query counts as old.
  public func isDue(
    at now: Date, interests: Set<InstallationStateInterest>,
    record: InstallationStateRecord = InstallationStateRecord()
  ) -> Bool {
    guard pendingCount == 0, record.nextQueryNotBefore(automatic: true, at: now) == nil else {
      return false
    }
    guard let lastQueryStartedAt = record.lastQueryStartedAt else { return true }
    let elapsed = now.timeIntervalSince(lastQueryStartedAt)
    return elapsed < 0 || elapsed >= interval(for: interests)
  }

  /// Records a call, and returns what `recordCompletion` needs.
  public mutating func recordSubmission() -> Submission {
    pendingCount += 1
    return Submission(runtimeChangeCount: runtimeChangeCount)
  }

  /// Records that a call ended. A call that started or shared a query covers the extension's
  /// changes before it; one that was held back or cancelled leaves them for the next.
  public mutating func recordCompletion(_ submission: Submission, queried: Bool) {
    pendingCount = max(0, pendingCount - 1)
    if queried {
      coveredRuntimeChangeCount = max(coveredRuntimeChangeCount, submission.runtimeChangeCount)
    }
  }

  /// A call recorded with `recordSubmission`.
  public struct Submission: Sendable {
    fileprivate let runtimeChangeCount: Int
  }

  /// Asks for the states at the shorter interval after the extension started or stopped
  /// answering, or restarted: macOS may have enabled, approved, replaced or removed it.
  public mutating func recordRuntimeChange() {
    runtimeChangeCount += 1
  }
}
