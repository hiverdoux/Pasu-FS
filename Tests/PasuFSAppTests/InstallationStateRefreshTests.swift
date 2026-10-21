import Foundation
import PasuFSConfiguration
import PasuFSHostCore
import XCTest

@testable import PasuFSApp

/// How often the app asks macOS for the installation states, the Refresh commands that ask at
/// once, and what the app shows while macOS doesn't answer.
@MainActor
final class InstallationStateRefreshTests: XCTestCase {
  private let enforcing = ExtensionStatusSnapshot(
    runtimeInstanceIdentifier: UUID(), phase: .enforcing, activePolicyRevision: 4,
    extensionVersion: "1.2.3", extensionBuildVersion: "123")

  /// The 2-second status checks read the installation states only at launch and when they are
  /// due; the extension's status is read every time.
  func testPeriodicChecksReadTheInstallationStatesOnlyWhenDue() async {
    let lifecycle = ScriptedLifecycle(installations: [installed()])
    let runtime = SwitchableRuntime(status: enforcing)
    let model = makeModel(lifecycle: lifecycle, runtime: runtime)

    for _ in 0..<5 {
      await model.refreshHealth(installationStates: .whenDue)
    }

    XCTAssertEqual(lifecycle.propertiesCallCount, 1)
    let statusQueries = await runtime.statusQueryCount
    XCTAssertEqual(statusQueries, 5)
    XCTAssertEqual(model.health.protection, .enforcingOpenEvents(revision: 4))
    XCTAssertNotNil(model.installationStatesReportedAt)
  }

  /// Between reads, the state uses the installations macOS reported last; Refresh reads them
  /// again at once, whatever the interval.
  func testRefreshReadsTheInstallationStatesAtOnce() async {
    let lifecycle = ScriptedLifecycle(installations: [installed()])
    let model = makeModel(lifecycle: lifecycle, runtime: SwitchableRuntime(status: enforcing))
    await model.refreshHealth(installationStates: .whenDue)

    lifecycle.installations = [installed(enabled: false, uninstalling: true)]
    await model.refreshHealth(installationStates: .whenDue)
    XCTAssertEqual(lifecycle.propertiesCallCount, 1)
    XCTAssertFalse(model.extensionRemovalIsPending)

    await model.refreshStatusNow()
    XCTAssertEqual(lifecycle.propertiesCallCount, 2)
    XCTAssertTrue(model.extensionRemovalIsPending)
    XCTAssertEqual(model.health.protection, .uninstalling)
    XCTAssertEqual(model.health.changeAtRestart, .removal)
    XCTAssertFalse(model.isRefreshingStatus)
  }

  /// A second Refresh while one runs sends no second request, and the command shows that it runs.
  func testRefreshWhileOneRunsSendsNoSecondRequest() async {
    let lifecycle = ScriptedLifecycle(installations: [installed()], answerDelay: .milliseconds(200))
    let model = makeModel(lifecycle: lifecycle, runtime: SwitchableRuntime(status: enforcing))

    let first = Task { await model.refreshStatusNow() }
    for _ in 0..<100 where lifecycle.propertiesCallCount == 0 {
      try? await Task.sleep(for: .milliseconds(5))
    }
    XCTAssertTrue(model.isRefreshingStatus)
    await model.refreshStatusNow()
    await model.refreshStatusNow()
    await first.value

    XCTAssertEqual(lifecycle.propertiesCallCount, 1)
    XCTAssertFalse(model.isRefreshingStatus)
  }

  /// macOS can stop answering requests for the installation states. After the timeout, the app
  /// stops waiting, names how long macOS hasn't answered and what restarts the daemon that
  /// answers, and shows the extension's own state: protection continues while it answers.
  func testUnansweredInstallationStatesShowTheAnsweringExtension() async throws {
    let lifecycle = ScriptedLifecycle(installations: [installed()], answers: false)
    let model = makeModel(
      lifecycle: lifecycle, runtime: SwitchableRuntime(status: enforcing), timeout: 0.1)
    defer { lifecycle.releaseHeldRequests() }

    XCTAssertEqual(model.installationStateDescription, String(localized: "Checking…"))
    let started = Date()
    await model.refreshHealth(installationStates: .whenDue)

    XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    let since = try XCTUnwrap(model.installationStatesUnansweredSince)
    XCTAssertEqual(model.health.protection, .enforcingOpenEvents(revision: 4))
    let item = try XCTUnwrap(
      model.attentionItems().first { $0.id == "installationStatesUnanswered" })
    XCTAssertEqual(item.text, InstallationStateText.unanswered(since: since, now: Date()))
    XCTAssertEqual(
      item.detail, String(localized: "The extension still answers, so protection continues."))
    XCTAssertEqual(item.action, .extensionSettings)
    XCTAssertFalse(model.attentionItems().contains { $0.id == "versions" })

    let overview = model.extensionVersionOverview(now: Date())
    XCTAssertFalse(overview.isWaitingForFirstReport)
    XCTAssertEqual(overview.active, String(localized: "Can’t confirm"))
    XCTAssertEqual(overview.notices.map(\.id), ["unavailable"])
    // Without a report, the installation is unknown, not missing.
    XCTAssertEqual(model.installationStateDescription, String(localized: "Can’t confirm"))
  }

  /// The first check waits for macOS, and the periodic checks pause meanwhile, so after a long
  /// wait the extension's status is read again rather than shown as out of date.
  func testFirstCheckReadsTheStatusAgainAfterALongWait() async {
    let lifecycle = ScriptedLifecycle(installations: [installed()], answers: false)
    let runtime = SwitchableRuntime(status: enforcing)
    let model = makeModel(lifecycle: lifecycle, runtime: runtime, timeout: 2.1)
    defer { lifecycle.releaseHeldRequests() }

    await model.refreshHealth(installationStates: .whenDue)

    let statusQueries = await runtime.statusQueryCount
    XCTAssertEqual(statusQueries, 2)
    XCTAssertNotNil(model.installationStatesUnansweredSince)
    XCTAssertEqual(model.health.protection, .enforcingOpenEvents(revision: 4))
  }

  /// Without macOS's report and without an answer from the extension, the state says that macOS
  /// doesn't report the extension, not that it isn't installed, and no setup assistant appears.
  func testUnansweredInstallationStatesWithoutTheExtension() async throws {
    let lifecycle = ScriptedLifecycle(installations: [], answers: false)
    let model = makeModel(
      lifecycle: lifecycle, runtime: SwitchableRuntime(status: nil), timeout: 0.1)
    defer { lifecycle.releaseHeldRequests() }

    await model.refreshHealth(installationStates: .whenDue)

    XCTAssertEqual(
      model.health.protection,
      .degraded(reason: HealthStateReducer.installationStatesUnreportedReason))
    XCTAssertEqual(
      model.status.detail, String(localized: "macOS isn’t reporting the system extension state."))
    XCTAssertFalse(model.showsOnboarding)
    let item = try XCTUnwrap(
      model.attentionItems().first { $0.id == "installationStatesUnanswered" })
    XCTAssertNil(item.detail)
  }

  /// Once macOS answers again, a Refresh clears the notice and shows the reported state.
  func testAnswerAfterTimeoutClearsTheNotice() async {
    let lifecycle = ScriptedLifecycle(installations: [installed()], answers: false)
    let model = makeModel(
      lifecycle: lifecycle, runtime: SwitchableRuntime(status: enforcing), timeout: 0.1,
      retryPolicy: noRetryLimit)
    defer { lifecycle.releaseHeldRequests() }
    await model.refreshHealth(installationStates: .whenDue)
    XCTAssertNotNil(model.installationStatesUnansweredSince)

    lifecycle.answers = true
    await model.refreshStatusNow()

    XCTAssertNil(model.installationStatesUnansweredSince)
    XCTAssertFalse(model.attentionItems().contains { $0.id == "installationStatesUnanswered" })
    XCTAssertTrue(model.extensionVersionOverview(now: Date()).isConfirmed)
    XCTAssertEqual(lifecycle.propertiesCallCount, 2)
  }

  /// A failed answer before the first report keeps macOS's own message in the state.
  func testFailedFirstAnswerIsShownInTheState() async {
    let lifecycle = ScriptedLifecycle(
      installations: [], failure: "The operation couldn’t be completed.")
    let model = makeModel(lifecycle: lifecycle, runtime: SwitchableRuntime(status: nil))

    await model.refreshHealth(installationStates: .whenDue)

    XCTAssertEqual(
      model.health.protection,
      .degraded(
        reason: String(
          localized:
            "macOS did not report the system extension state: The operation couldn’t be completed."
        )))
    XCTAssertNil(model.installationStatesUnansweredSince)
  }

  /// Settings → Extension asks sooner while it is on screen, and the setup assistant while it
  /// waits for approval.
  func testScreensOnViewMakeTheStatesWorthReadingSooner() async {
    let model = makeModel(
      lifecycle: ScriptedLifecycle(installations: [installed()]),
      runtime: SwitchableRuntime(status: enforcing))
    await model.refreshHealth()
    XCTAssertEqual(model.installationStateInterests, [])

    model.statusScreen(.extensionSettings, isVisible: true)
    XCTAssertEqual(model.installationStateInterests, [.extensionSettings])
    model.statusScreen(.extensionSettings, isVisible: false)
    XCTAssertEqual(model.installationStateInterests, [])
    // A disappearance without an appearance doesn't hide a later appearance.
    model.statusScreen(.extensionSettings, isVisible: false)
    model.statusScreen(.extensionSettings, isVisible: true)
    XCTAssertEqual(model.installationStateInterests, [.extensionSettings])

    // The setup assistant counts only while it waits for approval.
    model.statusScreen(.setupAssistant, isVisible: true)
    XCTAssertFalse(model.installationStateInterests.contains(.approval))

    let approving = makeModel(
      lifecycle: ScriptedLifecycle(installations: [
        installed(enabled: false, awaitingApproval: true)
      ]),
      runtime: SwitchableRuntime(status: nil))
    await approving.refreshHealth()
    XCTAssertTrue(approving.showsOnboarding)
    XCTAssertEqual(approving.installationStateInterests, [])
    approving.statusScreen(.setupAssistant, isVisible: true)
    XCTAssertEqual(approving.installationStateInterests, [.approval])
    approving.statusScreen(.setupAssistant, isVisible: false)
    XCTAssertEqual(approving.installationStateInterests, [])
  }

  /// An extension that starts or stops answering may have been approved, replaced or removed, so
  /// the next read comes sooner.
  func testExtensionThatStopsAnsweringIsCheckedSooner() async {
    let runtime = SwitchableRuntime(status: enforcing)
    let model = makeModel(
      lifecycle: ScriptedLifecycle(installations: [installed()]), runtime: runtime)
    await model.refreshHealth(installationStates: .whenDue)
    await model.refreshHealth(installationStates: .whenDue)
    XCTAssertFalse(model.installationQueries.runtimeChanged)

    await runtime.setStatus(nil)
    await model.refreshHealth(installationStates: .whenDue)
    XCTAssertTrue(model.installationQueries.runtimeChanged)
    XCTAssertEqual(
      model.installationQueries.interval(for: model.installationStateInterests),
      InstallationStateQueries.runtimeChangeInterval)
  }

  /// A deactivation reads the installation states first, so it sends no request that macOS
  /// would refuse while it already removes every version, even before the first status check.
  func testDeactivationReadsTheInstallationStatesFirst() async {
    let removing = ScriptedLifecycle(installations: [installed(enabled: false, uninstalling: true)])
    let model = makeModel(lifecycle: removing, runtime: SwitchableRuntime(status: nil))

    await model.deactivate()

    XCTAssertEqual(removing.deactivationCallCount, 0)
    XCTAssertEqual(removing.propertiesCallCount, 1)

    // Otherwise the request goes to macOS, and the states are read again once it ends.
    let enabled = ScriptedLifecycle(installations: [installed()])
    let deactivating = makeModel(lifecycle: enabled, runtime: SwitchableRuntime(status: nil))
    await deactivating.deactivate()
    XCTAssertEqual(enabled.deactivationCallCount, 1)
    XCTAssertEqual(enabled.propertiesCallCount, 2)
  }

  /// The check after a deactivation doesn't take the answer of a query that started before the
  /// request: it waits for a query of its own, which reports the removal.
  func testCheckAfterADeactivationWaitsForANewQuery() async {
    let lifecycle = ScriptedLifecycle(
      installations: [installed()], answerDelay: .milliseconds(300),
      installationsAfterDeactivation: [installed(enabled: false, uninstalling: true)])
    let model = makeModel(lifecycle: lifecycle, runtime: SwitchableRuntime(status: enforcing))
    await model.refreshHealth()
    XCTAssertFalse(model.extensionRemovalIsPending)

    // A refresh starts a query that answers from before the deactivation.
    let refresh = Task { await model.refreshStatusNow() }
    while lifecycle.propertiesCallCount < 2 { try? await Task.sleep(for: .milliseconds(5)) }
    await model.deactivate()
    await refresh.value

    XCTAssertEqual(lifecycle.deactivationCallCount, 1)
    XCTAssertEqual(lifecycle.propertiesCallCount, 3)
    XCTAssertTrue(model.extensionRemovalIsPending)
    XCTAssertEqual(model.health.protection, .uninstalling)
  }

  /// macOS keeps an activation request open until the user approves it. Once it reports that the
  /// request waits for approval, the installation is read at once, so the setup assistant shows
  /// the approval step (and checks every few seconds) without waiting for the request to end.
  func testApprovalWaitIsReadWhileTheActivationRequestIsOpen() async {
    let lifecycle = ScriptedLifecycle(
      installations: [],
      installationsWhileApprovalWaits: [installed(enabled: false, awaitingApproval: true)])
    let model = makeModel(lifecycle: lifecycle, runtime: SwitchableRuntime(status: nil))
    defer { lifecycle.releaseHeldRequests() }
    await model.refreshHealth()
    XCTAssertEqual(model.health.protection, .notInstalled)

    let activation = Task { await model.activate() }
    for _ in 0..<200 where model.health.protection != .waitingForApproval {
      try? await Task.sleep(for: .milliseconds(10))
    }

    XCTAssertEqual(model.health.protection, .waitingForApproval)
    XCTAssertEqual(lifecycle.propertiesCallCount, 2)
    XCTAssertTrue(model.isBusy, "the request is still open")
    model.statusScreen(.setupAssistant, isVisible: true)
    XCTAssertEqual(model.installationStateInterests, [.approval])
    lifecycle.releaseHeldRequests()
    await activation.value
  }

  /// While macOS doesn't answer, Refresh starts no further query within the minute, however
  /// often it is chosen; the extension's status is still read.
  func testRefreshDuringTheRetryLimitStartsNoQuery() async {
    let lifecycle = ScriptedLifecycle(installations: [installed()], answers: false)
    let runtime = SwitchableRuntime(status: enforcing)
    let model = makeModel(lifecycle: lifecycle, runtime: runtime, timeout: 0.1)
    defer { lifecycle.releaseHeldRequests() }
    await model.refreshHealth(installationStates: .whenDue)
    XCTAssertNotNil(model.installationStatesUnansweredSince)

    lifecycle.answers = true
    for _ in 0..<10 { await model.refreshStatusNow() }
    for _ in 0..<10 { await model.refreshHealth(installationStates: .whenDue) }

    XCTAssertEqual(lifecycle.propertiesCallCount, 1)
    let statusQueries = await runtime.statusQueryCount
    XCTAssertEqual(statusQueries, 21)
    XCTAssertNotNil(model.installationStatesUnansweredSince)
    XCTAssertEqual(model.health.protection, .enforcingOpenEvents(revision: 4))
  }

  /// Installations reported more than 90 seconds ago describe the Mac no longer: an empty report
  /// doesn't show the extension as not installed, and no setup assistant appears.
  func testOutOfDateInstallationsAreUnknownRatherThanAbsent() async {
    for status in [nil, enforcing] {
      let lifecycle = ScriptedLifecycle(installations: [])
      let model = makeModel(
        lifecycle: lifecycle, runtime: SwitchableRuntime(status: status),
        querier: InstallationStateQueryManager(
          launcher: lifecycle.inProcessInstallationStateLauncher(), timeout: 5,
          now: { Date().addingTimeInterval(-(InstallationStateQueries.maximumAge + 10)) }))

      await model.refreshHealth()

      XCTAssertNotNil(model.installationStatesReportedAt)
      XCTAssertNotEqual(model.health.protection, .notInstalled)
      XCTAssertFalse(model.showsOnboarding)
      XCTAssertEqual(model.installationStateDescription, String(localized: "Can’t confirm"))
      XCTAssertFalse(model.extensionVersionOverview(now: Date()).isConfirmed)
      if status == nil {
        XCTAssertEqual(
          model.health.protection,
          .degraded(reason: HealthStateReducer.installationStatesUnreportedReason))
      } else {
        XCTAssertEqual(model.health.protection, .enforcingOpenEvents(revision: 4))
      }
    }
  }

  /// A query that fails after a report makes the reported installations unknown: removal isn't
  /// shown as pending or complete, and the running extension's status decides.
  func testFailureAfterAReportShowsTheInstallationAsUnknown() async {
    let lifecycle = ScriptedLifecycle(installations: [installed(enabled: false, uninstalling: true)]
    )
    let model = makeModel(lifecycle: lifecycle, runtime: SwitchableRuntime(status: enforcing))
    await model.refreshHealth()
    XCTAssertTrue(model.extensionRemovalIsPending)
    XCTAssertEqual(model.installationStateDescription, String(localized: "Uninstalling"))

    lifecycle.failure = "The operation couldn’t be completed."
    await model.refreshStatusNow()

    XCTAssertFalse(model.extensionRemovalIsPending)
    XCTAssertEqual(model.installationStateDescription, String(localized: "Can’t confirm"))
    XCTAssertEqual(model.health.protection, .enforcingOpenEvents(revision: 4))
    XCTAssertNil(model.health.changeAtRestart)
    XCTAssertEqual(
      model.extensionVersionOverview(now: Date()).notices.map(\.text),
      [
        String(
          localized:
            "Could not refresh extension versions: The operation couldn’t be completed.")
      ])
  }

  /// An unreadable answer from the query process is a failure with its own message, not an
  /// empty installation.
  func testUnreadableAnswerIsShownAsAFailure() async {
    let model = makeModel(
      lifecycle: ScriptedLifecycle(installations: []), runtime: SwitchableRuntime(status: nil),
      querier: InstallationStateQueryManager(launcher: UnreadableAnswerLauncher(), timeout: 5))

    await model.refreshHealth()

    let detail = String(localized: "The installation state check returned an unreadable result.")
    XCTAssertEqual(
      model.health.protection,
      .degraded(
        reason: String(localized: "macOS did not report the system extension state: \(detail)")))
    XCTAssertEqual(model.installationStateDescription, String(localized: "Can’t confirm"))
    XCTAssertFalse(model.showsOnboarding)
  }

  // MARK: - Helpers

  private let noRetryLimit = InstallationStateRetryPolicy(
    minimumInterval: 0, maximumAutomaticDelay: 0)

  private func makeModel(
    lifecycle: ScriptedLifecycle, runtime: SwitchableRuntime, timeout: TimeInterval = 5,
    retryPolicy: InstallationStateRetryPolicy = .standard,
    querier: (any InstallationStateQuerying)? = nil
  ) -> AppModel {
    AppModel(
      activationController: lifecycle, runtimeController: runtime,
      loginItemController: StaticLoginItemController(),
      embeddedVersionProvider: NoEmbeddedVersion(),
      installationStateQuerier: querier
        ?? InstallationStateQueryManager(
          launcher: lifecycle.inProcessInstallationStateLauncher(), timeout: timeout,
          retryPolicy: retryPolicy))
  }

  private func installed(
    enabled: Bool = true, awaitingApproval: Bool = false, uninstalling: Bool = false
  ) -> ExtensionInstallationProperties {
    ExtensionInstallationProperties(
      bundleIdentifier: ActivationController.extensionIdentifier, bundleVersion: "123",
      bundleShortVersion: "1.2.3", isEnabled: enabled, isAwaitingUserApproval: awaitingApproval,
      isUninstalling: uninstalling)
  }
}

/// Answers properties requests with its installations, after a delay, with an error, or never.
private final class ScriptedLifecycle: ExtensionLifecycleControlling, @unchecked Sendable {
  func installationStateLauncher() -> any InstallationStateChildLaunching {
    inProcessInstallationStateLauncher()
  }

  private let lock = NSLock()
  private var storedInstallations: [ExtensionInstallationProperties]
  private var storedAnswers: Bool
  private var storedFailure: String?
  private let answerDelay: Duration
  private let installationsAfterDeactivation: [ExtensionInstallationProperties]?
  private let installationsWhileApprovalWaits: [ExtensionInstallationProperties]?
  private var propertiesCalls = 0
  private var deactivationCalls = 0
  private var held: [AsyncStream<ActivationEvent>.Continuation] = []

  /// - Parameter installationsAfterDeactivation: The installations macOS reports once a
  ///   deactivation request was sent, or nil to keep reporting `installations`.
  init(
    installations: [ExtensionInstallationProperties], answers: Bool = true,
    failure: String? = nil, answerDelay: Duration = .zero,
    installationsAfterDeactivation: [ExtensionInstallationProperties]? = nil,
    installationsWhileApprovalWaits: [ExtensionInstallationProperties]? = nil
  ) {
    storedInstallations = installations
    storedAnswers = answers
    storedFailure = failure
    self.answerDelay = answerDelay
    self.installationsAfterDeactivation = installationsAfterDeactivation
    self.installationsWhileApprovalWaits = installationsWhileApprovalWaits
  }

  /// The error macOS answers new requests with, or nil to report the installations.
  var failure: String? {
    get { lock.withLock { storedFailure } }
    set { lock.withLock { storedFailure = newValue } }
  }

  var installations: [ExtensionInstallationProperties] {
    get { lock.withLock { storedInstallations } }
    set { lock.withLock { storedInstallations = newValue } }
  }

  /// Whether macOS answers new requests.
  var answers: Bool {
    get { lock.withLock { storedAnswers } }
    set { lock.withLock { storedAnswers = newValue } }
  }

  var propertiesCallCount: Int { lock.withLock { propertiesCalls } }
  var deactivationCallCount: Int { lock.withLock { deactivationCalls } }

  /// Ends the requests that were never answered.
  func releaseHeldRequests() {
    let continuations = lock.withLock {
      defer { held = [] }
      return held
    }
    for continuation in continuations { continuation.finish() }
  }

  /// With `installationsWhileApprovalWaits`, the request waits for approval and stays open
  /// until `releaseHeldRequests()`, as macOS keeps it until the user approves.
  func activationEvents() -> AsyncStream<ActivationEvent> {
    guard let installationsWhileApprovalWaits else {
      return AsyncStream { continuation in
        continuation.yield(.completed(rebootRequired: false))
        continuation.finish()
      }
    }
    lock.withLock { storedInstallations = installationsWhileApprovalWaits }
    return AsyncStream { continuation in
      continuation.yield(.submitted(action: "activate"))
      continuation.yield(.waitingForUserApproval)
      lock.withLock { held.append(continuation) }
    }
  }

  func deactivationEvents() -> AsyncStream<ActivationEvent> {
    lock.withLock {
      deactivationCalls += 1
      if let installationsAfterDeactivation { storedInstallations = installationsAfterDeactivation }
    }
    return AsyncStream { continuation in
      continuation.yield(.submitted(action: "deactivate"))
      continuation.yield(.completed(rebootRequired: false))
      continuation.finish()
    }
  }

  func propertiesEvents() -> AsyncStream<ActivationEvent> {
    let (installations, answers, failure) = lock.withLock {
      propertiesCalls += 1
      return (storedInstallations, storedAnswers, storedFailure)
    }
    let answer: ActivationEvent =
      failure.map { .failed(domain: "OSSystemExtensionErrorDomain", code: 1, description: $0) }
      ?? .properties(installations)
    let delay = answerDelay
    return AsyncStream { continuation in
      continuation.yield(.submitted(action: "properties"))
      guard answers else {
        lock.withLock { held.append(continuation) }
        return
      }
      Task {
        if delay > .zero { try? await Task.sleep(for: delay) }
        continuation.yield(answer)
        continuation.finish()
      }
    }
  }
}

/// Answers status requests with its status, or fails the connection without one.
private actor SwitchableRuntime: ExtensionRuntimeControlling {
  private var status: ExtensionStatusSnapshot?
  private(set) var statusQueryCount = 0

  init(status: ExtensionStatusSnapshot?) {
    self.status = status
  }

  func setStatus(_ status: ExtensionStatusSnapshot?) {
    self.status = status
  }

  func queryStatus() async throws -> ExtensionStatusSnapshot {
    statusQueryCount += 1
    guard var answer = status else { throw ExtensionControlClientError.interfaceUnavailable }
    answer.timestamp = Date()
    return answer
  }

  func applyPolicySet(
    _ document: PolicySetDocument, authorization: Data?, savedPolicyIdentifier: UUID?
  ) async throws -> PolicyApplyReceipt {
    throw ExtensionControlClientError.interfaceUnavailable
  }

  func queryPolicySet() async throws -> PolicySetDocument {
    throw ExtensionControlClientError.interfaceUnavailable
  }

  func readAuditLog(maximumLineCount: Int) async throws -> AuditLogBatch {
    throw ExtensionControlClientError.interfaceUnavailable
  }

  func readPolicyAuditLog(
    setIdentifier: UUID, policyIdentifier: UUID, maximumLineCount: Int
  ) async throws -> AuditLogBatch {
    throw ExtensionControlClientError.interfaceUnavailable
  }

  func invalidate() {}
}

private struct StaticLoginItemController: LoginItemControlling {
  var state: LoginItemState { .notRegistered }
  func register() throws {}
  func unregister() throws {}
  func openSystemSettings() {}
}

private struct NoEmbeddedVersion: EmbeddedSystemExtensionVersionProviding {
  func buildVersion(in hostBundleURL: URL) -> String? { nil }
}

/// A query process that exits successfully with output in no known format.
private struct UnreadableAnswerLauncher: InstallationStateChildLaunching {
  func launch() throws -> any InstallationStateChild { UnreadableAnswer() }
}

private struct UnreadableAnswer: InstallationStateChild {
  func waitForTermination() async -> InstallationStateChildTermination {
    InstallationStateChildTermination(reason: .exited(0), standardOutput: Data("sample\n".utf8))
  }
  func kill() {}
}
