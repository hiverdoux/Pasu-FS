import Foundation
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSIPC
import PasuFSMaintenanceCore
import PasuFSPolicy
import XCTest

@testable import PasuFSApp

@MainActor
final class UserFacingTextTests: XCTestCase {
  func testRecognizedExtensionMessagesAreRewrittenAndOthersKept() {
    XCTAssertNotEqual(
      RuntimeText.localized("Authenticated runtime status is stale."),
      "Authenticated runtime status is stale.")

    let prefixed = RuntimeText.localized("Stored policy set could not be activated: disk full")
    XCTAssertFalse(prefixed.hasPrefix("Stored policy set"))
    XCTAssertTrue(prefixed.hasSuffix("disk full"))

    let revision = RuntimeText.localized(
      "Policy-set revision 12 was accepted but could not be activated: busy")
    XCTAssertTrue(revision.contains("12"))
    XCTAssertTrue(revision.hasSuffix("busy"))

    let inactive = RuntimeText.localized(
      "System-compatibility profile example.profile is inactive: needsReview.")
    XCTAssertTrue(inactive.contains("example.profile"))
    XCTAssertFalse(inactive.contains("needsReview"))
    let named = RuntimeText.localized(
      "System-compatibility profile container-management cannot be turned on: unsupportedOS.")
    XCTAssertTrue(
      named.contains(
        SystemCompatibilityText.name(
          identifier: BuiltInSystemCompatibilityCatalog.containerManagementIdentifier)))
    XCTAssertFalse(named.contains("unsupportedOS"))
    let several = RuntimeText.localized("2 enabled system-compatibility profiles are inactive.")
    XCTAssertTrue(several.contains("2"))
    XCTAssertFalse(several.contains("enabled system-compatibility"))

    XCTAssertEqual(
      RuntimeText.localized("A message from a newer extension."),
      "A message from a newer extension.")
  }

  /// Each built-in profile has its own name and description in the app's strings. The app
  /// describes the folder's owner as the user's own account, unlike the catalog.
  func testEveryBuiltInProfileHasItsOwnText() {
    for profile in BuiltInSystemCompatibilityCatalog.catalog.profiles {
      XCTAssertNotEqual(SystemCompatibilityText.name(identifier: profile.id), profile.id)
      XCTAssertNotEqual(SystemCompatibilityText.role(profile), profile.roleDescription, profile.id)
      XCTAssertFalse(SystemCompatibilityText.consequence(profile).isEmpty, profile.id)
    }
  }

  func testFolderWarningsAreTranslatedLineByLine() {
    let missing = RuntimeText.localized("Protected folder missing: /Users/example/Secret (Secret)")
    XCTAssertFalse(missing.hasPrefix("Protected folder missing"))
    XCTAssertTrue(missing.contains("/Users/example/Secret (Secret)"))
    let moved = RuntimeText.localized(
      "Protected folder moved but not followed: /Volumes (Secret): denied")
    XCTAssertFalse(moved.hasPrefix("Protected folder moved"))
    XCTAssertTrue(moved.hasSuffix("/Volumes (Secret): denied"))
    let failed = RuntimeText.localized("Protected folder check failed: busy")
    XCTAssertFalse(failed.hasPrefix("Protected folder check failed"))

    let combined = RuntimeText.localized(
      "Protected volume unmounted: /Volumes/Data (Secret)\n"
        + "Protected folder missing: /Volumes/Data/Secret (Secret)")
    let lines = combined.split(separator: "\n").map(String.init)
    XCTAssertEqual(lines.count, 2)
    XCTAssertEqual(
      lines[0], RuntimeText.localized("Protected volume unmounted: /Volumes/Data (Secret)"))
    XCTAssertEqual(
      lines[1], RuntimeText.localized("Protected folder missing: /Volumes/Data/Secret (Secret)"))
    XCTAssertNotEqual(
      PolicyRuleMatchKind.enclosingFolder.displayName, PolicyRuleMatchKind.mountPoint.displayName)
  }

  func testEveryCheckedRequestKindHasAName() {
    var names = Set<String>()
    for eventType in AuthorizationEventCatalog.supportedEventNames {
      let name = RequestKindText.name(eventType)
      XCTAssertNotEqual(name, eventType)
      XCTAssertTrue(name.hasSuffix("(\(eventType))"), name)
      names.insert(name)
    }
    XCTAssertEqual(names.count, AuthorizationEventCatalog.supportedEventNames.count)
    XCTAssertEqual(RequestKindText.name("NOTIFY_EXEC"), "NOTIFY_EXEC")
  }

  func testMaintenanceFailuresArriveTranslatedAcrossXPC() throws {
    // The maintenance service replies with an NSError; the app must read the code from it.
    let error = MaintenanceContract.remoteError(
      MaintenanceError(.authorizationDenied, detail: "-60005"))
    let data = try NSKeyedArchiver.archivedData(withRootObject: error, requiringSecureCoding: true)
    let decoded = try XCTUnwrap(
      NSKeyedUnarchiver.unarchivedObject(ofClass: NSError.self, from: data))
    XCTAssertEqual(
      UserFacingError.message(decoded),
      UserFacingError.maintenance(.authorizationDenied, detail: "-60005"))
    XCTAssertTrue(UserFacingError.message(decoded).contains("-60005"))

    // A reply without a code, or with a code this app does not know, keeps its own text.
    let withoutCode = NSError(
      domain: MaintenanceContract.errorDomain, code: 1,
      userInfo: [NSLocalizedDescriptionKey: "Older service text."])
    XCTAssertEqual(UserFacingError.message(withoutCode), "Older service text.")
    let unknownCode = NSError(
      domain: MaintenanceContract.errorDomain, code: 1,
      userInfo: [
        NSLocalizedDescriptionKey: "Newer service text.",
        MaintenanceContract.errorCodeKey: "somethingNewer",
      ])
    XCTAssertEqual(UserFacingError.message(unknownCode), "Newer service text.")

    XCTAssertEqual(
      UserFacingError.message(MaintenanceError(.connectionLost)),
      UserFacingError.maintenance(.connectionLost, detail: nil))
  }

  func testAuthorizationFailuresBecomeReadableMessages() {
    // Authorization errors carry the right name and status but never the command-line wording.
    let registration = UserFacingError.message(
      AdministrativeAuthorizationError.rightRegistrationFailed(
        name: "com.example.pasu.fs.uninstall", status: -60005))
    XCTAssertTrue(registration.contains("com.example.pasu.fs.uninstall"))
    XCTAssertTrue(registration.contains("-60005"))
    XCTAssertFalse(registration.contains("Could not register"))
    XCTAssertEqual(
      UserFacingError.message(AdministrativeAuthorizationError.canceled),
      UserFacingError.authorization(.canceled))
    XCTAssertFalse(UserFacingError.authorization(.canceled).contains("request was not submitted"))
  }

  func testAuthorizationFailuresFromTheExtensionAreExplained() {
    let canceled = UserFacingError.message(
      PasuFSXPCError.make(
        .authorizationCanceled, description: "Administrator authentication was canceled."))
    XCTAssertTrue(canceled.contains("canceled"))
    XCTAssertTrue(canceled.contains("not changed"))
    let required = UserFacingError.message(
      PasuFSXPCError.make(.authorizationRequired, description: "no authorization"))
    XCTAssertTrue(required.contains("administrator authentication"))
    XCTAssertTrue(required.hasSuffix("no authorization"))
  }

  /// Only a history that did not start with an observed launch gets a line of its own.
  func testHistoryEvidenceIsExplainedWhenItIsNotAnObservedLaunch() {
    XCTAssertNil(OriginText.evidence(.observed))
    let restored = OriginText.evidence(.kernelLaunchdStart)
    XCTAssertEqual(
      restored,
      "This history begins with a process that launchd started before the extension started tracking processes."
    )
  }

  func testLineageSequenceRestartIsExplained() {
    let issue = LineageIssue(reason: "sequenceRestarted", at: Date())
    XCTAssertNotEqual(LineageText.explanation(issue), "sequenceRestarted")
    XCTAssertNotEqual(issue.explanation, "sequenceRestarted")
  }

  func testDroppedMessagesAreNamedAsMessagesOfEveryKind() {
    // The collector counts every skipped message number, not only lost process events.
    let dropped = LineageIssue(
      reason: LineageText.droppedMessagesReason, count: 12, at: Date())
    let text = LineageText.text(dropped, alwaysShowingCount: false)
    XCTAssertTrue(text.hasPrefix("Dropped messages (all kinds): 12."), text)
    let single = LineageIssue(reason: "queueOverflow", at: Date())
    XCTAssertEqual(
      LineageText.text(single, alwaysShowingCount: false), LineageText.explanation(single))
    XCTAssertEqual(
      LineageText.text(single, alwaysShowingCount: true),
      "\(LineageText.explanation(single)) (1)")
  }

  func testErrorsFromEveryLayerBecomeReadableMessages() {
    let validation = UserFacingError.message(PolicyValidationError.duplicatePolicyName("Keys"))
    XCTAssertTrue(validation.contains("Keys"))

    // The current extension and the versions before 0.9.0 word the rejection differently.
    for description in [
      "Stored policy set rejected; protected scopes could not be recovered: bad",
      "Stored policy set rejected: bad",
    ] {
      let xpc = PasuFSXPCError.make(.policyRejected, description: description)
      let rejected = UserFacingError.message(xpc)
      XCTAssertTrue(
        rejected.hasSuffix(String(localized: "The saved policies were rejected: \("bad")")),
        description)
      XCTAssertFalse(rejected.contains("Error Domain"), description)
    }

    XCTAssertEqual(
      UserFacingError.message(ProtectedFolderIssue.notChosen),
      ProtectedFolderIssue.notChosen.userFacingMessage)
    XCTAssertTrue(
      UserFacingError.message(ExtensionControlClientError.policyAuditLogUnsupported)
        .contains("Update the extension"))
  }

  func testFolderCheckMirrorsTheExtensionRules() throws {
    let base = FileManager.default.temporaryDirectory
      .appendingPathComponent("folder-check-\(UUID().uuidString)", isDirectory: true)
    let folder = base.appendingPathComponent("Secrets", isDirectory: true)
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: base) }
    let file = base.appendingPathComponent("note.txt")
    try Data("example".utf8).write(to: file)

    let home = base.path
    XCTAssertNil(ProtectedFolderCheck.issue(for: folder.path, homeDirectory: home))
    XCTAssertEqual(ProtectedFolderCheck.issue(for: "", homeDirectory: home), .notChosen)
    XCTAssertEqual(ProtectedFolderCheck.issue(for: "relative", homeDirectory: home), .notAbsolute)
    XCTAssertEqual(
      ProtectedFolderCheck.issue(
        for: base.appendingPathComponent("missing").path, homeDirectory: home),
      .missing)
    XCTAssertEqual(ProtectedFolderCheck.issue(for: file.path, homeDirectory: home), .notDirectory)
    XCTAssertNotNil(ProtectedFolderCheck.issue(for: base.path, homeDirectory: home))
    XCTAssertNotNil(ProtectedFolderCheck.issue(for: "/", homeDirectory: home))
    XCTAssertNotNil(ProtectedFolderCheck.issue(for: "/Users", homeDirectory: home))

    let canonicalFolder = ProtectedFolderCheck.canonicalPath(for: folder)
    XCTAssertEqual(
      ProtectedFolderCheck.path(fromTypedText: "  \(folder.path)/  ", homeDirectory: home),
      canonicalFolder)
    XCTAssertEqual(
      ProtectedFolderCheck.path(
        fromTypedText: "~/\(folder.lastPathComponent)", homeDirectory: home),
      canonicalFolder)
    XCTAssertEqual(
      ProtectedFolderCheck.path(fromTypedText: "~", homeDirectory: home),
      ProtectedFolderCheck.canonicalPath(for: base))
    XCTAssertEqual(ProtectedFolderCheck.path(fromTypedText: " ", homeDirectory: home), "")
    XCTAssertEqual(
      ProtectedFolderCheck.path(fromTypedText: "relative", homeDirectory: home), "relative")
  }

  func testStatusNeverCallsAuditProtection() {
    let auditing = StatusPresentation(
      health: HealthState(protection: .monitoringOpenEvents(revision: 2), auditPolicyCount: 1))
    let protecting = StatusPresentation(
      health: HealthState(
        protection: .enforcingOpenEvents(revision: 2), protectionPolicyCount: 1,
        auditPolicyCount: 1))
    let degraded = StatusPresentation(
      health: HealthState(protection: .degraded(reason: "Authenticated runtime status is stale.")))

    XCTAssertEqual(auditing.tone, .auditing)
    XCTAssertNotEqual(auditing.title, protecting.title)
    XCTAssertEqual(protecting.tone, .protecting)
    XCTAssertEqual(degraded.tone, .attention)
    XCTAssertNotEqual(degraded.detail, "Authenticated runtime status is stale.")
  }

  func testPendingUninstallAndLoginApprovalNeedAttention() {
    let model = AppModel(
      activationController: NoExtensionLifecycle(),
      loginItemController: ApprovalLoginItem(),
      uninstallStateReader: { UninstallState(phase: .awaitingRestart, removeData: false) })

    let actions = model.attentionItems().compactMap { $0.action }
    XCTAssertTrue(actions.contains(.continueUninstall))
    XCTAssertTrue(actions.contains(.loginItems))
  }

  func testStaleVersionReportIsNotShownAsNoInstallation() {
    let installed = ExtensionInstallationProperties(
      bundleIdentifier: ActivationController.extensionIdentifier, bundleVersion: "1",
      bundleShortVersion: "0.6.1", isEnabled: true, isAwaitingUserApproval: false,
      isUninstalling: false)
    let version = ProductVersion(installation: installed)
    let observedAt = Date(timeIntervalSince1970: 1_000_000)
    func overview(secondsLater: TimeInterval, unansweredSince: Date? = nil)
      -> ExtensionVersionOverview
    {
      ExtensionVersionOverview(
        app: version, included: version, installations: [installed], observedAt: observedAt,
        unansweredSince: unansweredSince, queryError: nil, isRequestingActivation: false,
        activationProgress: nil, activationOutcome: nil,
        now: observedAt.addingTimeInterval(secondsLater))
    }

    // The app reads the installations every minute in the background, so a report from the
    // latest request stays confirmed until the next one is overdue.
    for seconds in [2.0, 60, InstallationStateQueries.maximumAge] {
      let fresh = overview(secondsLater: seconds)
      XCTAssertTrue(fresh.isConfirmed, "\(seconds)")
      XCTAssertFalse(fresh.isWaitingForFirstReport, "\(seconds)")
      XCTAssertEqual(fresh.entries.count, 1, "\(seconds)")
      XCTAssertEqual(fresh.tone, .matching, "\(seconds)")
    }

    let stale = overview(secondsLater: InstallationStateQueries.maximumAge + 1)
    XCTAssertFalse(stale.isConfirmed)
    XCTAssertTrue(stale.entries.isEmpty)
    XCTAssertEqual(stale.tone, .attention)
    XCTAssertEqual(
      stale.notices.map(\.text),
      [String(localized: "Extension version information is out of date. Refresh to check again.")])

    // A request that macOS left unanswered replaces the earlier report with the notice.
    let unanswered = overview(secondsLater: 30, unansweredSince: observedAt.addingTimeInterval(5))
    XCTAssertFalse(unanswered.isConfirmed)
    XCTAssertFalse(unanswered.isWaitingForFirstReport)
    XCTAssertTrue(unanswered.entries.isEmpty)
    XCTAssertEqual(unanswered.active, String(localized: "Can’t confirm"))
    XCTAssertEqual(unanswered.tone, .attention)
    XCTAssertEqual(
      unanswered.notices.map(\.text),
      [
        InstallationStateText.unanswered(
          since: observedAt.addingTimeInterval(5), now: observedAt.addingTimeInterval(30))
      ])
  }

  /// Until macOS answers the first request, Settings → Extension says that it is checking; once
  /// macOS doesn't answer within the timeout, it says that instead.
  func testFirstVersionReportIsAwaitedUntilMacOSAnswersOrTimesOut() {
    let app = ProductVersion(installation: installation(build: "1", enabled: true))
    let now = Date(timeIntervalSince1970: 1_000_000)
    let waiting = ExtensionVersionOverview(
      app: app, included: app, installations: [], observedAt: nil, queryError: nil,
      isRequestingActivation: false, activationProgress: nil, activationOutcome: nil, now: now)
    XCTAssertTrue(waiting.isWaitingForFirstReport)
    XCTAssertEqual(waiting.tone, .neutral)
    XCTAssertTrue(waiting.notices.isEmpty)

    let unanswered = ExtensionVersionOverview(
      app: app, included: app, installations: [], observedAt: nil,
      unansweredSince: now.addingTimeInterval(-25), queryError: nil,
      isRequestingActivation: false, activationProgress: nil, activationOutcome: nil, now: now)
    XCTAssertFalse(unanswered.isWaitingForFirstReport)
    XCTAssertEqual(unanswered.comparison, String(localized: "Version check unavailable"))
    XCTAssertEqual(unanswered.notices.map(\.id), ["unavailable"])
  }

  func testUnansweredInstallationStatesNameTheDurationAndTheRemedy() {
    let since = Date(timeIntervalSince1970: 1_000_000)
    let text = InstallationStateText.unanswered(since: since, now: since.addingTimeInterval(25))
    let duration = Duration.seconds(25).formatted(
      .units(allowed: [.hours, .minutes, .seconds], width: .wide, maximumUnitCount: 1))
    XCTAssertTrue(text.contains(duration), text)
    XCTAssertTrue(text.contains("sudo killall sysextd"), text)
    // A clock that moved back doesn't show a negative duration.
    let backwards = InstallationStateText.unanswered(
      since: since, now: since.addingTimeInterval(-5))
    XCTAssertTrue(
      backwards.contains(
        Duration.seconds(0).formatted(
          .units(allowed: [.hours, .minutes, .seconds], width: .wide, maximumUnitCount: 1))),
      backwards)
  }

  /// While an update waits for a restart, the version the running extension reports is the one
  /// shown as running; macOS reports none as enabled. An extension that predates the report is
  /// taken to be the version being replaced, and without a status no version is shown.
  func testUpdateWaitingForRestartNamesTheRunningAndTheNextVersion() {
    let running = installation(build: "1", enabled: false, uninstalling: true)
    let next = installation(build: "2", enabled: false)
    let app = ProductVersion(installation: next)
    let observedAt = Date(timeIntervalSince1970: 1_000_000)
    func overview(_ runningExtension: ProductVersion?) -> ExtensionVersionOverview {
      ExtensionVersionOverview(
        app: app, included: app, installations: [running, next], observedAt: observedAt,
        queryError: nil, runningExtension: runningExtension, isRequestingActivation: false,
        activationProgress: nil, activationOutcome: nil, now: observedAt)
    }
    let reported = ProductVersion(
      runningExtension: ExtensionStatusSnapshot(
        runtimeInstanceIdentifier: UUID(), phase: .enforcing, extensionVersion: "0.11.0",
        extensionBuildVersion: "1"))
    let unreported = ProductVersion(
      runningExtension: ExtensionStatusSnapshot(
        runtimeInstanceIdentifier: UUID(), phase: .enforcing))
    let runningText = ProductVersion(installation: running).description
    let nextText = ProductVersion(installation: next).description

    for runningExtension in [reported, unreported] {
      let answering = overview(runningExtension)
      XCTAssertEqual(answering.active, runningText)
      XCTAssertEqual(
        answering.comparison, String(localized: "Restart to finish the extension update"))
      XCTAssertEqual(answering.tone, .attention)
      XCTAssertEqual(
        answering.entries.map(\.state),
        [String(localized: "Starts after restart"), String(localized: "Running until restart")])
      XCTAssertEqual(
        answering.notices.map(\.text),
        [
          String(
            localized:
              "The extension that is running keeps checking requests until this Mac restarts. macOS then starts \(nextText)."
          ),
          String(
            localized: "\(runningText): keeps running until a restart; macOS then removes it."),
        ])
    }

    // A newer package installed while the update waits needs a second restart.
    let newerApp = ProductVersion(installation: installation(build: "3", enabled: false))
    let twice = ExtensionVersionOverview(
      app: newerApp, included: newerApp, installations: [running, next], observedAt: observedAt,
      queryError: nil, runningExtension: reported, isRequestingActivation: false,
      activationProgress: nil, activationOutcome: nil, now: observedAt)
    XCTAssertEqual(
      twice.notices.first { $0.id == "updateRestartAgain" }?.text,
      String(
        localized:
          "This app includes a newer extension than \(nextText). After the restart, open Pasu FS to update the extension again; that update also finishes with a restart."
      ))
    XCTAssertFalse(overview(reported).notices.contains { $0.id == "updateRestartAgain" })

    let unanswered = overview(nil)
    XCTAssertEqual(unanswered.active, String(localized: "None reported by macOS"))
    XCTAssertEqual(
      unanswered.comparison, String(localized: "Restart to finish the extension update"))
    XCTAssertEqual(
      unanswered.entries.map(\.state),
      [String(localized: "Starts after restart"), String(localized: "Cleanup after restart")])
    XCTAssertEqual(
      unanswered.notices.first?.text,
      String(localized: "macOS starts \(nextText) when this Mac restarts."))
  }

  /// A deactivation that waits for a restart: the running extension still answers.
  func testRemovalWaitingForRestartShowsTheRunningVersion() {
    let removing = installation(build: "1", enabled: false, uninstalling: true)
    let app = ProductVersion(installation: removing)
    let observedAt = Date(timeIntervalSince1970: 1_000_000)
    let overview = ExtensionVersionOverview(
      app: app, included: app, installations: [removing], observedAt: observedAt,
      queryError: nil,
      runningExtension: ProductVersion(
        runningExtension: ExtensionStatusSnapshot(
          runtimeInstanceIdentifier: UUID(), phase: .enforcing, extensionVersion: "0.11.0",
          extensionBuildVersion: "1")),
      isRequestingActivation: false, activationProgress: nil, activationOutcome: nil,
      now: observedAt)
    XCTAssertEqual(overview.active, app.description)
    XCTAssertEqual(overview.tone, .matching)
    XCTAssertEqual(overview.entries.map(\.state), [String(localized: "Running until restart")])
    XCTAssertEqual(
      overview.notices.map(\.text),
      [
        String(
          localized: "\(app.description): keeps running until a restart; macOS then removes it.")
      ])

    let stopped = StatusPresentation(health: HealthState(protection: .uninstalling))
    let running = StatusPresentation(
      health: HealthState(protection: .uninstalling, changeAtRestart: .removal))
    XCTAssertEqual(stopped.title, running.title)
    XCTAssertNotEqual(stopped.detail, running.detail)
  }

  private func installation(
    build: String, enabled: Bool, uninstalling: Bool = false
  ) -> ExtensionInstallationProperties {
    ExtensionInstallationProperties(
      bundleIdentifier: ActivationController.extensionIdentifier, bundleVersion: build,
      bundleShortVersion: "0.11.0", isEnabled: enabled, isAwaitingUserApproval: false,
      isUninstalling: uninstalling)
  }

  /// A request a compatibility profile allowed shows the profile in the log list, as in the
  /// details, not the program lists' reason, which would contradict the decision.
  func testProfileAllowanceNamesTheProfileInTheList() throws {
    // The extension records the program lists' evidence along with the profile.
    let evidence = """
      {"bootIdentifier":"example-boot","isAllowed":false,"reason":"originNotAllowed",
       "isBlacklistEnabled":false,
       "actor":{"instance":{"processID":321,"processVersion":2},
         "executablePath":"/usr/libexec/containermanagerd",
         "signingIdentifier":"com.apple.containermanagerd","isPlatformBinary":true,
         "codeSigningFlags":1,"pathWasTruncated":false}}
      """
    let origin = try JSONDecoder().decode(ExecutionOriginDecision.self, from: Data(evidence.utf8))
    for profile in BuiltInSystemCompatibilityCatalog.catalog.profiles {
      let evaluation = PolicyEvaluationRecord(
        policyIdentifier: UUID(), policyName: "Container", mode: .protection,
        policyType: .whitelist, match: .systemCompatibilityProfile,
        systemCompatibilityProfileIdentifier: profile.id, decision: .allow,
        executionOrigin: origin)
      let name = SystemCompatibilityText.name(identifier: profile.id)
      let expected = String(localized: "Allowed by the compatibility profile “\(name)”")
      XCTAssertEqual(DecisionReasonText.summary(evaluation), expected)
      XCTAssertEqual(DecisionReasonText.match(evaluation), expected)
      XCTAssertNotEqual(
        DecisionReasonText.summary(evaluation), OriginText.reason(.originNotAllowed))
    }

    // Without a profile the list keeps the recorded reason, and without evidence shows none.
    let listed = PolicyEvaluationRecord(
      policyIdentifier: UUID(), policyName: "Container", mode: .protection,
      policyType: .whitelist, match: .none, decision: .deny, executionOrigin: origin)
    XCTAssertEqual(DecisionReasonText.summary(listed), OriginText.reason(.originNotAllowed))
    let withoutEvidence = PolicyEvaluationRecord(
      policyIdentifier: UUID(), policyName: "Container", mode: .protection,
      policyType: .whitelist, match: .direct, decision: .allow)
    XCTAssertNil(DecisionReasonText.summary(withoutEvidence))
  }

  /// A response that missed the deadline shows what macOS did with the request, as far as the
  /// current deadline miss mode tells.
  func testMissedDeadlineShowsWhatMacOSDid() {
    let response = "response-error"
    let denied = DeadlineMissModeStatus(setting: .failClosed, maximumDeadlineMilliseconds: 3_000)
    let allowed = [
      DeadlineMissModeStatus(setting: .killUnavailable),
      DeadlineMissModeStatus(setting: .killAfterFailure, error: "failed"),
    ]

    XCTAssertEqual(MissedDeadlineOutcome(denied), .denied)
    XCTAssertEqual(
      KernelResponseText.label(response, deadlineMissMode: denied), String(localized: "Deny"))
    XCTAssertEqual(
      KernelResponseText.headline(response, deadlineMissMode: denied),
      String(localized: "Denied (missed deadline)"))
    for mode in allowed {
      XCTAssertEqual(MissedDeadlineOutcome(mode), .allowed)
      XCTAssertEqual(
        KernelResponseText.label(response, deadlineMissMode: mode), String(localized: "Allow"))
      XCTAssertEqual(
        KernelResponseText.headline(response, deadlineMissMode: mode),
        String(localized: "Allowed (missed deadline)"))
    }
    XCTAssertEqual(MissedDeadlineOutcome(nil), .unknown)
    XCTAssertEqual(
      KernelResponseText.label(response, deadlineMissMode: nil),
      String(localized: "Missed deadline"))
    XCTAssertEqual(
      KernelResponseText.headline(response, deadlineMissMode: nil),
      String(localized: "Missed deadline"))

    // Answers that reached macOS don't depend on the mode.
    for mode in [denied, nil] + allowed {
      XCTAssertEqual(
        KernelResponseText.label("allow", deadlineMissMode: mode), String(localized: "Allow"))
      XCTAssertEqual(
        KernelResponseText.headline("deny", deadlineMissMode: mode), String(localized: "Denied"))
      XCTAssertEqual(
        KernelResponseText.label("notify-only", deadlineMissMode: mode),
        String(localized: "Notify"))
    }
  }
}

private struct NoExtensionLifecycle: ExtensionLifecycleControlling {
  func installationStateLauncher() -> any InstallationStateChildLaunching {
    inProcessInstallationStateLauncher()
  }

  func activationEvents() -> AsyncStream<ActivationEvent> { AsyncStream { $0.finish() } }
  func deactivationEvents() -> AsyncStream<ActivationEvent> { AsyncStream { $0.finish() } }
  func propertiesEvents() -> AsyncStream<ActivationEvent> {
    AsyncStream { continuation in
      continuation.yield(.properties([]))
      continuation.finish()
    }
  }
}

private final class ApprovalLoginItem: LoginItemControlling {
  var state: LoginItemState { .requiresApproval }
  func register() throws {}
  func unregister() throws {}
  func openSystemSettings() {}
}
