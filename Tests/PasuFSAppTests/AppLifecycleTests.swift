import Foundation
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSMaintenanceCore
import XCTest

@testable import PasuFSApp

@MainActor
final class AppLifecycleTests: XCTestCase {
  func testBundleBuildVersionUsesNumericComponents() throws {
    let version1 = try XCTUnwrap(BundleBuildVersion("1"))
    let version1Dot0 = try XCTUnwrap(BundleBuildVersion("1.0"))
    let version1Dot2 = try XCTUnwrap(BundleBuildVersion("1.2"))
    let version1Dot10 = try XCTUnwrap(BundleBuildVersion("1.10"))

    XCTAssertEqual(version1, version1Dot0)
    XCTAssertLessThan(version1Dot2, version1Dot10)
    XCTAssertNil(BundleBuildVersion("1..2"))
    XCTAssertNil(BundleBuildVersion("1.2.3.4"))
    XCTAssertNil(BundleBuildVersion("1.2-beta"))
  }

  func testUpdatePlannerRequestsOnlyANewerVersionForAnActiveInstallation() {
    XCTAssertTrue(
      ExtensionUpdatePlanner.shouldRequestActivation(
        embeddedBuildVersion: "12",
        installations: [installation(version: "11")]
      )
    )

    let ineligibleInstallations = [
      installation(version: "11", enabled: false),
      installation(version: "11", awaitingApproval: true),
      installation(version: "11", uninstalling: true),
      installation(version: "11", identifier: "com.example.other"),
    ]
    for installation in ineligibleInstallations {
      XCTAssertFalse(
        ExtensionUpdatePlanner.shouldRequestActivation(
          embeddedBuildVersion: "12",
          installations: [installation]
        )
      )
    }

    XCTAssertFalse(
      ExtensionUpdatePlanner.shouldRequestActivation(
        embeddedBuildVersion: "11",
        installations: [installation(version: "11")]
      )
    )
    XCTAssertFalse(
      ExtensionUpdatePlanner.shouldRequestActivation(
        embeddedBuildVersion: "10",
        installations: [installation(version: "11")]
      )
    )
    XCTAssertFalse(
      ExtensionUpdatePlanner.shouldRequestActivation(
        embeddedBuildVersion: "invalid",
        installations: [installation(version: "11")]
      )
    )
    XCTAssertFalse(
      ExtensionUpdatePlanner.shouldRequestActivation(
        embeddedBuildVersion: "12",
        installations: [installation(version: "invalid")]
      )
    )
    XCTAssertTrue(
      ExtensionUpdatePlanner.shouldRequestActivation(
        embeddedBuildVersion: "12",
        installations: [
          installation(version: "11"),
          installation(version: "10", enabled: false, uninstalling: true),
        ]
      )
    )
  }

  func testUpdatePlannerOnlyIgnoresDisabledRemovalOlderThanTheActiveVersion() {
    let blockingInstallations = [
      installation(version: "10", uninstalling: true),
      installation(version: "11", enabled: false, uninstalling: true),
      installation(version: "12", enabled: false, uninstalling: true),
      installation(version: "10", enabled: false, awaitingApproval: true, uninstalling: true),
      installation(version: "invalid", enabled: false, uninstalling: true),
    ]
    for blocking in blockingInstallations {
      XCTAssertFalse(
        ExtensionUpdatePlanner.shouldRequestActivation(
          embeddedBuildVersion: "13",
          installations: [installation(version: "11"), blocking]
        )
      )
    }
    XCTAssertFalse(
      ExtensionUpdatePlanner.shouldRequestActivation(
        embeddedBuildVersion: "12",
        installations: [installation(version: "10", enabled: false, uninstalling: true)]
      )
    )
  }

  func testUpdatePlannerDoesNotDowngradeWhenMultipleInstallationsAreReported() {
    XCTAssertFalse(
      ExtensionUpdatePlanner.shouldRequestActivation(
        embeddedBuildVersion: "12",
        installations: [
          installation(version: "11"),
          installation(version: "12"),
        ]
      )
    )
    XCTAssertFalse(
      ExtensionUpdatePlanner.shouldRequestActivation(
        embeddedBuildVersion: "12",
        installations: [
          installation(version: "11"),
          installation(version: "13", enabled: false),
        ]
      )
    )
  }

  func testAutomaticUpdateCheckEvaluatesOnlyOnce() {
    var check = AutomaticExtensionUpdateCheck()
    let installations = [installation(version: "11")]

    XCTAssertTrue(
      check.shouldRequestActivation(
        embeddedBuildVersion: "12",
        installations: installations
      )
    )
    XCTAssertFalse(
      check.shouldRequestActivation(
        embeddedBuildVersion: "13",
        installations: installations
      )
    )
    XCTAssertTrue(check.hasEvaluated)
  }

  func testStartingTwiceSubmitsOnlyOneAutomaticUpdateRequest() async {
    let lifecycleController = FakeExtensionLifecycleController(
      properties: [installation(version: "11")]
    )
    let model = AppModel(
      activationController: lifecycleController,
      runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      embeddedVersionProvider: FakeEmbeddedVersionProvider(buildVersion: "12")
    )

    model.start()
    model.start()
    for _ in 0..<50 where lifecycleController.activationCallCount == 0 {
      try? await Task.sleep(for: .milliseconds(10))
    }
    model.stop()

    XCTAssertEqual(lifecycleController.activationCallCount, 1)
  }

  func testReplacingRunningExtensionRecommendsRestartUntilNextBoot() async throws {
    let suite = "PasuFSAppTests.\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let record = ExtensionReplacementRecord(defaults: defaults, currentBootSession: { "boot-1" })
    let policies = restrictingPolicySet(protectionPolicy(allowRules: [editorRule]))
    let model = replacementModel(
      activation: [
        .replacing(existingVersion: "11", newVersion: "12"), .completed(rebootRequired: false),
      ], record: record, policies: policies)
    XCTAssertFalse(model.attentionItems().contains { $0.id == "extensionReplaced" })

    model.start()
    for _ in 0..<50 where !model.recommendsRestartAfterExtensionUpdate {
      try? await Task.sleep(for: .milliseconds(10))
    }
    model.stop()
    XCTAssertTrue(model.attentionItems().contains { $0.id == "extensionReplaced" })

    // Reopening the app in the same boot session keeps the recommendation; a restart ends it.
    let reopened = replacementModel(activation: [], record: record, policies: policies)
    XCTAssertTrue(reopened.attentionItems().contains { $0.id == "extensionReplaced" })
    let restarted = replacementModel(
      activation: [],
      record: ExtensionReplacementRecord(defaults: defaults, currentBootSession: { "boot-2" }),
      policies: policies)
    XCTAssertFalse(restarted.attentionItems().contains { $0.id == "extensionReplaced" })
  }

  func testReplacementIsRecordedButNotShownWithoutPolicies() async throws {
    let suite = "PasuFSAppTests.\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let record = ExtensionReplacementRecord(defaults: defaults, currentBootSession: { "boot-1" })
    let model = replacementModel(
      activation: [
        .replacing(existingVersion: "11", newVersion: "12"), .completed(rebootRequired: false),
      ], record: record)

    model.start()
    for _ in 0..<50 where !model.recommendsRestartAfterExtensionUpdate {
      try? await Task.sleep(for: .milliseconds(10))
    }
    model.stop()

    XCTAssertTrue(record.recommendsRestart)
    XCTAssertTrue(model.recommendsRestartAfterExtensionUpdate)
    XCTAssertFalse(model.showsRestartRecommendationAfterExtensionUpdate)
    XCTAssertFalse(model.attentionItems().contains { $0.id == "extensionReplaced" })
  }

  func testRestartRecommendationNeedsAPolicyThatDeniesIncompleteHistory() throws {
    let suite = "PasuFSAppTests.\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let record = ExtensionReplacementRecord(defaults: defaults, currentBootSession: { "boot-1" })
    record.recordReplacement()

    let expectations: [(String, [DirectoryPolicy], Bool)] = [
      ("no policies", [], false),
      (
        "Audit policies only",
        [auditPolicy(allowRules: [editorRule]), auditPolicy(blockList: true)], false
      ),
      ("Protection policy with an allow rule", [protectionPolicy(allowRules: [editorRule])], true),
      ("Protection policy with the allow list off", [protectionPolicy(blockList: true)], true),
      ("Protection policy with an empty allow list", [protectionPolicy()], false),
      (
        "Protection policy whose only allow rule is off",
        [protectionPolicy(allowRules: [editorRule(isEnabled: false)])], false
      ),
      (
        "Audit and Protection policies",
        [auditPolicy(allowRules: [editorRule]), protectionPolicy(allowRules: [editorRule])], true
      ),
    ]
    for (label, policies, shows) in expectations {
      let model = replacementModel(
        activation: [], record: record, policies: restrictingPolicySet(policies))
      XCTAssertTrue(model.recommendsRestartAfterExtensionUpdate, label)
      XCTAssertEqual(model.showsRestartRecommendationAfterExtensionUpdate, shows, label)
      XCTAssertEqual(
        model.attentionItems().contains { $0.id == "extensionReplaced" }, shows, label)
    }
  }

  func testRestartRecommendationFollowsPolicyChangesInTheSameBootSession() throws {
    let suite = "PasuFSAppTests.\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let record = ExtensionReplacementRecord(defaults: defaults, currentBootSession: { "boot-1" })
    record.recordReplacement()
    let audit = auditPolicy(allowRules: [editorRule])
    let model = replacementModel(
      activation: [], record: record, policies: restrictingPolicySet(audit))
    XCTAssertFalse(model.attentionItems().contains { $0.id == "extensionReplaced" })

    // Adding a Protection policy with an allow rule shows the recommendation.
    let protection = protectionPolicy(allowRules: [editorRule])
    model.installActivePolicySet(restrictingPolicySet([audit, protection], revision: 2))
    XCTAssertTrue(model.attentionItems().contains { $0.id == "extensionReplaced" })

    // Switching that policy to Audit hides it again.
    var switched = protection
    switched.mode = .audit
    model.installActivePolicySet(restrictingPolicySet([audit, switched], revision: 3))
    XCTAssertFalse(model.attentionItems().contains { $0.id == "extensionReplaced" })
  }

  func testReplacementThatWaitsForRestartDoesNotRecommendAnotherRestart() async throws {
    let suite = "PasuFSAppTests.\(UUID().uuidString)"
    let defaults = try XCTUnwrap(UserDefaults(suiteName: suite))
    defer { defaults.removePersistentDomain(forName: suite) }
    let record = ExtensionReplacementRecord(defaults: defaults, currentBootSession: { "boot-1" })
    let lifecycle = FakeExtensionLifecycleController(
      properties: [installation(version: "11")],
      activation: [
        .replacing(existingVersion: "11", newVersion: "12"), .completed(rebootRequired: true),
      ])
    let model = AppModel(
      activationController: lifecycle, runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      embeddedVersionProvider: FakeEmbeddedVersionProvider(buildVersion: "12"),
      extensionReplacementRecord: record)

    model.start()
    for _ in 0..<50 where lifecycle.activationCallCount == 0 || model.isBusy {
      try? await Task.sleep(for: .milliseconds(10))
    }
    model.stop()

    XCTAssertEqual(lifecycle.activationCallCount, 1)
    XCTAssertFalse(record.recommendsRestart)
    XCTAssertFalse(model.attentionItems().contains { $0.id == "extensionReplaced" })
  }

  /// The extension sets NSEndpointSecurityRebootRequired, so macOS defers replacing a running
  /// version to the next restart. The app finds the waiting update in the installation states
  /// each time it reads them, so reopening the app keeps the notice, and it sends no request.
  func testUpdateWaitingForRestartIsShownAgainAfterReopeningWithoutARequest() async {
    let installations = [
      installation(version: "11", enabled: false, uninstalling: true),
      installation(version: "12", enabled: false),
    ]
    let status = ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(), phase: .enforcing, activePolicyRevision: 4,
      extensionVersion: "11", extensionBuildVersion: "11")
    for embedded in ["12", "13"] {
      for launch in 0..<2 {
        let label = "embedded \(embedded), launch \(launch)"
        let lifecycle = FakeExtensionLifecycleController(properties: installations)
        let model = AppModel(
          activationController: lifecycle, runtimeController: FakeRuntimeController(status: status),
          loginItemController: FakeLoginItemController(state: .notRegistered),
          embeddedVersionProvider: FakeEmbeddedVersionProvider(buildVersion: embedded))

        model.start()
        for _ in 0..<100 where model.health.changeAtRestart == nil {
          try? await Task.sleep(for: .milliseconds(10))
        }
        try? await Task.sleep(for: .milliseconds(50))
        model.stop()

        XCTAssertEqual(lifecycle.activationCallCount, 0, label)
        XCTAssertEqual(model.health.protection, .enforcingOpenEvents(revision: 4), label)
        XCTAssertEqual(model.health.changeAtRestart, .update, label)
        let item = model.attentionItems().first { $0.id == "extensionUpdateAwaitsRestart" }
        XCTAssertEqual(
          item?.text,
          String(localized: "The extension update finishes when you restart this Mac."), label)
        XCTAssertNotNil(item?.detail, label)
        XCTAssertFalse(model.attentionItems().contains { $0.id == "versions" }, label)
        let overview = model.extensionVersionOverview(now: Date())
        XCTAssertEqual(
          overview.comparison, String(localized: "Restart to finish the extension update"), label)
        XCTAssertEqual(
          overview.active,
          ProductVersion(runningExtension: status).description, label)
        XCTAssertEqual(
          model.installationStateDescription, String(localized: "Update waiting for restart"),
          label)
      }
    }
  }

  /// With the reboot key, macOS stops a running extension only at the next restart.
  func testDeactivationThatWaitsForRestartKeepsTheAppOpen() async {
    let deferred: [ActivationEvent] = [.completed(rebootRequired: true)]
    let quitting = AppModel(
      activationController: FakeExtensionLifecycleController(
        properties: [installation(version: "12")], deactivation: deferred),
      runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .notRegistered))
    let quitOutcome = await quitting.stopProtectionForQuit()
    XCTAssertEqual(quitOutcome, .requiresRestart)

    let deactivating = AppModel(
      activationController: FakeExtensionLifecycleController(
        properties: [installation(version: "12")], deactivation: deferred),
      runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .notRegistered))
    await deactivating.deactivate()
    XCTAssertEqual(
      deactivating.operationMessage,
      String(localized: "The request will finish after the Mac restarts."))
    XCTAssertNil(deactivating.lastError)
  }

  /// Deactivate… has nothing left to do while macOS removes every version it reports, as it does
  /// until the next restart after a deactivation of an extension with the reboot key.
  func testDeactivationIsUnavailableOnlyWhileEveryVersionIsBeingRemoved() async {
    let cases: [(String, [ExtensionInstallationProperties], Bool)] = [
      ("removal waits", [installation(version: "12", enabled: false, uninstalling: true)], true),
      (
        "older versions only",
        [
          installation(version: "11", enabled: false, uninstalling: true),
          installation(version: "12", enabled: false, uninstalling: true),
        ], true
      ),
      ("enabled", [installation(version: "12")], false),
      (
        "update waits",
        [
          installation(version: "11", enabled: false, uninstalling: true),
          installation(version: "12", enabled: false),
        ], false
      ),
      (
        "enabled with an older removal",
        [
          installation(version: "11", enabled: false, uninstalling: true),
          installation(version: "12"),
        ], false
      ),
      ("waiting for approval", [installation(version: "12", awaitingApproval: true)], false),
      ("not installed", [], false),
    ]
    for (label, installations, pending) in cases {
      let model = AppModel(
        activationController: FakeExtensionLifecycleController(properties: installations),
        runtimeController: FakeRuntimeController(),
        loginItemController: FakeLoginItemController(state: .notRegistered))
      XCTAssertFalse(model.extensionRemovalIsPending, "\(label) before the first check")
      await model.refreshHealth()
      XCTAssertEqual(model.extensionRemovalIsPending, pending, label)
    }
  }

  /// Deactivate… has nothing to do while macOS reports no installed extension. Before macOS has
  /// reported the installation states, the app can't tell, and Deactivate… stays available.
  func testDeactivationIsUnavailableWhileMacOSReportsNoExtension() async {
    let cases: [(String, [ExtensionInstallationProperties], Bool)] = [
      ("not installed", [], true),
      ("enabled", [installation(version: "12")], false),
      ("waiting for approval", [installation(version: "12", awaitingApproval: true)], false),
    ]
    for (label, installations, notInstalled) in cases {
      let lifecycle = FakeExtensionLifecycleController(properties: installations)
      let model = AppModel(
        activationController: lifecycle,
        runtimeController: FakeRuntimeController(),
        loginItemController: FakeLoginItemController(state: .notRegistered))
      XCTAssertFalse(model.extensionIsReportedNotInstalled, "\(label) before the first check")
      await model.refreshHealth()
      XCTAssertEqual(model.extensionIsReportedNotInstalled, notInstalled, label)

      await model.deactivate()
      XCTAssertEqual(lifecycle.deactivationCallCount, notInstalled ? 0 : 1, label)
    }
  }

  /// macOS answers another deactivation request with OSSystemExtensionError.extensionNotFound
  /// while it removes the extension, so neither Deactivate… nor Stop Protection and Quit… sends
  /// one then. Stop Protection and Quit… quits only when the extension no longer answers.
  func testNoSecondDeactivationRequestWhileTheRemovalWaitsForRestart() async {
    let removal = [installation(version: "12", enabled: false, uninstalling: true)]
    let status = ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(), phase: .enforcing, activePolicyRevision: 4,
      extensionVersion: "12", extensionBuildVersion: "12")
    for (label, answering, expected) in [
      ("still running", true, StopProtectionQuitOutcome.requiresRestart),
      ("stopped", false, .stopped),
    ] {
      let lifecycle = FakeExtensionLifecycleController(
        properties: removal,
        deactivation: [.failed(domain: "OSSystemExtensionErrorDomain", code: 4, description: "")])
      let model = AppModel(
        activationController: lifecycle,
        runtimeController: FakeRuntimeController(status: answering ? status : nil),
        loginItemController: FakeLoginItemController(state: .notRegistered))
      await model.refreshHealth()

      await model.deactivate()
      let outcome = await model.stopProtectionForQuit()

      XCTAssertEqual(lifecycle.deactivationCallCount, 0, label)
      XCTAssertEqual(outcome, expected, label)
      XCTAssertNil(model.lastError, label)
    }
  }

  /// While an update waits for a restart, macOS answers a deactivation request by removing the
  /// waiting version at once and completes the request; the earlier version keeps running until
  /// the restart. The app then reports the removal at the restart instead of the withdrawn update.
  func testDeactivationWhileAnUpdateWaitsReportsTheRemovalAtRestart() async {
    let lifecycle = FakeExtensionLifecycleController(
      properties: updateWaitingForRestart, activation: [.completed(rebootRequired: true)],
      propertiesAfterDeactivation: earlierVersionRunningUntilRemoval)
    let model = AppModel(
      activationController: lifecycle,
      runtimeController: FakeRuntimeController(status: earlierVersionStatus),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      embeddedVersionProvider: FakeEmbeddedVersionProvider(buildVersion: "12"))
    // The update request that macOS finishes at the restart.
    await model.activate()
    XCTAssertEqual(model.health.changeAtRestart, .update)
    XCTAssertFalse(model.extensionRemovalIsPending)

    await model.deactivate()

    XCTAssertEqual(lifecycle.deactivationCallCount, 1)
    XCTAssertNil(model.lastError)
    XCTAssertEqual(
      model.operationMessage,
      String(localized: "The request will finish after the Mac restarts."))
    XCTAssertEqual(model.health.changeAtRestart, .removal)
    XCTAssertTrue(model.extensionRemovalIsPending)
    XCTAssertFalse(model.attentionItems().contains { $0.id == "extensionUpdateAwaitsRestart" })
    let overview = model.extensionVersionOverview(now: Date())
    XCTAssertNotEqual(
      overview.comparison, String(localized: "Restart to finish the extension update"))
    XCTAssertFalse(overview.notices.contains { $0.id == "updateRestart" })
  }

  /// Stop Protection and Quit… while an update waits: the earlier version keeps running after
  /// macOS completes the request, so the app stays open until the restart.
  func testStopProtectionAndQuitWhileAnUpdateWaitsRequiresRestart() async {
    let lifecycle = FakeExtensionLifecycleController(
      properties: updateWaitingForRestart,
      propertiesAfterDeactivation: earlierVersionRunningUntilRemoval)
    let model = AppModel(
      activationController: lifecycle,
      runtimeController: FakeRuntimeController(status: earlierVersionStatus),
      loginItemController: FakeLoginItemController(state: .notRegistered))
    await model.refreshHealth()

    let outcome = await model.stopProtectionForQuit()

    XCTAssertEqual(lifecycle.deactivationCallCount, 1)
    XCTAssertEqual(outcome, .requiresRestart)
    XCTAssertNil(model.lastError)
  }

  func testStopProtectionQuitPolicyRequiresCompletedAndVerifiedStop() {
    XCTAssertEqual(
      StopProtectionQuitPolicy.outcome(
        for: .completed,
        extensionWasVerifiedStopped: true
      ),
      .stopped
    )
    XCTAssertEqual(
      StopProtectionQuitPolicy.outcome(
        for: .requiresRestart,
        extensionWasVerifiedStopped: false
      ),
      .requiresRestart
    )
    XCTAssertEqual(
      StopProtectionQuitPolicy.outcome(
        for: .failed("cancelled"),
        extensionWasVerifiedStopped: false
      ),
      .failed("cancelled")
    )
    XCTAssertEqual(
      StopProtectionQuitPolicy.outcome(
        for: .completed,
        extensionWasVerifiedStopped: false,
        extensionStopsAtRestart: true
      ),
      .requiresRestart
    )
    guard
      case .failed = StopProtectionQuitPolicy.outcome(
        for: .completed,
        extensionWasVerifiedStopped: false
      )
    else {
      return XCTFail("An unverified stop must keep the app open")
    }
  }

  func testProtectionStopVerificationRequiresDisabledInstallAndUnavailableRuntime() {
    XCTAssertTrue(
      ProtectionStopVerification.isStopped(
        installations: [installation(version: "11", enabled: false)],
        authenticatedRuntimeIsAvailable: false
      )
    )
    XCTAssertFalse(
      ProtectionStopVerification.isStopped(
        installations: [installation(version: "11")],
        authenticatedRuntimeIsAvailable: false
      )
    )
    XCTAssertFalse(
      ProtectionStopVerification.isStopped(
        installations: [installation(version: "11", enabled: false)],
        authenticatedRuntimeIsAvailable: true
      )
    )
  }

  func testLoginItemStatesMapToRegistrationAndAvailability() {
    let expectations: [(LoginItemState, Bool, Bool)] = [
      (.notRegistered, false, true),
      (.enabled, true, true),
      (.requiresApproval, true, true),
      (.notFound, false, true),
    ]

    for (state, isRegistered, canChange) in expectations {
      let controller = FakeLoginItemController(state: state)
      let model = AppModel(loginItemController: controller)
      XCTAssertEqual(model.loginItemState, state)
      XCTAssertEqual(model.isOpenAtLoginRegistered, isRegistered)
      XCTAssertEqual(model.canChangeOpenAtLogin, canChange)
    }
  }

  func testLoginItemCanRegisterUnregisterAndOpenSettings() {
    let controller = FakeLoginItemController(state: .notRegistered)
    let model = AppModel(loginItemController: controller)

    model.setOpenAtLogin(true)
    XCTAssertEqual(controller.registerCallCount, 1)
    XCTAssertEqual(model.loginItemState, .enabled)

    controller.state = .requiresApproval
    model.setOpenAtLogin(false)
    XCTAssertEqual(controller.unregisterCallCount, 1)
    XCTAssertEqual(model.loginItemState, .notRegistered)

    model.openLoginItemsSettings()
    XCTAssertEqual(controller.openSettingsCallCount, 1)
  }

  func testUnseenLoginItemRemainsOptInAndCanRegister() async {
    let controller = FakeLoginItemController(state: .notFound)
    let model = AppModel(
      activationController: FakeExtensionLifecycleController(properties: []),
      runtimeController: FakeRuntimeController(),
      loginItemController: controller
    )

    await model.refreshHealth()

    XCTAssertEqual(controller.registerCallCount, 0)
    XCTAssertFalse(model.isOpenAtLoginRegistered)
    XCTAssertTrue(model.canChangeOpenAtLogin)
    XCTAssertNil(model.loginItemError)

    model.setOpenAtLogin(true)

    XCTAssertEqual(controller.registerCallCount, 1)
    XCTAssertEqual(model.loginItemState, .enabled)
    XCTAssertTrue(model.isOpenAtLoginRegistered)
    XCTAssertNil(model.loginItemError)
  }

  func testUnseenLoginItemRegistrationFailureCanBeRetried() {
    let controller = FakeLoginItemController(state: .notFound)
    controller.registerError = FakeLoginItemError.denied
    let model = AppModel(loginItemController: controller)

    model.setOpenAtLogin(true)

    XCTAssertEqual(controller.registerCallCount, 1)
    XCTAssertEqual(model.loginItemState, .notFound)
    XCTAssertFalse(model.isOpenAtLoginRegistered)
    XCTAssertTrue(model.canChangeOpenAtLogin)
    XCTAssertTrue(model.loginItemError?.contains("denied") == true)

    controller.registerError = nil
    model.setOpenAtLogin(true)

    XCTAssertEqual(controller.registerCallCount, 2)
    XCTAssertEqual(model.loginItemState, .enabled)
    XCTAssertNil(model.loginItemError)
  }

  func testLoginItemFailureIsPresentedWithoutChangingTheEffectiveState() {
    let controller = FakeLoginItemController(state: .notRegistered)
    controller.registerError = FakeLoginItemError.denied
    let model = AppModel(loginItemController: controller)

    model.setOpenAtLogin(true)

    XCTAssertEqual(model.loginItemState, .notRegistered)
    XCTAssertEqual(controller.registerCallCount, 1)
    XCTAssertTrue(model.loginItemError?.contains("denied") == true)
  }

  func testUninstallAuthorizationCancellationDoesNotDeactivateOrRemove() async {
    let helper = FakeMaintenanceClient()
    let authorizer = FakeUninstallAuthorizer()
    authorizer.denied = true
    let lifecycle = UninstallLifecycle(properties: [installation(version: "11")])
    let login = FakeLoginItemController(state: .enabled)
    let model = AppModel(
      activationController: lifecycle, runtimeController: FakeRuntimeController(),
      loginItemController: login, maintenanceClient: helper, uninstallAuthorizer: authorizer,
      uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: true)
    XCTAssertFalse(accepted)
    XCTAssertEqual(lifecycle.deactivations, 0)
    XCTAssertEqual(login.unregisterCallCount, 0)
    let actions = await helper.actions
    XCTAssertTrue(actions.isEmpty)
  }

  func testUninstallOnlyHandsOffAfterVerifiedRemovalAndLoginUnregistration() async {
    let helper = FakeMaintenanceClient()
    let lifecycle = UninstallLifecycle(properties: [installation(version: "11")])
    let login = FakeLoginItemController(state: .enabled)
    let model = AppModel(
      activationController: lifecycle, runtimeController: FakeRuntimeController(),
      loginItemController: login, maintenanceClient: helper,
      uninstallAuthorizer: FakeUninstallAuthorizer(),
      uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: false)
    XCTAssertTrue(accepted)
    XCTAssertTrue(model.isFinalizingUninstall)
    XCTAssertTrue(model.takeUninstallTerminationRequest())
    XCTAssertFalse(model.takeUninstallTerminationRequest())
    XCTAssertEqual(lifecycle.deactivations, 1)
    XCTAssertEqual(login.unregisterCallCount, 1)
    let actions = await helper.actions
    XCTAssertEqual(actions, [.removeFiles])
    let removeData = await helper.requestedRemoval
    XCTAssertEqual(removeData, false)
  }

  func testAcceptedCleanupCannotBeSubmittedAgain() async {
    let helper = FakeMaintenanceClient()
    let authorizer = FakeUninstallAuthorizer()
    let model = AppModel(
      activationController: UninstallLifecycle(properties: []),
      runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      maintenanceClient: helper,
      uninstallAuthorizer: authorizer, uninstallStateReader: { nil })
    XCTAssertFalse(model.takeUninstallTerminationRequest())
    let first = await model.uninstall(removeData: false)
    let second = await model.uninstall(removeData: true)
    XCTAssertTrue(first)
    XCTAssertFalse(second)
    XCTAssertEqual(authorizer.calls, 1)
    let actions = await helper.actions
    XCTAssertEqual(actions, [.removeFiles])
  }

  func testUninstallNativeCancellationCancelsPreparation() async {
    let helper = FakeMaintenanceClient()
    let lifecycle = UninstallLifecycle(
      properties: [installation(version: "11")],
      result: .failed(domain: "test", code: 1, description: "User cancelled"))
    let login = FakeLoginItemController(state: .enabled)
    let model = AppModel(
      activationController: lifecycle, runtimeController: FakeRuntimeController(),
      loginItemController: login, maintenanceClient: helper,
      uninstallAuthorizer: FakeUninstallAuthorizer(),
      uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: false)
    XCTAssertFalse(accepted)
    let actions = await helper.actions
    XCTAssertEqual(actions, [.cancel])
    XCTAssertEqual(login.unregisterCallCount, 0)
  }

  func testUninstallSkipsLoginUnregistrationWhenNoServiceExists() async {
    for state in [LoginItemState.notRegistered, .notFound] {
      let helper = FakeMaintenanceClient()
      let login = FakeLoginItemController(state: state)
      login.unregisterError = FakeLoginItemError.denied
      let model = AppModel(
        activationController: UninstallLifecycle(properties: []),
        runtimeController: FakeRuntimeController(),
        loginItemController: login, maintenanceClient: helper,
        uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { nil })
      let accepted = await model.uninstall(removeData: false)
      XCTAssertTrue(accepted)
      XCTAssertEqual(login.unregisterCallCount, 0)
      let actions = await helper.actions
      XCTAssertEqual(actions, [.removeFiles])
    }
  }

  func testUninstallStopsWhenKnownLoginRegistrationCannotBeRemoved() async {
    for state in [LoginItemState.enabled, .requiresApproval] {
      let helper = FakeMaintenanceClient()
      let login = FakeLoginItemController(state: state)
      login.unregisterError = FakeLoginItemError.denied
      let model = AppModel(
        activationController: UninstallLifecycle(properties: []),
        runtimeController: FakeRuntimeController(),
        loginItemController: login, maintenanceClient: helper,
        uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { nil })
      let accepted = await model.uninstall(removeData: false)
      XCTAssertFalse(accepted)
      XCTAssertEqual(login.unregisterCallCount, 1)
      let actions = await helper.actions
      XCTAssertTrue(actions.isEmpty)
      XCTAssertTrue(model.lastError?.contains("login registration") == true)
      XCTAssertNil(model.operationMessage)
    }
  }

  func testUninstallVerifiesLoginRegistrationWasActuallyRemoved() async {
    let helper = FakeMaintenanceClient()
    let login = FakeLoginItemController(state: .enabled)
    login.unregisterLeavesStateUnchanged = true
    let model = AppModel(
      activationController: UninstallLifecycle(properties: []),
      runtimeController: FakeRuntimeController(),
      loginItemController: login, maintenanceClient: helper,
      uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: false)
    XCTAssertFalse(accepted)
    let actions = await helper.actions
    XCTAssertTrue(actions.isEmpty)
  }

  func testUninstallRestartDeferralDoesNotCommitFileRemoval() async {
    let helper = FakeMaintenanceClient()
    let lifecycle = UninstallLifecycle(
      properties: [installation(version: "11")],
      result: .completed(rebootRequired: true))
    let model = AppModel(
      activationController: lifecycle, runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .enabled), maintenanceClient: helper,
      uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: true)
    XCTAssertFalse(accepted)
    let actions = await helper.actions
    XCTAssertEqual(actions, [.awaitRestart])
    XCTAssertTrue(model.operationMessage?.contains("Restart") == true)
  }

  /// An extension with the reboot key keeps running and answering after macOS accepts its
  /// removal. The uninstall then waits for a restart without removing any file.
  func testUninstallOfAnExtensionThatKeepsRunningUntilRestartAwaitsRestart() async {
    let helper = FakeMaintenanceClient()
    let lifecycle = UninstallLifecycle(
      properties: [installation(version: "12")],
      result: .completed(rebootRequired: true))
    let model = AppModel(
      activationController: lifecycle,
      runtimeController: FakeRuntimeController(
        status: ExtensionStatusSnapshot(
          runtimeInstanceIdentifier: UUID(), phase: .enforcing, activePolicyRevision: 2)),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      maintenanceClient: helper,
      uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: false)
    XCTAssertFalse(accepted)
    XCTAssertEqual(lifecycle.deactivations, 1)
    let actions = await helper.actions
    XCTAssertEqual(actions, [.awaitRestart])
    XCTAssertTrue(model.operationMessage?.contains("Restart") == true)
  }

  func testPendingUninstallFailureIsShownInTheUsersLanguage() throws {
    let failed = UninstallState(
      phase: .failed, removeData: false, failure: MaintenanceError(.dataDirectoryNotRemoved))
    let model = AppModel(
      runtimeController: FakeRuntimeController(),
      maintenanceClient: FakeMaintenanceClient(pending: failed),
      uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { failed })
    XCTAssertEqual(
      model.pendingUninstallFailureMessage,
      UserFacingError.maintenance(.dataDirectoryNotRemoved, detail: nil))

    // A state file from a service without failure codes keeps its English text.
    let older = try MaintenanceContract.decode(
      UninstallState.self,
      from: Data(
        """
        {"formatVersion":1,"phase":"failed","removeData":false,"failure":"Older text."}
        """.utf8))
    let olderModel = AppModel(
      runtimeController: FakeRuntimeController(),
      maintenanceClient: FakeMaintenanceClient(pending: older),
      uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { older })
    XCTAssertEqual(olderModel.pendingUninstallFailureMessage, "Older text.")
  }

  func testUninstallCannotContinueBeforeRequiredRestart() async {
    let pending = UninstallState(phase: .awaitingRestart, removeData: true)
    let helper = FakeMaintenanceClient(pending: pending)
    let authorizer = FakeUninstallAuthorizer()
    let model = AppModel(
      runtimeController: FakeRuntimeController(), maintenanceClient: helper,
      uninstallAuthorizer: authorizer, uninstallStateReader: { pending })
    let accepted = await model.uninstall(removeData: true)
    XCTAssertFalse(accepted)
    XCTAssertEqual(authorizer.calls, 0)
    XCTAssertTrue(model.lastError?.contains("Restart") == true)
  }

  func testCompletedRemovalWithUninstallingEntryPersistsRestartBarrier() async {
    let helper = FakeMaintenanceClient()
    let lifecycle = UninstallLifecycle(
      properties: [installation(version: "11")],
      propertiesAfterDeactivation: [installation(version: "11", enabled: false, uninstalling: true)]
    )
    let model = AppModel(
      activationController: lifecycle, runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      maintenanceClient: helper,
      uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: false)
    XCTAssertFalse(accepted)
    XCTAssertFalse(model.isFinalizingUninstall)
    XCTAssertNil(model.lastError)
    XCTAssertEqual(lifecycle.deactivations, 1)
    let actions = await helper.actions
    XCTAssertEqual(actions, [.awaitRestart])
    XCTAssertTrue(model.operationMessage?.contains("Restart") == true)
  }

  func testExistingUninstallingEntryDoesNotResubmitDeactivation() async {
    let helper = FakeMaintenanceClient()
    let lifecycle = UninstallLifecycle(
      properties: [installation(version: "11", enabled: false, uninstalling: true)])
    let model = AppModel(
      activationController: lifecycle, runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      maintenanceClient: helper,
      uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: true)
    XCTAssertFalse(accepted)
    XCTAssertEqual(lifecycle.deactivations, 0)
    let actions = await helper.actions
    XCTAssertEqual(actions, [.awaitRestart])
    let removeData = await helper.requestedRemoval
    XCTAssertEqual(removeData, true)
  }

  func testOldUninstallingEntryDoesNotSkipDeactivationOfCurrentVersion() async {
    let helper = FakeMaintenanceClient()
    let lifecycle = UninstallLifecycle(properties: [
      installation(version: "10", enabled: false, uninstalling: true),
      installation(version: "11"),
    ])
    let model = AppModel(
      activationController: lifecycle, runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      maintenanceClient: helper,
      uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: false)
    XCTAssertTrue(accepted)
    XCTAssertEqual(lifecycle.deactivations, 1)
    let actions = await helper.actions
    XCTAssertEqual(actions, [.removeFiles])
  }

  /// While an update waits for a restart, the waiting version is not being removed. Uninstalling
  /// asks macOS to deactivate it, which removes it at once, so the restart that removes the
  /// earlier version finishes the removal. Without that request macOS would start the waiting
  /// version at the restart, and the removal would need a second restart.
  func testUninstallWhileAnUpdateWaitsDeactivatesTheWaitingVersion() async {
    let helper = FakeMaintenanceClient()
    let lifecycle = UninstallLifecycle(
      properties: updateWaitingForRestart,
      propertiesAfterDeactivation: earlierVersionRunningUntilRemoval)
    let model = AppModel(
      activationController: lifecycle,
      runtimeController: FakeRuntimeController(status: earlierVersionStatus),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      maintenanceClient: helper,
      uninstallAuthorizer: FakeUninstallAuthorizer(), uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: false)
    XCTAssertFalse(accepted)
    XCTAssertNil(model.lastError)
    XCTAssertEqual(lifecycle.deactivations, 1)
    let actions = await helper.actions
    XCTAssertEqual(actions, [.awaitRestart])
    XCTAssertTrue(model.operationMessage?.contains("Restart") == true)
  }

  func testUninstallCommitFailureKeepsApplicationOpen() async {
    let helper = FakeMaintenanceClient(failCommit: true)
    let model = AppModel(
      activationController: UninstallLifecycle(properties: []),
      runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      maintenanceClient: helper, uninstallAuthorizer: FakeUninstallAuthorizer(),
      uninstallStateReader: { nil })
    let accepted = await model.uninstall(removeData: false)
    XCTAssertFalse(accepted)
    XCTAssertEqual(
      model.lastError, UserFacingError.maintenance(.requestNotAccepted, detail: nil))
  }

  func testPendingUninstallSuppressesAutomaticExtensionUpdate() async {
    let pending = UninstallState(phase: .failed, removeData: false)
    let lifecycle = FakeExtensionLifecycleController(properties: [installation(version: "11")])
    let model = AppModel(
      activationController: lifecycle, runtimeController: FakeRuntimeController(),
      embeddedVersionProvider: FakeEmbeddedVersionProvider(buildVersion: "12"),
      uninstallStateReader: { pending })
    model.start()
    try? await Task.sleep(for: .milliseconds(50))
    model.stop()
    XCTAssertEqual(lifecycle.activationCallCount, 0)
  }

  private func replacementModel(
    activation: [ActivationEvent], record: ExtensionReplacementRecord,
    policies: PolicySetDocument? = nil
  ) -> AppModel {
    AppModel(
      initialPolicySet: policies,
      activationController: FakeExtensionLifecycleController(
        properties: [installation(version: "11")], activation: activation),
      runtimeController: FakeRuntimeController(),
      loginItemController: FakeLoginItemController(state: .notRegistered),
      embeddedVersionProvider: FakeEmbeddedVersionProvider(buildVersion: "12"),
      extensionReplacementRecord: record)
  }

  private func restrictingPolicySet(
    _ policies: DirectoryPolicy..., revision: UInt64 = 1
  ) -> PolicySetDocument {
    restrictingPolicySet(policies, revision: revision)
  }

  private func restrictingPolicySet(
    _ policies: [DirectoryPolicy], revision: UInt64 = 1
  ) -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(uuidString: "00000000-0000-0000-0000-000000000100")!,
      revision: revision, policies: policies)
  }

  private func protectionPolicy(
    allowRules: [PolicyRule] = [], blockList: Bool = false
  ) -> DirectoryPolicy {
    DirectoryPolicy(
      name: "Protection", mode: .protection, isBlacklistEnabled: blockList,
      protectedRootPath: "/Users/example/Protected\(UUID().uuidString)",
      allowRules: allowRules)
  }

  private func auditPolicy(
    allowRules: [PolicyRule] = [], blockList: Bool = false
  ) -> DirectoryPolicy {
    DirectoryPolicy(
      name: "Audit", mode: .audit, isBlacklistEnabled: blockList,
      protectedRootPath: "/Users/example/Audited\(UUID().uuidString)",
      allowRules: allowRules)
  }

  private var editorRule: PolicyRule { editorRule(isEnabled: true) }

  private func editorRule(isEnabled: Bool) -> PolicyRule {
    .teamSigned(
      id: "rule.editor", teamIdentifier: "TEAM123456",
      signingIdentifier: "com.example.Editor", isEnabled: isEnabled, allowsDescendants: false)
  }

  /// An update from one extension version to the next that waits for a restart, as macOS
  /// reports it.
  private var updateWaitingForRestart: [ExtensionInstallationProperties] {
    [
      installation(version: "11", enabled: false, uninstalling: true),
      installation(version: "12", enabled: false),
    ]
  }

  /// What macOS reports after a deactivation request during that wait: it has removed the
  /// waiting version, and the earlier version runs until the restart.
  private var earlierVersionRunningUntilRemoval: [ExtensionInstallationProperties] {
    [installation(version: "11", enabled: false, uninstalling: true)]
  }

  private var earlierVersionStatus: ExtensionStatusSnapshot {
    ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(), phase: .enforcing, activePolicyRevision: 4,
      extensionVersion: "11", extensionBuildVersion: "11")
  }

  private func installation(
    version: String,
    enabled: Bool = true,
    awaitingApproval: Bool = false,
    uninstalling: Bool = false,
    identifier: String = ActivationController.extensionIdentifier
  ) -> ExtensionInstallationProperties {
    ExtensionInstallationProperties(
      bundleIdentifier: identifier,
      bundleVersion: version,
      bundleShortVersion: version,
      isEnabled: enabled,
      isAwaitingUserApproval: awaitingApproval,
      isUninstalling: uninstalling
    )
  }
}

@MainActor
private final class FakeLoginItemController: LoginItemControlling {
  var state: LoginItemState
  var registerError: (any Error)?
  var unregisterError: (any Error)?
  var unregisterLeavesStateUnchanged = false
  private(set) var registerCallCount = 0
  private(set) var unregisterCallCount = 0
  private(set) var openSettingsCallCount = 0

  init(state: LoginItemState) {
    self.state = state
  }

  func register() throws {
    registerCallCount += 1
    if let registerError {
      throw registerError
    }
    state = .enabled
  }

  func unregister() throws {
    unregisterCallCount += 1
    if let unregisterError {
      throw unregisterError
    }
    if !unregisterLeavesStateUnchanged { state = .notRegistered }
  }

  func openSystemSettings() {
    openSettingsCallCount += 1
  }
}

private enum FakeLoginItemError: LocalizedError {
  case denied

  var errorDescription: String? {
    "denied for testing"
  }
}

private final class FakeExtensionLifecycleController: ExtensionLifecycleControlling,
  @unchecked Sendable
{
  func installationStateLauncher() -> any InstallationStateChildLaunching {
    inProcessInstallationStateLauncher()
  }

  private let lock = NSLock()
  private var properties: [ExtensionInstallationProperties]
  private let activation: [ActivationEvent]
  private let deactivation: [ActivationEvent]
  private let propertiesAfterDeactivation: [ExtensionInstallationProperties]?
  private var activationCalls = 0
  private var deactivationCalls = 0

  /// - Parameter propertiesAfterDeactivation: The installations macOS reports after a
  ///   deactivation request, or nil to keep reporting `properties`.
  init(
    properties: [ExtensionInstallationProperties],
    activation: [ActivationEvent] = [.completed(rebootRequired: false)],
    deactivation: [ActivationEvent] = [.completed(rebootRequired: false)],
    propertiesAfterDeactivation: [ExtensionInstallationProperties]? = nil
  ) {
    self.properties = properties
    self.activation = activation
    self.deactivation = deactivation
    self.propertiesAfterDeactivation = propertiesAfterDeactivation
  }

  var activationCallCount: Int {
    lock.withLock { activationCalls }
  }

  func activationEvents() -> AsyncStream<ActivationEvent> {
    lock.withLock { activationCalls += 1 }
    let activation = activation
    return AsyncStream { continuation in
      continuation.yield(.submitted(action: "activate"))
      for event in activation { continuation.yield(event) }
      continuation.finish()
    }
  }

  var deactivationCallCount: Int {
    lock.withLock { deactivationCalls }
  }

  func deactivationEvents() -> AsyncStream<ActivationEvent> {
    lock.withLock {
      deactivationCalls += 1
      if let propertiesAfterDeactivation { properties = propertiesAfterDeactivation }
    }
    let deactivation = deactivation
    return AsyncStream { continuation in
      continuation.yield(.submitted(action: "deactivate"))
      for event in deactivation { continuation.yield(event) }
      continuation.finish()
    }
  }

  func propertiesEvents() -> AsyncStream<ActivationEvent> {
    let properties = lock.withLock { properties }
    return AsyncStream { continuation in
      continuation.yield(.properties(properties))
      continuation.finish()
    }
  }
}

private actor FakeRuntimeController: ExtensionRuntimeControlling {
  /// The status the extension answers with; without one, the connection fails.
  private let status: ExtensionStatusSnapshot?

  init(status: ExtensionStatusSnapshot? = nil) {
    self.status = status
  }

  func applyPolicySet(
    _ document: PolicySetDocument, authorization: Data?, savedPolicyIdentifier: UUID?
  ) async throws -> PolicyApplyReceipt {
    throw FakeRuntimeError.unused
  }

  func queryStatus() async throws -> ExtensionStatusSnapshot {
    guard let status else { throw ExtensionControlClientError.interfaceUnavailable }
    var answer = status
    answer.timestamp = Date()
    return answer
  }

  func queryPolicySet() async throws -> PolicySetDocument {
    throw FakeRuntimeError.unused
  }

  func readAuditLog(maximumLineCount: Int) async throws -> AuditLogBatch {
    throw FakeRuntimeError.unused
  }

  func invalidate() {}
}

private struct FakeEmbeddedVersionProvider: EmbeddedSystemExtensionVersionProviding {
  let buildVersion: String?

  func buildVersion(in hostBundleURL: URL) -> String? {
    buildVersion
  }
}

private enum FakeRuntimeError: Error {
  case unused
}

@MainActor
private final class FakeUninstallAuthorizer: UninstallAuthorizing {
  var denied = false
  var calls = 0
  func prepare(using client: any MaintenanceControlling, removeData: Bool) async throws
    -> UninstallTicket
  {
    calls += 1
    if denied { throw MaintenanceError(.authorizationCanceled) }
    return try await client.prepare(authorization: Data(), removeData: removeData)
  }
}

private actor FakeMaintenanceClient: MaintenanceControlling {
  let pending: UninstallState?
  let failCommit: Bool
  private(set) var actions: [UninstallCommitAction] = []
  private(set) var requestedRemoval: Bool?
  init(pending: UninstallState? = nil, failCommit: Bool = false) {
    self.pending = pending
    self.failCommit = failCommit
  }
  func status() async throws -> UninstallState? { pending }
  func prepare(authorization: Data, removeData: Bool) async throws -> UninstallTicket {
    requestedRemoval = removeData
    return UninstallTicket(identifier: UUID())
  }
  func commit(ticket: UninstallTicket, action: UninstallCommitAction) async throws {
    actions.append(action)
    if failCommit { throw MaintenanceError(.requestNotAccepted) }
  }
  func invalidate() async {}
}

private final class UninstallLifecycle: ExtensionLifecycleControlling, @unchecked Sendable {
  func installationStateLauncher() -> any InstallationStateChildLaunching {
    inProcessInstallationStateLauncher()
  }

  private let lock = NSLock()
  private var properties: [ExtensionInstallationProperties]
  private var deactivationCount = 0
  private let result: ActivationEvent
  private let propertiesAfterDeactivation: [ExtensionInstallationProperties]
  var deactivations: Int { lock.withLock { deactivationCount } }
  init(
    properties: [ExtensionInstallationProperties],
    result: ActivationEvent = .completed(rebootRequired: false),
    propertiesAfterDeactivation: [ExtensionInstallationProperties] = []
  ) {
    self.properties = properties
    self.result = result
    self.propertiesAfterDeactivation = propertiesAfterDeactivation
  }
  func activationEvents() -> AsyncStream<ActivationEvent> { AsyncStream { $0.finish() } }
  func deactivationEvents() -> AsyncStream<ActivationEvent> {
    lock.withLock {
      deactivationCount += 1
      if case .completed(rebootRequired: false) = result {
        properties = propertiesAfterDeactivation
      }
    }
    return AsyncStream { continuation in
      continuation.yield(result)
      continuation.finish()
    }
  }
  func propertiesEvents() -> AsyncStream<ActivationEvent> {
    let snapshot = lock.withLock { properties }
    return AsyncStream { continuation in
      continuation.yield(.properties(snapshot))
      continuation.finish()
    }
  }
}
