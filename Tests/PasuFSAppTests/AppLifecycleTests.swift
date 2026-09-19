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
    XCTAssertTrue(model.lastError?.contains("cleanup rejected") == true)
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
  private let lock = NSLock()
  private let properties: [ExtensionInstallationProperties]
  private var activationCalls = 0

  init(properties: [ExtensionInstallationProperties]) {
    self.properties = properties
  }

  var activationCallCount: Int {
    lock.withLock { activationCalls }
  }

  func activationEvents() -> AsyncStream<ActivationEvent> {
    lock.withLock { activationCalls += 1 }
    return AsyncStream { continuation in
      continuation.yield(.submitted(action: "activate"))
      continuation.yield(.completed(rebootRequired: false))
      continuation.finish()
    }
  }

  func deactivationEvents() -> AsyncStream<ActivationEvent> {
    AsyncStream { continuation in
      continuation.yield(.completed(rebootRequired: false))
      continuation.finish()
    }
  }

  func propertiesEvents() -> AsyncStream<ActivationEvent> {
    let properties = properties
    return AsyncStream { continuation in
      continuation.yield(.properties(properties))
      continuation.finish()
    }
  }
}

private actor FakeRuntimeController: ExtensionRuntimeControlling {
  func applyPolicySet(_ document: PolicySetDocument) async throws -> PolicyApplyReceipt {
    throw FakeRuntimeError.unused
  }

  func queryStatus() async throws -> ExtensionStatusSnapshot {
    throw ExtensionControlClientError.interfaceUnavailable
  }

  func queryPolicySet() async throws -> PolicySetDocument {
    throw FakeRuntimeError.unused
  }

  func applySystemCompatibilitySettings(
    _ document: SystemCompatibilitySettingsDocument
  ) async throws -> SystemCompatibilitySettingsApplyReceipt {
    throw FakeRuntimeError.unused
  }

  func querySystemCompatibilityState() async throws -> SystemCompatibilityStateSnapshot {
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
    if denied { throw MaintenanceError("Authorization cancelled") }
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
    if failCommit { throw MaintenanceError("cleanup rejected") }
  }
  func invalidate() async {}
}

private final class UninstallLifecycle: ExtensionLifecycleControlling, @unchecked Sendable {
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
