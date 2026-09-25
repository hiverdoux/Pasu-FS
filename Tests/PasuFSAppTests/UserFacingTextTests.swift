import Foundation
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSIPC
import PasuFSMaintenanceCore
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

    let combined = RuntimeText.localized(
      SystemCompatibilityWarningState.storageRejectionMessage
        + " System-compatibility profile example.profile is inactive: needsReview.")
    XCTAssertTrue(combined.contains("example.profile"))
    XCTAssertFalse(combined.contains("needsReview"))

    XCTAssertEqual(
      RuntimeText.localized("A message from a newer extension."),
      "A message from a newer extension.")
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

  func testLineageSequenceRestartIsExplained() {
    let issue = LineageIssue(reason: "sequenceRestarted", at: Date())
    XCTAssertNotEqual(LineageText.explanation(issue), "sequenceRestarted")
    XCTAssertNotEqual(issue.explanation, "sequenceRestarted")
  }

  func testErrorsFromEveryLayerBecomeReadableMessages() {
    let validation = UserFacingError.message(PolicyValidationError.duplicatePolicyName("Keys"))
    XCTAssertTrue(validation.contains("Keys"))

    let xpc = PasuFSXPCError.make(.policyRejected, description: "Stored policy set rejected: bad")
    let rejected = UserFacingError.message(xpc)
    XCTAssertTrue(rejected.hasSuffix("bad"))
    XCTAssertFalse(rejected.contains("Error Domain"))

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
      bundleIdentifier: ActivationController.extensionIdentifier, bundleVersion: "33",
      bundleShortVersion: "0.6.1", isEnabled: true, isAwaitingUserApproval: false,
      isUninstalling: false)
    let version = ProductVersion(installation: installed)
    let observedAt = Date(timeIntervalSince1970: 1_000_000)
    func overview(secondsLater: TimeInterval) -> ExtensionVersionOverview {
      ExtensionVersionOverview(
        app: version, included: version, installations: [installed], observedAt: observedAt,
        queryError: nil, isRequestingActivation: false, activationProgress: nil,
        activationOutcome: nil, now: observedAt.addingTimeInterval(secondsLater))
    }

    let fresh = overview(secondsLater: 2)
    XCTAssertTrue(fresh.isConfirmed)
    XCTAssertEqual(fresh.entries.count, 1)
    XCTAssertEqual(fresh.tone, .matching)

    let stale = overview(secondsLater: 60)
    XCTAssertFalse(stale.isConfirmed)
    XCTAssertTrue(stale.entries.isEmpty)
    XCTAssertEqual(stale.tone, .attention)
  }
}

private struct NoExtensionLifecycle: ExtensionLifecycleControlling {
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
