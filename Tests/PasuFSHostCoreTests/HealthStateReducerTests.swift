import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSHostCore

final class HealthStateReducerTests: XCTestCase {
  private let now = Date(timeIntervalSince1970: 10_000)

  func testNoPropertiesMeansNotInstalled() {
    XCTAssertEqual(
      HealthStateReducer.reduce(
        installationProperties: [],
        runtimeEvidence: nil,
        now: now
      ).protection,
      .notInstalled
    )
  }

  func testEnabledExtensionRequiresAuthenticatedFreshRuntimeForProtection() {
    let snapshot = ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(),
      phase: .enforcing,
      activePolicyRevision: 7,
      activePolicyDigest: String(repeating: "a", count: 64)
    )
    let diagnostic = RuntimeStatusEvidence(
      snapshot: snapshot,
      source: .diagnosticFile,
      receivedAt: now
    )
    let diagnosticState = HealthStateReducer.reduce(
      installationProperties: [enabledProperties()],
      runtimeEvidence: diagnostic,
      now: now
    )
    guard case .degraded = diagnosticState.protection else {
      return XCTFail("Diagnostic status must never establish protection.")
    }

    let authenticated = RuntimeStatusEvidence(
      snapshot: snapshot,
      source: .authenticatedXPC,
      receivedAt: now
    )
    XCTAssertEqual(
      HealthStateReducer.reduce(
        installationProperties: [enabledProperties()],
        runtimeEvidence: authenticated,
        now: now
      ).protection,
      .enforcingOpenEvents(revision: 7)
    )
  }

  func testPolicyWarningDoesNotEraseActiveEnforcement() {
    let snapshot = ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(),
      phase: .enforcing,
      activePolicyRevision: 4,
      policyWarning: "Revision 3 was rejected."
    )
    let state = HealthStateReducer.reduce(
      installationProperties: [enabledProperties()],
      runtimeEvidence: RuntimeStatusEvidence(
        snapshot: snapshot,
        source: .authenticatedXPC,
        receivedAt: now
      ),
      now: now
    )
    XCTAssertEqual(state.protection, .enforcingOpenEvents(revision: 4))
    XCTAssertEqual(state.policyWarning, "Revision 3 was rejected.")
  }

  func testAuthenticatedEmptyPolicySetProducesIdleStateAndCounts() {
    let setIdentifier = UUID()
    let snapshot = ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(),
      phase: .idle,
      activePolicySetIdentifier: setIdentifier,
      activePolicyRevision: 5,
      protectionPolicyCount: 0,
      auditPolicyCount: 0
    )
    let state = HealthStateReducer.reduce(
      installationProperties: [enabledProperties()],
      runtimeEvidence: RuntimeStatusEvidence(
        snapshot: snapshot,
        source: .authenticatedXPC,
        receivedAt: now
      ),
      now: now
    )

    XCTAssertEqual(state.protection, .idle(revision: 5))
    XCTAssertEqual(state.activePolicySetIdentifier, setIdentifier)
    XCTAssertEqual(state.protectionPolicyCount, 0)
    XCTAssertEqual(state.auditPolicyCount, 0)
  }

  func testStaleAuthenticatedRuntimeIsDegraded() {
    let evidence = RuntimeStatusEvidence(
      snapshot: ExtensionStatusSnapshot(
        runtimeInstanceIdentifier: UUID(),
        phase: .enforcing,
        activePolicyRevision: 1
      ),
      source: .authenticatedXPC,
      receivedAt: now.addingTimeInterval(-30)
    )
    let state = HealthStateReducer.reduce(
      installationProperties: [enabledProperties()],
      runtimeEvidence: evidence,
      now: now
    )
    guard case .degraded = state.protection else {
      return XCTFail("Stale runtime status must be degraded.")
    }
  }

  func testActiveReplacementWinsOverOlderUninstallingVersion() {
    var uninstalling = enabledProperties()
    uninstalling.bundleVersion = "2"
    uninstalling.isEnabled = false
    uninstalling.isUninstalling = true
    var active = enabledProperties()
    active.bundleVersion = "3"

    let snapshot = ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(),
      phase: .enforcing,
      activePolicyRevision: 9
    )
    let state = HealthStateReducer.reduce(
      installationProperties: [uninstalling, active],
      runtimeEvidence: RuntimeStatusEvidence(
        snapshot: snapshot,
        source: .authenticatedXPC,
        receivedAt: now
      ),
      now: now
    )

    XCTAssertEqual(state.protection, .enforcingOpenEvents(revision: 9))
  }

  func testPreferredInstallationMatchesReducerPriority() {
    var oldUninstalling = enabledProperties()
    oldUninstalling.bundleVersion = "4"
    oldUninstalling.isUninstalling = true
    var active = enabledProperties()
    active.bundleVersion = "5"

    XCTAssertEqual(
      HealthStateReducer.preferredInstallation(from: [oldUninstalling, active]),
      active
    )
  }

  /// While an update waits for a restart, macOS reports neither version as enabled. The earlier
  /// version still runs, so its authenticated status decides, not the installation states.
  func testUpdateWaitingForRestartFollowsTheRunningExtension() {
    let installations = waitingUpdate()
    let state = HealthStateReducer.reduce(
      installationProperties: installations,
      runtimeEvidence: authenticated(phase: .enforcing, revision: 7),
      now: now
    )
    XCTAssertEqual(state.protection, .enforcingOpenEvents(revision: 7))
    XCTAssertEqual(state.changeAtRestart, .update)
    XCTAssertEqual(state.runtimeEvidenceSource, .authenticatedXPC)
    XCTAssertEqual(state.activePolicyRevision, 7)

    // Without a status, protection is unconfirmed rather than stopped.
    let unanswered = HealthStateReducer.reduce(
      installationProperties: installations, runtimeEvidence: nil, now: now)
    XCTAssertEqual(unanswered.protection, .starting)
    XCTAssertEqual(unanswered.changeAtRestart, .update)
    let diagnostic = HealthStateReducer.reduce(
      installationProperties: installations,
      runtimeEvidence: RuntimeStatusEvidence(
        snapshot: authenticated(phase: .enforcing, revision: 7).snapshot,
        source: .diagnosticFile, receivedAt: now),
      now: now)
    guard case .degraded = diagnostic.protection else {
      return XCTFail("A diagnostic file must not establish protection while an update waits.")
    }
    XCTAssertEqual(diagnostic.changeAtRestart, .update)
  }

  /// A deactivation that waits for a restart leaves the extension running; its status stays.
  func testRemovalWaitingForRestartKeepsTheRunningStatus() {
    var removing = enabledProperties()
    removing.isEnabled = false
    removing.isUninstalling = true

    let answering = HealthStateReducer.reduce(
      installationProperties: [removing],
      runtimeEvidence: authenticated(phase: .enforcing, revision: 3),
      now: now
    )
    XCTAssertEqual(answering.protection, .uninstalling)
    XCTAssertEqual(answering.changeAtRestart, .removal)
    XCTAssertEqual(answering.runtimeEvidenceSource, .authenticatedXPC)
    XCTAssertEqual(answering.activePolicyRevision, 3)

    for evidence in [
      nil,
      authenticated(phase: .enforcing, revision: 3, receivedAt: now.addingTimeInterval(-30)),
      RuntimeStatusEvidence(
        snapshot: authenticated(phase: .enforcing, revision: 3).snapshot,
        source: .diagnosticFile, receivedAt: now),
    ] {
      let state = HealthStateReducer.reduce(
        installationProperties: [removing], runtimeEvidence: evidence, now: now)
      XCTAssertEqual(state, HealthState(protection: .uninstalling))
    }
  }

  /// An extension that answers over the authenticated connection is not stopped, whatever macOS
  /// reports; a stale or unauthenticated status doesn't count.
  func testStoppedOnlyWithoutAFreshAuthenticatedStatus() {
    var disabled = enabledProperties()
    disabled.isEnabled = false

    XCTAssertEqual(
      HealthStateReducer.reduce(
        installationProperties: [disabled],
        runtimeEvidence: authenticated(phase: .monitoring, revision: 2),
        now: now
      ).protection,
      .monitoringOpenEvents(revision: 2))
    for evidence in [
      nil,
      authenticated(phase: .enforcing, revision: 2, receivedAt: now.addingTimeInterval(-30)),
      RuntimeStatusEvidence(
        snapshot: authenticated(phase: .enforcing, revision: 2).snapshot,
        source: .diagnosticFile, receivedAt: now),
    ] {
      XCTAssertEqual(
        HealthStateReducer.reduce(
          installationProperties: [disabled], runtimeEvidence: evidence, now: now
        ).protection,
        .stopped)
    }
  }

  func testUpdateWaitingForRestartNeedsANewerVersionBesideARemovedOlderOne() {
    let installations = waitingUpdate()
    let waiting = ExtensionUpdateAwaitingRestart(installations: installations)
    XCTAssertEqual(waiting?.next.bundleVersion, "3")
    XCTAssertEqual(waiting?.replaced.bundleVersion, "2")

    // Two earlier versions being removed: the newest one is the one replaced.
    var oldest = installations[0]
    oldest.bundleVersion = "1"
    XCTAssertEqual(
      ExtensionUpdateAwaitingRestart(installations: [oldest] + installations)?.replaced
        .bundleVersion, "2")

    // An update that replaced the running version at once, as without the reboot key.
    var replaced = installations[0]
    replaced.bundleVersion = "1"
    var active = enabledProperties()
    active.bundleVersion = "2"
    XCTAssertNil(ExtensionUpdateAwaitingRestart(installations: [replaced, active]))

    // A deactivation, an approval and a newer version being removed are not updates.
    XCTAssertNil(ExtensionUpdateAwaitingRestart(installations: [installations[0]]))
    var approval = installations[1]
    approval.isAwaitingUserApproval = true
    XCTAssertNil(ExtensionUpdateAwaitingRestart(installations: [installations[0], approval]))
    var newerRemoved = installations[0]
    newerRemoved.bundleVersion = "4"
    XCTAssertNil(ExtensionUpdateAwaitingRestart(installations: [newerRemoved, installations[1]]))
    var enabledNew = installations[1]
    enabledNew.isEnabled = true
    XCTAssertNil(ExtensionUpdateAwaitingRestart(installations: [installations[0], enabledNew]))

    // Another bundle identifier is ignored.
    var other = installations[1]
    other.bundleIdentifier = "com.example.other"
    XCTAssertNil(ExtensionUpdateAwaitingRestart(installations: [installations[0], other]))
  }

  /// Before macOS reports the installations, or while it doesn't answer, an extension that answers
  /// over the authenticated connection still shows its state; without one, the state says that
  /// macOS hasn't reported the installation, not that the extension isn't installed.
  func testUnreportedInstallationsShowTheAnsweringExtension() {
    XCTAssertEqual(
      HealthStateReducer.reduce(
        installationProperties: nil,
        runtimeEvidence: authenticated(phase: .enforcing, revision: 3), now: now
      ).protection,
      .enforcingOpenEvents(revision: 3))

    let unreported = ProtectionState.degraded(
      reason: HealthStateReducer.installationStatesUnreportedReason)
    XCTAssertEqual(
      HealthStateReducer.reduce(installationProperties: nil, runtimeEvidence: nil, now: now)
        .protection,
      unreported)
    // A stale status and the diagnostic file don't show that the extension runs.
    let stale = authenticated(
      phase: .enforcing, revision: 3, receivedAt: now.addingTimeInterval(-60))
    XCTAssertEqual(
      HealthStateReducer.reduce(installationProperties: nil, runtimeEvidence: stale, now: now)
        .protection,
      unreported)
    let diagnostic = RuntimeStatusEvidence(
      snapshot: ExtensionStatusSnapshot(
        runtimeInstanceIdentifier: UUID(), phase: .enforcing, activePolicyRevision: 3),
      source: .diagnosticFile, receivedAt: now)
    let fileOnly = HealthStateReducer.reduce(
      installationProperties: nil, runtimeEvidence: diagnostic, now: now)
    XCTAssertEqual(fileOnly.protection, unreported)
    XCTAssertEqual(fileOnly.runtimeEvidenceSource, .diagnosticFile)
  }

  /// The installation states macOS reports while an update from one extension version to the
  /// next waits for a restart: the earlier version is being removed, and the new one is neither
  /// enabled nor being removed.
  private func waitingUpdate() -> [ExtensionInstallationProperties] {
    var running = enabledProperties()
    running.bundleVersion = "2"
    running.isEnabled = false
    running.isUninstalling = true
    var next = enabledProperties()
    next.bundleVersion = "3"
    next.isEnabled = false
    return [running, next]
  }

  private func authenticated(
    phase: ExtensionRuntimePhase, revision: UInt64, receivedAt: Date? = nil
  ) -> RuntimeStatusEvidence {
    RuntimeStatusEvidence(
      snapshot: ExtensionStatusSnapshot(
        runtimeInstanceIdentifier: UUID(), phase: phase, activePolicyRevision: revision),
      source: .authenticatedXPC,
      receivedAt: receivedAt ?? now
    )
  }

  private func enabledProperties() -> ExtensionInstallationProperties {
    ExtensionInstallationProperties(
      bundleIdentifier: ActivationController.extensionIdentifier,
      bundleVersion: "2",
      bundleShortVersion: "0.2",
      isEnabled: true,
      isAwaitingUserApproval: false,
      isUninstalling: false
    )
  }
}
