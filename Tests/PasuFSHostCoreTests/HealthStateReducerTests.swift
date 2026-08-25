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
