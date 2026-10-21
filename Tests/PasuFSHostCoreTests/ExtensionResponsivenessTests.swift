import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSHostCore

final class ExtensionResponsivenessTests: XCTestCase {
  private let now = Date(timeIntervalSince1970: 1_800_000_000)

  func testStatusFileOlderThanThirtySecondsAfterAFailedConnection() {
    for age in [30.0, 45, 600] {
      let written = now.addingTimeInterval(-age)
      XCTAssertEqual(
        lastStatus(installation: installation(), evidence: fileEvidence(writtenAt: written)),
        written, "\(age)")
      XCTAssertEqual(
        lastStatus(
          installation: installation(), evidence: fileEvidence(writtenAt: written),
          timedOut: true),
        written, "\(age)")
    }
  }

  func testRecentStatusFileIsNotUnresponsive() {
    // The connection can fail for other reasons while the extension keeps writing its status.
    for age in [0.0, 5, 29.9] {
      XCTAssertNil(
        lastStatus(
          installation: installation(),
          evidence: fileEvidence(writtenAt: now.addingTimeInterval(-age)), timedOut: true),
        "\(age)")
    }
    // A timestamp from the future is not old.
    XCTAssertNil(
      lastStatus(
        installation: installation(), evidence: fileEvidence(writtenAt: now.addingTimeInterval(60))
      ))
  }

  func testAnsweringExtensionIsNotUnresponsive() {
    // An authenticated status that has grown old is a stale check, not a stuck extension.
    let old = now.addingTimeInterval(-120)
    let evidence = RuntimeStatusEvidence(
      snapshot: ExtensionStatusSnapshot(
        runtimeInstanceIdentifier: UUID(), phase: .enforcing, activePolicyRevision: 1,
        timestamp: old),
      source: .authenticatedXPC, receivedAt: old)
    XCTAssertNil(lastStatus(installation: installation(), evidence: evidence, timedOut: true))
    XCTAssertNil(lastStatus(installation: installation(), evidence: nil, timedOut: true))
  }

  func testExtensionThatStoppedNormallyIsNotUnresponsive() {
    let old = fileEvidence(writtenAt: now.addingTimeInterval(-120), phase: .stopped)
    XCTAssertNil(lastStatus(installation: installation(), evidence: old, timedOut: true))
    XCTAssertNil(lastStatus(installation: nil, evidence: old, timedOut: true))
  }

  /// Unless macOS reports an enabled installation, an old status file counts only after a
  /// request timed out, which shows that a process still holds the extension's service.
  func testInstallationThatIsNotEnabledCountsOnlyAfterATimeout() {
    let written = now.addingTimeInterval(-120)
    let old = fileEvidence(writtenAt: written)
    for installation in [
      installation(isEnabled: false), installation(isAwaitingUserApproval: true),
      installation(isUninstalling: true), installation(isEnabled: false, isUninstalling: true),
    ] {
      XCTAssertNil(lastStatus(installation: installation, evidence: old, timedOut: false))
      XCTAssertEqual(lastStatus(installation: installation, evidence: old, timedOut: true), written)
    }
  }

  /// With NSEndpointSecurityRebootRequired, an update or a deactivation waits for a restart and
  /// the earlier extension keeps running, although macOS reports no version as enabled.
  func testEarlierExtensionThatStopsAnsweringWhileAChangeWaitsForARestart() {
    let written = now.addingTimeInterval(-120)
    let old = fileEvidence(writtenAt: written)
    let update = [
      installation(version: "1", isEnabled: false, isUninstalling: true),
      installation(version: "2", isEnabled: false),
    ]
    XCTAssertNotNil(ExtensionUpdateAwaitingRestart(installations: update))
    let removal = [installation(version: "2", isEnabled: false, isUninstalling: true)]
    for (label, installations) in [("update", update), ("removal", removal)] {
      // The app passes the installation it prefers among those macOS reports.
      let preferred = HealthStateReducer.preferredInstallation(from: installations)
      XCTAssertEqual(
        lastStatus(installation: preferred, evidence: old, timedOut: true), written, label)
      // The connection fails at once when the earlier extension has stopped.
      XCTAssertNil(lastStatus(installation: preferred, evidence: old, timedOut: false), label)
      XCTAssertNil(
        lastStatus(
          installation: preferred, evidence: fileEvidence(writtenAt: now.addingTimeInterval(-10)),
          timedOut: true), label)
      XCTAssertNil(
        lastStatus(
          installation: preferred, evidence: fileEvidence(writtenAt: written, phase: .stopped),
          timedOut: true), label)
    }
  }

  /// Without an installation, an old status file is a leftover unless a process holds the
  /// extension's service without answering.
  func testWithoutAnInstallationOnlyATimeoutCounts() {
    let written = now.addingTimeInterval(-120)
    let old = fileEvidence(writtenAt: written)
    XCTAssertNil(lastStatus(installation: nil, evidence: old, timedOut: false))
    XCTAssertEqual(lastStatus(installation: nil, evidence: old, timedOut: true), written)
  }

  private func lastStatus(
    installation: ExtensionInstallationProperties?, evidence: RuntimeStatusEvidence?,
    timedOut: Bool = false
  ) -> Date? {
    ExtensionResponsiveness.lastStatusOfUnresponsiveExtension(
      installation: installation, evidence: evidence, requestTimedOutSinceLastAnswer: timedOut,
      now: now)
  }

  /// The status the app reads from the diagnostic file after the connection failed.
  private func fileEvidence(
    writtenAt timestamp: Date, phase: ExtensionRuntimePhase = .enforcing
  ) -> RuntimeStatusEvidence {
    RuntimeStatusEvidence(
      snapshot: ExtensionStatusSnapshot(
        runtimeInstanceIdentifier: UUID(), phase: phase, activePolicyRevision: 1,
        timestamp: timestamp),
      source: .diagnosticFile, receivedAt: timestamp)
  }

  private func installation(
    version: String = "1", isEnabled: Bool = true, isAwaitingUserApproval: Bool = false,
    isUninstalling: Bool = false
  ) -> ExtensionInstallationProperties {
    ExtensionInstallationProperties(
      bundleIdentifier: ActivationController.extensionIdentifier, bundleVersion: version,
      bundleShortVersion: "0.9.0", isEnabled: isEnabled,
      isAwaitingUserApproval: isAwaitingUserApproval, isUninstalling: isUninstalling)
  }
}
