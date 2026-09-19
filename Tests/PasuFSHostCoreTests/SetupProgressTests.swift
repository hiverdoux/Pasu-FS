import XCTest

@testable import PasuFSHostCore

final class SetupProgressTests: XCTestCase {
  private func health(
    _ protection: ProtectionState,
    revision: UInt64? = nil,
    source: RuntimeEvidenceSource? = nil
  ) -> HealthState {
    HealthState(
      protection: protection,
      activePolicyRevision: revision,
      runtimeEvidenceSource: source
    )
  }

  func testInstallationStatesShowOnboarding() {
    XCTAssertTrue(
      SetupProgress.showsOnboarding(health(.notInstalled), hasEverSeenActivePolicy: false)
    )
    XCTAssertTrue(
      SetupProgress.showsOnboarding(health(.waitingForApproval), hasEverSeenActivePolicy: true)
    )
    XCTAssertTrue(
      SetupProgress.showsOnboarding(
        health(.waitingForFullDiskAccess),
        hasEverSeenActivePolicy: true
      )
    )
  }

  func testStartingShowsOnboardingOnlyBeforeAnyPolicyWasSeen() {
    XCTAssertTrue(
      SetupProgress.showsOnboarding(health(.starting), hasEverSeenActivePolicy: false)
    )
    XCTAssertFalse(
      SetupProgress.showsOnboarding(health(.starting), hasEverSeenActivePolicy: true)
    )
  }

  func testOnlyAuthenticatedNoPolicyDegradedStateCountsAsFirstPolicySetup() {
    let awaiting = health(
      .degraded(reason: SetupProgress.awaitingFirstPolicyReason),
      source: .authenticatedXPC
    )
    XCTAssertTrue(SetupProgress.isAwaitingFirstPolicy(awaiting))
    XCTAssertTrue(SetupProgress.showsOnboarding(awaiting, hasEverSeenActivePolicy: false))
    XCTAssertFalse(SetupProgress.showsOnboarding(awaiting, hasEverSeenActivePolicy: true))

    let staleDegraded = health(
      .degraded(reason: "Authenticated runtime status is stale."),
      source: .authenticatedXPC
    )
    XCTAssertFalse(SetupProgress.isAwaitingFirstPolicy(staleDegraded))
    XCTAssertFalse(
      SetupProgress.showsOnboarding(staleDegraded, hasEverSeenActivePolicy: false)
    )

    let diagnosticOnly = health(
      .degraded(reason: SetupProgress.awaitingFirstPolicyReason),
      source: .diagnosticFile
    )
    XCTAssertFalse(SetupProgress.isAwaitingFirstPolicy(diagnosticOnly))
  }

  func testConfiguredStatesNeverShowOnboarding() {
    XCTAssertFalse(
      SetupProgress.showsOnboarding(
        health(.idle(revision: 3), revision: 3),
        hasEverSeenActivePolicy: false
      )
    )
    XCTAssertFalse(
      SetupProgress.showsOnboarding(
        health(.enforcingOpenEvents(revision: 3), revision: 3),
        hasEverSeenActivePolicy: false
      )
    )
    XCTAssertFalse(
      SetupProgress.showsOnboarding(
        health(.monitoringOpenEvents(revision: 3), revision: 3),
        hasEverSeenActivePolicy: false
      )
    )
    XCTAssertFalse(
      SetupProgress.showsOnboarding(health(.stopped), hasEverSeenActivePolicy: false)
    )
    XCTAssertFalse(
      SetupProgress.showsOnboarding(health(.uninstalling), hasEverSeenActivePolicy: false)
    )
  }

  func testStepStatesFollowTheProtectionState() {
    XCTAssertEqual(
      SetupProgress.stepStates(health(.notInstalled)),
      SetupStepStates(
        activateExtension: .active,
        approveExtension: .pending,
        grantFullDiskAccess: .pending,
        configurePolicy: .pending
      )
    )
    XCTAssertEqual(
      SetupProgress.stepStates(health(.waitingForApproval)),
      SetupStepStates(
        activateExtension: .done,
        approveExtension: .active,
        grantFullDiskAccess: .pending,
        configurePolicy: .pending
      )
    )
    XCTAssertEqual(
      SetupProgress.stepStates(health(.waitingForFullDiskAccess)),
      SetupStepStates(
        activateExtension: .done,
        approveExtension: .done,
        grantFullDiskAccess: .active,
        configurePolicy: .pending
      )
    )
    XCTAssertEqual(
      SetupProgress.stepStates(
        health(
          .degraded(reason: SetupProgress.awaitingFirstPolicyReason),
          source: .authenticatedXPC
        )
      ),
      SetupStepStates(
        activateExtension: .done,
        approveExtension: .done,
        grantFullDiskAccess: .done,
        configurePolicy: .active
      )
    )
    XCTAssertEqual(
      SetupProgress.stepStates(health(.enforcingOpenEvents(revision: 7), revision: 7)),
      SetupStepStates(
        activateExtension: .done,
        approveExtension: .done,
        grantFullDiskAccess: .done,
        configurePolicy: .done
      )
    )
    XCTAssertEqual(
      SetupProgress.stepStates(health(.idle(revision: 8), revision: 8)),
      SetupStepStates(
        activateExtension: .done,
        approveExtension: .done,
        grantFullDiskAccess: .done,
        configurePolicy: .done
      )
    )
  }
}
