import Foundation

public enum SetupStepState: Equatable, Sendable {
  case done
  case active
  case pending
}

public struct SetupStepStates: Equatable, Sendable {
  public var activateExtension: SetupStepState
  public var approveExtension: SetupStepState
  public var grantFullDiskAccess: SetupStepState
  public var configurePolicy: SetupStepState

  public init(
    activateExtension: SetupStepState,
    approveExtension: SetupStepState,
    grantFullDiskAccess: SetupStepState,
    configurePolicy: SetupStepState
  ) {
    self.activateExtension = activateExtension
    self.approveExtension = approveExtension
    self.grantFullDiskAccess = grantFullDiskAccess
    self.configurePolicy = configurePolicy
  }
}

public enum SetupProgress {
  /// The extension's status detail while it runs healthily without an
  /// accepted policy. Must match `ExtensionRuntime`'s literal so onboarding
  /// can distinguish "needs the first policy" from other degraded states.
  public static let awaitingFirstPolicyReason = "No accepted policy set is stored."

  public static func isAwaitingFirstPolicy(_ health: HealthState) -> Bool {
    guard case .degraded(let reason) = health.protection else { return false }
    return reason == awaitingFirstPolicyReason
      && health.runtimeEvidenceSource == .authenticatedXPC
  }

  public static func showsOnboarding(
    _ health: HealthState,
    hasEverSeenActivePolicy: Bool
  ) -> Bool {
    switch health.protection {
    case .notInstalled, .waitingForApproval, .waitingForFullDiskAccess:
      return true
    case .starting:
      return !hasEverSeenActivePolicy
    case .degraded:
      return !hasEverSeenActivePolicy && isAwaitingFirstPolicy(health)
    case .idle, .enforcingOpenEvents, .monitoringOpenEvents, .stopped, .uninstalling:
      return false
    }
  }

  public static func stepStates(_ health: HealthState) -> SetupStepStates {
    switch health.protection {
    case .notInstalled, .uninstalling, .stopped:
      return SetupStepStates(
        activateExtension: .active,
        approveExtension: .pending,
        grantFullDiskAccess: .pending,
        configurePolicy: .pending
      )
    case .waitingForApproval:
      return SetupStepStates(
        activateExtension: .done,
        approveExtension: .active,
        grantFullDiskAccess: .pending,
        configurePolicy: .pending
      )
    case .starting, .waitingForFullDiskAccess:
      return SetupStepStates(
        activateExtension: .done,
        approveExtension: .done,
        grantFullDiskAccess: .active,
        configurePolicy: .pending
      )
    case .degraded:
      return SetupStepStates(
        activateExtension: .done,
        approveExtension: .done,
        grantFullDiskAccess: .done,
        configurePolicy: isAwaitingFirstPolicy(health)
          ? .active
          : (health.activePolicyRevision == nil ? .pending : .done)
      )
    case .idle, .enforcingOpenEvents, .monitoringOpenEvents:
      return SetupStepStates(
        activateExtension: .done,
        approveExtension: .done,
        grantFullDiskAccess: .done,
        configurePolicy: .done
      )
    }
  }
}
