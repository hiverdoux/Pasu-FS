import Foundation
import PasuFSConfiguration

public enum RuntimeEvidenceSource: String, Equatable, Sendable {
  case authenticatedXPC
  case diagnosticFile
}

public struct RuntimeStatusEvidence: Equatable, Sendable {
  public var snapshot: ExtensionStatusSnapshot
  public var source: RuntimeEvidenceSource
  public var receivedAt: Date

  public init(
    snapshot: ExtensionStatusSnapshot,
    source: RuntimeEvidenceSource,
    receivedAt: Date = Date()
  ) {
    self.snapshot = snapshot
    self.source = source
    self.receivedAt = receivedAt
  }
}

public enum ProtectionState: Equatable, Sendable {
  case notInstalled
  case waitingForApproval
  case uninstalling
  case stopped
  case starting
  case waitingForFullDiskAccess
  case idle(revision: UInt64)
  case enforcingOpenEvents(revision: UInt64)
  case monitoringOpenEvents(revision: UInt64)
  case degraded(reason: String)
}

public struct HealthState: Equatable, Sendable {
  public var protection: ProtectionState
  public var activePolicySetIdentifier: UUID?
  public var activePolicyRevision: UInt64?
  public var protectionPolicyCount: Int
  public var auditPolicyCount: Int
  public var policyWarning: String?
  public var coveredAuthorizationEvents: [String]
  public var runtimeEvidenceSource: RuntimeEvidenceSource?

  public init(
    protection: ProtectionState,
    activePolicySetIdentifier: UUID? = nil,
    activePolicyRevision: UInt64? = nil,
    protectionPolicyCount: Int = 0,
    auditPolicyCount: Int = 0,
    policyWarning: String? = nil,
    coveredAuthorizationEvents: [String] = [],
    runtimeEvidenceSource: RuntimeEvidenceSource? = nil
  ) {
    self.protection = protection
    self.activePolicySetIdentifier = activePolicySetIdentifier
    self.activePolicyRevision = activePolicyRevision
    self.protectionPolicyCount = protectionPolicyCount
    self.auditPolicyCount = auditPolicyCount
    self.policyWarning = policyWarning
    self.coveredAuthorizationEvents = coveredAuthorizationEvents
    self.runtimeEvidenceSource = runtimeEvidenceSource
  }
}

public enum HealthStateReducer {
  public static let runtimeFreshnessInterval: TimeInterval = 15

  public static func reduce(
    installationProperties: [ExtensionInstallationProperties],
    runtimeEvidence: RuntimeStatusEvidence?,
    now: Date = Date()
  ) -> HealthState {
    guard let installed = preferredInstallation(from: installationProperties) else {
      return HealthState(protection: .notInstalled)
    }
    if installed.isAwaitingUserApproval {
      return HealthState(protection: .waitingForApproval)
    }
    if installed.isUninstalling {
      return HealthState(protection: .uninstalling)
    }
    guard installed.isEnabled else {
      return HealthState(protection: .stopped)
    }
    guard let runtimeEvidence else {
      return HealthState(protection: .starting)
    }

    let age = now.timeIntervalSince(runtimeEvidence.receivedAt)
    guard age >= 0, age <= runtimeFreshnessInterval else {
      return HealthState(
        protection: .degraded(reason: "Authenticated runtime status is stale."),
        runtimeEvidenceSource: runtimeEvidence.source
      )
    }
    guard runtimeEvidence.source == .authenticatedXPC else {
      return HealthState(
        protection: .degraded(
          reason: "Only an unauthenticated diagnostic status file is available."
        ),
        activePolicySetIdentifier: runtimeEvidence.snapshot.activePolicySetIdentifier,
        activePolicyRevision: runtimeEvidence.snapshot.activePolicyRevision,
        protectionPolicyCount: runtimeEvidence.snapshot.protectionPolicyCount,
        auditPolicyCount: runtimeEvidence.snapshot.auditPolicyCount,
        policyWarning: runtimeEvidence.snapshot.policyWarning,
        coveredAuthorizationEvents: runtimeEvidence.snapshot.coveredAuthorizationEvents,
        runtimeEvidenceSource: runtimeEvidence.source
      )
    }

    let snapshot = runtimeEvidence.snapshot
    let base = HealthState(
      protection: .starting,
      activePolicySetIdentifier: snapshot.activePolicySetIdentifier,
      activePolicyRevision: snapshot.activePolicyRevision,
      protectionPolicyCount: snapshot.protectionPolicyCount,
      auditPolicyCount: snapshot.auditPolicyCount,
      policyWarning: snapshot.policyWarning,
      coveredAuthorizationEvents: snapshot.coveredAuthorizationEvents,
      runtimeEvidenceSource: runtimeEvidence.source
    )
    switch snapshot.phase {
    case .starting:
      return replacingProtection(in: base, with: .starting)
    case .waitingForFullDiskAccess:
      return replacingProtection(in: base, with: .waitingForFullDiskAccess)
    case .idle:
      guard let revision = snapshot.activePolicyRevision else {
        return replacingProtection(
          in: base,
          with: .degraded(reason: "The extension reported idle without a policy-set revision.")
        )
      }
      return replacingProtection(in: base, with: .idle(revision: revision))
    case .enforcing:
      guard let revision = snapshot.activePolicyRevision else {
        return replacingProtection(
          in: base,
          with: .degraded(reason: "The extension reported enforcement without a policy revision.")
        )
      }
      return replacingProtection(in: base, with: .enforcingOpenEvents(revision: revision))
    case .monitoring:
      guard let revision = snapshot.activePolicyRevision else {
        return replacingProtection(
          in: base,
          with: .degraded(reason: "The extension reported monitoring without a policy revision.")
        )
      }
      return replacingProtection(in: base, with: .monitoringOpenEvents(revision: revision))
    case .degraded:
      return replacingProtection(
        in: base,
        with: .degraded(reason: snapshot.detail ?? "The extension is degraded.")
      )
    case .stopped:
      return replacingProtection(in: base, with: .stopped)
    }
  }

  private static func replacingProtection(
    in state: HealthState,
    with protection: ProtectionState
  ) -> HealthState {
    var state = state
    state.protection = protection
    return state
  }

  public static func preferredInstallation(
    from properties: [ExtensionInstallationProperties]
  ) -> ExtensionInstallationProperties? {
    properties.max(by: {
      installationPriority($0) < installationPriority($1)
    })
  }

  private static func installationPriority(
    _ properties: ExtensionInstallationProperties
  ) -> (Int, Int) {
    let statePriority: Int
    if properties.isEnabled && !properties.isUninstalling {
      statePriority = 4
    } else if properties.isAwaitingUserApproval && !properties.isUninstalling {
      statePriority = 3
    } else if !properties.isUninstalling {
      statePriority = 2
    } else {
      statePriority = 1
    }
    return (statePriority, Int(properties.bundleVersion) ?? 0)
  }
}
