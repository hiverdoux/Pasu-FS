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

/// A change to the extension that macOS finishes at the next restart.
public enum ExtensionChangeAtRestart: Equatable, Sendable {
  /// A newer version starts at the next restart (see `ExtensionUpdateAwaitingRestart`).
  case update
  /// macOS removes the extension at the next restart, and the extension still answers over the
  /// authenticated connection, so it keeps checking requests until then.
  case removal
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
  public var changeAtRestart: ExtensionChangeAtRestart?

  public init(
    protection: ProtectionState,
    activePolicySetIdentifier: UUID? = nil,
    activePolicyRevision: UInt64? = nil,
    protectionPolicyCount: Int = 0,
    auditPolicyCount: Int = 0,
    policyWarning: String? = nil,
    coveredAuthorizationEvents: [String] = [],
    runtimeEvidenceSource: RuntimeEvidenceSource? = nil,
    changeAtRestart: ExtensionChangeAtRestart? = nil
  ) {
    self.protection = protection
    self.activePolicySetIdentifier = activePolicySetIdentifier
    self.activePolicyRevision = activePolicyRevision
    self.protectionPolicyCount = protectionPolicyCount
    self.auditPolicyCount = auditPolicyCount
    self.policyWarning = policyWarning
    self.coveredAuthorizationEvents = coveredAuthorizationEvents
    self.runtimeEvidenceSource = runtimeEvidenceSource
    self.changeAtRestart = changeAtRestart
  }
}

public enum HealthStateReducer {
  public static let runtimeFreshnessInterval: TimeInterval = 15
  /// The reason while macOS has not reported the installation states and the extension doesn't
  /// answer over the authenticated connection.
  public static let installationStatesUnreportedReason =
    "macOS has not reported the system extension state."

  /// The state from the installations in `installationRecord` while they still describe the Mac
  /// (see `InstallationStateRecord.currentInstallations`). Installations that are out of date, or
  /// older than a failed or unanswered query, count as unreported rather than as the Mac's: they
  /// neither show the extension as not installed nor its removal as complete.
  public static func reduce(
    installationRecord: InstallationStateRecord,
    runtimeEvidence: RuntimeStatusEvidence?,
    now: Date = Date()
  ) -> HealthState {
    reduce(
      installationProperties: installationRecord.currentInstallations(at: now),
      runtimeEvidence: runtimeEvidence, now: now)
  }

  /// - Parameter installationProperties: Installations that macOS reported and that still
  ///   describe the Mac, or nil without such a report. Without them, only an extension that answers
  ///   over the authenticated connection shows a state.
  public static func reduce(
    installationProperties: [ExtensionInstallationProperties]?,
    runtimeEvidence: RuntimeStatusEvidence?,
    now: Date = Date()
  ) -> HealthState {
    guard let installationProperties else {
      if authenticatedFreshEvidence(runtimeEvidence, now: now) != nil {
        return runtimeState(runtimeEvidence, now: now)
      }
      return HealthState(
        protection: .degraded(reason: installationStatesUnreportedReason),
        runtimeEvidenceSource: runtimeEvidence?.source)
    }
    guard let installed = preferredInstallation(from: installationProperties) else {
      return HealthState(protection: .notInstalled)
    }
    if installed.isAwaitingUserApproval {
      return HealthState(protection: .waitingForApproval)
    }
    // macOS reports no version as enabled while an update waits for a restart. The earlier
    // version keeps running, so its status decides, as for an enabled installation.
    if ExtensionUpdateAwaitingRestart(installations: installationProperties) != nil {
      var state = runtimeState(runtimeEvidence, now: now)
      state.changeAtRestart = .update
      return state
    }
    let answering = authenticatedFreshEvidence(runtimeEvidence, now: now)
    if installed.isUninstalling {
      guard answering != nil else { return HealthState(protection: .uninstalling) }
      var state = runtimeState(runtimeEvidence, now: now)
      state.protection = .uninstalling
      state.changeAtRestart = .removal
      return state
    }
    // An extension that answers over the authenticated connection runs, whatever macOS reports.
    guard installed.isEnabled || answering != nil else {
      return HealthState(protection: .stopped)
    }
    return runtimeState(runtimeEvidence, now: now)
  }

  /// The evidence when it came over the authenticated connection within the freshness interval.
  private static func authenticatedFreshEvidence(
    _ evidence: RuntimeStatusEvidence?, now: Date
  ) -> RuntimeStatusEvidence? {
    guard let evidence, evidence.source == .authenticatedXPC else { return nil }
    let age = now.timeIntervalSince(evidence.receivedAt)
    return age >= 0 && age <= runtimeFreshnessInterval ? evidence : nil
  }

  /// The state of a running extension, from its status.
  private static func runtimeState(
    _ runtimeEvidence: RuntimeStatusEvidence?, now: Date
  ) -> HealthState {
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
