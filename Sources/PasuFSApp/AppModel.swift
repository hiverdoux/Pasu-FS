import AppKit
import Foundation
import Observation
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSMaintenanceCore

enum SidebarSelection: Hashable {
  case protection
  case auditLog
  case policy(UUID)
}

struct AuditRuleCandidate: Identifiable, Equatable {
  let id: String
  let kind: PolicyRuleKind
  let teamIdentifier: String?
  let signingIdentifier: String
  let displayName: String
  let executablePath: String?
  let lastSeen: Date
  let observationCount: Int
  let latestResult: String
}

struct SystemCompatibilityAuditCandidate: Identifiable, Equatable {
  let policyIdentifier: UUID
  let policyName: String
  let policyMode: PolicyMode
  let signingIdentifier: String
  let operatingSystemBuild: String
  let displayName: String
  let executablePath: String?
  let observationCount: Int
  let firstSeen: Date
  let lastSeen: Date
  let requestedFlagValues: [UInt32]
  let requestedFlagUnion: UInt32
  let codeSigningFlagValues: [UInt32]
  let targetPathSamples: [String]
  let uniqueTargetPathCount: Int
  let incompleteObservationCount: Int

  var id: String {
    "\(policyIdentifier.uuidString):\(operatingSystemBuild):\(signingIdentifier)"
  }

  var hasCompleteEvidence: Bool {
    incompleteObservationCount == 0
      && !requestedFlagValues.isEmpty
      && !codeSigningFlagValues.isEmpty
      && uniqueTargetPathCount > 0
  }
}

struct SystemCompatibilityProfileItem: Identifiable, Equatable {
  let profile: SystemCompatibilityProfile
  let state: SystemCompatibilityProfileState
  let isEnabled: Bool

  var id: String { profile.id }
}

private struct SystemCompatibilitySettingsCandidate {
  var document: SystemCompatibilitySettingsDocument
  var removedObsoleteItemCount: Int
}

@Observable
@MainActor
final class AppModel {
  var health = HealthState(protection: .starting)
  var auditBatch = AuditLogBatch(records: [])
  var auditFilterText = ""
  private(set) var policyLogs: [PolicyAuditLogKey: PolicyLogState] = [:]
  var selectedSection: SidebarSelection = .protection
  var lastError: String?
  var operationMessage: String?
  var isBusy = false
  private(set) var loginItemState: LoginItemState
  private(set) var loginItemError: String?
  private(set) var isChangingLoginItem = false
  private(set) var isStoppingProtectionForQuit = false
  private(set) var isUninstalling = false
  private(set) var isFinalizingUninstall = false
  private var hasRequestedUninstallTermination = false
  var isPresentingUninstall = false
  private(set) var pendingUninstall: UninstallState?
  private(set) var uninstallStateError: String?

  private(set) var activePolicySet: PolicySetDocument?
  private(set) var latestEvidence: RuntimeStatusEvidence?
  private(set) var installation: ExtensionInstallationProperties?
  private(set) var policySynchronizationWarning: String?
  private(set) var systemCompatibilityState: SystemCompatibilityStateSnapshot?
  private(set) var systemCompatibilitySynchronizationWarning: String?
  private(set) var hasEverSeenActivePolicySet = false
  private(set) var policyDrafts: [UUID: DirectoryPolicyDraft] = [:]
  private(set) var policyOrder: [UUID] = []

  private var hasChosenFirstPolicySetup = false
  private let activationController: any ExtensionLifecycleControlling
  private let controlClient: any ExtensionRuntimeControlling
  private let loginItemController: any LoginItemControlling
  private let embeddedSystemExtensionBuildVersion: String?
  private let appProductVersion: ProductVersion
  private let includedExtensionVersion: ProductVersion
  private let systemCompatibilityCatalog: SystemCompatibilityCatalog
  private let systemCompatibilityCatalogDigest: String
  private let diagnosticStatusReader = DiagnosticStatusReader()
  private var pendingSetIdentifier = UUID()
  private var acceptedRevision: UInt64 = 0
  private var pollingTask: Task<Void, Never>?
  private var installationProperties: [ExtensionInstallationProperties] = []
  private var hasFetchedInstallationProperties = false
  private var installationPropertiesObservedAt: Date?
  private var installationPropertiesError: String?
  private var isRequestingActivation = false
  private var activationProgress: String?
  private var activationOutcome: LifecycleRequestOutcome?
  private var automaticExtensionUpdateCheck = AutomaticExtensionUpdateCheck()
  private let maintenanceClient: any MaintenanceControlling
  private let uninstallAuthorizer: any UninstallAuthorizing
  private let readUninstallState: @MainActor () throws -> UninstallState?

  init(
    hostBundleURL: URL = Bundle.main.bundleURL,
    initialPolicySet: PolicySetDocument? = nil,
    systemCompatibilityCatalog: SystemCompatibilityCatalog =
      BuiltInSystemCompatibilityCatalog.catalog,
    activationController: any ExtensionLifecycleControlling = ActivationController(),
    runtimeController: (any ExtensionRuntimeControlling)? = nil,
    loginItemController: any LoginItemControlling = MainAppLoginItemController(),
    embeddedVersionProvider: any EmbeddedSystemExtensionVersionProviding =
      BundleEmbeddedSystemExtensionVersionProvider(),
    maintenanceClient: (any MaintenanceControlling)? = nil,
    uninstallAuthorizer: any UninstallAuthorizing = SystemUninstallAuthorizer(),
    uninstallStateReader: (@MainActor () throws -> UninstallState?)? = nil
  ) {
    self.maintenanceClient = maintenanceClient ?? MaintenanceClient(hostBundleURL: hostBundleURL)
    self.uninstallAuthorizer = uninstallAuthorizer
    self.readUninstallState =
      uninstallStateReader ?? {
        guard hostBundleURL.path == MaintenanceContract.appPath else { return nil }
        return try UninstallStateStore().read()
      }
    do { pendingUninstall = try self.readUninstallState() } catch {
      uninstallStateError = String(describing: error)
    }
    self.activationController = activationController
    appProductVersion = ProductVersion(bundleURL: hostBundleURL)
    includedExtensionVersion = ProductVersion(
      bundleURL: hostBundleURL.appendingPathComponent(
        "Contents/Library/SystemExtensions/\(ActivationController.extensionIdentifier).systemextension"
      )
    )
    self.loginItemController = loginItemController
    loginItemState = loginItemController.state
    embeddedSystemExtensionBuildVersion =
      embeddedVersionProvider.buildVersion(in: hostBundleURL)
    self.systemCompatibilityCatalog = systemCompatibilityCatalog
    self.systemCompatibilityCatalogDigest =
      (try? systemCompatibilityCatalog.catalogDigest()) ?? ""
    if let runtimeController {
      controlClient = runtimeController
    } else {
      controlClient = ExtensionControlClient(
        hostBundleURL: hostBundleURL,
        systemCompatibilityCatalog: systemCompatibilityCatalog
      )
    }
    if let initialPolicySet {
      installActivePolicySet(initialPolicySet)
    }
  }

  // MARK: - Health presentation

  var menuBarSymbolName: String {
    switch health.protection {
    case .enforcingOpenEvents: "lock.shield.fill"
    case .monitoringOpenEvents: "eye.fill"
    case .waitingForApproval, .waitingForFullDiskAccess, .starting: "hourglass"
    case .degraded: "exclamationmark.shield.fill"
    case .idle, .notInstalled, .stopped, .uninstalling: "lock.shield"
    }
  }

  var healthTitle: String {
    switch health.protection {
    case .notInstalled: "Not installed"
    case .waitingForApproval: "Waiting for system-extension approval"
    case .uninstalling: "Uninstalling"
    case .stopped: "Stopped"
    case .starting: "Starting"
    case .waitingForFullDiskAccess: "Waiting for Full Disk Access"
    case .idle: "No policies configured"
    case .enforcingOpenEvents: "Enforcing Protection policies"
    case .monitoringOpenEvents: "Monitoring Audit policies"
    case .degraded: "Degraded"
    }
  }

  var healthDetail: String {
    switch health.protection {
    case .degraded(let reason): reason
    case .enforcingOpenEvents:
      "A supported open must pass every matching Protection policy."
    case .monitoringOpenEvents:
      "Audit policies record hypothetical results but never deny a kernel request."
    case .idle:
      "No path is currently protected or audited."
    case .waitingForFullDiskAccess:
      "Grant Full Disk Access to the Pasu FS Endpoint Security extension in System Settings."
    case .notInstalled:
      "Activate the Endpoint Security system extension to begin setup."
    case .stopped:
      "The extension is installed but not active."
    case .waitingForApproval:
      "Approve the extension in System Settings."
    case .uninstalling:
      "Removal may require a restart before enforcement stops."
    case .starting:
      "Waiting for authenticated runtime readiness."
    }
  }

  var healthSubtitle: String {
    var parts: [String] = []
    switch health.protection {
    case .idle(let revision), .enforcingOpenEvents(let revision),
      .monitoringOpenEvents(let revision):
      parts.append("Policy-set revision \(revision)")
    default:
      break
    }
    if health.protectionPolicyCount > 0 || health.auditPolicyCount > 0 {
      parts.append(
        "\(health.protectionPolicyCount) Protection · \(health.auditPolicyCount) Audit"
      )
    }
    switch health.runtimeEvidenceSource {
    case .authenticatedXPC: parts.append("Authenticated XPC")
    case .diagnosticFile: parts.append("Diagnostic file only")
    case nil: break
    }
    if let age = evidenceAgeDescription {
      parts.append(age)
    }
    return parts.isEmpty ? healthDetail : parts.joined(separator: " · ")
  }

  var evidenceAgeDescription: String? {
    guard let latestEvidence else { return nil }
    let age = max(0, Date().timeIntervalSince(latestEvidence.receivedAt))
    return "updated \(Int(age.rounded())) s ago"
  }

  var coveredEventsDescription: String {
    let events = health.coveredAuthorizationEvents
    return events.isEmpty ? "None reported yet" : events.joined(separator: ", ")
  }

  var runtimeEvidenceDescription: String {
    switch health.runtimeEvidenceSource {
    case .authenticatedXPC:
      "Authenticated XPC (\(Int(HealthStateReducer.runtimeFreshnessInterval)) s freshness window)"
    case .diagnosticFile:
      "Diagnostic status file only — cannot establish protection"
    case nil:
      "No runtime evidence"
    }
  }

  var installationSummary: String {
    guard let installation else { return "Not installed" }
    let state =
      installation.isUninstalling
      ? "Uninstalling"
      : installation.isAwaitingUserApproval
        ? "Awaiting approval"
        : installation.isEnabled ? "Enabled" : "Not enabled"
    return "\(state) · \(installation.bundleIdentifier)"
  }

  func extensionVersionOverview(now: Date) -> ExtensionVersionOverview {
    ExtensionVersionOverview(
      app: appProductVersion, included: includedExtensionVersion,
      installations: installationProperties, observedAt: installationPropertiesObservedAt,
      queryError: installationPropertiesError, isRequestingActivation: isRequestingActivation,
      activationProgress: activationProgress, activationOutcome: activationOutcome, now: now
    )
  }

  var auditDeliveryMetrics: AuditDeliveryMetrics? { latestEvidence?.snapshot.auditDelivery }
  var authorizationMetrics: AuthorizationMetrics? { latestEvidence?.snapshot.authorization }
  var processLineageStatus: ProcessLineageStatus? { latestEvidence?.snapshot.processLineageStatus }

  var droppedAuditEventCount: UInt64 {
    latestEvidence?.snapshot.droppedAuditEventCount ?? 0
  }

  var menuBarPolicySummary: String {
    guard let activePolicySet else { return "No accepted policy set" }
    let protectionCount = activePolicySet.policies.lazy.filter { $0.mode == .protection }.count
    let auditCount = activePolicySet.policies.count - protectionCount
    return "\(protectionCount) Protection · \(auditCount) Audit"
  }

  var isOpenAtLoginRegistered: Bool {
    switch loginItemState {
    case .enabled, .requiresApproval:
      true
    case .notRegistered, .notFound:
      false
    }
  }

  var canChangeOpenAtLogin: Bool {
    // An unseen login item can be .notFound before its first registration.
    // Let an explicit user request attempt registration and report any error.
    !isChangingLoginItem
  }

  var hasUnsavedPolicyChanges: Bool {
    !dirtyPolicyIDs.isEmpty
  }

  // MARK: - Onboarding

  var showsOnboarding: Bool {
    guard !hasChosenFirstPolicySetup else { return false }
    return SetupProgress.showsOnboarding(
      health,
      hasEverSeenActivePolicy: hasEverSeenActivePolicySet
    )
  }

  var setupStepStates: SetupStepStates {
    SetupProgress.stepStates(health)
  }

  func beginFirstPolicySetup() {
    hasChosenFirstPolicySetup = true
    createNewPolicy()
  }

  func openExtensionApprovalSettings() {
    openSystemSettings(candidates: [
      "x-apple.systempreferences:com.apple.LoginItems-Settings.extension",
      "x-apple.systempreferences:com.apple.preference.security",
    ])
  }

  func openFullDiskAccessSettings() {
    openSystemSettings(candidates: [
      "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles",
      "x-apple.systempreferences:com.apple.preference.security",
    ])
  }

  private func openSystemSettings(candidates: [String]) {
    for candidate in candidates {
      if let url = URL(string: candidate), NSWorkspace.shared.open(url) {
        return
      }
    }
    if let settingsURL = NSWorkspace.shared.urlForApplication(
      withBundleIdentifier: "com.apple.systempreferences"
    ),
      NSWorkspace.shared.open(settingsURL)
    {
      return
    }
    lastError = "System Settings could not be opened."
  }

  // MARK: - Lifecycle

  func start() {
    guard pollingTask == nil else { return }
    pollingTask = Task { [weak self] in
      guard let self else { return }
      while !Task.isCancelled {
        await refreshHealth()
        await requestAutomaticExtensionUpdateIfNeeded()
        try? await Task.sleep(for: .seconds(2))
      }
    }
  }

  func stop() {
    pollingTask?.cancel()
    pollingTask = nil
    Task { await controlClient.invalidate() }
  }

  func refreshHealth() async {
    refreshLoginItemState()
    let properties: [ExtensionInstallationProperties]
    do {
      properties = try await fetchInstallationProperties()
    } catch {
      health = HealthState(
        protection: .degraded(
          reason: "System-extension properties are unavailable: \(error)"
        )
      )
      return
    }
    installationProperties = properties
    hasFetchedInstallationProperties = true
    installation = HealthStateReducer.preferredInstallation(from: properties)

    let evidence: RuntimeStatusEvidence?
    var authenticatedStatus: ExtensionStatusSnapshot?
    do {
      let status = try await controlClient.queryStatus()
      authenticatedStatus = status
      evidence = RuntimeStatusEvidence(
        snapshot: status,
        source: .authenticatedXPC
      )
      if status.activePolicyRevision != nil {
        hasEverSeenActivePolicySet = true
      }
    } catch let error as ExtensionControlClientError {
      if case .configurationProtocolMismatch = error {
        latestEvidence = nil
        health = HealthState(protection: .degraded(reason: error.description))
        policySynchronizationWarning = error.description
        return
      }
      do {
        let diagnostic = try diagnosticStatusReader.read()
        evidence = RuntimeStatusEvidence(
          snapshot: diagnostic,
          source: .diagnosticFile,
          receivedAt: diagnostic.timestamp
        )
      } catch {
        evidence = nil
      }
    } catch {
      do {
        let diagnostic = try diagnosticStatusReader.read()
        evidence = RuntimeStatusEvidence(
          snapshot: diagnostic,
          source: .diagnosticFile,
          receivedAt: diagnostic.timestamp
        )
      } catch {
        evidence = nil
      }
    }
    latestEvidence = evidence
    health = HealthStateReducer.reduce(
      installationProperties: properties,
      runtimeEvidence: evidence
    )
    if let authenticatedStatus {
      await synchronizeActivePolicySet(
        reportedIdentifier: authenticatedStatus.activePolicySetIdentifier,
        reportedRevision: authenticatedStatus.activePolicyRevision
      )
      await synchronizeSystemCompatibilityState()
      if let warning = authenticatedStatus.systemCompatibilityWarning {
        systemCompatibilitySynchronizationWarning = warning
      }
    }
  }

  func activate() async {
    guard !isUninstalling, pendingUninstall == nil, uninstallStateError == nil else { return }
    _ = await performLifecycleRequest(
      events: activationController.activationEvents(), tracksActivation: true
    )
  }

  func deactivate() async {
    guard !isUninstalling else { return }
    _ = await performLifecycleRequest(events: activationController.deactivationEvents())
  }

  func setOpenAtLogin(_ isEnabled: Bool) {
    guard canChangeOpenAtLogin else { return }
    isChangingLoginItem = true
    loginItemError = nil
    defer { isChangingLoginItem = false }

    do {
      if isEnabled {
        try loginItemController.register()
      } else {
        try loginItemController.unregister()
      }
      refreshLoginItemState()
    } catch {
      refreshLoginItemState()
      loginItemError = "Open at Login could not be changed: \(error.localizedDescription)"
    }
  }

  func openLoginItemsSettings() {
    loginItemController.openSystemSettings()
  }

  func stopProtectionForQuit() async -> StopProtectionQuitOutcome {
    guard !isBusy, !isStoppingProtectionForQuit else {
      return .failed("Another Pasu FS operation is already in progress.")
    }
    isStoppingProtectionForQuit = true
    defer { isStoppingProtectionForQuit = false }

    let requestOutcome = await performLifecycleRequest(
      events: activationController.deactivationEvents()
    )
    guard requestOutcome == .completed else {
      return StopProtectionQuitPolicy.outcome(
        for: requestOutcome,
        extensionWasVerifiedStopped: false
      )
    }

    isBusy = true
    let extensionWasVerifiedStopped = await verifyExtensionStopped()
    isBusy = false
    let outcome = StopProtectionQuitPolicy.outcome(
      for: requestOutcome,
      extensionWasVerifiedStopped: extensionWasVerifiedStopped
    )
    if case .failed(let description) = outcome {
      lastError = description
    }
    return outcome
  }

  // MARK: - Policies and drafts

  /// Returns true only when the helper has accepted the final cleanup, not when removal has finished.
  func uninstall(removeData: Bool) async -> Bool {
    guard !isBusy, !isUninstalling, !isFinalizingUninstall, !isStoppingProtectionForQuit else {
      return false
    }
    isUninstalling = true
    lastError = nil
    defer { isUninstalling = false }
    var ticket: UninstallTicket?
    var extensionRequestAccepted = false
    do {
      pendingUninstall = try await maintenanceClient.status()
      uninstallStateError = nil
      if let pending = pendingUninstall, pending.phase == .awaitingRestart {
        guard let previousBoot = pending.bootSession, let currentBoot = BootSession.identifier()
        else {
          throw MaintenanceError(
            "Pasu FS could not verify that the Mac restarted. No files were removed.")
        }
        guard previousBoot != currentBoot else {
          throw MaintenanceError(
            "Restart this Mac, then open Pasu FS again to finish uninstalling. No application or policy files have been removed."
          )
        }
      }
      ticket = try await uninstallAuthorizer.prepare(
        using: maintenanceClient, removeData: removeData)
      guard let ticket else { throw MaintenanceError("No uninstall approval was returned.") }
      operationMessage = "Checking whether protection can be removed…"
      let stopped = await verifyExtensionStopped(requireRemovalComplete: true)
      var outcome: LifecycleRequestOutcome
      if stopped {
        outcome = .completed
      } else if try await extensionRemovalAwaitsRestart() {
        outcome = .requiresRestart
      } else {
        outcome = await performLifecycleRequest(events: activationController.deactivationEvents())
      }
      if case .completed = outcome {
        extensionRequestAccepted = true
        if !(await verifyExtensionStopped(requireRemovalComplete: true)) {
          // macOS can complete the request while retaining an uninstalling entry
          // until reboot. Persist the restart barrier instead of treating it as removal.
          guard try await extensionRemovalAwaitsRestart() else {
            throw MaintenanceError(
              "Pasu FS could not verify that system-extension removal completed. No application files were removed."
            )
          }
          outcome = .requiresRestart
        }
      }
      switch outcome {
      case .failed(let description): throw MaintenanceError(description)
      case .requiresRestart:
        extensionRequestAccepted = true
        // Persist the reboot barrier even if login-item unregistration then fails.
        try await maintenanceClient.commit(ticket: ticket, action: .awaitRestart)
        try unregisterLoginItemForUninstall()
        pendingUninstall = try readUninstallState()
        operationMessage =
          "Restart this Mac, then open Pasu FS to finish uninstalling. The app and its data remain in place."
        return false
      case .completed:
        extensionRequestAccepted = true
      }
      try unregisterLoginItemForUninstall()
      try await maintenanceClient.commit(ticket: ticket, action: .removeFiles)
      isFinalizingUninstall = true
      operationMessage =
        "The maintenance service accepted the final cleanup. Pasu FS will now quit."
      return true
    } catch {
      if let ticket, !extensionRequestAccepted {
        try? await maintenanceClient.commit(ticket: ticket, action: .cancel)
      }
      await maintenanceClient.invalidate()
      do { pendingUninstall = try readUninstallState() } catch {
        uninstallStateError = String(describing: error)
      }
      lastError =
        (error as NSError).userInfo[NSLocalizedDescriptionKey] as? String
        ?? String(describing: error)
      operationMessage = nil
      return false
    }
  }

  private func extensionRemovalAwaitsRestart() async throws -> Bool {
    let properties = try await fetchInstallationProperties().filter {
      $0.bundleIdentifier == ActivationController.extensionIdentifier
    }
    // A replaced older version may await cleanup while the current version still
    // protects files. That active version must receive its own deactivation request.
    return !properties.contains { $0.isEnabled || $0.isAwaitingUserApproval }
      && properties.contains { $0.isUninstalling }
  }

  /// The owning window consumes this only after the uninstall sheet has finished dismissing.
  func takeUninstallTerminationRequest() -> Bool {
    guard isFinalizingUninstall, !hasRequestedUninstallTermination else { return false }
    hasRequestedUninstallTermination = true
    return true
  }

  private func unregisterLoginItemForUninstall() throws {
    refreshLoginItemState()
    switch loginItemState {
    case .notRegistered, .notFound:
      // There is no discoverable registration to remove. An unconditional unregister
      // can fail with EPERM / "record not found" on a fresh installation.
      return
    case .enabled, .requiresApproval:
      operationMessage = "Removing the login registration…"
      do {
        try loginItemController.unregister()
      } catch {
        throw MaintenanceError(
          "Could not remove the login registration: \(error.localizedDescription)")
      }
      refreshLoginItemState()
      guard loginItemState == .notRegistered || loginItemState == .notFound else {
        throw MaintenanceError(
          "macOS still reports a login registration. No application files were removed.")
      }
    }
  }

  var activeRevision: UInt64? {
    acceptedRevision > 0 ? acceptedRevision : nil
  }

  var nextRevisionDescription: String {
    "policy-set revision \(acceptedRevision + 1)"
  }

  var sidebarPolicies: [DirectoryPolicyDraft] {
    policyOrder.compactMap { policyDrafts[$0] }
  }

  var activePolicies: [DirectoryPolicy] {
    activePolicySet?.policies ?? []
  }

  var selectedPolicyID: UUID? {
    guard case .policy(let id) = selectedSection else { return nil }
    return id
  }

  var dirtyPolicyIDs: Set<UUID> {
    Set(policyOrder.filter(isPolicyDirty))
  }

  func policyDraft(id: UUID) -> DirectoryPolicyDraft? {
    policyDrafts[id]
  }

  func activePolicy(id: UUID) -> DirectoryPolicy? {
    activePolicySet?.policies.first { $0.id == id }
  }

  func isPolicyDirty(_ id: UUID) -> Bool {
    guard let draft = policyDrafts[id] else { return false }
    guard let active = activePolicy(id: id) else { return true }
    return draft.makePolicy() != active
  }

  func draftValidationMessage(for id: UUID) -> String? {
    guard acceptedRevision < UInt64.max else {
      return "The policy-set revision counter is exhausted."
    }
    do {
      _ = try candidateDocument(replacing: id, with: policyDrafts[id])
      return nil
    } catch {
      return String(describing: error)
    }
  }

  func createNewPolicy() {
    guard policyOrder.count < PolicySetDocument.maximumPolicyCount else {
      lastError =
        "A policy set can contain at most \(PolicySetDocument.maximumPolicyCount) policies."
      return
    }
    let draft = DirectoryPolicyDraft(name: nextAvailablePolicyName())
    policyDrafts[draft.id] = draft
    policyOrder.append(draft.id)
    selectedSection = .policy(draft.id)
    hasChosenFirstPolicySetup = true
    lastError = nil
  }

  func updatePolicyDraft(
    id: UUID,
    _ update: (inout DirectoryPolicyDraft) -> Void
  ) {
    guard var draft = policyDrafts[id] else { return }
    update(&draft)
    policyDrafts[id] = draft
    lastError = nil
  }

  func savePolicy(id: UUID) async {
    guard !isBusy, let draft = policyDrafts[id] else { return }
    isBusy = true
    lastError = nil
    defer { isBusy = false }
    do {
      let document = try candidateDocument(replacing: id, with: draft)
      let receipt = try await controlClient.applyPolicySet(document)
      guard receipt.acceptedSetIdentifier == document.setIdentifier,
        receipt.acceptedRevision == document.revision
      else {
        throw AppModelError.policySetReceiptMismatch
      }
      installActivePolicySet(document, markingClean: id)
      operationMessage = "Policy-set revision \(receipt.acceptedRevision) was accepted."
      await refreshHealth()
    } catch {
      lastError = String(describing: error)
      await refreshHealth()
    }
  }

  func revertPolicy(id: UUID) {
    if let active = activePolicy(id: id) {
      policyDrafts[id] = DirectoryPolicyDraft(policy: active)
      policySynchronizationWarning = nil
      lastError = nil
    } else {
      discardUnsavedPolicy(id: id)
    }
  }

  func deletePolicy(id: UUID) async {
    guard !isBusy else { return }
    guard activePolicy(id: id) != nil else {
      discardUnsavedPolicy(id: id)
      return
    }
    isBusy = true
    lastError = nil
    defer { isBusy = false }
    do {
      guard acceptedRevision < UInt64.max, let activePolicySet else {
        throw AppModelError.policyRevisionExhausted
      }
      let policies = activePolicySet.policies.filter { $0.id != id }
      let document = PolicySetDocument(
        setIdentifier: activePolicySet.setIdentifier,
        revision: acceptedRevision + 1,
        policies: policies
      )
      try document.validate()
      let receipt = try await controlClient.applyPolicySet(document)
      guard receipt.acceptedSetIdentifier == document.setIdentifier,
        receipt.acceptedRevision == document.revision
      else {
        throw AppModelError.policySetReceiptMismatch
      }
      policyDrafts.removeValue(forKey: id)
      policyOrder.removeAll { $0 == id }
      installActivePolicySet(document, markingClean: id)
      selectAfterRemovingPolicy(id)
      operationMessage = "Policy deleted in policy-set revision \(receipt.acceptedRevision)."
      await refreshHealth()
    } catch {
      lastError = String(describing: error)
      await refreshHealth()
    }
  }

  private func discardUnsavedPolicy(id: UUID) {
    policyDrafts.removeValue(forKey: id)
    policyOrder.removeAll { $0 == id }
    selectAfterRemovingPolicy(id)
    lastError = nil
  }

  private func selectAfterRemovingPolicy(_ id: UUID) {
    guard selectedPolicyID == id else { return }
    if let next = policyOrder.first {
      selectedSection = .policy(next)
    } else {
      selectedSection = .protection
    }
  }

  func candidateDocument(
    replacing id: UUID,
    with draft: DirectoryPolicyDraft?
  ) throws -> PolicySetDocument {
    guard acceptedRevision < UInt64.max else {
      throw AppModelError.policyRevisionExhausted
    }
    var policies = activePolicySet?.policies ?? []
    if let draft {
      if let index = policies.firstIndex(where: { $0.id == id }) {
        policies[index] = draft.makePolicy()
      } else {
        policies.append(draft.makePolicy())
      }
    } else {
      policies.removeAll { $0.id == id }
    }
    let policiesByID = Dictionary(uniqueKeysWithValues: policies.map { ($0.id, $0) })
    var orderedPolicies = policyOrder.compactMap { policiesByID[$0] }
    let orderedIDs = Set(orderedPolicies.map(\.id))
    orderedPolicies.append(contentsOf: policies.filter { !orderedIDs.contains($0.id) })
    let document = PolicySetDocument(
      setIdentifier: activePolicySet?.setIdentifier ?? pendingSetIdentifier,
      revision: acceptedRevision + 1,
      policies: orderedPolicies
    )
    try document.validate()
    return document
  }

  private func nextAvailablePolicyName() -> String {
    let used = Set(
      policyDrafts.values.map {
        $0.name.folding(
          options: [.caseInsensitive, .diacriticInsensitive],
          locale: Locale(identifier: "en_US_POSIX")
        )
      })
    var number = 1
    while used.contains("policy \(number)") {
      number += 1
    }
    return "Policy \(number)"
  }

  // MARK: - Rules

  func addTeamSignedRule(policyID: UUID) {
    updatePolicyDraft(id: policyID) { $0.addRule(kind: .teamSigned) }
  }

  func addPlatformRule(policyID: UUID) {
    updatePolicyDraft(id: policyID) { $0.addRule(kind: .platformBinary) }
  }

  func addRule(policyID: UUID, fromApplicationAt url: URL) {
    do {
      let info = try SigningInfoReader.read(fromApplicationAt: url)
      let candidate = AuditRuleCandidate(
        id: identityKey(
          kind: info.isPlatformBinary ? .platformBinary : .teamSigned,
          teamIdentifier: info.teamIdentifier,
          signingIdentifier: info.signingIdentifier
        ),
        kind: info.isPlatformBinary ? .platformBinary : .teamSigned,
        teamIdentifier: info.teamIdentifier,
        signingIdentifier: info.signingIdentifier,
        displayName: FileManager.default.displayName(atPath: url.path),
        executablePath: url.path,
        lastSeen: Date(),
        observationCount: 1,
        latestResult: "selected application"
      )
      try addRule(policyID: policyID, from: candidate)
    } catch {
      lastError = String(describing: error)
    }
  }

  func addRule(policyID: UUID, from candidate: AuditRuleCandidate) throws {
    guard !policyContainsIdentity(policyID: policyID, candidate: candidate) else {
      throw AppModelError.duplicateRuleIdentity
    }
    let rule: PolicyRule
    switch candidate.kind {
    case .teamSigned:
      guard let teamIdentifier = candidate.teamIdentifier, !teamIdentifier.isEmpty else {
        throw AppModelError.auditIdentityIncomplete
      }
      rule = .teamSigned(
        id: "rule.\(UUID().uuidString.lowercased())",
        teamIdentifier: teamIdentifier.uppercased(),
        signingIdentifier: candidate.signingIdentifier,
        isEnabled: true,
        allowsDescendants: false
      )
    case .platformBinary:
      rule = .platformBinary(
        id: "rule.\(UUID().uuidString.lowercased())",
        signingIdentifier: candidate.signingIdentifier,
        isEnabled: true,
        allowsDescendants: false
      )
    }
    updatePolicyDraft(id: policyID) { $0.rules.append(rule) }
  }

  func removeRule(policyID: UUID, ruleID: String) {
    updatePolicyDraft(id: policyID) { draft in
      draft.rules.removeAll { $0.id == ruleID }
    }
  }

  func updateRule(policyID: UUID, rule: PolicyRule) {
    updatePolicyDraft(id: policyID) { draft in
      guard let index = draft.rules.firstIndex(where: { $0.id == rule.id }) else { return }
      draft.rules[index] = rule
    }
  }

  func applyPolicyTypeChange(
    policyID: UUID,
    to policyType: PolicyType,
    deletingAllRules: Bool
  ) {
    updatePolicyDraft(id: policyID) { draft in
      draft.policyType = policyType
      if deletingAllRules {
        draft.rules.removeAll()
      }
    }
  }

  func ruleDisplayName(for rule: PolicyRule) -> String {
    let identifier = rule.signingIdentifier
    guard !identifier.isEmpty else { return "New rule" }
    if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: identifier) {
      return FileManager.default.displayName(atPath: url.path)
    }
    return identifier
  }

  func policyContainsIdentity(policyID: UUID, candidate: AuditRuleCandidate) -> Bool {
    guard let draft = policyDrafts[policyID] else { return false }
    return draft.rules.contains {
      identityKey(
        kind: $0.kind,
        teamIdentifier: $0.teamIdentifier,
        signingIdentifier: $0.signingIdentifier
      ) == candidate.id
    }
  }

  // MARK: - System compatibility profiles

  var systemCompatibilityCatalogMatchesExtension: Bool {
    guard let remoteDigest = systemCompatibilityState?.catalogDigest else { return false }
    return !systemCompatibilityCatalogDigest.isEmpty
      && remoteDigest == systemCompatibilityCatalogDigest
  }

  func systemCompatibilityProfileItems(
    policyID: UUID
  ) -> [SystemCompatibilityProfileItem] {
    systemCompatibilityCatalog.profiles.map { profile in
      let resolution = systemCompatibilityState?.profileResolutions.first {
        $0.policyIdentifier == policyID && $0.profileIdentifier == profile.id
      }
      return SystemCompatibilityProfileItem(
        profile: profile,
        state: resolution?.state ?? .disabled,
        isEnabled: resolution?.isEnabled ?? false
      )
    }
  }

  func setSystemCompatibilityProfile(
    policyID: UUID,
    profileID: String,
    enabled: Bool
  ) async {
    guard !isBusy else { return }
    isBusy = true
    lastError = nil
    defer { isBusy = false }

    do {
      guard systemCompatibilityCatalogMatchesExtension else {
        throw AppModelError.systemCompatibilityCatalogMismatch
      }
      guard let policy = activePolicy(id: policyID) else {
        throw AppModelError.systemCompatibilityRequiresSavedPolicy
      }
      guard policy.policyType == .whitelist else {
        throw AppModelError.systemCompatibilityRequiresWhitelist
      }
      guard let profile = systemCompatibilityCatalog.profile(identifier: profileID) else {
        throw AppModelError.systemCompatibilityProfileMissing
      }
      let authorizationDigest = try systemCompatibilityCatalog.authorizationDigest(for: profile)
      let candidate = try candidateSystemCompatibilitySettings(
        policy: policy,
        profileID: profileID,
        authorizationDigest: authorizationDigest,
        enabled: enabled
      )
      let receipt = try await controlClient.applySystemCompatibilitySettings(candidate.document)
      guard receipt.acceptedSettingsIdentifier == candidate.document.settingsIdentifier,
        receipt.acceptedRevision == candidate.document.revision
      else {
        throw AppModelError.systemCompatibilityReceiptMismatch
      }
      systemCompatibilityState = try await controlClient.querySystemCompatibilityState()
      systemCompatibilitySynchronizationWarning = nil
      let result =
        enabled
        ? "System compatibility profile enabled."
        : "System compatibility profile disabled."
      operationMessage =
        candidate.removedObsoleteItemCount == 0
        ? result
        : "\(result) Removed \(candidate.removedObsoleteItemCount) obsolete compatibility setting(s)."
    } catch {
      lastError = String(describing: error)
      await synchronizeSystemCompatibilityState()
    }
  }

  private func candidateSystemCompatibilitySettings(
    policy: DirectoryPolicy,
    profileID: String,
    authorizationDigest: String,
    enabled: Bool
  ) throws -> SystemCompatibilitySettingsCandidate {
    guard let activePolicySet else {
      throw AppModelError.systemCompatibilityRequiresSavedPolicy
    }
    let activeSettings = systemCompatibilityState?.settings.flatMap {
      $0.policySetIdentifier == activePolicySet.setIdentifier ? $0 : nil
    }
    let nextRevision: UInt64
    let settingsIdentifier: UUID
    if let activeSettings {
      guard activeSettings.revision < UInt64.max else {
        throw AppModelError.systemCompatibilityRevisionExhausted
      }
      nextRevision = activeSettings.revision + 1
      settingsIdentifier = activeSettings.settingsIdentifier
    } else {
      nextRevision = 1
      settingsIdentifier = UUID()
    }

    let reconciliation = try activeSettings.map {
      try SystemCompatibilitySettingsReconciler.reconcile(
        $0,
        policySet: activePolicySet,
        catalog: systemCompatibilityCatalog
      )
    }
    var bindings = reconciliation?.document.bindings ?? []
    let existingIndex = bindings.firstIndex { $0.policyIdentifier == policy.id }
    var approvals: [ApprovedSystemCompatibilityProfile]
    if let existingIndex, bindings[existingIndex].matchesContext(of: policy) {
      approvals = bindings[existingIndex].profiles
    } else if let existingIndex {
      approvals = bindings[existingIndex].profiles.map {
        var approval = $0
        approval.isEnabled = false
        return approval
      }
    } else {
      approvals = []
    }

    if let approvalIndex = approvals.firstIndex(where: {
      $0.profileIdentifier == profileID
    }) {
      approvals[approvalIndex].approvedAuthorizationDigest = authorizationDigest
      approvals[approvalIndex].isEnabled = enabled
    } else {
      approvals.append(
        ApprovedSystemCompatibilityProfile(
          profileIdentifier: profileID,
          approvedAuthorizationDigest: authorizationDigest,
          isEnabled: enabled
        )
      )
    }
    let binding = PolicySystemCompatibilityBinding(policy: policy, profiles: approvals)
    if let existingIndex {
      bindings[existingIndex] = binding
    } else {
      bindings.append(binding)
    }

    let document = SystemCompatibilitySettingsDocument(
      settingsIdentifier: settingsIdentifier,
      revision: nextRevision,
      policySetIdentifier: activePolicySet.setIdentifier,
      bindings: bindings
    )
    try document.validateStructure()
    return SystemCompatibilitySettingsCandidate(
      document: document,
      removedObsoleteItemCount: reconciliation?.removedItemCount ?? 0
    )
  }

  // MARK: - Audit log

  var filteredAuditRecords: [AuditEventRecord] {
    let records = Array(auditBatch.records.reversed())
    let needle = auditFilterText.trimmingCharacters(in: .whitespaces)
    guard !needle.isEmpty else { return records }
    return records.filter { record in
      var values: [String?] = [
        record.targetPath,
        record.executablePath,
        record.signingIdentifier,
        record.teamIdentifier,
        record.policyDecision,
        record.kernelResponse,
        record.eventType,
      ]
      values.append(
        contentsOf: (record.policyEvaluations ?? []).flatMap {
          [
            $0.policyName, $0.policyType.rawValue, $0.decision.rawValue,
            $0.ruleIdentifier, $0.systemCompatibilityProfileIdentifier,
          ]
        })
      values.append(contentsOf: record.lineageSearchValues.map(Optional.some))
      return values.compactMap { $0 }.contains {
        $0.localizedCaseInsensitiveContains(needle)
      }
    }
  }

  var auditRuleCandidates: [AuditRuleCandidate] {
    struct Accumulator {
      var kind: PolicyRuleKind
      var teamIdentifier: String?
      var signingIdentifier: String
      var executablePath: String?
      var lastSeen: Date
      var observationCount: Int
      var latestResult: String
    }

    var grouped: [String: Accumulator] = [:]
    for record in auditBatch.records {
      guard let signingIdentifier = record.signingIdentifier, !signingIdentifier.isEmpty else {
        continue
      }
      let kind: PolicyRuleKind
      let teamIdentifier: String?
      if record.isPlatformBinary == true {
        kind = .platformBinary
        teamIdentifier = nil
      } else if record.isPlatformBinary == false,
        let team = record.teamIdentifier,
        !team.isEmpty
      {
        kind = .teamSigned
        teamIdentifier = team.uppercased()
      } else {
        continue
      }
      let key = identityKey(
        kind: kind,
        teamIdentifier: teamIdentifier,
        signingIdentifier: signingIdentifier
      )
      if var existing = grouped[key] {
        existing.observationCount += 1
        if record.timestamp >= existing.lastSeen {
          existing.lastSeen = record.timestamp
          existing.executablePath = record.executablePath
          existing.latestResult = record.kernelResponse
        }
        grouped[key] = existing
      } else {
        grouped[key] = Accumulator(
          kind: kind,
          teamIdentifier: teamIdentifier,
          signingIdentifier: signingIdentifier,
          executablePath: record.executablePath,
          lastSeen: record.timestamp,
          observationCount: 1,
          latestResult: record.kernelResponse
        )
      }
    }

    return grouped.map { key, value in
      AuditRuleCandidate(
        id: key,
        kind: value.kind,
        teamIdentifier: value.teamIdentifier,
        signingIdentifier: value.signingIdentifier,
        displayName: displayName(
          signingIdentifier: value.signingIdentifier,
          executablePath: value.executablePath
        ),
        executablePath: value.executablePath,
        lastSeen: value.lastSeen,
        observationCount: value.observationCount,
        latestResult: value.latestResult
      )
    }
    .sorted { $0.lastSeen > $1.lastSeen }
  }

  func systemCompatibilityAuditCandidates(
    policyID: UUID? = nil
  ) -> [SystemCompatibilityAuditCandidate] {
    guard let activePolicySet else { return [] }
    let activePoliciesByID = Dictionary(
      uniqueKeysWithValues: activePolicySet.policies.map { ($0.id, $0) }
    )
    struct CandidateKey: Hashable {
      var policyIdentifier: UUID
      var signingIdentifier: String
      var operatingSystemBuild: String
    }
    struct Accumulator {
      var policyName: String
      var policyMode: PolicyMode
      var executablePath: String?
      var observationCount: Int
      var firstSeen: Date
      var lastSeen: Date
      var requestedFlags: Set<UInt32>
      var codeSigningFlags: Set<UInt32>
      var targetPaths: Set<String>
      var incompleteObservationCount: Int
    }

    var grouped: [CandidateKey: Accumulator] = [:]
    for record in auditBatch.records {
      guard record.eventType == "AUTH_OPEN",
        record.policySetIdentifier == activePolicySet.setIdentifier,
        record.policyRevision == activePolicySet.revision,
        record.isPlatformBinary == true,
        record.pathWasTruncated != true,
        let signingIdentifier = record.signingIdentifier,
        !signingIdentifier.isEmpty,
        let operatingSystemBuild = record.operatingSystemBuild,
        !operatingSystemBuild.isEmpty
      else {
        continue
      }
      for evaluation in record.policyEvaluations ?? [] {
        guard let activePolicy = activePoliciesByID[evaluation.policyIdentifier],
          activePolicy.policyType == .whitelist,
          activePolicy.mode == evaluation.mode,
          evaluation.policyType == .whitelist,
          evaluation.match == .none,
          evaluation.decision == .deny || evaluation.decision == .wouldDeny,
          policyID == nil || evaluation.policyIdentifier == policyID
        else {
          continue
        }
        let key = CandidateKey(
          policyIdentifier: evaluation.policyIdentifier,
          signingIdentifier: signingIdentifier,
          operatingSystemBuild: operatingSystemBuild
        )
        let requestedFlags = record.requestedFlags.map { UInt32(bitPattern: $0) }
        let incomplete =
          requestedFlags == nil || requestedFlags == 0
            || record.codeSigningFlags == nil || record.targetPath == nil ? 1 : 0

        if var existing = grouped[key] {
          existing.observationCount += 1
          existing.firstSeen = min(existing.firstSeen, record.timestamp)
          if record.timestamp >= existing.lastSeen {
            existing.lastSeen = record.timestamp
            existing.executablePath = record.executablePath
          }
          if let requestedFlags, requestedFlags != 0 {
            existing.requestedFlags.insert(requestedFlags)
          }
          if let codeSigningFlags = record.codeSigningFlags {
            existing.codeSigningFlags.insert(codeSigningFlags)
          }
          if let targetPath = record.targetPath {
            existing.targetPaths.insert(targetPath)
          }
          existing.incompleteObservationCount += incomplete
          grouped[key] = existing
        } else {
          grouped[key] = Accumulator(
            policyName: evaluation.policyName,
            policyMode: evaluation.mode,
            executablePath: record.executablePath,
            observationCount: 1,
            firstSeen: record.timestamp,
            lastSeen: record.timestamp,
            requestedFlags: requestedFlags.map { $0 == 0 ? [] : [$0] } ?? [],
            codeSigningFlags: record.codeSigningFlags.map { [$0] } ?? [],
            targetPaths: record.targetPath.map { [$0] } ?? [],
            incompleteObservationCount: incomplete
          )
        }
      }
    }

    return grouped.map { key, value in
      let flagValues = value.requestedFlags.sorted()
      return SystemCompatibilityAuditCandidate(
        policyIdentifier: key.policyIdentifier,
        policyName: value.policyName,
        policyMode: value.policyMode,
        signingIdentifier: key.signingIdentifier,
        operatingSystemBuild: key.operatingSystemBuild,
        displayName: displayName(
          signingIdentifier: key.signingIdentifier,
          executablePath: value.executablePath
        ),
        executablePath: value.executablePath,
        observationCount: value.observationCount,
        firstSeen: value.firstSeen,
        lastSeen: value.lastSeen,
        requestedFlagValues: flagValues,
        requestedFlagUnion: flagValues.reduce(UInt32(0), |),
        codeSigningFlagValues: value.codeSigningFlags.sorted(),
        targetPathSamples: Array(value.targetPaths.sorted().prefix(5)),
        uniqueTargetPathCount: value.targetPaths.count,
        incompleteObservationCount: value.incompleteObservationCount
      )
    }
    .sorted { $0.lastSeen > $1.lastSeen }
  }

  func refreshAuditLog() async {
    do {
      auditBatch = try await controlClient.readAuditLog(maximumLineCount: 500)
      lastError = nil
    } catch {
      lastError = String(describing: error)
    }
  }

  func policyLogState(policyID: UUID) -> PolicyLogState? {
    guard let set = activePolicySet else { return nil }
    return policyLogs[
      PolicyAuditLogKey(setIdentifier: set.setIdentifier, policyIdentifier: policyID)]
  }

  func refreshPolicyAuditLog(policyID: UUID) async {
    guard let log = policyLogState(policyID: policyID) else { return }
    let requestID = UUID()
    log.requestID = requestID
    log.isLoading = true
    defer {
      if log.requestID == requestID { log.isLoading = false }
    }
    do {
      let batch = try await controlClient.readPolicyAuditLog(
        setIdentifier: log.key.setIdentifier, policyIdentifier: policyID, maximumLineCount: 500)
      guard !Task.isCancelled, policyLogs[log.key] === log, log.requestID == requestID else {
        return
      }
      log.batch = batch
      log.hasLoaded = true
      log.error = nil
      log.selectedEventIDs.formIntersection(Set(batch.records.map(\.id)))
    } catch {
      guard !Task.isCancelled, policyLogs[log.key] === log, log.requestID == requestID else {
        return
      }
      log.error = String(describing: error)
    }
  }

  private func displayName(
    signingIdentifier: String,
    executablePath: String?
  ) -> String {
    if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: signingIdentifier) {
      return FileManager.default.displayName(atPath: url.path)
    }
    if let executablePath, !executablePath.isEmpty {
      return (executablePath as NSString).lastPathComponent
    }
    return signingIdentifier
  }

  private func identityKey(
    kind: PolicyRuleKind,
    teamIdentifier: String?,
    signingIdentifier: String
  ) -> String {
    switch kind {
    case .teamSigned:
      "team:\((teamIdentifier ?? "").uppercased()):\(signingIdentifier)"
    case .platformBinary:
      "platform:\(signingIdentifier)"
    }
  }

  // MARK: - Synchronization

  private func synchronizeSystemCompatibilityState() async {
    do {
      let snapshot = try await controlClient.querySystemCompatibilityState()
      systemCompatibilityState = snapshot
      if snapshot.catalogDigest != systemCompatibilityCatalogDigest {
        systemCompatibilitySynchronizationWarning =
          "The app and protection extension use different system compatibility definitions. Ordinary policy editing remains available, but profile editing is disabled until the installed components match."
      } else {
        let unresolved = snapshot.profileResolutions.filter {
          $0.isEnabled && $0.state != .active
        }
        systemCompatibilitySynchronizationWarning =
          unresolved.isEmpty
          ? nil
          : "One or more enabled system compatibility profiles require review."
      }
    } catch {
      systemCompatibilityState = nil
      systemCompatibilitySynchronizationWarning =
        "System compatibility state could not be synchronized: \(error)"
    }
  }

  private func synchronizeActivePolicySet(
    reportedIdentifier: UUID?,
    reportedRevision: UInt64?
  ) async {
    if let reportedIdentifier, let reportedRevision,
      activePolicySet?.setIdentifier == reportedIdentifier,
      activePolicySet?.revision == reportedRevision
    {
      acceptedRevision = reportedRevision
      return
    }
    do {
      let policySet = try await controlClient.queryPolicySet()
      if let current = activePolicySet,
        current.setIdentifier == policySet.setIdentifier,
        current.revision > policySet.revision
      {
        return
      }

      installActivePolicySet(policySet)
      var warnings: [String] = []
      if let reportedIdentifier, policySet.setIdentifier != reportedIdentifier {
        warnings.append(
          "Runtime status and the policy query reported different policy-set identifiers."
        )
      }
      if let reportedRevision, policySet.revision != reportedRevision {
        warnings.append(
          "Runtime status reported revision \(reportedRevision), but the policy query returned revision \(policySet.revision)."
        )
      }
      if !dirtyPolicyIDs.isEmpty {
        warnings.append(
          "The active policy set changed while local drafts were edited. The drafts were kept; saving replaces only the selected policy in the latest active set."
        )
      }
      policySynchronizationWarning =
        warnings.isEmpty
        ? nil
        : warnings.joined(separator: " ")
    } catch {
      if reportedRevision == nil, activePolicySet == nil {
        acceptedRevision = 0
        policySynchronizationWarning = nil
      } else {
        let runtimeDescription =
          reportedRevision.map {
            "reports policy-set revision \($0)"
          } ?? "does not currently report an active policy-set revision"
        policySynchronizationWarning =
          "Runtime status \(runtimeDescription), but the stored policy set could not be synchronized: \(error)"
      }
    }
  }

  func installActivePolicySet(
    _ policySet: PolicySetDocument,
    markingClean cleanPolicyID: UUID? = nil
  ) {
    var previouslyDirty = dirtyPolicyIDs
    if let cleanPolicyID {
      previouslyDirty.remove(cleanPolicyID)
    }
    let previousDrafts = policyDrafts
    let previousOrder = policyOrder

    activePolicySet = policySet
    let logKeys = Set(
      policySet.policies.map {
        PolicyAuditLogKey(setIdentifier: policySet.setIdentifier, policyIdentifier: $0.id)
      })
    policyLogs = policyLogs.filter { logKeys.contains($0.key) }
    for key in logKeys where policyLogs[key] == nil {
      policyLogs[key] = PolicyLogState(key: key)
    }
    pendingSetIdentifier = policySet.setIdentifier
    acceptedRevision = policySet.revision
    hasEverSeenActivePolicySet = true

    var nextDrafts: [UUID: DirectoryPolicyDraft] = [:]
    for policy in policySet.policies {
      if previouslyDirty.contains(policy.id), let draft = previousDrafts[policy.id] {
        nextDrafts[policy.id] = draft
      } else {
        nextDrafts[policy.id] = DirectoryPolicyDraft(policy: policy)
      }
    }
    for id in previousOrder where previouslyDirty.contains(id) && nextDrafts[id] == nil {
      if let draft = previousDrafts[id] {
        nextDrafts[id] = draft
      }
    }
    let activeIDs = Set(policySet.policies.map(\.id))
    let retainedIDs = activeIDs.union(previouslyDirty)
    var nextOrder = previousOrder.filter { retainedIDs.contains($0) }
    let orderedIDs = Set(nextOrder)
    nextOrder.append(contentsOf: policySet.policies.map(\.id).filter { !orderedIDs.contains($0) })
    policyDrafts = nextDrafts
    policyOrder = nextOrder
    if dirtyPolicyIDs.isEmpty {
      policySynchronizationWarning = nil
    }
  }

  private func fetchInstallationProperties() async throws -> [ExtensionInstallationProperties] {
    for await event in activationController.propertiesEvents() {
      switch event {
      case .properties(let properties):
        installationPropertiesObservedAt = Date()
        installationPropertiesError = nil
        return properties
      case .failed(_, _, let description):
        installationPropertiesError = description
        throw AppModelError.installationPropertiesFailed(description)
      default:
        break
      }
    }
    let description = "The extension query ended without returning version information."
    installationPropertiesError = description
    throw AppModelError.installationPropertiesFailed(description)
  }

  private func requestAutomaticExtensionUpdateIfNeeded() async {
    guard hasFetchedInstallationProperties, !isBusy, !isUninstalling, !isFinalizingUninstall,
      pendingUninstall == nil, uninstallStateError == nil
    else { return }
    let shouldRequestActivation = automaticExtensionUpdateCheck.shouldRequestActivation(
      embeddedBuildVersion: embeddedSystemExtensionBuildVersion,
      installations: installationProperties
    )
    guard shouldRequestActivation else { return }

    operationMessage = "A newer embedded system extension was found. Requesting an update."
    _ = await performLifecycleRequest(
      events: activationController.activationEvents(), tracksActivation: true
    )
  }

  private func refreshLoginItemState() {
    let previousState = loginItemState
    loginItemState = loginItemController.state
    if loginItemState != previousState {
      loginItemError = nil
    }
  }

  private func verifyExtensionStopped(requireRemovalComplete: Bool = false) async -> Bool {
    for attempt in 0..<3 {
      do {
        let properties = try await fetchInstallationProperties()
        installationProperties = properties
        hasFetchedInstallationProperties = true
        installation = HealthStateReducer.preferredInstallation(from: properties)

        let hasEnabledInstallation = properties.contains {
          $0.bundleIdentifier == ActivationController.extensionIdentifier && $0.isEnabled
        }
        let authenticatedRuntimeIsAvailable: Bool
        if hasEnabledInstallation {
          authenticatedRuntimeIsAvailable = true
        } else {
          authenticatedRuntimeIsAvailable = (try? await controlClient.queryStatus()) != nil
        }
        if ProtectionStopVerification.isStopped(
          installations: properties,
          authenticatedRuntimeIsAvailable: authenticatedRuntimeIsAvailable
        ),
          !requireRemovalComplete
            || !properties.contains(where: { $0.isUninstalling || $0.isAwaitingUserApproval })
        {
          return true
        }
      } catch {
        // A transient properties failure is not proof that protection stopped.
      }

      if attempt < 2 {
        try? await Task.sleep(for: .seconds(1))
      }
    }
    await refreshHealth()
    return false
  }

  private func performLifecycleRequest(
    events: AsyncStream<ActivationEvent>, tracksActivation: Bool = false
  ) async -> LifecycleRequestOutcome {
    guard !isBusy else {
      return .failed("Another Pasu FS operation is already in progress.")
    }
    isBusy = true
    lastError = nil
    if tracksActivation {
      isRequestingActivation = true
      activationProgress = "Updating extension…"
      activationOutcome = nil
    }
    defer {
      isBusy = false
      if tracksActivation {
        isRequestingActivation = false
        activationProgress = nil
      }
    }
    var outcome: LifecycleRequestOutcome?
    for await event in events {
      switch event {
      case .submitted(let action):
        operationMessage = "Submitted \(action) request."
      case .waitingForUserApproval:
        operationMessage = "Waiting for approval in System Settings."
        if tracksActivation { activationProgress = "Approval required in System Settings" }
      case .replacing(let existing, let new):
        operationMessage = "Replacing version \(existing) with \(new)."
        if tracksActivation { activationProgress = "Updating extension…" }
      case .completed(let rebootRequired):
        operationMessage =
          rebootRequired
          ? "The request will complete after restart."
          : "The request completed."
        outcome = rebootRequired ? .requiresRestart : .completed
      case .failed(_, _, let description):
        lastError = description
        outcome = .failed(description)
      case .properties:
        break
      }
    }
    await refreshHealth()
    let result =
      outcome
      ?? .failed("The system-extension request ended without a completion result.")
    if tracksActivation { activationOutcome = result }
    return result
  }
}

private enum AppModelError: Error, CustomStringConvertible {
  case policyRevisionExhausted
  case policySetReceiptMismatch
  case duplicateRuleIdentity
  case auditIdentityIncomplete
  case systemCompatibilityCatalogMismatch
  case systemCompatibilityRequiresSavedPolicy
  case systemCompatibilityRequiresWhitelist
  case systemCompatibilityProfileMissing
  case systemCompatibilityReceiptMismatch
  case systemCompatibilityRevisionExhausted
  case installationPropertiesFailed(String)

  var description: String {
    switch self {
    case .policyRevisionExhausted:
      "The policy-set revision counter is exhausted."
    case .policySetReceiptMismatch:
      "The extension returned a receipt for a different policy set or revision."
    case .duplicateRuleIdentity:
      "This program identity already has a rule in the selected policy."
    case .auditIdentityIncomplete:
      "The audit record does not contain a complete supported signing identity."
    case .systemCompatibilityCatalogMismatch:
      "System compatibility profiles cannot be edited until the app and extension use matching built-in catalogs."
    case .systemCompatibilityRequiresSavedPolicy:
      "Save this policy before changing its system compatibility profiles."
    case .systemCompatibilityRequiresWhitelist:
      "System compatibility profiles apply only to Whitelist policies."
    case .systemCompatibilityProfileMissing:
      "The selected system compatibility profile is not in the built-in catalog."
    case .systemCompatibilityReceiptMismatch:
      "The extension returned a receipt for different system compatibility settings."
    case .systemCompatibilityRevisionExhausted:
      "The system compatibility settings revision counter is exhausted."
    case .installationPropertiesFailed(let description):
      description
    }
  }
}
