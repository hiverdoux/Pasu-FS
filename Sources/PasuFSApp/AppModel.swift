import AppKit
import Foundation
import Observation
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSMaintenanceCore

enum SidebarSelection: Hashable {
  case overview
  case policy(UUID)
}

enum SettingsTab: Hashable {
  case general
  case extensionStatus
  case diagnostics
}

/// Opens the Add Program sheet for a policy, optionally with an identity already chosen.
struct AddProgramRequest: Identifiable, Equatable {
  let id = UUID()
  let policyID: UUID
  var preselected: AuditRuleCandidate?
}

struct AttentionItem: Identifiable, Equatable {
  enum Action: Equatable {
    case diagnostics
    case extensionSettings
    case generalSettings
    case continueUninstall
    case loginItems
  }

  let id: String
  let text: String
  var detail: String?
  var action: Action?
}

/// A request Pasu FS denied, with the policy whose log recorded it.
struct RecentDenial: Identifiable {
  let policyID: UUID
  let policyName: String
  let record: AuditEventRecord

  var id: String { record.id }
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
  private(set) var policyLogs: [PolicyAuditLogKey: PolicyLogState] = [:]
  var selectedSection: SidebarSelection = .overview
  var settingsTab: SettingsTab = .general
  /// A new policy whose folder field takes keyboard focus when its screen appears.
  var pendingFolderEntryPolicyID: UUID?
  var addProgramRequest: AddProgramRequest?
  /// A policy whose screen opens on its Log tab the next time it appears.
  var pendingPolicyLogPolicyID: UUID?
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
  // Until the first status check finishes, the setup state is unknown. The main window then shows
  // its regular screens, which report that the status is being checked, rather than the setup
  // assistant.
  private var hasCompletedStatusCheck = false
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
      uninstallStateError = UserFacingError.message(error)
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

  var status: StatusPresentation {
    StatusPresentation(health: health)
  }

  var menuBarSymbolName: String {
    status.menuBarSymbolName
  }

  var activeRevisionFromHealth: UInt64? {
    switch health.protection {
    case .idle(let revision), .enforcingOpenEvents(let revision),
      .monitoringOpenEvents(let revision):
      revision
    default:
      nil
    }
  }

  /// How old the latest runtime evidence is, formatted for the current language.
  var evidenceAgeDescription: String? {
    guard let latestEvidence else { return nil }
    let receivedAt = min(latestEvidence.receivedAt, Date())
    return receivedAt.formatted(.relative(presentation: .named, unitsStyle: .abbreviated))
  }

  var evidenceIsStale: Bool {
    guard let latestEvidence else { return false }
    return Date().timeIntervalSince(latestEvidence.receivedAt)
      > HealthStateReducer.runtimeFreshnessInterval
  }

  /// One line naming the source of the status and its age.
  var evidenceSummary: String {
    let age = evidenceAgeDescription ?? ""
    switch health.runtimeEvidenceSource {
    case .authenticatedXPC:
      if evidenceIsStale {
        return String(localized: "Last authenticated check · \(age)")
      }
      return String(localized: "Verified over an authenticated connection · \(age)")
    case .diagnosticFile:
      return String(localized: "Diagnostic file only · not authenticated")
    case nil:
      return String(localized: "No runtime evidence")
    }
  }

  var coveredEventsDescription: String {
    let events = health.coveredAuthorizationEvents
    return events.isEmpty
      ? String(localized: "None reported yet") : events.joined(separator: ", ")
  }

  var runtimeEvidenceDescription: String {
    switch health.runtimeEvidenceSource {
    case .authenticatedXPC:
      String(
        localized:
          "Authenticated connection (within \(Int(HealthStateReducer.runtimeFreshnessInterval)) seconds)"
      )
    case .diagnosticFile:
      String(localized: "Diagnostic file only (cannot confirm protection)")
    case nil:
      String(localized: "No runtime evidence")
    }
  }

  var installationStateDescription: String {
    guard let installation else { return String(localized: "Not installed") }
    if installation.isUninstalling { return String(localized: "Uninstalling") }
    if installation.isAwaitingUserApproval { return String(localized: "Waiting for approval") }
    return installation.isEnabled
      ? String(localized: "Enabled") : String(localized: "Not enabled")
  }

  var installedExtensionIdentifier: String? {
    installation?.bundleIdentifier
  }

  /// Pass the current time as `now`. A `TimelineView` entry date can be earlier than the latest
  /// query, and a query from the future reads as out of date.
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
    guard let activePolicySet else { return String(localized: "No saved policies") }
    let protectionCount = activePolicySet.policies.lazy.filter { $0.mode == .protection }.count
    let auditCount = activePolicySet.policies.count - protectionCount
    return String(
      localized: "Protection policies: \(protectionCount) · Audit policies: \(auditCount)")
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

  /// Problems listed under "Needs attention" on the Overview. The status summary is not repeated.
  func attentionItems(now: Date = Date()) -> [AttentionItem] {
    var items: [AttentionItem] = []
    if let warning = health.policyWarning {
      items.append(
        AttentionItem(
          id: "policyWarning",
          text: String(localized: "The extension reported a policy warning."),
          detail: RuntimeText.localized(warning)))
    }
    if let warning = policySynchronizationWarning {
      items.append(AttentionItem(id: "policySync", text: warning))
    }
    if let warning = systemCompatibilitySynchronizationWarning {
      items.append(AttentionItem(id: "compatibility", text: RuntimeText.localized(warning)))
    }
    let dropped = droppedAuditEventCount
    let storageProblems =
      (auditDeliveryMetrics?.storageFailures ?? 0) + (auditDeliveryMetrics?.admissionDrops ?? 0)
    if dropped > 0 || storageProblems > 0 {
      let text =
        dropped > 0 && storageProblems == 0
        ? String(localized: "\(dropped) log records couldn’t be saved during this run.")
        : String(localized: "Some log records couldn’t be saved during this run.")
      items.append(
        AttentionItem(
          id: "auditLoss", text: text, action: .diagnostics))
    }
    if let responses = authorizationMetrics, responses.failures + responses.deadlineExceeded > 0 {
      items.append(
        AttentionItem(
          id: "authorization",
          text: String(
            localized: "Some authorization responses failed or finished after the deadline."),
          action: .diagnostics))
    }
    switch health.protection {
    case .idle, .enforcingOpenEvents, .monitoringOpenEvents, .degraded:
      let overview = extensionVersionOverview(now: now)
      if overview.tone == .attention {
        items.append(
          AttentionItem(
            id: "versions", text: overview.comparison, detail: overview.notices.first?.text,
            action: .extensionSettings))
      }
    default:
      break
    }
    if pendingUninstall != nil || uninstallStateError != nil {
      items.append(
        AttentionItem(
          id: "uninstall",
          text: String(
            localized: "An uninstall is in progress. Automatic extension updates are paused."),
          action: .continueUninstall))
    }
    if loginItemState == .requiresApproval {
      items.append(
        AttentionItem(
          id: "loginItem",
          text: String(localized: "Open at Login needs approval in System Settings."),
          action: .loginItems))
    }
    if let error = loginItemError {
      items.append(AttentionItem(id: "loginItemError", text: error, action: .generalSettings))
    }
    return items
  }

  // MARK: - Onboarding

  var showsOnboarding: Bool {
    guard hasCompletedStatusCheck, !hasChosenFirstPolicySetup else { return false }
    return SetupProgress.showsOnboarding(
      health,
      hasEverSeenActivePolicy: hasEverSeenActivePolicySet
    )
  }

  var setupStepStates: SetupStepStates {
    SetupProgress.stepStates(health)
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
    lastError = String(localized: "System Settings could not be opened.")
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
    defer { hasCompletedStatusCheck = true }
    refreshLoginItemState()
    let properties: [ExtensionInstallationProperties]
    do {
      properties = try await fetchInstallationProperties()
    } catch {
      health = HealthState(
        protection: .degraded(
          reason: String(
            localized:
              "macOS did not report the system extension state: \(UserFacingError.message(error))")
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
        let message = UserFacingError.extensionClient(error)
        health = HealthState(protection: .degraded(reason: message))
        policySynchronizationWarning = message
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
      loginItemError = String(
        localized: "Open at Login could not be changed: \(error.localizedDescription)")
    }
  }

  func openLoginItemsSettings() {
    loginItemController.openSystemSettings()
  }

  func stopProtectionForQuit() async -> StopProtectionQuitOutcome {
    guard !isBusy, !isStoppingProtectionForQuit else {
      return .failed(String(localized: "Another Pasu FS operation is already in progress."))
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
          throw UninstallFlowError(
            String(
              localized: "Pasu FS could not verify that the Mac restarted. No files were removed."
            ))
        }
        guard previousBoot != currentBoot else {
          throw UninstallFlowError(
            String(
              localized:
                "Restart this Mac, then open Pasu FS again to finish uninstalling. No application or policy files have been removed."
            ))
        }
      }
      ticket = try await uninstallAuthorizer.prepare(
        using: maintenanceClient, removeData: removeData)
      guard let ticket else {
        throw UninstallFlowError(String(localized: "No uninstall approval was returned."))
      }
      operationMessage = String(localized: "Checking whether protection can be removed…")
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
            throw UninstallFlowError(
              String(
                localized:
                  "Pasu FS could not verify that the system extension was removed. No application files were removed."
              ))
          }
          outcome = .requiresRestart
        }
      }
      switch outcome {
      case .failed(let description): throw UninstallFlowError(description)
      case .requiresRestart:
        extensionRequestAccepted = true
        // Persist the reboot barrier even if login-item unregistration then fails.
        try await maintenanceClient.commit(ticket: ticket, action: .awaitRestart)
        try unregisterLoginItemForUninstall()
        pendingUninstall = try readUninstallState()
        operationMessage = String(
          localized:
            "Restart this Mac, then open Pasu FS to finish uninstalling. The app and its data remain in place."
        )
        return false
      case .completed:
        extensionRequestAccepted = true
      }
      try unregisterLoginItemForUninstall()
      try await maintenanceClient.commit(ticket: ticket, action: .removeFiles)
      isFinalizingUninstall = true
      operationMessage = String(
        localized: "The maintenance service accepted the final cleanup. Pasu FS will now quit.")
      return true
    } catch {
      if let ticket, !extensionRequestAccepted {
        try? await maintenanceClient.commit(ticket: ticket, action: .cancel)
      }
      await maintenanceClient.invalidate()
      do { pendingUninstall = try readUninstallState() } catch {
        uninstallStateError = UserFacingError.message(error)
      }
      lastError = UserFacingError.message(error)
      operationMessage = nil
      return false
    }
  }

  /// The failure recorded by the maintenance service, in the user's language when its code is
  /// known. Older state files carry only the English text.
  var pendingUninstallFailureMessage: String? {
    guard let pending = pendingUninstall, let failure = pending.failure else { return nil }
    guard let code = pending.failureCode else { return failure }
    return UserFacingError.maintenance(code, detail: pending.failureDetail)
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
      operationMessage = String(localized: "Removing the login registration…")
      do {
        try loginItemController.unregister()
      } catch {
        throw UninstallFlowError(
          String(
            localized: "Could not remove the login registration: \(error.localizedDescription)"
          ))
      }
      refreshLoginItemState()
      guard loginItemState == .notRegistered || loginItemState == .notFound else {
        throw UninstallFlowError(
          String(
            localized:
              "macOS still reports a login registration. No application files were removed."))
      }
    }
  }

  var activeRevision: UInt64? {
    acceptedRevision > 0 ? acceptedRevision : nil
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
      return UserFacingError.message(AppModelError.policyRevisionExhausted)
    }
    if let path = policyDrafts[id]?.protectedRootPath,
      let issue = ProtectedFolderCheck.issue(for: path)
    {
      return issue.userFacingMessage
    }
    do {
      _ = try candidateDocument(replacing: id, with: policyDrafts[id])
      return nil
    } catch {
      return UserFacingError.message(error)
    }
  }

  var canCreatePolicy: Bool {
    policyOrder.count < PolicySetDocument.maximumPolicyCount
  }

  /// Adds an unsaved Audit whitelist without a folder and opens it with its folder field
  /// focused. Audit blocks nothing, so the log can show which programs to allow before the
  /// policy is switched to Protection.
  func createNewPolicy() {
    let countBefore = policyOrder.count
    createPolicy(
      name: nextAvailablePolicyName(), protectedRootPath: "", mode: .audit, policyType: .whitelist)
    guard policyOrder.count > countBefore, case .policy(let id) = selectedSection else { return }
    pendingFolderEntryPolicyID = id
  }

  /// Adds an unsaved draft and opens it. Nothing is applied until the policy is saved.
  func createPolicy(
    name: String,
    protectedRootPath: String,
    mode: PolicyMode,
    policyType: PolicyType
  ) {
    guard canCreatePolicy else {
      lastError = UserFacingError.message(
        PolicyValidationError.tooManyPolicies(policyOrder.count + 1))
      return
    }
    let trimmedName = name.trimmingCharacters(in: .whitespacesAndNewlines)
    let draft = DirectoryPolicyDraft(
      name: trimmedName.isEmpty ? nextAvailablePolicyName() : trimmedName,
      mode: mode,
      policyType: policyType,
      protectedRootPath: protectedRootPath
    )
    policyDrafts[draft.id] = draft
    policyOrder.append(draft.id)
    selectedSection = .policy(draft.id)
    hasChosenFirstPolicySetup = true
    lastError = nil
    operationMessage = nil
  }

  /// The name of another policy that already uses this folder in the same mode.
  func conflictingPolicyName(mode: PolicyMode, path: String, excluding id: UUID? = nil) -> String? {
    guard !path.isEmpty else { return nil }
    let key = PolicySetDocument.canonicalPathComparisonKey(path)
    return policyOrder.lazy
      .compactMap { self.policyDrafts[$0] }
      .first {
        $0.id != id && $0.mode == mode
          && !$0.protectedRootPath.isEmpty
          && PolicySetDocument.canonicalPathComparisonKey($0.protectedRootPath) == key
      }?
      .name
  }

  private static func policyNameKey(_ name: String) -> String {
    name.trimmingCharacters(in: .whitespacesAndNewlines).folding(
      options: [.caseInsensitive, .diacriticInsensitive],
      locale: Locale(identifier: "en_US_POSIX")
    )
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
      operationMessage = String(
        localized: "Saved. The policies were applied as revision \(receipt.acceptedRevision).")
      await refreshHealth()
    } catch {
      lastError = UserFacingError.message(error)
      await refreshHealth()
    }
  }

  /// Switches an Audit policy to Protection and saves it in one step.
  func switchToProtection(policyID: UUID) async {
    guard policyDrafts[policyID] != nil else { return }
    updatePolicyDraft(id: policyID) { $0.mode = .protection }
    await savePolicy(id: policyID)
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
      operationMessage = String(
        localized:
          "The policy was deleted. The remaining policies were applied as revision \(receipt.acceptedRevision)."
      )
      await refreshHealth()
    } catch {
      lastError = UserFacingError.message(error)
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
      selectedSection = .overview
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
    let used = Set(policyDrafts.values.map { Self.policyNameKey($0.name) })
    var number = 1
    while used.contains(Self.policyNameKey(Self.numberedPolicyName(number))) {
      number += 1
    }
    return Self.numberedPolicyName(number)
  }

  private static func numberedPolicyName(_ number: Int) -> String {
    String(localized: "Policy \(number)")
  }

  // MARK: - Rules

  /// Reads an application's code signature and returns the identity a rule would store.
  func applicationCandidate(at url: URL) throws -> AuditRuleCandidate {
    let info = try SigningInfoReader.read(fromApplicationAt: url)
    if !info.isPlatformBinary, info.teamIdentifier?.isEmpty ?? true {
      throw AppModelError.applicationHasNoTeamIdentifier
    }
    let kind: PolicyRuleKind = info.isPlatformBinary ? .platformBinary : .teamSigned
    return AuditRuleCandidate(
      id: identityKey(
        kind: kind, teamIdentifier: info.teamIdentifier,
        signingIdentifier: info.signingIdentifier),
      kind: kind,
      teamIdentifier: info.isPlatformBinary ? nil : info.teamIdentifier?.uppercased(),
      signingIdentifier: info.signingIdentifier,
      displayName: FileManager.default.displayName(atPath: url.path),
      executablePath: url.path,
      lastSeen: Date(),
      observationCount: 0
    )
  }

  /// A candidate for a manually entered identity. Validation matches the saved policy rules.
  func manualCandidate(
    kind: PolicyRuleKind, teamIdentifier: String, signingIdentifier: String
  ) -> AuditRuleCandidate {
    let team = teamIdentifier.trimmingCharacters(in: .whitespacesAndNewlines).uppercased()
    let signing = signingIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
    return AuditRuleCandidate(
      id: identityKey(
        kind: kind, teamIdentifier: kind == .teamSigned ? team : nil, signingIdentifier: signing),
      kind: kind,
      teamIdentifier: kind == .teamSigned ? team : nil,
      signingIdentifier: signing,
      displayName: signing,
      executablePath: nil,
      lastSeen: Date(),
      observationCount: 0
    )
  }

  func addRule(
    policyID: UUID, from candidate: AuditRuleCandidate, allowsDescendants: Bool = false
  ) throws {
    guard !candidate.signingIdentifier.isEmpty else {
      throw AppModelError.signingIdentifierRequired
    }
    guard !policyContainsIdentity(policyID: policyID, candidate: candidate) else {
      throw AppModelError.duplicateRuleIdentity
    }
    let ruleID = "rule.\(UUID().uuidString.lowercased())"
    let rule: PolicyRule
    switch candidate.kind {
    case .teamSigned:
      guard let teamIdentifier = candidate.teamIdentifier, !teamIdentifier.isEmpty else {
        throw AppModelError.auditIdentityIncomplete
      }
      rule = .teamSigned(
        id: ruleID,
        teamIdentifier: teamIdentifier.uppercased(),
        signingIdentifier: candidate.signingIdentifier,
        isEnabled: true,
        allowsDescendants: allowsDescendants
      )
    case .platformBinary:
      rule = .platformBinary(
        id: ruleID,
        signingIdentifier: candidate.signingIdentifier,
        isEnabled: true,
        allowsDescendants: allowsDescendants
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
    guard !identifier.isEmpty else { return String(localized: "New program") }
    if let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: identifier) {
      return FileManager.default.displayName(atPath: url.path)
    }
    if let path = observedExecutablePath(for: rule) {
      return (path as NSString).lastPathComponent
    }
    return identifier
  }

  /// The executable most recently seen with this rule's identity in the loaded records.
  private func observedExecutablePath(for rule: PolicyRule) -> String? {
    let batches = policyLogs.values.map(\.batch)
    for batch in batches {
      let match = batch.records.last { record in
        guard record.signingIdentifier == rule.signingIdentifier else { return false }
        switch rule.kind {
        case .platformBinary:
          return record.isPlatformBinary == true
        case .teamSigned:
          return record.teamIdentifier?.uppercased() == rule.teamIdentifier?.uppercased()
        }
      }
      if let path = match?.executablePath, !path.isEmpty {
        return path
      }
    }
    return nil
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
        ? String(localized: "The system compatibility profile was turned on.")
        : String(localized: "The system compatibility profile was turned off.")
      let removed = candidate.removedObsoleteItemCount
      operationMessage =
        removed == 0
        ? result
        : result + " "
          + String(localized: "Removed \(removed) compatibility settings that no longer apply.")
    } catch {
      lastError = UserFacingError.message(error)
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

  // MARK: - Policy logs

  /// Signed programs that opened files in this policy's folder, from its loaded log.
  func ruleCandidates(policyID: UUID) -> [AuditRuleCandidate] {
    struct Accumulator {
      var kind: PolicyRuleKind
      var teamIdentifier: String?
      var signingIdentifier: String
      var executablePath: String?
      var lastSeen: Date
      var observationCount: Int
    }

    var grouped: [String: Accumulator] = [:]
    for record in policyLogState(policyID: policyID)?.batch.records ?? [] {
      guard record.eventType == "AUTH_OPEN",
        let signingIdentifier = record.signingIdentifier, !signingIdentifier.isEmpty
      else {
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
        }
        grouped[key] = existing
      } else {
        grouped[key] = Accumulator(
          kind: kind,
          teamIdentifier: teamIdentifier,
          signingIdentifier: signingIdentifier,
          executablePath: record.executablePath,
          lastSeen: record.timestamp,
          observationCount: 1
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
        observationCount: value.observationCount
      )
    }
    .sorted { $0.lastSeen > $1.lastSeen }
  }

  /// Reloads the log of every saved policy.
  func refreshPolicyAuditLogs() async {
    for policy in activePolicySet?.policies ?? [] {
      await refreshPolicyAuditLog(policyID: policy.id)
    }
  }

  /// Whether any saved policy's log has been loaded.
  var hasLoadedPolicyLogs: Bool {
    (activePolicySet?.policies ?? []).contains {
      policyLogState(policyID: $0.id)?.hasLoaded == true
    }
  }

  /// Errors from loading saved policies' logs.
  var policyLogErrors: [String] {
    (activePolicySet?.policies ?? []).compactMap { policyLogState(policyID: $0.id)?.error }
  }

  /// The newest opens that Pasu FS actually denied among the loaded policy logs.
  func recentDenials(limit: Int = 3) -> [RecentDenial] {
    let denials = (activePolicySet?.policies ?? []).flatMap { policy in
      (policyLogState(policyID: policy.id)?.batch.records ?? [])
        .filter { $0.kernelResponse == "deny" }
        .map { RecentDenial(policyID: policy.id, policyName: policy.name, record: $0) }
    }
    // An open that falls under several policies is recorded in each of their logs.
    var seen = Set<String>()
    let unique = denials.sorted { $0.record.timestamp > $1.record.timestamp }
      .filter { seen.insert($0.record.id).inserted }
    return Array(unique.prefix(limit))
  }

  /// Opens a policy's Log tab with one record selected in its details.
  func showPolicyLogRecord(policyID: UUID, recordID: String) {
    if let log = policyLogState(policyID: policyID) {
      log.presentation = .events
      log.filterText = ""
      log.selectedEventIDs = [recordID]
      log.wantsInspector = true
    }
    pendingPolicyLogPolicyID = policyID
    selectedSection = .policy(policyID)
  }

  func policyProgramSummaries(policyID: UUID) -> [PolicyProgramSummary] {
    guard let log = policyLogState(policyID: policyID) else { return [] }
    return PolicyProgramSummarizer.summaries(
      records: log.batch.records, policyID: policyID,
      displayName: { signing, path in
        self.displayName(signingIdentifier: signing, executablePath: path)
      })
  }

  /// Loaded programs whose opens would be denied if this policy enforced its current draft.
  func projectedDenials(policyID: UUID) -> [PolicyProgramSummary] {
    guard let draft = policyDrafts[policyID] else { return [] }
    return PolicyProgramSummarizer.projectedDenials(
      summaries: policyProgramSummaries(policyID: policyID),
      policyType: draft.policyType,
      rules: draft.rules)
  }

  func draftContainsRule(policyID: UUID, summary: PolicyProgramSummary) -> PolicyRule? {
    policyDrafts[policyID]?.rules.first { PolicyProgramSummarizer.ruleKey($0) == summary.id }
  }

  /// Whether the main window drops its minimum width: the selected policy's Log tab is on
  /// screen and shows its inspector or is about to. See MainWindowLayout.
  var relaxesMainWindowMinimumWidth: Bool {
    guard case .policy(let id) = selectedSection, let log = policyLogState(policyID: id) else {
      return false
    }
    return log.isOnScreen && log.wantsInspector
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
      log.error = UserFacingError.message(error)
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
        systemCompatibilitySynchronizationWarning = String(
          localized:
            "The app and extension use different system compatibility definitions. You can still edit policies, but compatibility profiles can’t be changed until matching versions are installed."
        )
      } else {
        let unresolved = snapshot.profileResolutions.filter {
          $0.isEnabled && $0.state != .active
        }
        systemCompatibilitySynchronizationWarning =
          unresolved.isEmpty
          ? nil
          : String(localized: "One or more turned-on system compatibility profiles need review.")
      }
    } catch {
      systemCompatibilityState = nil
      systemCompatibilitySynchronizationWarning = String(
        localized:
          "The system compatibility state could not be read: \(UserFacingError.message(error))")
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
          String(
            localized:
              "The runtime status and the saved policies report different policy set identifiers.")
        )
      }
      if let reportedRevision, policySet.revision != reportedRevision {
        warnings.append(
          String(
            localized:
              "The runtime status reports revision \(reportedRevision), but the saved policies are revision \(policySet.revision)."
          )
        )
      }
      if !dirtyPolicyIDs.isEmpty {
        warnings.append(
          String(
            localized:
              "The saved policies changed while you were editing. Your unsaved changes were kept; saving replaces only the selected policy in the latest saved policies."
          )
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
        let detail = UserFacingError.message(error)
        policySynchronizationWarning =
          reportedRevision.map {
            String(
              localized:
                "The extension reports policy revision \($0), but the saved policies could not be read: \(detail)"
            )
          }
          ?? String(localized: "The saved policies could not be read: \(detail)")
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
    let description = String(
      localized: "macOS finished the extension query without returning version information.")
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

    operationMessage = String(
      localized: "The app includes a newer extension. Asking macOS to update it.")
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
      return .failed(String(localized: "Another Pasu FS operation is already in progress."))
    }
    isBusy = true
    lastError = nil
    if tracksActivation {
      isRequestingActivation = true
      activationProgress = String(localized: "Updating the extension…")
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
        operationMessage =
          action == "deactivate"
          ? String(localized: "Sent the deactivation request to macOS.")
          : String(localized: "Sent the activation request to macOS.")
      case .waitingForUserApproval:
        operationMessage = String(localized: "Waiting for approval in System Settings.")
        if tracksActivation {
          activationProgress = String(localized: "Approval needed in System Settings")
        }
      case .replacing(let existing, let new):
        operationMessage = String(localized: "Replacing build \(existing) with build \(new).")
        if tracksActivation { activationProgress = String(localized: "Updating the extension…") }
      case .completed(let rebootRequired):
        operationMessage =
          rebootRequired
          ? String(localized: "The request will finish after the Mac restarts.")
          : String(localized: "macOS completed the request.")
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
      ?? .failed(
        String(localized: "macOS ended the system extension request without a result."))
    if tracksActivation { activationOutcome = result }
    return result
  }
}

enum AppModelError: Error, CustomStringConvertible, UserFacingErrorConvertible {
  case policyRevisionExhausted
  case policySetReceiptMismatch
  case duplicateRuleIdentity
  case auditIdentityIncomplete
  case signingIdentifierRequired
  case applicationHasNoTeamIdentifier
  case systemCompatibilityCatalogMismatch
  case systemCompatibilityRequiresSavedPolicy
  case systemCompatibilityRequiresWhitelist
  case systemCompatibilityProfileMissing
  case systemCompatibilityReceiptMismatch
  case systemCompatibilityRevisionExhausted
  case installationPropertiesFailed(String)

  /// Interpolated into runtime messages; the properties failure keeps macOS's own text.
  var description: String {
    switch self {
    case .installationPropertiesFailed(let description):
      description
    default:
      userFacingMessage
    }
  }

  var userFacingMessage: String {
    switch self {
    case .policyRevisionExhausted:
      String(localized: "The policy revision counter has reached its limit.")
    case .policySetReceiptMismatch:
      String(localized: "The extension confirmed a different policy set or revision.")
    case .duplicateRuleIdentity:
      String(localized: "This program already has a rule in this policy.")
    case .auditIdentityIncomplete:
      String(localized: "The record does not contain a complete signing identity.")
    case .signingIdentifierRequired:
      String(localized: "Enter a Signing ID.")
    case .applicationHasNoTeamIdentifier:
      String(
        localized:
          "This app has no Team ID. Only developer-signed apps and Apple platform binaries can be added."
      )
    case .systemCompatibilityCatalogMismatch:
      String(
        localized:
          "Compatibility profiles can’t be changed until the app and extension use the same built-in definitions."
      )
    case .systemCompatibilityRequiresSavedPolicy:
      String(localized: "Save this policy before changing its compatibility profiles.")
    case .systemCompatibilityRequiresWhitelist:
      String(localized: "Compatibility profiles apply only to Whitelist policies.")
    case .systemCompatibilityProfileMissing:
      String(localized: "The selected compatibility profile is not in the built-in definitions.")
    case .systemCompatibilityReceiptMismatch:
      String(localized: "The extension confirmed different compatibility settings.")
    case .systemCompatibilityRevisionExhausted:
      String(localized: "The compatibility settings revision counter has reached its limit.")
    case .installationPropertiesFailed(let description):
      String(localized: "macOS did not report the system extension state: \(description)")
    }
  }
}
