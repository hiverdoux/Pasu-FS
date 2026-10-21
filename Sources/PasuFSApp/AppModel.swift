import AppKit
import Foundation
import Observation
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSIPC
import PasuFSMaintenanceCore
import PasuFSPolicy

enum SidebarSelection: Hashable {
  case overview
  case policy(UUID)
}

enum SettingsTab: Hashable {
  case general
  case extensionStatus
  case diagnostics
}

/// Opens the Add Program sheet for one of a policy's lists, optionally with an identity already
/// chosen.
struct AddProgramRequest: Identifiable, Equatable {
  let id = UUID()
  let policyID: UUID
  var list: PolicyRuleList = .allow
  var preselected: AuditRuleCandidate?
}

struct AttentionItem: Identifiable, Equatable {
  enum Action: Equatable {
    case diagnostics
    case extensionSettings
    case generalSettings
    case continueUninstall
    case loginItems
    case showPolicy(UUID)
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

/// Whether the running extension reported the two-list execution-origin contract this app edits.
enum ExecutionOriginSupport: Equatable {
  /// No authenticated status has been read yet.
  case unknown
  case supported
  /// The extension answered without the contract, or with a version this app does not know.
  case unsupported
}

/// A save whose reply was lost. The extension may or may not have stored it.
private struct UnresolvedSave {
  var document: PolicySetDocument
  var policyID: UUID
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
  private(set) var systemCompatibilityWarning: String?
  /// The latest save the extension stored, until its authenticated status reports that revision
  /// and digest as the policies in effect. Storing a policy does not prove it was applied.
  private(set) var unconfirmedSave: PolicyApplyReceipt?
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
  private let diagnosticStatusReader = DiagnosticStatusReader()
  private var pendingSetIdentifier = UUID()
  private var acceptedRevision: UInt64 = 0
  private var activePolicySetDigest: String?
  private var unresolvedSave: UnresolvedSave?
  /// Set when the authenticated connection was lost or the extension restarted. The saved
  /// policies are then read again before the previous copy is treated as current.
  private var needsPolicyReread = false
  private var lastRuntimeInstanceIdentifier: UUID?
  /// Whether a status request waited out its timeout since the extension last answered one.
  private var statusRequestTimedOutSinceLastAnswer = false
  private var pollingTask: Task<Void, Never>?
  // Until the first status check finishes, the setup state is unknown. The main window then shows
  // its regular screens, which report that the status is being checked, rather than the setup
  // assistant.
  private var hasCompletedStatusCheck = false
  /// Reads the installation states in short-lived child processes; every reason to ask goes
  /// through it.
  private let installationStates: any InstallationStateQuerying
  /// The newest record of the installation states that a query returned.
  private(set) var installationRecord = InstallationStateRecord()
  /// The installations in `installationRecord` while they describe the Mac, as of the latest
  /// update of the state; nil means unknown, not that nothing is installed.
  private var currentInstallations: [ExtensionInstallationProperties]?
  private(set) var installationQueries = InstallationStateQueries()
  /// The screens on view that show the installation states, counted per screen.
  private var visibleStatusScreens: [StatusScreen: Int] = [:]
  /// Whether the extension answered the latest status request, or nil before the first one.
  private var runtimeAnsweredLastCheck: Bool?
  /// Why the extension's status can't be used, when the extension refused the app's protocol.
  private var runtimeFailureMessage: String?
  /// True while a Refresh command reads the installation states and the status again.
  private(set) var isRefreshingStatus = false
  private var isRequestingActivation = false
  private var activationProgress: String?
  private var activationOutcome: LifecycleRequestOutcome?
  private var automaticExtensionUpdateCheck = AutomaticExtensionUpdateCheck()
  private let extensionReplacementRecord: ExtensionReplacementRecord
  /// True from the replacement of a running extension until the Mac restarts.
  private(set) var recommendsRestartAfterExtensionUpdate: Bool

  /// Whether the Overview recommends a restart after an extension update. Programs opened before
  /// it can have incomplete histories, which some policies deny. The recommendation follows the
  /// saved policies as they change during the boot session.
  var showsRestartRecommendationAfterExtensionUpdate: Bool {
    recommendsRestartAfterExtensionUpdate
      && (activePolicySet?.policies ?? []).contains(where: \.deniesProgramsWithIncompleteHistory)
  }
  private let maintenanceClient: any MaintenanceControlling
  private let uninstallAuthorizer: any UninstallAuthorizing
  private let policyChangeAuthorizer: any PolicyChangeAuthorizing
  private let readUninstallState: @MainActor () throws -> UninstallState?
  /// The compatibility profiles the policy editor offers.
  let systemCompatibilityCatalog: SystemCompatibilityCatalog

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
    policyChangeAuthorizer: any PolicyChangeAuthorizing = SystemPolicyChangeAuthorizer(),
    uninstallStateReader: (@MainActor () throws -> UninstallState?)? = nil,
    extensionReplacementRecord: ExtensionReplacementRecord = ExtensionReplacementRecord(),
    installationStateTimeout: TimeInterval = InstallationStateQueries.answerTimeout,
    installationStateQuerier: (any InstallationStateQuerying)? = nil
  ) {
    self.extensionReplacementRecord = extensionReplacementRecord
    installationStates =
      installationStateQuerier
      ?? InstallationStateQueryManager(
        launcher: activationController.installationStateLauncher(),
        timeout: installationStateTimeout)
    self.systemCompatibilityCatalog = systemCompatibilityCatalog
    recommendsRestartAfterExtensionUpdate = extensionReplacementRecord.recommendsRestart
    self.maintenanceClient = maintenanceClient ?? MaintenanceClient(hostBundleURL: hostBundleURL)
    self.uninstallAuthorizer = uninstallAuthorizer
    self.policyChangeAuthorizer = policyChangeAuthorizer
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
    if let runtimeController {
      controlClient = runtimeController
    } else {
      controlClient = ExtensionControlClient(hostBundleURL: hostBundleURL)
    }
    if let initialPolicySet {
      installActivePolicySet(initialPolicySet)
    }
  }

  // MARK: - Health presentation

  var status: StatusPresentation {
    // Without trustworthy policies or folders, the saved policies protect nothing, whatever
    // state the extension reports for the policies it has left.
    if policyStorageState == .unavailable {
      var unprotected = health
      unprotected.protection = .degraded(reason: PolicyStorageText.summary(.unavailable) ?? "")
      return StatusPresentation(health: unprotected)
    }
    return StatusPresentation(health: health)
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

  /// The time of the extension's last status while the extension doesn't respond, or nil. See
  /// `ExtensionResponsiveness`.
  func unresponsiveExtensionLastStatus(now: Date = Date()) -> Date? {
    ExtensionResponsiveness.lastStatusOfUnresponsiveExtension(
      installation: installation, evidence: latestEvidence,
      requestTimedOutSinceLastAnswer: statusRequestTimedOutSinceLastAnswer, now: now)
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
    // Without a current report, an empty installation is unknown rather than absent.
    guard currentInstallations != nil else {
      return installationRecord.installations == nil && installationRecord.failure == nil
        && installationRecord.unansweredSince == nil
        ? String(localized: "Checking…") : String(localized: "Can’t confirm")
    }
    guard let installation else { return String(localized: "Not installed") }
    if health.changeAtRestart == .update {
      return String(localized: "Update waiting for restart")
    }
    if installation.isUninstalling { return String(localized: "Uninstalling") }
    if installation.isAwaitingUserApproval { return String(localized: "Waiting for approval") }
    return installation.isEnabled
      ? String(localized: "Enabled") : String(localized: "Not enabled")
  }

  var installedExtensionIdentifier: String? {
    installation?.bundleIdentifier
  }

  /// Whether macOS already removes every version of the extension it reports. The preferred
  /// installation is being removed only when all of them are. A deactivation that waits for a
  /// restart leaves the extension running and reported as being removed until then.
  var extensionRemovalIsPending: Bool {
    installation?.isUninstalling == true
  }

  /// Whether macOS reports that no version of the extension is installed, in a report that still
  /// describes the Mac. Without such a report the app can't tell, and macOS answers a request.
  var extensionIsReportedNotInstalled: Bool {
    currentInstallations != nil && installation == nil
  }

  /// Pass the current time as `now`. A `TimelineView` entry date can be earlier than the latest
  /// query, and a query from the future reads as out of date.
  func extensionVersionOverview(now: Date) -> ExtensionVersionOverview {
    var runningExtension: ProductVersion?
    if let latestEvidence, latestEvidence.source == .authenticatedXPC,
      (0...HealthStateReducer.runtimeFreshnessInterval).contains(
        now.timeIntervalSince(latestEvidence.receivedAt))
    {
      runningExtension = ProductVersion(runningExtension: latestEvidence.snapshot)
    }
    return ExtensionVersionOverview(
      app: appProductVersion, included: includedExtensionVersion,
      installations: installationRecord.installations ?? [],
      observedAt: installationRecord.reportedAt,
      unansweredSince: installationRecord.unansweredSince,
      queryError: installationRecord.failure.map(InstallationStateText.failureDetail),
      runningExtension: runningExtension,
      isRequestingActivation: isRequestingActivation, activationProgress: activationProgress,
      activationOutcome: activationOutcome, now: now
    )
  }

  var auditDeliveryMetrics: AuditDeliveryMetrics? { latestEvidence?.snapshot.auditDelivery }
  var authorizationMetrics: AuthorizationMetrics? { latestEvidence?.snapshot.authorization }
  var uncheckedRequestMetrics: UncheckedRequestMetrics? {
    latestEvidence?.snapshot.uncheckedRequests
  }
  var processLineageStatus: ProcessLineageStatus? { latestEvidence?.snapshot.processLineageStatus }
  var executionOriginStatus: ExecutionOriginStatus? {
    latestEvidence?.snapshot.executionOriginStatus
  }
  /// When the extension connected to Endpoint Security; absent from older extensions.
  var endpointConnection: EndpointConnectionStatus? {
    latestEvidence?.snapshot.endpointConnection
  }

  /// The latest status the running extension answered directly. A diagnostic file is not one.
  private var authenticatedSnapshot: ExtensionStatusSnapshot? {
    guard let latestEvidence, latestEvidence.source == .authenticatedXPC else { return nil }
    return latestEvidence.snapshot
  }

  /// A status without the capability report does not establish support.
  var executionOriginSupport: ExecutionOriginSupport {
    guard let snapshot = authenticatedSnapshot else { return .unknown }
    guard let capabilities = snapshot.executionOriginCapabilities,
      capabilities.version == ExecutionOriginCapabilities.currentVersion,
      capabilities.policySchemaVersion == PolicySetDocument.currentSchemaVersion,
      capabilities.usesCommonAllowListForOriginAndActor, capabilities.preservesInactiveAllowList,
      capabilities.supportsDescendantAccessGrants
    else { return .unsupported }
    return .supported
  }

  /// Whether the running extension applies compatibility profiles. Until an authenticated status
  /// says so, the policy editor offers none; profiles a policy already has are still shown.
  var supportsSystemCompatibilityProfiles: Bool {
    authenticatedSnapshot?.executionOriginCapabilities?.supportsSystemCompatibilityBypass == true
  }

  /// The compatibility profiles active in the policies in effect, as the extension reports.
  var activeSystemCompatibilityProfileCount: Int? {
    latestEvidence?.snapshot.activeSystemCompatibilityProfileCount
  }

  /// How the extension obtained the saved policies it reports.
  var policyStorageState: PolicyStorageState? { authenticatedSnapshot?.policyStorageState }

  /// True while the extension serves emergency policies that deny every request in the Protection
  /// folders it still knows. Their programs were lost and are not the saved configuration.
  var isServingRecoveryPolicies: Bool { policyStorageState == .denyAllRecovery }

  var activePolicyDigestDescription: String? { authenticatedSnapshot?.activePolicyDigest }

  /// The retired folder paths of a saved policy, oldest first, as the running extension last
  /// reported them. Saving the policy releases them.
  func retiredFolderPaths(policyID: UUID) -> [String] {
    guard activePolicy(id: policyID) != nil else { return [] }
    return authenticatedSnapshot?.retiredFolderPaths?.first { $0.policyIdentifier == policyID }?
      .paths ?? []
  }

  /// The number of retired folder paths of all policies, or nil when the extension does not
  /// report them.
  var retiredFolderPathCount: Int? {
    latestEvidence?.snapshot.retiredFolderPaths?.reduce(0) { $0 + $1.paths.count }
  }

  /// Which requests Endpoint Security delivers to the extension; absent from older extensions.
  var targetPathMuting: TargetPathMutingStatus? {
    latestEvidence?.snapshot.targetPathMuting
  }

  /// What macOS does with the requests the extension doesn't answer; absent from older extensions.
  var deadlineMissMode: DeadlineMissModeStatus? {
    latestEvidence?.snapshot.deadlineMissMode
  }

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
    if let lastStatus = unresponsiveExtensionLastStatus(now: now) {
      let age = Duration.seconds(now.timeIntervalSince(lastStatus)).formatted(
        .units(allowed: [.hours, .minutes, .seconds], width: .wide, maximumUnitCount: 1))
      items.append(
        AttentionItem(
          id: "unresponsiveExtension",
          text: String(
            localized: "The extension isn’t responding (last status \(age) ago). Restart this Mac."
          )))
    }
    if let item = installationStatesUnansweredItem(now: now) {
      items.append(item)
    }
    let storageSummary = policyStorageState.flatMap(PolicyStorageText.summary)
    if let storageSummary {
      items.append(
        AttentionItem(
          id: "policyStorage", text: storageSummary,
          detail: health.policyWarning.map(RuntimeText.localized)))
    } else if let warning = health.policyWarning {
      items.append(
        AttentionItem(
          id: "policyWarning",
          text: String(localized: "The extension reported a policy warning."),
          detail: RuntimeText.localized(warning)))
    }
    if executionOriginSupport == .unsupported {
      items.append(
        AttentionItem(
          id: "originSupport",
          text: UserFacingError.message(AppModelError.executionOriginUnsupported),
          action: .extensionSettings))
    }
    if let unconfirmedSave, unresolvedSave == nil, authenticatedSnapshot != nil {
      items.append(
        AttentionItem(
          id: "unconfirmedSave",
          text: String(
            localized:
              "Saved as revision \(unconfirmedSave.acceptedRevision). The extension has not confirmed that it is in effect."
          )))
    }
    if let warning = policySynchronizationWarning {
      items.append(AttentionItem(id: "policySync", text: warning))
    }
    if let warning = systemCompatibilityWarning {
      items.append(AttentionItem(id: "compatibility", text: RuntimeText.localized(warning)))
    }
    for policy in activePolicies {
      let paths = retiredFolderPaths(policyID: policy.id)
      guard !paths.isEmpty else { continue }
      items.append(
        AttentionItem(
          id: "retiredFolderPaths-\(policy.id.uuidString)",
          text: paths.count == 1
            ? String(
              localized: "“\(policy.name)” protects a retired path until the policy is saved.")
            : String(
              localized: "“\(policy.name)” protects retired paths until the policy is saved."),
          detail: paths.map(PathText.abbreviated).joined(separator: "\n"),
          action: .showPolicy(policy.id)))
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
    if let unchecked = uncheckedRequestMetrics?.estimatedCount, unchecked > 0 {
      let text =
        deadlineMissMode?.deniesUnansweredRequests == true
        ? String(
          localized:
            "macOS denied up to \(unchecked) requests without asking Pasu FS during this run.")
        : String(
          localized:
            "macOS allowed up to \(unchecked) requests without asking Pasu FS during this run.")
      items.append(AttentionItem(id: "uncheckedRequests", text: text, action: .diagnostics))
    }
    if health.changeAtRestart == .update {
      items.append(
        AttentionItem(
          id: "extensionUpdateAwaitsRestart",
          text: String(localized: "The extension update finishes when you restart this Mac."),
          detail: health.runtimeEvidenceSource == .authenticatedXPC
            ? String(
              localized:
                "Until then, the extension that was running before the update keeps checking requests."
            ) : nil,
          action: .extensionSettings))
    } else if installationRecord.unansweredSince == nil {
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
    }
    if showsRestartRecommendationAfterExtensionUpdate {
      items.append(
        AttentionItem(
          id: "extensionReplaced",
          text: String(
            localized: "The extension was updated. Restarting this Mac is recommended."),
          detail: String(
            localized:
              "Programs with incomplete execution history can be denied access to protected folders until reopened."
          )))
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

  /// The notice while macOS doesn't answer requests for the installation states. The Overview,
  /// the menu bar and the setup assistant show it.
  func installationStatesUnansweredItem(now: Date) -> AttentionItem? {
    guard let since = installationRecord.unansweredSince else { return nil }
    return AttentionItem(
      id: "installationStatesUnanswered",
      text: InstallationStateText.unanswered(since: since, now: now),
      detail: answeringExtensionDetail(now: now),
      action: .extensionSettings)
  }

  /// While macOS doesn't report the installation states, whether the extension still answers
  /// over the authenticated connection, and so still checks requests.
  func answeringExtensionDetail(now: Date) -> String? {
    guard let latestEvidence, latestEvidence.source == .authenticatedXPC,
      (0...HealthStateReducer.runtimeFreshnessInterval).contains(
        now.timeIntervalSince(latestEvidence.receivedAt))
    else { return nil }
    if case .enforcingOpenEvents = health.protection {
      return String(localized: "The extension still answers, so protection continues.")
    }
    return String(localized: "The extension still answers.")
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
        await refreshHealth(installationStates: .whenDue)
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

  /// How `refreshHealth` reads macOS's installation states.
  enum InstallationStateRead {
    /// Asks macOS now, or shares the answer of a query that already runs, and waits for the
    /// answer or the timeout.
    case now
    /// Asks macOS only when `InstallationStateQueries` says so, and waits for the answer only on
    /// the first check. A later answer updates the state when it arrives.
    case whenDue
    /// Asks macOS in a query that starts after the call, after a change to the installation, and
    /// waits for the answer or the timeout.
    case afterChange
  }

  /// Reads the extension's status over the authenticated connection, and macOS's installation
  /// states as `installationStates` says.
  func refreshHealth(installationStates read: InstallationStateRead = .now) async {
    defer { hasCompletedStatusCheck = true }
    refreshLoginItemState()
    let kind: InstallationStateQueryKind? =
      switch read {
      case .now: .refresh
      case .afterChange: .afterChange
      case .whenDue:
        installationQueries.isDue(
          at: Date(), interests: installationStateInterests, record: installationRecord)
          ? .automatic : nil
      }
    var query: Task<Void, Never>?
    if let kind {
      query = Task { _ = await self.queryInstallationStates(kind) }
    }
    let authenticatedStatus = await readRuntimeStatus()
    if let authenticatedStatus {
      await synchronizeActivePolicySet(with: authenticatedStatus)
      confirmSavedPolicies(with: authenticatedStatus)
      systemCompatibilityWarning = authenticatedStatus.systemCompatibilityWarning
    }
    // The first check waits for macOS, so that the window shows neither the setup assistant nor a
    // state without the installations before macOS answered or the timeout passed.
    if let query, read != .whenDue || !hasCompletedStatusCheck {
      let waitStarted = Date()
      await query.value
      // The periodic checks pause during the first check, so a status read before a long wait
      // would no longer count as fresh.
      if !hasCompletedStatusCheck, Date().timeIntervalSince(waitStarted) >= 2 {
        _ = await readRuntimeStatus()
      }
    }
    updateHealth()
  }

  /// Reads the installation states and the extension's status again at once, whatever the
  /// interval: the Refresh commands. A second command while one runs does nothing.
  func refreshStatusNow() async {
    guard !isRefreshingStatus else { return }
    isRefreshingStatus = true
    defer { isRefreshingStatus = false }
    await refreshHealth(installationStates: .now)
  }

  /// Records that a screen showing the installation states appeared or disappeared.
  func statusScreen(_ screen: StatusScreen, isVisible: Bool) {
    let count = (visibleStatusScreens[screen] ?? 0) + (isVisible ? 1 : -1)
    visibleStatusScreens[screen] = max(0, count)
  }

  /// What makes the installation states worth reading sooner now.
  var installationStateInterests: Set<InstallationStateInterest> {
    var interests = Set<InstallationStateInterest>()
    if visibleStatusScreens[.extensionSettings, default: 0] > 0 {
      interests.insert(.extensionSettings)
    }
    if visibleStatusScreens[.setupAssistant, default: 0] > 0, showsOnboarding,
      setupStepStates.approveExtension == .active
    {
      interests.insert(.approval)
    }
    return interests
  }

  /// Asks the extension for its status, falling back to the diagnostic file, and returns the
  /// status when the extension answered.
  private func readRuntimeStatus() async -> ExtensionStatusSnapshot? {
    let evidence: RuntimeStatusEvidence?
    var authenticatedStatus: ExtensionStatusSnapshot?
    do {
      let status = try await controlClient.queryStatus()
      authenticatedStatus = status
      statusRequestTimedOutSinceLastAnswer = false
      runtimeFailureMessage = nil
      evidence = RuntimeStatusEvidence(
        snapshot: status,
        source: .authenticatedXPC
      )
      if status.activePolicyRevision != nil {
        hasEverSeenActivePolicySet = true
      }
      if lastRuntimeInstanceIdentifier != status.runtimeInstanceIdentifier {
        // A restarted extension loads its policies again, possibly from a recovery copy.
        needsPolicyReread = lastRuntimeInstanceIdentifier != nil || needsPolicyReread
        if lastRuntimeInstanceIdentifier != nil {
          installationQueries.recordRuntimeChange()
        }
        lastRuntimeInstanceIdentifier = status.runtimeInstanceIdentifier
      }
    } catch let error as ExtensionControlClientError {
      needsPolicyReread = true
      if case .requestTimedOut = error {
        statusRequestTimedOutSinceLastAnswer = true
      }
      if case .configurationProtocolMismatch = error {
        latestEvidence = nil
        let message = UserFacingError.extensionClient(error)
        runtimeFailureMessage = message
        policySynchronizationWarning = message
        noteRuntimeAnswered(false)
        return nil
      }
      runtimeFailureMessage = nil
      evidence = diagnosticEvidence()
    } catch {
      needsPolicyReread = true
      runtimeFailureMessage = nil
      evidence = diagnosticEvidence()
    }
    latestEvidence = evidence
    noteRuntimeAnswered(authenticatedStatus != nil)
    return authenticatedStatus
  }

  private func diagnosticEvidence() -> RuntimeStatusEvidence? {
    guard let diagnostic = try? diagnosticStatusReader.read() else { return nil }
    return RuntimeStatusEvidence(
      snapshot: diagnostic,
      source: .diagnosticFile,
      receivedAt: diagnostic.timestamp
    )
  }

  /// An extension that starts or stops answering may have been enabled, approved, replaced or
  /// removed, so the installation states are read again soon.
  private func noteRuntimeAnswered(_ answered: Bool) {
    if let previous = runtimeAnsweredLastCheck, previous != answered {
      installationQueries.recordRuntimeChange()
    }
    runtimeAnsweredLastCheck = answered
  }

  /// Derives the state from the latest installation states and status. Installations that no
  /// longer describe the Mac count as unknown everywhere: in the state, the installation row and
  /// the lifecycle commands.
  private func updateHealth(now: Date = Date()) {
    currentInstallations = installationRecord.currentInstallations(at: now)
    installation = currentInstallations.flatMap(HealthStateReducer.preferredInstallation)
    if let runtimeFailureMessage {
      health = HealthState(protection: .degraded(reason: runtimeFailureMessage))
      return
    }
    health = HealthStateReducer.reduce(
      installationRecord: installationRecord, runtimeEvidence: latestEvidence, now: now)
    // Without a current report, a failed query says more than that macOS hasn't answered.
    if health.protection
      == .degraded(reason: HealthStateReducer.installationStatesUnreportedReason),
      let failure = installationRecord.failure
    {
      health.protection = .degraded(
        reason: UserFacingError.message(
          AppModelError.installationPropertiesFailed(InstallationStateText.failureDetail(failure))))
    }
  }

  /// When macOS last reported the installation states, or nil before it has.
  var installationStatesReportedAt: Date? { installationRecord.reportedAt }

  /// Since when macOS hasn't answered requests for the installation states, or nil while it
  /// answers.
  var installationStatesUnansweredSince: Date? { installationRecord.unansweredSince }

  /// Clears the pending confirmation once the extension reports the saved revision and digest
  /// as the policies in effect, or a later revision replaced them.
  private func confirmSavedPolicies(with status: ExtensionStatusSnapshot) {
    guard let receipt = unconfirmedSave else { return }
    guard status.activePolicySetIdentifier == receipt.acceptedSetIdentifier,
      let revision = status.activePolicyRevision
    else { return }
    if revision > receipt.acceptedRevision
      || (revision == receipt.acceptedRevision
        && status.activePolicyDigest == receipt.acceptedDigest)
    {
      unconfirmedSave = nil
    }
  }

  func activate() async {
    guard !isUninstalling, pendingUninstall == nil, uninstallStateError == nil else { return }
    _ = await performLifecycleRequest(
      events: activationController.activationEvents, tracksActivation: true
    )
  }

  func deactivate() async {
    guard !isUninstalling, !isBusy else { return }
    await readInstallationStatesBeforeRequest()
    // macOS would answer with an error while it already removes the extension, or when none is
    // installed.
    guard !extensionRemovalIsPending, !extensionIsReportedNotInstalled else { return }
    let outcome = await performLifecycleRequest(events: activationController.deactivationEvents)
    // While an update waits for a restart, macOS removes the waiting version at once and
    // completes the request, but the earlier version keeps running until the restart.
    if outcome == .completed, health.changeAtRestart == .removal {
      operationMessage = String(localized: "The request will finish after the Mac restarts.")
    }
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
    await readInstallationStatesBeforeRequest()

    // While macOS removes the extension, it answers another deactivation request with an error
    // (OSSystemExtensionError.extensionNotFound). The earlier request stands, and the extension
    // stops at the latest at the next restart.
    if extensionRemovalIsPending {
      isBusy = true
      let extensionWasVerifiedStopped = await verifyExtensionStopped()
      isBusy = false
      return extensionWasVerifiedStopped ? .stopped : .requiresRestart
    }

    let requestOutcome = await performLifecycleRequest(
      events: activationController.deactivationEvents
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
      extensionWasVerifiedStopped: extensionWasVerifiedStopped,
      extensionStopsAtRestart: health.changeAtRestart == .removal
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
        outcome = await performLifecycleRequest(events: activationController.deactivationEvents)
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

  /// Whether macOS already removes every version it reports at the next restart, so that a
  /// deactivation request has nothing left to remove.
  private func extensionRemovalAwaitsRestart() async throws -> Bool {
    let properties = try await fetchInstallationProperties(.afterChange).filter {
      $0.bundleIdentifier == ActivationController.extensionIdentifier
    }
    // A replaced older version may await removal while the current version still protects
    // files, or while an update to it waits for a restart. That version must receive its own
    // deactivation request: macOS would otherwise start a waiting version at the restart, and
    // the removal would need a second one.
    return !properties.isEmpty && properties.allSatisfy(\.isUninstalling)
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

  /// True when the saved policies can be saved again without a change: the extension lost the
  /// originals, so what the app shows is not what is stored.
  var savedPoliciesNeedSaving: Bool {
    policyStorageState == .denyAllRecovery || policyStorageState == .unavailable
  }

  func draftValidationMessage(for id: UUID) -> String? {
    guard acceptedRevision < UInt64.max else {
      return UserFacingError.message(AppModelError.policyRevisionExhausted)
    }
    if unresolvedSave != nil {
      return UserFacingError.message(AppModelError.previousSaveUnresolved)
    }
    if executionOriginSupport == .unsupported {
      return UserFacingError.message(AppModelError.executionOriginUnsupported)
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

  /// Adds an unsaved Audit policy that uses Programs to Allow, without a folder, and opens it
  /// with its folder field focused. Audit blocks nothing, so the log can show which programs to
  /// allow before the policy is switched to Protection.
  func createNewPolicy() {
    let countBefore = policyOrder.count
    createPolicy(name: nextAvailablePolicyName(), protectedRootPath: "", mode: .audit)
    guard policyOrder.count > countBefore, case .policy(let id) = selectedSection else { return }
    pendingFolderEntryPolicyID = id
  }

  /// Adds an unsaved draft and opens it. Nothing is applied until the policy is saved.
  func createPolicy(
    name: String,
    protectedRootPath: String,
    mode: PolicyMode
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
      protectedRootPath: protectedRootPath
    )
    policyDrafts[draft.id] = draft
    policyOrder.append(draft.id)
    selectedSection = .policy(draft.id)
    hasChosenFirstPolicySetup = true
    lastError = nil
    operationMessage = nil
  }

  /// Adds an unsaved copy of a policy and opens it with its folder field focused. The copy has
  /// the policy's lists and settings as they are shown, saved or not, but no folder, and is
  /// named after the policy. Nothing is applied until the copy is saved.
  func duplicatePolicy(id: UUID) {
    guard let source = policyDrafts[id] else { return }
    guard canCreatePolicy else {
      lastError = UserFacingError.message(
        PolicyValidationError.tooManyPolicies(policyOrder.count + 1))
      return
    }
    var copy = source
    copy.id = UUID()
    copy.name = copyName(of: source.name)
    copy.protectedRootPath = ""
    copy.allowRules = source.allowRules.map(Self.withNewRuleID)
    copy.denyRules = source.denyRules.map(Self.withNewRuleID)
    policyDrafts[copy.id] = copy
    let position = policyOrder.firstIndex(of: id).map { $0 + 1 } ?? policyOrder.count
    policyOrder.insert(copy.id, at: position)
    selectedSection = .policy(copy.id)
    pendingFolderEntryPolicyID = copy.id
    hasChosenFirstPolicySetup = true
    lastError = nil
    operationMessage = nil
  }

  private static func withNewRuleID(_ rule: PolicyRule) -> PolicyRule {
    var copy = rule
    copy.id = newRuleID()
    return copy
  }

  /// "Name copy", or the first free "Name copy N", within the length limit of a policy name.
  private func copyName(of name: String) -> String {
    let base = name.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !base.isEmpty else { return nextAvailablePolicyName() }
    let used = Set(policyDrafts.values.map { Self.policyNameKey($0.name) })
    var number = 1
    while true {
      let candidate = Self.copyName(of: base, number: number)
      if !used.contains(Self.policyNameKey(candidate)) { return candidate }
      number += 1
    }
  }

  private static func copyName(of base: String, number: Int) -> String {
    var base = base
    while true {
      let name =
        number == 1
        ? String(localized: "\(base) copy")
        : String(localized: "\(base) copy \(number)")
      let overflow = name.count - PolicySetDocument.maximumPolicyNameLength
      guard overflow > 0, base.count > overflow else { return name }
      base = String(base.dropLast(overflow)).trimmingCharacters(in: .whitespacesAndNewlines)
    }
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

  // MARK: - System compatibility profiles

  /// The state of a profile turned on in the draft of `policyID`, or nil while it is off.
  func systemCompatibilityState(policyID: UUID, profileIdentifier: String)
    -> SystemCompatibilityProfileState?
  {
    guard
      let entry = policyDrafts[policyID]?.systemCompatibilityProfiles.first(where: {
        $0.profileIdentifier == profileIdentifier
      })
    else { return nil }
    return
      (try? SystemCompatibilityResolver.resolve(
        entry, policyIdentifier: policyID, catalog: systemCompatibilityCatalog))?.0.state
      ?? .missingProfile
  }

  /// Whether any actor of the profile is trusted on the macOS version of this Mac.
  func isSupportedOnThisMac(_ profile: SystemCompatibilityProfile) -> Bool {
    let version = ProcessInfo.processInfo.operatingSystemVersion
    return profile.actors.contains { $0.supportedOSRange.contains(version) }
  }

  /// Turns a profile on or off in the draft. Turning it on records the profile as the built-in
  /// catalog describes it now, which also renews a profile that needs review.
  func setSystemCompatibilityProfile(_ identifier: String, isOn: Bool, policyID: UUID) {
    let entry =
      isOn ? try? systemCompatibilityCatalog.policyEntry(profileIdentifier: identifier) : nil
    guard !isOn || entry != nil else { return }
    updatePolicyDraft(id: policyID) { draft in
      draft.systemCompatibilityProfiles.removeAll { $0.profileIdentifier == identifier }
      if let entry { draft.systemCompatibilityProfiles.append(entry) }
      draft.systemCompatibilityProfiles.sort { $0.profileIdentifier < $1.profileIdentifier }
    }
  }

  func savePolicy(id: UUID) async {
    guard !isBusy, let draft = policyDrafts[id] else { return }
    isBusy = true
    lastError = nil
    defer { isBusy = false }
    do {
      try checkCanStorePolicies()
      let document = try candidateDocument(replacing: id, with: draft)
      guard await store(document, policyID: id, releasesRetiredFolderPaths: true) else {
        await refreshHealth(installationStates: .whenDue)
        return
      }
      installStoredPolicySet(document, policyID: id)
      await refreshHealth(installationStates: .whenDue)
      operationMessage =
        unconfirmedSave == nil
        ? String(
          localized: "Saved. The policies were applied as revision \(document.revision).")
        : String(
          localized:
            "Saved as revision \(document.revision). The extension has not confirmed that it is in effect."
        )
    } catch {
      lastError = UserFacingError.message(error)
    }
  }

  private func checkCanStorePolicies() throws {
    guard unresolvedSave == nil else { throw AppModelError.previousSaveUnresolved }
    guard executionOriginSupport != .unsupported else {
      throw AppModelError.executionOriginUnsupported
    }
  }

  /// Whether saving the draft of `policyID` reduces protection and therefore asks for an
  /// administrator password.
  func savingWeakensProtection(policyID: UUID) -> Bool {
    guard let document = try? candidateDocument(replacing: policyID, with: policyDrafts[policyID])
    else { return false }
    return PolicyWeakeningAnalyzer.weakens(candidate: document, comparedTo: activePolicySet)
  }

  /// Sends a whole policy set and returns whether the extension stored it. A stored set is not
  /// yet confirmed as the one in effect; see `unconfirmedSave`. A change that reduces protection
  /// is sent with a fresh administrator authorization; the extension verifies it while macOS
  /// shows the password dialog, and a canceled dialog leaves the draft as it is. A save of
  /// `policyID` itself also releases that policy's retired folder paths.
  private func store(
    _ document: PolicySetDocument, policyID: UUID, releasesRetiredFolderPaths: Bool
  ) async -> Bool {
    do {
      let weakening = PolicyWeakeningAnalyzer.weakens(
        candidate: document, comparedTo: activePolicySet)
      let receipt = try await policyChangeAuthorizer.apply(
        document, weakening: weakening,
        savedPolicyIdentifier: releasesRetiredFolderPaths ? policyID : nil, using: controlClient)
      guard receipt.acceptedSetIdentifier == document.setIdentifier,
        receipt.acceptedRevision == document.revision,
        receipt.acceptedDigest == (try PolicySetDocumentCodec.digest(of: document))
      else {
        throw AppModelError.policySetReceiptMismatch
      }
      unconfirmedSave = receipt
      return true
    } catch let error where Self.leavesSaveUncertain(error) {
      return await resolveLostReply(for: document, policyID: policyID)
    } catch {
      lastError = UserFacingError.message(error)
      return false
    }
  }

  /// A rejection names its reason. Without a usable reply, the extension may have stored the
  /// set before the reply was lost.
  private static func leavesSaveUncertain(_ error: any Error) -> Bool {
    switch error {
    case ExtensionControlClientError.requestTimedOut, ExtensionControlClientError.invalidReply,
      ExtensionControlClientError.connectionInterrupted:
      return true
    case is ExtensionControlClientError, is AppModelError, is PolicyValidationError,
      is AdministrativeAuthorizationError:
      return false
    default:
      let nsError = error as NSError
      guard nsError.domain == PasuFSXPCError.domain else { return true }
      return PasuFSXPCErrorCode(rawValue: nsError.code) == .timeout
    }
  }

  private static func reportsNoStoredPolicies(_ error: any Error) -> Bool {
    let nsError = error as NSError
    return nsError.domain == PasuFSXPCError.domain
      && PasuFSXPCErrorCode(rawValue: nsError.code) == .invalidRequest
  }

  /// Asks the extension what it stored before reporting a failure or using another revision.
  private func resolveLostReply(for document: PolicySetDocument, policyID: UUID) async -> Bool {
    do {
      let stored = try await controlClient.queryPolicySet()
      if stored == document {
        unconfirmedSave = Self.receipt(for: document)
        return true
      }
      lastError = UserFacingError.message(AppModelError.saveNotStored)
    } catch let error where Self.reportsNoStoredPolicies(error) {
      lastError = UserFacingError.message(AppModelError.saveNotStored)
    } catch {
      unresolvedSave = UnresolvedSave(document: document, policyID: policyID)
      lastError = UserFacingError.message(AppModelError.previousSaveUnresolved)
    }
    return false
  }

  private static func receipt(for document: PolicySetDocument) -> PolicyApplyReceipt {
    PolicyApplyReceipt(
      result: .unchanged, acceptedSetIdentifier: document.setIdentifier,
      acceptedRevision: document.revision,
      acceptedDigest: (try? PolicySetDocumentCodec.digest(of: document)) ?? "")
  }

  /// Makes a stored set the saved policies, dropping the draft of a policy the set removed.
  private func installStoredPolicySet(_ document: PolicySetDocument, policyID: UUID) {
    let wasRemoved = !document.policies.contains { $0.id == policyID }
    if wasRemoved {
      policyDrafts.removeValue(forKey: policyID)
      policyOrder.removeAll { $0 == policyID }
    }
    installActivePolicySet(document, markingClean: policyID)
    if wasRemoved { selectAfterRemovingPolicy(policyID) }
  }

  /// Settles a save whose reply was lost, now that the stored policies could be read.
  private func settleUnresolvedSave(stored: PolicySetDocument?) {
    guard let unresolved = unresolvedSave else { return }
    unresolvedSave = nil
    if stored == unresolved.document {
      unconfirmedSave = Self.receipt(for: unresolved.document)
      installStoredPolicySet(unresolved.document, policyID: unresolved.policyID)
      lastError = nil
    } else {
      lastError = UserFacingError.message(AppModelError.saveNotStored)
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
      try checkCanStorePolicies()
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
      guard await store(document, policyID: id, releasesRetiredFolderPaths: false) else {
        await refreshHealth(installationStates: .whenDue)
        return
      }
      installStoredPolicySet(document, policyID: id)
      operationMessage = String(
        localized:
          "The policy was deleted. The remaining policies were applied as revision \(document.revision)."
      )
      await refreshHealth(installationStates: .whenDue)
    } catch {
      lastError = UserFacingError.message(error)
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

  /// Validates the code signature of an app or executable and returns the identity a rule would
  /// store. The check reads the whole program, so it runs away from the main thread. Unsigned
  /// and ad-hoc signed programs are refused.
  func programCandidate(at url: URL) async throws -> AuditRuleCandidate {
    let rule = try await Task.detached(priority: .userInitiated) {
      try ProgramRuleReader.read(at: url)
    }.value
    let team = rule.kind == .teamSigned ? rule.teamIdentifier?.uppercased() : nil
    return AuditRuleCandidate(
      id: identityKey(
        kind: rule.kind, teamIdentifier: team, signingIdentifier: rule.signingIdentifier),
      kind: rule.kind,
      teamIdentifier: team,
      signingIdentifier: rule.signingIdentifier,
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

  /// Adds a program to one of the policy's lists. The same program can be in both lists; a
  /// block rule then takes precedence.
  func addRule(
    policyID: UUID, to list: PolicyRuleList, from candidate: AuditRuleCandidate,
    allowsDescendants: Bool = false
  ) throws {
    try addRules(
      policyID: policyID, to: list, from: [candidate], allowsDescendants: allowsDescendants)
  }

  /// Adds programs to one of the policy's lists together, all with the same descendant option.
  /// Nothing is added when one of them can't be: an incomplete identity, a program already in
  /// the list, or one named twice.
  func addRules(
    policyID: UUID, to list: PolicyRuleList, from candidates: [AuditRuleCandidate],
    allowsDescendants: Bool = false
  ) throws {
    var rules: [PolicyRule] = []
    var added = Set<String>()
    for candidate in candidates {
      guard !candidate.signingIdentifier.isEmpty else {
        throw AppModelError.signingIdentifierRequired
      }
      guard !policyContainsIdentity(policyID: policyID, list: list, identityKey: candidate.id),
        added.insert(candidate.id).inserted
      else {
        throw AppModelError.duplicateRuleIdentity
      }
      switch candidate.kind {
      case .teamSigned:
        guard let teamIdentifier = candidate.teamIdentifier, !teamIdentifier.isEmpty else {
          throw AppModelError.auditIdentityIncomplete
        }
        rules.append(
          .teamSigned(
            id: Self.newRuleID(),
            teamIdentifier: teamIdentifier.uppercased(),
            signingIdentifier: candidate.signingIdentifier,
            isEnabled: true,
            allowsDescendants: list == .allow && allowsDescendants
          ))
      case .platformBinary:
        rules.append(
          .platformBinary(
            id: Self.newRuleID(),
            signingIdentifier: candidate.signingIdentifier,
            isEnabled: true,
            allowsDescendants: list == .allow && allowsDescendants
          ))
      }
    }
    updatePolicyDraft(id: policyID) { $0[list].append(contentsOf: rules) }
  }

  /// Copies rules, typically from the same list of another policy, into one of the policy's
  /// lists as new rules. Each copy keeps the original's settings: whether it is in use and, in
  /// Programs to Allow, descendant access. Nothing is copied when a program is already in the
  /// list or appears twice.
  func addRules(policyID: UUID, to list: PolicyRuleList, copying rules: [PolicyRule]) throws {
    var copies: [PolicyRule] = []
    var added = Set<String>()
    for rule in rules {
      guard !rule.signingIdentifier.isEmpty else {
        throw AppModelError.signingIdentifierRequired
      }
      var copy = rule
      copy.id = Self.newRuleID()
      switch rule.kind {
      case .teamSigned:
        guard let teamIdentifier = rule.teamIdentifier, !teamIdentifier.isEmpty else {
          throw AppModelError.auditIdentityIncomplete
        }
        copy.teamIdentifier = teamIdentifier.uppercased()
      case .platformBinary:
        copy.teamIdentifier = nil
      }
      copy.allowsDescendants = list == .allow && rule.allowsDescendants
      let key = identityKey(
        kind: copy.kind, teamIdentifier: copy.teamIdentifier,
        signingIdentifier: copy.signingIdentifier)
      guard !policyContainsIdentity(policyID: policyID, list: list, identityKey: key),
        added.insert(key).inserted
      else {
        throw AppModelError.duplicateRuleIdentity
      }
      copies.append(copy)
    }
    updatePolicyDraft(id: policyID) { $0[list].append(contentsOf: copies) }
  }

  private static func newRuleID() -> String {
    "rule.\(UUID().uuidString.lowercased())"
  }

  /// Rule IDs are unique across both lists of a policy.
  func removeRule(policyID: UUID, ruleID: String) {
    updatePolicyDraft(id: policyID) { draft in
      draft.allowRules.removeAll { $0.id == ruleID }
      draft.denyRules.removeAll { $0.id == ruleID }
    }
  }

  func updateRule(policyID: UUID, rule: PolicyRule) {
    updatePolicyDraft(id: policyID) { draft in
      for list in PolicyRuleList.allCases {
        if let index = draft[list].firstIndex(where: { $0.id == rule.id }) {
          draft[list][index] = rule
        }
      }
    }
  }

  /// Changes only whether decisions use Programs to Allow. Both lists stay as they are.
  func setAllowListInUse(policyID: UUID, _ isInUse: Bool) {
    updatePolicyDraft(id: policyID) { $0.isBlacklistEnabled = !isInUse }
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

  func policyContainsIdentity(
    policyID: UUID, list: PolicyRuleList, candidate: AuditRuleCandidate
  ) -> Bool {
    policyContainsIdentity(policyID: policyID, list: list, identityKey: candidate.id)
  }

  /// Whether the list already names the program of a rule, such as a rule of another policy.
  func policyContainsIdentity(policyID: UUID, list: PolicyRuleList, rule: PolicyRule) -> Bool {
    policyContainsIdentity(
      policyID: policyID, list: list,
      identityKey: identityKey(
        kind: rule.kind, teamIdentifier: rule.teamIdentifier,
        signingIdentifier: rule.signingIdentifier))
  }

  private func policyContainsIdentity(
    policyID: UUID, list: PolicyRuleList, identityKey key: String
  ) -> Bool {
    guard let draft = policyDrafts[policyID] else { return false }
    return draft[list].contains {
      identityKey(
        kind: $0.kind,
        teamIdentifier: $0.teamIdentifier,
        signingIdentifier: $0.signingIdentifier
      ) == key
    }
  }

  // MARK: - Policy logs

  /// Signed programs in this policy's loaded log that a rule can name: the programs that opened
  /// files, and the first programs the extension recorded for those opens. A policy that uses
  /// Programs to Allow needs a rule for both.
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
    func add(
      kind: PolicyRuleKind, teamIdentifier: String?, signingIdentifier: String,
      executablePath: String?, at timestamp: Date, counted: inout Set<String>
    ) {
      let key = identityKey(
        kind: kind, teamIdentifier: teamIdentifier, signingIdentifier: signingIdentifier)
      // A program that is both the first program and the access process is one observation.
      guard counted.insert(key).inserted else { return }
      if var existing = grouped[key] {
        existing.observationCount += 1
        if timestamp >= existing.lastSeen {
          existing.lastSeen = timestamp
          existing.executablePath = executablePath
        }
        grouped[key] = existing
      } else {
        grouped[key] = Accumulator(
          kind: kind, teamIdentifier: teamIdentifier, signingIdentifier: signingIdentifier,
          executablePath: executablePath, lastSeen: timestamp, observationCount: 1)
      }
    }

    for record in policyLogState(policyID: policyID)?.batch.records ?? []
    where AuthorizationEventCatalog.isAuthorizationEvent(record.eventType) {
      var counted = Set<String>()
      if let signingIdentifier = record.signingIdentifier, !signingIdentifier.isEmpty {
        if record.isPlatformBinary == true {
          add(
            kind: .platformBinary, teamIdentifier: nil, signingIdentifier: signingIdentifier,
            executablePath: record.executablePath, at: record.timestamp, counted: &counted)
        } else if record.isPlatformBinary == false, let team = record.teamIdentifier,
          !team.isEmpty
        {
          add(
            kind: .teamSigned, teamIdentifier: team.uppercased(),
            signingIdentifier: signingIdentifier, executablePath: record.executablePath,
            at: record.timestamp, counted: &counted)
        }
      }
      // Only an identity the kernel reported as validly signed can be matched by a rule.
      guard let origin = record.evaluation(for: policyID)?.executionOrigin?.origin else {
        continue
      }
      switch origin.identity {
      case .teamSigned(let identity):
        add(
          kind: .teamSigned, teamIdentifier: identity.teamIdentifier.uppercased(),
          signingIdentifier: identity.signingIdentifier, executablePath: origin.executablePath,
          at: record.timestamp, counted: &counted)
      case .platformBinary(let signingIdentifier):
        add(
          kind: .platformBinary, teamIdentifier: nil, signingIdentifier: signingIdentifier,
          executablePath: origin.executablePath, at: record.timestamp, counted: &counted)
      case nil:
        break
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
      records: log.batch.records, policyID: policyID, currentRevision: activePolicySet?.revision,
      displayName: { signing, path in
        self.displayName(signingIdentifier: signing, executablePath: path)
      })
  }

  func draftRule(
    policyID: UUID, list: PolicyRuleList, summary: PolicyProgramSummary
  ) -> PolicyRule? {
    policyDrafts[policyID]?[list].first { PolicyProgramSummarizer.ruleKey($0) == summary.id }
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

  /// The installed app's name for a signing identifier, or the executable's file name.
  func displayName(
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

  private func synchronizeActivePolicySet(with status: ExtensionStatusSnapshot) async {
    let reportedIdentifier = status.activePolicySetIdentifier
    let reportedRevision = status.activePolicyRevision
    let digestIsCurrent =
      status.activePolicyDigest == nil || activePolicySetDigest == nil
      || status.activePolicyDigest == activePolicySetDigest
    if !needsPolicyReread, unresolvedSave == nil, digestIsCurrent,
      let reportedIdentifier, let reportedRevision,
      activePolicySet?.setIdentifier == reportedIdentifier,
      activePolicySet?.revision == reportedRevision
    {
      acceptedRevision = reportedRevision
      return
    }
    do {
      let policySet = try await controlClient.queryPolicySet()
      needsPolicyReread = false
      settleUnresolvedSave(stored: policySet)
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
      if Self.reportsNoStoredPolicies(error) {
        needsPolicyReread = false
        settleUnresolvedSave(stored: nil)
      }
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
    let previousFolders = Dictionary(
      (activePolicySet?.policies ?? []).map { ($0.id, $0.protectedRootPath) },
      uniquingKeysWith: { first, _ in first })

    activePolicySet = policySet
    activePolicySetDigest = try? PolicySetDocumentCodec.digest(of: policySet)
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
      if previouslyDirty.contains(policy.id), var draft = previousDrafts[policy.id] {
        // The extension stores a new folder path when it follows a moved folder. An unsaved
        // draft that kept the old path takes the new one, so saving it does not move the
        // policy back to a path where the folder no longer is.
        if let previousFolder = previousFolders[policy.id],
          previousFolder != policy.protectedRootPath,
          draft.protectedRootPath == previousFolder
        {
          draft.protectedRootPath = policy.protectedRootPath
        }
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

  /// Asks macOS for the installation states and returns them, or throws when the query fails,
  /// macOS doesn't answer within the timeout or the query is held back.
  private func fetchInstallationProperties(
    _ kind: InstallationStateQueryKind
  ) async throws -> [ExtensionInstallationProperties] {
    switch await queryInstallationStates(kind) {
    case .reported(let properties):
      return properties
    case .failed(let failure):
      throw AppModelError.installationPropertiesFailed(InstallationStateText.failureDetail(failure))
    case .unanswered:
      throw AppModelError.installationStatesUnanswered(
        Int(InstallationStateQueries.answerTimeout))
    case .held:
      throw AppModelError.installationStatesHeld
    case .cancelled:
      throw CancellationError()
    }
  }

  /// Sends one query for the installation states, or shares one that runs, and keeps the newest
  /// record of their answers.
  @discardableResult
  private func queryInstallationStates(
    _ kind: InstallationStateQueryKind
  ) async -> InstallationStateQueryOutcome.Answer {
    let submission = installationQueries.recordSubmission()
    let outcome = await installationStates.query(kind)
    switch outcome.answer {
    case .reported, .failed, .unanswered:
      installationQueries.recordCompletion(submission, queried: true)
    case .held, .cancelled:
      installationQueries.recordCompletion(submission, queried: false)
    }
    // Calls can return in another order than their queries ended.
    if outcome.record.revision > installationRecord.revision {
      installationRecord = outcome.record
    }
    updateHealth()
    return outcome.answer
  }

  private func requestAutomaticExtensionUpdateIfNeeded() async {
    // The check runs once, so it waits for installation states that describe the Mac now.
    guard
      let installations = installationRecord.currentInstallations(
        at: Date(), maximumAge: HealthStateReducer.runtimeFreshnessInterval),
      !isBusy, !isUninstalling, !isFinalizingUninstall,
      pendingUninstall == nil, uninstallStateError == nil
    else { return }
    let shouldRequestActivation = automaticExtensionUpdateCheck.shouldRequestActivation(
      embeddedBuildVersion: embeddedSystemExtensionBuildVersion,
      installations: installations
    )
    guard shouldRequestActivation else { return }

    operationMessage = String(
      localized: "The app includes a newer extension. Asking macOS to update it.")
    _ = await performLifecycleRequest(
      events: activationController.activationEvents, tracksActivation: true
    )
  }

  /// Reads the installation states before a lifecycle request, unless macOS reported them moments
  /// ago or doesn't answer. The request then starts from what macOS reports now.
  private func readInstallationStatesBeforeRequest() async {
    guard installationRecord.unansweredSince == nil,
      !installationRecord.isCurrent(at: Date(), maximumAge: 2)
    else { return }
    await queryInstallationStates(.refresh)
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
        // Each attempt reads the states in a query that starts after the call, never one from
        // before the change it verifies.
        let properties = try await fetchInstallationProperties(.afterChange)
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

  /// Sends the request that `events` creates, after reading the installation states, and reads
  /// them again once macOS ends the request.
  private func performLifecycleRequest(
    events makeEvents: () -> AsyncStream<ActivationEvent>, tracksActivation: Bool = false
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
    await readInstallationStatesBeforeRequest()
    // Only the replacement of an extension that was in use leaves running programs unobserved.
    let extensionWasInUse = (currentInstallations ?? []).contains {
      $0.bundleIdentifier == ActivationController.extensionIdentifier && $0.isEnabled
    }
    var isReplacingExtension = false
    var outcome: LifecycleRequestOutcome?
    for await event in makeEvents() {
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
        // The request stays open until the approval, so the installation that now waits for it
        // is read without waiting for the request to end; the setup assistant then shows the
        // approval step and checks every few seconds.
        Task { await self.queryInstallationStates(.afterChange) }
      case .replacing(let existing, let new):
        operationMessage = String(localized: "Replacing build \(existing) with build \(new).")
        if tracksActivation { activationProgress = String(localized: "Updating the extension…") }
        isReplacingExtension = tracksActivation && extensionWasInUse
      case .completed(let rebootRequired):
        if isReplacingExtension, !rebootRequired {
          extensionReplacementRecord.recordReplacement()
          recommendsRestartAfterExtensionUpdate = extensionReplacementRecord.recommendsRestart
        }
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
    await refreshHealth(installationStates: .afterChange)
    let result =
      outcome
      ?? .failed(
        String(localized: "macOS ended the system extension request without a result."))
    switch (tracksActivation, result) {
    case (true, _):
      activationOutcome = result
    case (false, .failed):
      break
    case (false, _):
      // An accepted deactivation also withdraws an update that waited for a restart.
      activationOutcome = nil
    }
    return result
  }
}

enum AppModelError: Error, CustomStringConvertible, UserFacingErrorConvertible {
  case policyRevisionExhausted
  case policySetReceiptMismatch
  case duplicateRuleIdentity
  case auditIdentityIncomplete
  case signingIdentifierRequired
  case saveNotStored
  case previousSaveUnresolved
  case executionOriginUnsupported
  case installationPropertiesFailed(String)
  /// macOS didn't answer a request for the installation states within this many seconds.
  case installationStatesUnanswered(Int)
  /// No query started because macOS hasn't answered lately.
  case installationStatesHeld

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
      String(localized: "This program is already in this list.")
    case .auditIdentityIncomplete:
      String(localized: "The record does not contain a complete signing identity.")
    case .signingIdentifierRequired:
      String(localized: "Enter a Signing ID.")
    case .saveNotStored:
      String(localized: "The extension did not reply and did not store the change. Try again.")
    case .previousSaveUnresolved:
      String(
        localized:
          "The extension did not reply to the last save. Pasu FS is checking whether it was stored before saving again."
      )
    case .executionOriginUnsupported:
      String(
        localized:
          "The running extension did not report support for the allow and block lists. Update the extension before saving policies."
      )
    case .installationPropertiesFailed(let description):
      String(localized: "macOS did not report the system extension state: \(description)")
    case .installationStatesUnanswered(let seconds):
      String(
        localized: "macOS did not report the system extension state within \(seconds) seconds.")
    case .installationStatesHeld:
      String(
        localized:
          "macOS isn’t reporting the system extension state. Try again in a minute.")
    }
  }
}

/// Screens that show the installation states, so that the app reads them sooner while they are on
/// screen.
enum StatusScreen: Hashable {
  case setupAssistant
  case extensionSettings
}
