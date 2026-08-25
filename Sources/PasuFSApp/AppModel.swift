import AppKit
import Foundation
import Observation
import PasuFSConfiguration
import PasuFSHostCore

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

@Observable
@MainActor
final class AppModel {
  var health = HealthState(protection: .starting)
  var auditBatch = AuditLogBatch(records: [])
  var auditFilterText = ""
  var selectedSection: SidebarSelection = .protection
  var lastError: String?
  var operationMessage: String?
  var isBusy = false

  private(set) var activePolicySet: PolicySetDocument?
  private(set) var latestEvidence: RuntimeStatusEvidence?
  private(set) var installation: ExtensionInstallationProperties?
  private(set) var policySynchronizationWarning: String?
  private(set) var hasEverSeenActivePolicySet = false
  private(set) var policyDrafts: [UUID: DirectoryPolicyDraft] = [:]
  private(set) var policyOrder: [UUID] = []

  private var hasChosenFirstPolicySetup = false
  private let activationController = ActivationController()
  private let controlClient: ExtensionControlClient
  private let diagnosticStatusReader = DiagnosticStatusReader()
  private var pendingSetIdentifier = UUID()
  private var acceptedRevision: UInt64 = 0
  private var pollingTask: Task<Void, Never>?

  init(
    hostBundleURL: URL = Bundle.main.bundleURL,
    initialPolicySet: PolicySetDocument? = nil
  ) {
    controlClient = ExtensionControlClient(hostBundleURL: hostBundleURL)
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

  var droppedAuditEventCount: UInt64 {
    latestEvidence?.snapshot.droppedAuditEventCount ?? 0
  }

  var menuBarPolicySummary: String {
    guard let activePolicySet else { return "No accepted policy set" }
    let protectionCount = activePolicySet.policies.lazy.filter { $0.mode == .protection }.count
    let auditCount = activePolicySet.policies.count - protectionCount
    return "\(protectionCount) Protection · \(auditCount) Audit"
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
    }
  }

  func activate() async {
    await performLifecycleRequest(events: activationController.activationEvents())
  }

  func deactivate() async {
    await performLifecycleRequest(events: activationController.deactivationEvents())
  }

  // MARK: - Policies and drafts

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
          [$0.policyName, $0.policyType.rawValue, $0.decision.rawValue, $0.ruleIdentifier]
        })
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

  func refreshAuditLog() async {
    do {
      auditBatch = try await controlClient.readAuditLog(maximumLineCount: 500)
      lastError = nil
    } catch {
      lastError = String(describing: error)
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
        return properties
      case .failed(_, _, let description):
        throw AppModelError.installationPropertiesFailed(description)
      default:
        break
      }
    }
    return []
  }

  private func performLifecycleRequest(events: AsyncStream<ActivationEvent>) async {
    guard !isBusy else { return }
    isBusy = true
    lastError = nil
    defer { isBusy = false }
    for await event in events {
      switch event {
      case .submitted(let action):
        operationMessage = "Submitted \(action) request."
      case .waitingForUserApproval:
        operationMessage = "Waiting for approval in System Settings."
      case .replacing(let existing, let new):
        operationMessage = "Replacing version \(existing) with \(new)."
      case .completed(let rebootRequired):
        operationMessage =
          rebootRequired
          ? "The request will complete after restart."
          : "The request completed."
      case .failed(_, _, let description):
        lastError = description
      case .properties:
        break
      }
    }
    await refreshHealth()
  }
}

private enum AppModelError: Error, CustomStringConvertible {
  case policyRevisionExhausted
  case policySetReceiptMismatch
  case duplicateRuleIdentity
  case auditIdentityIncomplete
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
    case .installationPropertiesFailed(let description):
      description
    }
  }
}
