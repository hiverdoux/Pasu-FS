import PasuFSConfiguration
import SwiftUI
import UniformTypeIdentifiers

/// Adds programs to one of a policy's lists, or edits an existing rule.
struct AddProgramSheet: View {
  @Bindable var model: AppModel
  let policyID: UUID
  let list: PolicyRuleList
  let editingRule: PolicyRule?
  let preselected: AuditRuleCandidate?

  @Environment(\.dismiss) private var dismiss
  @AppStorage(ProgramSortOrder.defaultsKey) private var sortOrder = ProgramSortOrder.default
  @State private var source: Source
  @State private var selectedCandidateIDs: Set<String>
  @State private var applicationCandidate: AuditRuleCandidate?
  @State private var applicationError: String?
  /// The program whose signature is being checked. A newer choice replaces it.
  @State private var readingProgramURL: URL?
  @State private var kind: PolicyRuleKind
  @State private var teamIdentifier: String
  @State private var signingIdentifier: String
  @State private var allowsDescendants: Bool
  @State private var filterText = ""
  @State private var isChoosingApplication = false
  @State private var errorMessage: String?
  /// The policy chosen as the source of copies, once one has been chosen.
  @State private var chosenSourcePolicyID: UUID?
  @State private var selectedSourceRuleIDs: Set<String> = []

  enum Source: Hashable {
    case recent
    case application
    case manual
    case policy
  }

  init(model: AppModel, request: AddProgramRequest) {
    self.model = model
    policyID = request.policyID
    list = request.list
    editingRule = nil
    preselected = request.preselected
    _source = State(initialValue: .recent)
    _selectedCandidateIDs = State(initialValue: request.preselected.map { [$0.id] } ?? [])
    _kind = State(initialValue: .teamSigned)
    _teamIdentifier = State(initialValue: "")
    _signingIdentifier = State(initialValue: "")
    _allowsDescendants = State(initialValue: false)
  }

  init(model: AppModel, policyID: UUID, list: PolicyRuleList, editing rule: PolicyRule) {
    self.model = model
    self.policyID = policyID
    self.list = list
    editingRule = rule
    preselected = nil
    _source = State(initialValue: .manual)
    _selectedCandidateIDs = State(initialValue: [])
    _kind = State(initialValue: rule.kind)
    _teamIdentifier = State(initialValue: rule.teamIdentifier ?? "")
    _signingIdentifier = State(initialValue: rule.signingIdentifier)
    _allowsDescendants = State(initialValue: list == .allow && rule.allowsDescendants)
  }

  var body: some View {
    Form {
      Section {
        if editingRule == nil {
          Picker("Source", selection: $source) {
            Text("Recent Access").tag(Source.recent)
            Text("App or Executable").tag(Source.application)
            Text("Manual Entry").tag(Source.manual)
            Text("Other Policy").tag(Source.policy)
          }
          .pickerStyle(.segmented)
          .labelsHidden()
        }
      } header: {
        SheetTitle(title: title, subtitle: subtitle)
      }
      switch source {
      case .recent:
        recentSection
      case .application:
        applicationSection
      case .manual:
        manualSection
      case .policy:
        policySection
      }
      if list == .allow {
        descendantsSection
      }
      if let errorMessage {
        Section {
          Label(errorMessage, systemImage: "exclamationmark.circle")
            .foregroundStyle(.red)
        }
      }
    }
    .formStyle(.grouped)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) {
        Button("Cancel") {
          dismiss()
        }
      }
      ToolbarItem(placement: .confirmationAction) {
        Button(editingRule == nil ? "Add" : "Save") {
          commit()
        }
        .disabled(additions.isEmpty)
      }
    }
    .formSheetSizing()
    .task {
      if editingRule == nil {
        await model.refreshPolicyAuditLog(policyID: policyID)
      }
    }
  }

  /// The descendant option for the programs being added. A copy keeps the setting of the rule
  /// it is made from, so with that source the section only points out a copy that has it on.
  @ViewBuilder
  private var descendantsSection: some View {
    if source == .policy {
      if copies.contains(where: \.allowsDescendants) {
        Section {
          WarningLabel(
            text: String(localized: "A selected rule includes descendant processes."))
        }
      }
    } else {
      Section {
        Toggle("Include descendant processes", isOn: $allowsDescendants)
        if allowsDescendants {
          WarningLabel(
            text: String(localized: "Programs it starts can also access this folder."))
        }
      }
    }
  }

  // MARK: - Recent access

  /// The signed programs of the policy's log, with the preselected one first.
  private var allCandidates: [AuditRuleCandidate] {
    var list = model.ruleCandidates(policyID: policyID)
    if let preselected, !list.contains(where: { $0.id == preselected.id }) {
      list.insert(preselected, at: 0)
    }
    return list
  }

  /// The candidates that match the search text. The selection is kept across searches, so a
  /// program chosen before a search is still added while the search hides it.
  private var candidates: [AuditRuleCandidate] {
    let needle = filterText.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !needle.isEmpty else { return allCandidates }
    return allCandidates.filter {
      [$0.displayName, $0.signingIdentifier, $0.teamIdentifier, $0.executablePath]
        .compactMap { $0 }
        .contains { $0.localizedCaseInsensitiveContains(needle) }
    }
  }

  private var recentSection: some View {
    Section {
      TextField(
        "Search programs", text: $filterText, prompt: Text("Program, Team ID or Signing ID"))
      if candidates.isEmpty {
        ContentUnavailableView(
          "No Signed Programs in This Policy’s Log",
          systemImage: "list.bullet.rectangle"
        )
      } else {
        List(candidates, selection: $selectedCandidateIDs) { candidate in
          CandidateRow(
            candidate: candidate,
            isAlreadyAdded: model.policyContainsIdentity(
              policyID: policyID, list: list, candidate: candidate))
        }
        .frame(minHeight: 220)
      }
    }
  }

  // MARK: - Application

  private var applicationSection: some View {
    Section {
      LabeledContent {
        HStack {
          if readingProgramURL != nil {
            ProgressView()
              .controlSize(.small)
          }
          Button("Choose…") {
            isChoosingApplication = true
          }
        }
      } label: {
        if let applicationCandidate {
          Label {
            Text(applicationCandidate.displayName)
            SignatureLine(
              kind: applicationCandidate.kind.displayName,
              identifiers: CandidateText.identifiers(applicationCandidate))
          } icon: {
            ProgramIcon(
              signingIdentifier: applicationCandidate.signingIdentifier,
              executablePath: applicationCandidate.executablePath, size: 32)
          }
        } else {
          Text("Drag an app or executable here")
        }
      }
      if let applicationError {
        WarningLabel(text: applicationError)
      }
    }
    .dropDestination(for: URL.self) { urls, _ in
      guard let url = urls.first else { return false }
      readProgram(url)
      return true
    }
    .fileImporter(
      isPresented: $isChoosingApplication,
      allowedContentTypes: [.application, .unixExecutable, .executable],
      allowsMultipleSelection: false
    ) { result in
      if case .success(let urls) = result, let url = urls.first {
        readProgram(url)
      }
    }
  }

  // MARK: - Manual entry

  private var manualSection: some View {
    Section {
      Picker("Signature", selection: $kind) {
        Text("Developer signed").tag(PolicyRuleKind.teamSigned)
        Text("Apple platform binary").tag(PolicyRuleKind.platformBinary)
      }
      .pickerStyle(.segmented)
      if kind == .teamSigned {
        TextField("Team ID", text: $teamIdentifier, prompt: Text(verbatim: "ABCDE12345"))
          .monospaced()
      }
      TextField(
        "Signing ID", text: $signingIdentifier, prompt: Text(verbatim: "com.example.tool")
      )
      .monospaced()
    }
  }

  // MARK: - Other policy

  /// The other policies, in sidebar order.
  private var otherPolicies: [DirectoryPolicyDraft] {
    model.sidebarPolicies.filter { $0.id != policyID }
  }

  /// The chosen policy, or until one is chosen, the first other policy with programs in this
  /// list, or else the first other policy.
  private var sourcePolicy: DirectoryPolicyDraft? {
    let policies = otherPolicies
    if let chosen = policies.first(where: { $0.id == chosenSourcePolicyID }) {
      return chosen
    }
    return policies.first { !$0[list].isEmpty } ?? policies.first
  }

  /// The source policy's rules of this list, in the chosen sort order.
  private var sourceRules: [PolicyRule] {
    sortOrder.sorted(sourcePolicy?[list] ?? []) { model.ruleDisplayName(for: $0) }
  }

  private var sourcePolicyBinding: Binding<UUID?> {
    Binding(
      get: { sourcePolicy?.id },
      set: { id in
        chosenSourcePolicyID = id
        selectedSourceRuleIDs = []
      })
  }

  private var policySection: some View {
    Section {
      if otherPolicies.isEmpty {
        ContentUnavailableView("No Other Policies", systemImage: "lock.doc")
      } else {
        Picker("Policy", selection: sourcePolicyBinding) {
          ForEach(otherPolicies) { policy in
            Text(policy.name.isEmpty ? String(localized: "Untitled Policy") : policy.name)
              .tag(Optional(policy.id))
          }
        }
        if sourceRules.isEmpty {
          ContentUnavailableView("No Programs to Copy", systemImage: "list.bullet.rectangle")
        } else {
          List(sourceRules, selection: $selectedSourceRuleIDs) { rule in
            SourceRuleRow(
              rule: rule, list: list, displayName: model.ruleDisplayName(for: rule),
              isAlreadyAdded: model.policyContainsIdentity(
                policyID: policyID, list: list, rule: rule))
          }
          .frame(minHeight: 220)
        }
      }
    }
  }

  // MARK: - Text

  private var policy: DirectoryPolicyDraft? {
    model.policyDraft(id: policyID)
  }

  private var title: String {
    if editingRule != nil { return String(localized: "Edit Program") }
    switch list {
    case .allow: return String(localized: "Add a Program to Allow")
    case .deny: return String(localized: "Add a Program to Block")
    }
  }

  private var subtitle: String {
    guard let policy else { return "" }
    return "\(policy.name) · \(policy.mode.displayName)"
  }

  // MARK: - Actions

  /// What Add puts in the list.
  private enum Additions {
    case programs([AuditRuleCandidate])
    case copies([PolicyRule])

    var isEmpty: Bool {
      switch self {
      case .programs(let candidates): candidates.isEmpty
      case .copies(let rules): rules.isEmpty
      }
    }
  }

  /// The chosen programs that are not in the list yet. A program chosen in the file dialog or
  /// entered by hand is kept even when the list has it, so that adding it reports why.
  private var additions: Additions {
    switch source {
    case .recent:
      .programs(
        allCandidates.filter {
          selectedCandidateIDs.contains($0.id)
            && !model.policyContainsIdentity(policyID: policyID, list: list, candidate: $0)
        })
    case .application:
      .programs(applicationCandidate.map { [$0] } ?? [])
    case .manual:
      .programs(manualCandidate.map { [$0] } ?? [])
    case .policy:
      .copies(copies)
    }
  }

  /// The selected rules of the source policy whose programs are not in the list yet.
  private var copies: [PolicyRule] {
    sourceRules.filter {
      selectedSourceRuleIDs.contains($0.id)
        && !model.policyContainsIdentity(policyID: policyID, list: list, rule: $0)
    }
  }

  private var manualCandidate: AuditRuleCandidate? {
    let signing = signingIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
    let team = teamIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !signing.isEmpty, kind == .platformBinary || !team.isEmpty else { return nil }
    return model.manualCandidate(kind: kind, teamIdentifier: team, signingIdentifier: signing)
  }

  /// Checks the program's code signature in the background. The result of an earlier choice is
  /// dropped when another program has been chosen since.
  private func readProgram(_ url: URL) {
    readingProgramURL = url
    applicationCandidate = nil
    applicationError = nil
    Task {
      let result: Result<AuditRuleCandidate, any Error>
      do {
        result = .success(try await model.programCandidate(at: url))
      } catch {
        result = .failure(error)
      }
      guard readingProgramURL == url else { return }
      readingProgramURL = nil
      switch result {
      case .success(let candidate): applicationCandidate = candidate
      case .failure(let error): applicationError = UserFacingError.message(error)
      }
    }
  }

  private func commit() {
    do {
      if let editingRule {
        guard let candidate = manualCandidate else { return }
        try saveEdit(of: editingRule, as: candidate)
      } else {
        switch additions {
        case .programs(let candidates):
          guard !candidates.isEmpty else { return }
          try model.addRules(
            policyID: policyID, to: list, from: candidates, allowsDescendants: allowsDescendants)
        case .copies(let rules):
          guard !rules.isEmpty else { return }
          try model.addRules(policyID: policyID, to: list, copying: rules)
        }
      }
      dismiss()
    } catch {
      errorMessage = UserFacingError.message(error)
    }
  }

  private func saveEdit(of rule: PolicyRule, as candidate: AuditRuleCandidate) throws {
    // An identity is unique within its list; the other list may name the same program.
    let others = policy?[list].filter { $0.id != rule.id } ?? []
    let duplicate = others.contains {
      PolicyProgramSummarizer.ruleKey($0) == candidate.id
    }
    guard !duplicate else { throw AppModelError.duplicateRuleIdentity }
    var updated = rule
    updated.kind = candidate.kind
    updated.teamIdentifier = candidate.kind == .teamSigned ? candidate.teamIdentifier : nil
    updated.signingIdentifier = candidate.signingIdentifier
    updated.allowsDescendants = list == .allow && allowsDescendants
    model.updateRule(policyID: policyID, rule: updated)
  }
}

private struct CandidateRow: View {
  let candidate: AuditRuleCandidate
  let isAlreadyAdded: Bool

  var body: some View {
    HStack {
      ProgramIcon(
        signingIdentifier: candidate.signingIdentifier, executablePath: candidate.executablePath,
        size: 32)
      VStack(alignment: .leading) {
        Text(candidate.displayName)
        SignatureLine(
          kind: candidate.kind.displayName, identifiers: CandidateText.identifiers(candidate))
      }
      Spacer()
      VStack(alignment: .trailing) {
        if isAlreadyAdded {
          Text("Already added")
            .font(.caption)
            .foregroundStyle(.secondary)
        } else if candidate.observationCount > 0 {
          Text(candidate.lastSeen, format: .dateTime.hour().minute())
            .font(.caption)
          Text("Seen \(candidate.observationCount) times")
            .font(.caption)
            .foregroundStyle(.secondary)
        }
      }
    }
    .foregroundStyle(isAlreadyAdded ? .secondary : .primary)
  }
}

/// A rule of another policy, shown with the settings a copy of it keeps.
private struct SourceRuleRow: View {
  let rule: PolicyRule
  let list: PolicyRuleList
  let displayName: String
  let isAlreadyAdded: Bool

  var body: some View {
    HStack {
      ProgramIcon(signingIdentifier: rule.signingIdentifier, executablePath: nil, size: 32)
      VStack(alignment: .leading) {
        HStack {
          Text(displayName)
            .lineLimit(1)
          if !rule.isEnabled {
            Text("Off")
              .font(.caption)
              .foregroundStyle(.secondary)
          }
          if list == .allow && rule.allowsDescendants {
            Image(systemName: "arrow.triangle.branch")
              .foregroundStyle(.secondary)
              .help("Include descendant processes")
              .accessibilityLabel("Include descendant processes")
          }
        }
        SignatureLine(kind: rule.kind.displayName, identifiers: identifiers)
      }
      Spacer()
      if isAlreadyAdded {
        Text("Already added")
          .font(.caption)
          .foregroundStyle(.secondary)
      }
    }
    .foregroundStyle(isAlreadyAdded ? .secondary : .primary)
  }

  private var identifiers: String {
    switch rule.kind {
    case .teamSigned:
      "\(rule.teamIdentifier ?? "—") · \(rule.signingIdentifier)"
    case .platformBinary:
      rule.signingIdentifier
    }
  }
}

private enum CandidateText {
  static func identifiers(_ candidate: AuditRuleCandidate) -> String {
    switch candidate.kind {
    case .teamSigned:
      "\(candidate.teamIdentifier ?? "—") · \(candidate.signingIdentifier)"
    case .platformBinary:
      candidate.signingIdentifier
    }
  }
}
