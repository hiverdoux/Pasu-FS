import PasuFSConfiguration
import SwiftUI
import UniformTypeIdentifiers

/// Adds a program to a policy's list, or edits an existing rule.
struct AddProgramSheet: View {
  @Bindable var model: AppModel
  let policyID: UUID
  let editingRule: PolicyRule?
  let preselected: AuditRuleCandidate?

  @Environment(\.dismiss) private var dismiss
  @State private var source: Source
  @State private var selectedCandidateID: String?
  @State private var applicationCandidate: AuditRuleCandidate?
  @State private var applicationError: String?
  @State private var kind: PolicyRuleKind
  @State private var teamIdentifier: String
  @State private var signingIdentifier: String
  @State private var includesChildProcesses: Bool
  @State private var filterText = ""
  @State private var isChoosingApplication = false
  @State private var errorMessage: String?

  enum Source: Hashable {
    case recent
    case application
    case manual
  }

  init(model: AppModel, request: AddProgramRequest) {
    self.model = model
    policyID = request.policyID
    editingRule = nil
    preselected = request.preselected
    _source = State(initialValue: .recent)
    _selectedCandidateID = State(initialValue: request.preselected?.id)
    _kind = State(initialValue: .teamSigned)
    _teamIdentifier = State(initialValue: "")
    _signingIdentifier = State(initialValue: "")
    _includesChildProcesses = State(initialValue: false)
  }

  init(model: AppModel, policyID: UUID, editing rule: PolicyRule) {
    self.model = model
    self.policyID = policyID
    editingRule = rule
    preselected = nil
    _source = State(initialValue: .manual)
    _kind = State(initialValue: rule.kind)
    _teamIdentifier = State(initialValue: rule.teamIdentifier ?? "")
    _signingIdentifier = State(initialValue: rule.signingIdentifier)
    _includesChildProcesses = State(initialValue: rule.allowsDescendants)
  }

  var body: some View {
    Form {
      Section {
        if editingRule == nil {
          Picker("Source", selection: $source) {
            Text("Recent Access").tag(Source.recent)
            Text("Application").tag(Source.application)
            Text("Manual Entry").tag(Source.manual)
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
      }
      childProcessSection
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
        .disabled(currentCandidate == nil)
      }
    }
    .formSheetSizing()
    .task {
      if editingRule == nil {
        await model.refreshPolicyAuditLog(policyID: policyID)
      }
    }
  }

  // MARK: - Recent access

  private var candidates: [AuditRuleCandidate] {
    var list = model.ruleCandidates(policyID: policyID)
    if let preselected, !list.contains(where: { $0.id == preselected.id }) {
      list.insert(preselected, at: 0)
    }
    let needle = filterText.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !needle.isEmpty else { return list }
    return list.filter {
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
        List(candidates, selection: $selectedCandidateID) { candidate in
          CandidateRow(
            candidate: candidate,
            isAlreadyAdded: model.policyContainsIdentity(policyID: policyID, candidate: candidate))
        }
        .frame(minHeight: 220)
      }
    }
  }

  // MARK: - Application

  private var applicationSection: some View {
    Section {
      LabeledContent {
        Button("Choose Application…") {
          isChoosingApplication = true
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
          Text("Drag an application here")
        }
      }
      if let applicationError {
        WarningLabel(text: applicationError)
      }
    }
    .dropDestination(for: URL.self) { urls, _ in
      guard let url = urls.first else { return false }
      readApplication(url)
      return true
    }
    .fileImporter(
      isPresented: $isChoosingApplication,
      allowedContentTypes: [.application],
      allowsMultipleSelection: false
    ) { result in
      if case .success(let urls) = result, let url = urls.first {
        readApplication(url)
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

  // MARK: - Child processes

  private var childProcessSection: some View {
    Section {
      Toggle("Include child processes", isOn: $includesChildProcesses)
      if includesChildProcesses {
        WarningLabel(text: PolicyBehaviorText.descendantsWarning(policyType))
      }
    }
  }

  // MARK: - Text

  private var policy: DirectoryPolicyDraft? {
    model.policyDraft(id: policyID)
  }

  private var policyType: PolicyType {
    policy?.policyType ?? .whitelist
  }

  private var title: String {
    if editingRule != nil { return String(localized: "Edit Program") }
    switch policyType {
    case .whitelist: return String(localized: "Add a Program to Allow")
    case .blacklist: return String(localized: "Add a Program to Block")
    }
  }

  private var subtitle: String {
    guard let policy else { return "" }
    return "\(policy.name) · \(policy.mode.displayName) · \(policy.policyType.displayName)"
  }

  // MARK: - Actions

  private var currentCandidate: AuditRuleCandidate? {
    switch source {
    case .recent:
      guard let selectedCandidateID,
        let candidate = candidates.first(where: { $0.id == selectedCandidateID }),
        !model.policyContainsIdentity(policyID: policyID, candidate: candidate)
      else { return nil }
      return candidate
    case .application:
      return applicationCandidate
    case .manual:
      let signing = signingIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
      let team = teamIdentifier.trimmingCharacters(in: .whitespacesAndNewlines)
      guard !signing.isEmpty, kind == .platformBinary || !team.isEmpty else { return nil }
      return model.manualCandidate(kind: kind, teamIdentifier: team, signingIdentifier: signing)
    }
  }

  private func readApplication(_ url: URL) {
    do {
      applicationCandidate = try model.applicationCandidate(at: url)
      applicationError = nil
    } catch {
      applicationCandidate = nil
      applicationError = UserFacingError.message(error)
    }
  }

  private func commit() {
    guard let candidate = currentCandidate else { return }
    do {
      if let editingRule {
        try saveEdit(of: editingRule, as: candidate)
      } else {
        try model.addRule(
          policyID: policyID, from: candidate, allowsDescendants: includesChildProcesses)
      }
      dismiss()
    } catch {
      errorMessage = UserFacingError.message(error)
    }
  }

  private func saveEdit(of rule: PolicyRule, as candidate: AuditRuleCandidate) throws {
    let others = policy?.rules.filter { $0.id != rule.id } ?? []
    let duplicate = others.contains {
      PolicyProgramSummarizer.ruleKey($0) == candidate.id
    }
    guard !duplicate else { throw AppModelError.duplicateRuleIdentity }
    var updated = rule
    updated.kind = candidate.kind
    updated.teamIdentifier = candidate.kind == .teamSigned ? candidate.teamIdentifier : nil
    updated.signingIdentifier = candidate.signingIdentifier
    updated.allowsDescendants = includesChildProcesses
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
