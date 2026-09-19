import PasuFSConfiguration
import SwiftUI
import UniformTypeIdentifiers

struct PolicyView: View {
  @Bindable var model: AppModel
  let policyID: UUID

  @State private var selectedTab = PolicyEditorTab.settings

  @State private var isSelectingRoot = false
  @State private var isSelectingApplication = false
  @State private var isSelectingAuditRule = false
  @State private var isConfirmingDelete = false
  @State private var pendingTypeChange: PolicyTypeChangeRequest?

  var body: some View {
    Group {
      if let draft = model.policyDraft(id: policyID) {
        VStack(spacing: 0) {
          Picker("Policy tab", selection: $selectedTab) {
            Text("Settings").tag(PolicyEditorTab.settings)
            Text("Log").tag(PolicyEditorTab.log)
          }
          .pickerStyle(.segmented)
          .labelsHidden()
          .accessibilityLabel("Policy tab")
          .frame(width: 220)
          .padding(12)
          Divider()
          switch selectedTab {
          case .settings:
            policyEditor(draft)
          case .log:
            PolicyLogView(model: model, policyID: policyID)
              .frame(maxWidth: .infinity, maxHeight: .infinity)
          }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .top)
      } else {
        ContentUnavailableView(
          "Policy unavailable",
          systemImage: "lock.doc",
          description: Text("The selected policy no longer exists.")
        )
      }
    }
    .navigationTitle(model.policyDraft(id: policyID)?.name ?? "Policy")
    .onChange(of: policyID) { selectedTab = .settings }
    .navigationSubtitle(savedStateDescription)
    .toolbar {
      ToolbarItem {
        if model.isPolicyDirty(policyID) {
          HStack(spacing: 5) {
            Circle()
              .fill(.orange)
              .frame(width: 7, height: 7)
            Text("Unsaved changes")
              .font(.callout)
              .foregroundStyle(.orange)
          }
        }
      }
    }
    .sheet(isPresented: $isSelectingAuditRule) {
      AuditRulePicker(model: model, policyID: policyID)
        .frame(minWidth: 620, minHeight: 440)
    }
    .sheet(item: $pendingTypeChange) { request in
      PolicyTypeChangeSheet(
        currentType: request.currentType,
        targetType: request.targetType,
        ruleCount: request.ruleCount,
        onConfirm: { deletingAllRules in
          model.applyPolicyTypeChange(
            policyID: request.policyID,
            to: request.targetType,
            deletingAllRules: deletingAllRules
          )
          pendingTypeChange = nil
        },
        onCancel: { pendingTypeChange = nil }
      )
      .frame(width: 430)
    }
    .confirmationDialog(
      "Delete this policy?",
      isPresented: $isConfirmingDelete,
      titleVisibility: .visible
    ) {
      Button("Delete Policy", role: .destructive) {
        Task { await model.deletePolicy(id: policyID) }
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      if model.activePolicy(id: policyID) == nil {
        Text("This unsaved policy draft will be discarded.")
      } else {
        Text(
          "The policy and its separate log files will be removed immediately. Records in the overall Audit Log follow its existing retention limit."
        )
      }
    }
  }

  // MARK: - Layout

  @ViewBuilder
  private func policyEditor(_ draft: DirectoryPolicyDraft) -> some View {
    Form {
      identitySection(draft)
      rulesSection(draft)
      systemCompatibilitySection(draft)
      if hasMessages {
        messagesSection
      }
    }
    .formStyle(.grouped)
    .safeAreaInset(edge: .bottom, spacing: 0) {
      saveBar
    }
  }

  private var savedStateDescription: String {
    if model.activePolicy(id: policyID) == nil {
      return "Not saved yet"
    }
    if let revision = model.activeRevision {
      return "Saved in policy-set revision \(revision)"
    }
    return "Saved"
  }

  // MARK: - Identity section

  private func identitySection(_ draft: DirectoryPolicyDraft) -> some View {
    Section {
      LabeledContent("Name") {
        TextField("Policy name", text: nameBinding)
          .textFieldStyle(.roundedBorder)
          .labelsHidden()
          .frame(width: 260)
      }
      LabeledContent {
        Picker("Mode", selection: modeBinding) {
          Text("Protection").tag(PolicyMode.protection)
          Text("Audit").tag(PolicyMode.audit)
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .frame(width: 260)
      } label: {
        Text("Mode")
        Text("Protection blocks; Audit only records.")
      }
      LabeledContent {
        Picker("Type", selection: policyTypeBinding) {
          Text("Whitelist").tag(PolicyType.whitelist)
          Text("Blacklist").tag(PolicyType.blacklist)
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .frame(width: 260)
      } label: {
        Text("Type")
        Text(modeAndTypeExplanation(for: draft))
      }
      LabeledContent {
        HStack(spacing: 8) {
          TextField("Absolute directory path", text: protectedRootBinding)
            .textFieldStyle(.roundedBorder)
            .labelsHidden()
            .font(.body.monospaced())
            .frame(width: 240)
          Button("Choose…") { isSelectingRoot = true }
            .fileImporter(
              isPresented: $isSelectingRoot,
              allowedContentTypes: [.folder],
              allowsMultipleSelection: false
            ) { result in
              if case .success(let urls) = result, let url = urls.first {
                model.updatePolicyDraft(id: policyID) {
                  $0.protectedRootPath = url.standardizedFileURL.resolvingSymlinksInPath().path
                }
              }
            }
        }
      } label: {
        Text("Protected folder")
        Text(
          "One folder per policy. A directory can pair one Protection and one Audit policy, but duplicate mode-and-directory pairs are rejected."
        )
      }
    }
  }

  // MARK: - Rules

  private func rulesSection(_ draft: DirectoryPolicyDraft) -> some View {
    Section {
      if draft.rules.isEmpty {
        Text(emptyRulesMessage(for: draft))
          .font(.callout)
          .foregroundStyle(.secondary)
      }
      ForEach(draft.rules, id: \.id) { rule in
        RuleEditorRow(
          rule: Binding(
            get: {
              model.policyDraft(id: policyID)?.rules.first(where: { $0.id == rule.id })
                ?? rule
            },
            set: { model.updateRule(policyID: policyID, rule: $0) }
          ),
          policyType: draft.policyType,
          displayName: model.ruleDisplayName(for: rule)
        ) {
          model.removeRule(policyID: policyID, ruleID: rule.id)
        }
      }
    } header: {
      HStack {
        Text(
          "Rules · \(draft.rules.lazy.filter(\.isEnabled).count) of \(draft.rules.count) enabled"
        )
        Spacer()
        Menu("Add Rule") {
          Button("Choose Application…") { isSelectingApplication = true }
          Button("Choose from Audit Log…") { isSelectingAuditRule = true }
          Divider()
          Button("Signed app (manual)") { model.addTeamSignedRule(policyID: policyID) }
          Button("Apple platform binary (manual)") {
            model.addPlatformRule(policyID: policyID)
          }
        }
        .fixedSize()
        .fileImporter(
          isPresented: $isSelectingApplication,
          allowedContentTypes: [.application],
          allowsMultipleSelection: false
        ) { result in
          if case .success(let urls) = result, let url = urls.first {
            model.addRule(policyID: policyID, fromApplicationAt: url)
          }
        }
      }
    }
  }

  private func systemCompatibilitySection(
    _ draft: DirectoryPolicyDraft
  ) -> some View {
    Section {
      if draft.policyType == .blacklist {
        compatibilityEmptyRow(
          title: "Not used by Blacklist policies",
          detail:
            "A Blacklist already allows every non-matching process. Explicit blacklist matches always remain denied."
        )
      } else if model.systemCompatibilityProfileItems(policyID: policyID).isEmpty {
        compatibilityEmptyRow(
          title: "No verified profiles available",
          detail:
            "The infrastructure is active, but no macOS service is trusted automatically. A Time Machine profile will be added only after host entitlement testing establishes its exact actors and open flags."
        )
      } else {
        ForEach(model.systemCompatibilityProfileItems(policyID: policyID), id: \.id) { item in
          systemCompatibilityRow(item)
        }
      }
    } header: {
      HStack {
        Text("System compatibility")
        Spacer()
        Text("Built-in profiles · direct actors only")
          .font(.caption)
          .foregroundStyle(.tertiary)
      }
    }
  }

  private func compatibilityEmptyRow(title: String, detail: String) -> some View {
    HStack(alignment: .top, spacing: 12) {
      IconTile(systemImage: "puzzlepiece.extension", tint: .secondary)
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
          .font(.body.weight(.medium))
        Text(detail)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer()
    }
  }

  private func systemCompatibilityRow(
    _ item: SystemCompatibilityProfileItem
  ) -> some View {
    HStack(alignment: .top, spacing: 12) {
      IconTile(systemImage: "puzzlepiece.extension", tint: .secondary)
      VStack(alignment: .leading, spacing: 3) {
        HStack(spacing: 5) {
          Text(item.profile.displayName)
            .font(.body.weight(.medium))
          Text("· \(compatibilityStateText(item.state))")
            .font(.callout)
            .foregroundStyle(compatibilityTint(item.state))
        }
        Text(item.profile.roleDescription)
          .font(.caption)
          .foregroundStyle(.secondary)
        Text(item.profile.consequence)
          .font(.caption2)
          .foregroundStyle(.orange)
      }
      Spacer(minLength: 12)
      Button(
        needsCompatibilityReview(item.state)
          ? "Review & Enable" : item.isEnabled ? "Disable" : "Enable"
      ) {
        Task {
          await model.setSystemCompatibilityProfile(
            policyID: policyID,
            profileID: item.profile.id,
            enabled: needsCompatibilityReview(item.state) ? true : !item.isEnabled
          )
        }
      }
      .disabled(
        model.isBusy
          || model.activePolicy(id: policyID) == nil
          || model.isPolicyDirty(policyID)
          || !model.systemCompatibilityCatalogMatchesExtension
      )
    }
  }

  private func compatibilityStateText(
    _ state: SystemCompatibilityProfileState
  ) -> String {
    switch state {
    case .active: "Active"
    case .disabled: "Off"
    case .needsReview: "Review required"
    case .missingProfile: "Unavailable"
    case .unsupportedOS: "Unsupported on this macOS"
    case .policyContextChanged: "Policy changed"
    case .policyMissing: "Policy unavailable"
    }
  }

  private func needsCompatibilityReview(
    _ state: SystemCompatibilityProfileState
  ) -> Bool {
    state == .needsReview || state == .policyContextChanged
  }

  private func compatibilityTint(
    _ state: SystemCompatibilityProfileState
  ) -> Color {
    switch state {
    case .active: .green
    case .disabled: .secondary
    case .needsReview, .missingProfile, .unsupportedOS, .policyContextChanged,
      .policyMissing:
      .orange
    }
  }

  // MARK: - Messages

  private var hasMessages: Bool {
    model.draftValidationMessage(for: policyID) != nil
      || model.policySynchronizationWarning != nil
      || model.systemCompatibilitySynchronizationWarning != nil
      || model.lastError != nil
  }

  private var messagesSection: some View {
    Section {
      if let validationMessage = model.draftValidationMessage(for: policyID) {
        Label {
          Text(validationMessage)
        } icon: {
          Image(systemName: "exclamationmark.circle")
            .foregroundStyle(.orange)
        }
      }
      if let warning = model.policySynchronizationWarning {
        Label {
          Text(warning)
        } icon: {
          Image(systemName: "arrow.triangle.2.circlepath")
            .foregroundStyle(.orange)
        }
      }
      if let warning = model.systemCompatibilitySynchronizationWarning {
        Label {
          Text(warning)
        } icon: {
          Image(systemName: "puzzlepiece.extension")
            .foregroundStyle(.orange)
        }
      }
      if let error = model.lastError {
        Text(error)
          .font(.callout)
          .foregroundStyle(.red)
      }
    }
  }

  // MARK: - Save bar

  private var saveBar: some View {
    HStack(spacing: 10) {
      Button("Delete Policy…", role: .destructive) {
        isConfirmingDelete = true
      }
      .disabled(model.isBusy)
      Spacer()
      Text("Save submits the full policy set atomically as \(model.nextRevisionDescription).")
        .font(.caption)
        .foregroundStyle(.tertiary)
      Button("Revert") { model.revertPolicy(id: policyID) }
        .disabled(model.isBusy || !model.isPolicyDirty(policyID))
      Button(model.isBusy ? "Saving…" : "Save") {
        Task { await model.savePolicy(id: policyID) }
      }
      .buttonStyle(.borderedProminent)
      .keyboardShortcut("s", modifiers: .command)
      .disabled(
        model.isBusy || !model.isPolicyDirty(policyID)
          || model.draftValidationMessage(for: policyID) != nil
      )
    }
    .padding(.horizontal, 20)
    .padding(.vertical, 12)
    .background(.bar)
    .overlay(alignment: .top) {
      Divider()
    }
  }

  // MARK: - Bindings

  private var nameBinding: Binding<String> {
    Binding(
      get: { model.policyDraft(id: policyID)?.name ?? "" },
      set: { value in model.updatePolicyDraft(id: policyID) { $0.name = value } }
    )
  }

  private var modeBinding: Binding<PolicyMode> {
    Binding(
      get: { model.policyDraft(id: policyID)?.mode ?? .protection },
      set: { value in model.updatePolicyDraft(id: policyID) { $0.mode = value } }
    )
  }

  private var policyTypeBinding: Binding<PolicyType> {
    Binding(
      get: {
        if let pendingTypeChange, pendingTypeChange.policyID == policyID {
          return pendingTypeChange.targetType
        }
        return model.policyDraft(id: policyID)?.policyType ?? .whitelist
      },
      set: { value in
        guard let draft = model.policyDraft(id: policyID), value != draft.policyType else {
          return
        }
        if draft.rules.isEmpty {
          model.updatePolicyDraft(id: policyID) { $0.policyType = value }
        } else {
          pendingTypeChange = PolicyTypeChangeRequest(
            policyID: policyID,
            currentType: draft.policyType,
            targetType: value,
            ruleCount: draft.rules.count
          )
        }
      }
    )
  }

  private var protectedRootBinding: Binding<String> {
    Binding(
      get: { model.policyDraft(id: policyID)?.protectedRootPath ?? "" },
      set: { value in
        model.updatePolicyDraft(id: policyID) { $0.protectedRootPath = value }
      }
    )
  }

  private func modeAndTypeExplanation(for draft: DirectoryPolicyDraft) -> String {
    switch (draft.mode, draft.policyType) {
    case (.protection, .whitelist):
      "Matching enabled rules are allowed; programs without a matching rule are denied unless a system-compatibility exception applies."
    case (.protection, .blacklist):
      "Matching enabled rules are denied; every other program is allowed."
    case (.audit, .whitelist):
      "Records whether the whitelist would allow or deny, but never blocks."
    case (.audit, .blacklist):
      "Records whether the blacklist would deny or allow, but never blocks."
    }
  }

  private func emptyRulesMessage(for draft: DirectoryPolicyDraft) -> String {
    if draft.policyType == .whitelist {
      return "No rules. No program is explicitly allowed by this policy."
    }
    return "No rules. This policy is valid but currently matches no program identity."
  }

}

private enum PolicyEditorTab: Hashable {
  case settings
  case log
}

// MARK: - Rule row

private struct RuleEditorRow: View {
  @Binding var rule: PolicyRule
  let policyType: PolicyType
  let displayName: String
  let onDelete: () -> Void

  @State private var isExpanded: Bool

  init(
    rule: Binding<PolicyRule>,
    policyType: PolicyType,
    displayName: String,
    onDelete: @escaping () -> Void
  ) {
    self._rule = rule
    self.policyType = policyType
    self.displayName = displayName
    self.onDelete = onDelete
    self._isExpanded = State(initialValue: rule.wrappedValue.signingIdentifier.isEmpty)
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 0) {
      HStack(spacing: 12) {
        IconTile(systemImage: rule.kind.symbolName, tint: .secondary, size: 30)
        VStack(alignment: .leading, spacing: 1) {
          titleText
            .lineLimit(1)
          Text(identitySummary)
            .font(.caption.monospaced())
            .foregroundStyle(.secondary)
        }
        Spacer(minLength: 12)
        Toggle("Enabled", isOn: $rule.isEnabled)
          .toggleStyle(.switch)
          .labelsHidden()
          .controlSize(.small)
          .help(
            rule.isEnabled
              ? "Rule participates in decisions"
              : "Rule is excluded from decisions"
          )
        Button {
          withAnimation(.easeInOut(duration: 0.15)) {
            isExpanded.toggle()
          }
        } label: {
          Image(systemName: "chevron.right")
            .rotationEffect(.degrees(isExpanded ? 90 : 0))
        }
        .buttonStyle(.borderless)
        .help(isExpanded ? "Collapse rule details" : "Edit rule details")
        Button(role: .destructive, action: onDelete) {
          Image(systemName: "trash")
        }
        .buttonStyle(.borderless)
        .help("Remove this rule")
      }

      if isExpanded {
        expandedEditor
          .padding(.leading, 42)
          .padding(.top, 10)
          .padding(.bottom, 2)
      }
    }
    .opacity(rule.isEnabled ? 1 : 0.6)
    .onChange(of: rule.kind) { _, kind in
      rule.teamIdentifier = kind == .teamSigned ? (rule.teamIdentifier ?? "") : nil
    }
  }

  private var titleText: Text {
    var text =
      Text(displayName).font(.body.weight(.medium))
      + Text(" · \(rule.kind.displayName)").foregroundStyle(.secondary)
    if rule.allowsDescendants {
      text = text + Text(" · Descendants").foregroundStyle(.orange)
    }
    if !rule.isEnabled {
      text = text + Text(" · disabled, excluded from decisions").foregroundStyle(.secondary)
    }
    return text
  }

  private var expandedEditor: some View {
    VStack(alignment: .leading, spacing: 8) {
      Grid(alignment: .leading, verticalSpacing: 6) {
        GridRow {
          Text("Kind")
            .foregroundStyle(.secondary)
            .gridColumnAlignment(.trailing)
          Picker("Kind", selection: $rule.kind) {
            Text("Team signed").tag(PolicyRuleKind.teamSigned)
            Text("Apple platform").tag(PolicyRuleKind.platformBinary)
          }
          .labelsHidden()
          .fixedSize()
        }
        if rule.kind == .teamSigned {
          GridRow {
            Text("Team ID")
              .foregroundStyle(.secondary)
              .gridColumnAlignment(.trailing)
            TextField(
              "Team ID",
              text: Binding(
                get: { rule.teamIdentifier ?? "" },
                set: { rule.teamIdentifier = $0.uppercased() }
              )
            )
            .textFieldStyle(.roundedBorder)
            .font(.body.monospaced())
            .labelsHidden()
            .frame(width: 260)
          }
        }
        GridRow {
          Text("Signing ID")
            .foregroundStyle(.secondary)
            .gridColumnAlignment(.trailing)
          TextField("Signing ID", text: $rule.signingIdentifier)
            .textFieldStyle(.roundedBorder)
            .font(.body.monospaced())
            .labelsHidden()
            .frame(width: 260)
        }
      }

      VStack(alignment: .leading, spacing: 2) {
        Toggle(descendantsLabel, isOn: $rule.allowsDescendants)
          .toggleStyle(.checkbox)
        if rule.allowsDescendants {
          Text(descendantsWarning)
            .font(.caption)
            .foregroundStyle(.orange)
        }
      }
    }
    .font(.callout)
  }

  private var descendantsLabel: String {
    policyType == .whitelist ? "Allow observed descendants" : "Block observed descendants"
  }

  private var descendantsWarning: String {
    if policyType == .whitelist {
      return "Trusts every observed child process — even one that runs a different program."
    }
    return "Blocks every observed child process — even after it runs a different program."
  }

  private var identitySummary: String {
    switch rule.kind {
    case .teamSigned:
      let team = rule.teamIdentifier?.isEmpty == false ? rule.teamIdentifier! : "—"
      let signing = rule.signingIdentifier.isEmpty ? "—" : rule.signingIdentifier
      return "\(team) · \(signing)"
    case .platformBinary:
      let signing = rule.signingIdentifier.isEmpty ? "—" : rule.signingIdentifier
      return "\(signing) · platform binary"
    }
  }
}

// MARK: - Type change sheet

// Keep presentation and its content together so the sheet can never be empty.
private struct PolicyTypeChangeRequest: Identifiable {
  let id = UUID()
  let policyID: UUID
  let currentType: PolicyType
  let targetType: PolicyType
  let ruleCount: Int
}

private struct PolicyTypeChangeSheet: View {
  let currentType: PolicyType
  let targetType: PolicyType
  let ruleCount: Int
  let onConfirm: (Bool) -> Void
  let onCancel: () -> Void

  @State private var deletingAllRules = false
  @State private var showsDeletedFeedback = false
  @State private var feedbackTask: Task<Void, Never>?

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text("Change policy type?")
        .font(.title3.weight(.semibold))
      Text(
        "Changing from \(currentType.displayName) to \(targetType.displayName) reverses the meaning of \(ruleCount) existing rules and any currently observed descendants."
      )
      .foregroundStyle(.secondary)

      HStack {
        Button(showsDeletedFeedback ? "Deleted!" : "Delete All Rules", role: .destructive) {
          deletingAllRules = true
          showDeletedFeedback()
        }
        Spacer()
        Button("Cancel", action: onCancel)
          .keyboardShortcut(.cancelAction)
        Button("Confirm") { onConfirm(deletingAllRules) }
          .buttonStyle(.borderedProminent)
          .keyboardShortcut(.defaultAction)
      }
    }
    .padding(22)
    .interactiveDismissDisabled()
    .onDisappear { feedbackTask?.cancel() }
  }

  private func showDeletedFeedback() {
    feedbackTask?.cancel()
    showsDeletedFeedback = true
    feedbackTask = Task {
      try? await Task.sleep(for: .seconds(1))
      guard !Task.isCancelled else { return }
      showsDeletedFeedback = false
    }
  }
}

// MARK: - Audit rule picker

private struct AuditRulePicker: View {
  @Bindable var model: AppModel
  let policyID: UUID

  @Environment(\.dismiss) private var dismiss
  @State private var filterText = ""

  var body: some View {
    VStack(alignment: .leading, spacing: 12) {
      HStack(alignment: .top) {
        VStack(alignment: .leading, spacing: 2) {
          Text("Choose from Audit Log")
            .font(.title3.weight(.semibold))
          Text(
            "Signed identities from the newest 500 loaded records. Paths and names are display-only — rules store signing identity."
          )
          .font(.caption)
          .foregroundStyle(.secondary)
        }
        Spacer()
        TextField("Filter programs", text: $filterText)
          .textFieldStyle(.roundedBorder)
          .frame(width: 200)
      }

      if filteredCandidates.isEmpty {
        ContentUnavailableView(
          "No supported signed programs",
          systemImage: "list.bullet.rectangle",
          description: Text(
            "Records without a complete Team ID + Signing ID or platform-binary identity are excluded."
          )
        )
      } else {
        List(filteredCandidates) { candidate in
          HStack(alignment: .top, spacing: 12) {
            IconTile(systemImage: candidate.kind.symbolName, tint: .secondary, size: 32)
            VStack(alignment: .leading, spacing: 2) {
              (Text(candidate.displayName).font(.body.weight(.medium))
                + Text(" · \(candidate.kind.displayName)").foregroundStyle(.secondary))
                .lineLimit(1)
              Text(identitySummary(candidate))
                .font(.caption.monospaced())
                .foregroundStyle(.secondary)
              if let path = candidate.executablePath {
                Text(path)
                  .font(.caption2.monospaced())
                  .foregroundStyle(.tertiary)
              }
              Text(
                "Last seen \(candidate.lastSeen.formatted()) · \(candidate.observationCount) observations · latest: \(candidate.latestResult)"
              )
              .font(.caption2)
              .foregroundStyle(.secondary)
            }
            Spacer()
            let alreadyExists = model.policyContainsIdentity(
              policyID: policyID,
              candidate: candidate
            )
            Button(alreadyExists ? "Already Added" : "Add") {
              do {
                try model.addRule(policyID: policyID, from: candidate)
                dismiss()
              } catch {
                model.lastError = String(describing: error)
              }
            }
            .disabled(alreadyExists)
          }
          .padding(.vertical, 3)
        }
        .listStyle(.inset)
      }

      HStack {
        Text("Records without a complete supported signing identity are excluded.")
          .font(.caption)
          .foregroundStyle(.tertiary)
        Spacer()
        Button("Refresh") {
          Task { await model.refreshAuditLog() }
        }
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
      }
    }
    .padding()
    .task { await model.refreshAuditLog() }
  }

  private var filteredCandidates: [AuditRuleCandidate] {
    let needle = filterText.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !needle.isEmpty else { return model.auditRuleCandidates }
    return model.auditRuleCandidates.filter {
      [$0.displayName, $0.signingIdentifier, $0.teamIdentifier, $0.executablePath]
        .compactMap { $0 }
        .contains { $0.localizedCaseInsensitiveContains(needle) }
    }
  }

  private func identitySummary(_ candidate: AuditRuleCandidate) -> String {
    switch candidate.kind {
    case .teamSigned:
      "\(candidate.teamIdentifier ?? "—") · \(candidate.signingIdentifier)"
    case .platformBinary:
      "\(candidate.signingIdentifier) · platform binary"
    }
  }
}
