import PasuFSConfiguration
import SwiftUI
import UniformTypeIdentifiers

struct PolicyView: View {
  @Bindable var model: AppModel
  let policyID: UUID

  @State private var isSelectingRoot = false
  @State private var isSelectingApplication = false
  @State private var isSelectingAuditRule = false
  @State private var isConfirmingDelete = false
  @State private var isConfirmingTypeChange = false
  @State private var pendingPolicyType: PolicyType?

  var body: some View {
    Group {
      if let draft = model.policyDraft(id: policyID) {
        policyEditor(draft)
      } else {
        ContentUnavailableView(
          "Policy unavailable",
          systemImage: "lock.doc",
          description: Text("The selected policy no longer exists.")
        )
      }
    }
    .navigationTitle(model.policyDraft(id: policyID)?.name ?? "Policy")
    .navigationSubtitle(savedStateDescription)
    .toolbar {
      ToolbarItem {
        if model.isPolicyDirty(policyID) {
          TagBadge(text: "Unsaved changes", tint: .orange)
        }
      }
    }
    .sheet(isPresented: $isSelectingAuditRule) {
      AuditRulePicker(model: model, policyID: policyID)
        .frame(minWidth: 620, minHeight: 440)
    }
    .sheet(isPresented: $isConfirmingTypeChange, onDismiss: cancelTypeChange) {
      if let pendingPolicyType,
        let currentType = model.policyDraft(id: policyID)?.policyType
      {
        PolicyTypeChangeSheet(
          currentType: currentType,
          targetType: pendingPolicyType,
          ruleCount: model.policyDraft(id: policyID)?.rules.count ?? 0,
          onConfirm: { deletingAllRules in
            model.applyPolicyTypeChange(
              policyID: policyID,
              to: pendingPolicyType,
              deletingAllRules: deletingAllRules
            )
            self.pendingPolicyType = nil
            isConfirmingTypeChange = false
          },
          onCancel: {
            cancelTypeChange()
            isConfirmingTypeChange = false
          }
        )
        .frame(width: 430)
      }
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
        Text("The policy will be removed immediately in a new policy-set revision.")
      }
    }
  }

  // MARK: - Layout

  @ViewBuilder
  private func policyEditor(_ draft: DirectoryPolicyDraft) -> some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 12) {
        identityCard(draft)
        rulesSection(draft)
        messageBanners
      }
      .padding(20)
    }
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

  // MARK: - Identity card

  private func identityCard(_ draft: DirectoryPolicyDraft) -> some View {
    VStack(spacing: 0) {
      identityRow("Name", caption: nil) {
        TextField("Policy name", text: nameBinding)
          .textFieldStyle(.roundedBorder)
          .frame(width: 300)
      }
      CardDivider()
      identityRow("Mode", caption: "Protection blocks; Audit only records.") {
        Picker("Mode", selection: modeBinding) {
          Text("Protection").tag(PolicyMode.protection)
          Text("Audit").tag(PolicyMode.audit)
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .frame(width: 300)
      }
      CardDivider()
      identityRow("Type", caption: modeAndTypeExplanation(for: draft)) {
        Picker("Type", selection: policyTypeBinding) {
          Text("Whitelist").tag(PolicyType.whitelist)
          Text("Blacklist").tag(PolicyType.blacklist)
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .frame(width: 300)
      }
      CardDivider()
      identityRow(
        "Protected folder",
        caption:
          "One folder per policy. A directory can pair one Protection and one Audit policy, but duplicate mode-and-directory pairs are rejected."
      ) {
        HStack(spacing: 8) {
          TextField("Absolute directory path", text: protectedRootBinding)
            .textFieldStyle(.roundedBorder)
            .font(.body.monospaced())
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
        .frame(width: 360)
      }
    }
    .cardStyle()
  }

  private func identityRow(
    _ title: String,
    caption: String?,
    @ViewBuilder control: () -> some View
  ) -> some View {
    HStack(alignment: .center, spacing: 16) {
      VStack(alignment: .leading, spacing: 2) {
        Text(title)
        if let caption {
          Text(caption)
            .font(.caption)
            .foregroundStyle(.secondary)
        }
      }
      Spacer(minLength: 12)
      control()
    }
    .padding(.horizontal, 16)
    .padding(.vertical, 10)
  }

  // MARK: - Rules

  private func rulesSection(_ draft: DirectoryPolicyDraft) -> some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack {
        SectionHeading(
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
      .padding(.horizontal, 4)

      VStack(spacing: 0) {
        if draft.rules.isEmpty {
          Text(emptyRulesMessage(for: draft))
            .font(.callout)
            .foregroundStyle(.secondary)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.horizontal, 16)
            .padding(.vertical, 14)
        }
        ForEach(Array(draft.rules.enumerated()), id: \.element.id) { index, rule in
          if index > 0 {
            CardDivider()
          }
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
      }
      .cardStyle()
    }
  }

  private var messageBanners: some View {
    Group {
      if let validationMessage = model.draftValidationMessage(for: policyID) {
        WarningBanner(text: validationMessage, systemImage: "exclamationmark.circle")
      }
      if let warning = model.policySynchronizationWarning {
        WarningBanner(text: warning, systemImage: "arrow.triangle.2.circlepath")
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
      get: { model.policyDraft(id: policyID)?.policyType ?? .whitelist },
      set: { value in
        guard let draft = model.policyDraft(id: policyID), value != draft.policyType else {
          return
        }
        if draft.rules.isEmpty {
          model.updatePolicyDraft(id: policyID) { $0.policyType = value }
        } else {
          pendingPolicyType = value
          isConfirmingTypeChange = true
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
      "Matching enabled rules are allowed; every other program is denied. At least one rule must be enabled."
    case (.protection, .blacklist):
      "Matching enabled rules are denied; every other program is allowed."
    case (.audit, .whitelist):
      "Records whether the whitelist would allow or deny, but never blocks."
    case (.audit, .blacklist):
      "Records whether the blacklist would deny or allow, but never blocks."
    }
  }

  private func emptyRulesMessage(for draft: DirectoryPolicyDraft) -> String {
    if draft.mode == .protection, draft.policyType == .whitelist {
      return "No rules. A Protection whitelist requires at least one enabled rule."
    }
    return "No rules. This policy is valid but currently matches no program identity."
  }

  private func cancelTypeChange() {
    pendingPolicyType = nil
  }
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
          HStack(spacing: 7) {
            Text(displayName)
              .font(.body.weight(.medium))
            TagBadge(text: rule.kind.displayName, tint: .secondary)
            if rule.allowsDescendants {
              TagBadge(text: "Descendants", tint: .orange)
            }
            if !rule.isEnabled {
              TagBadge(text: "Disabled — excluded from decisions", tint: .secondary)
            }
          }
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
      .padding(.horizontal, 16)
      .padding(.vertical, 10)

      if isExpanded {
        expandedEditor
          .padding(.leading, 58)
          .padding(.trailing, 16)
          .padding(.bottom, 12)
      }
    }
    .opacity(rule.isEnabled ? 1 : 0.6)
    .onChange(of: rule.kind) { _, kind in
      rule.teamIdentifier = kind == .teamSigned ? (rule.teamIdentifier ?? "") : nil
    }
  }

  private var expandedEditor: some View {
    VStack(alignment: .leading, spacing: 8) {
      Picker("Kind", selection: $rule.kind) {
        Text("Team signed").tag(PolicyRuleKind.teamSigned)
        Text("Apple platform").tag(PolicyRuleKind.platformBinary)
      }
      .labelsHidden()
      .fixedSize()

      Grid(alignment: .leading, verticalSpacing: 6) {
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
              HStack(spacing: 7) {
                Text(candidate.displayName)
                  .font(.body.weight(.medium))
                TagBadge(text: candidate.kind.displayName, tint: .secondary)
              }
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
