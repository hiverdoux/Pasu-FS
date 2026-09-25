import AppKit
import PasuFSConfiguration
import SwiftUI
import UniformTypeIdentifiers

struct PolicyView: View {
  @Bindable var model: AppModel
  let policyID: UUID

  @State private var tab: PolicyEditorTab
  @State private var isChoosingFolder = false
  @State private var isConfirmingDelete = false
  @State private var pendingTypeChange: PolicyTypeChangeRequest?
  @State private var isConfirmingProtection = false
  @State private var editingRule: PolicyRule?

  init(model: AppModel, policyID: UUID, initialTab: PolicyEditorTab = .settings) {
    self.model = model
    self.policyID = policyID
    _tab = State(initialValue: initialTab)
  }

  var body: some View {
    presentingSheets(presentingDialogs(decorated(content)))
  }

  @ViewBuilder
  private var content: some View {
    if let draft = model.policyDraft(id: policyID) {
      switch tab {
      case .settings:
        settingsForm(draft)
      case .log:
        PolicyLogView(model: model, policyID: policyID) {
          isConfirmingProtection = true
        }
      }
    } else {
      ContentUnavailableView(
        "Policy Unavailable",
        systemImage: "lock.doc",
        description: Text("The selected policy no longer exists.")
      )
    }
  }

  private func decorated(_ view: some View) -> some View {
    view
      .navigationTitle(title)
      .navigationSubtitle(subtitle)
      .toolbar {
        ToolbarItem(placement: .navigation) {
          Button {
            revealFolder()
          } label: {
            Label("Show in Finder", systemImage: "folder")
          }
          .disabled(folderPath == nil)
          .help("Show the protected folder in Finder")
        }
        // Centered, it stays in the same place on both tabs and moves toward the free space when
        // the search field expands. The main window's minimum width keeps room for it then.
        ToolbarItem(placement: .principal) {
          Picker("View", selection: $tab) {
            Text("Settings").tag(PolicyEditorTab.settings)
            Text("Log").tag(PolicyEditorTab.log)
          }
          .pickerStyle(.segmented)
        }
      }
      .toolbarGroups(isShown: isDirty) {
        ToolbarItem {
          Button("Revert") {
            model.revertPolicy(id: policyID)
          }
          .disabled(!canRevert)
        }
      } _: {
        ToolbarItem {
          saveButton
        }
      }
      .onAppear(perform: takePendingLogRequest)
      .onChange(of: model.pendingPolicyLogPolicyID) { takePendingLogRequest() }
      .focusedSceneValue(
        \.policyCommands,
        PolicyCommandActions(
          save: canSave ? { save() } : nil,
          revert: canRevert ? { model.revertPolicy(id: policyID) } : nil,
          showInFinder: folderPath == nil ? nil : { revealFolder() }
        ))
  }

  private func presentingDialogs(_ view: some View) -> some View {
    view
      .alert(
        typeChangeTitle,
        isPresented: typeChangeIsPresented,
        presenting: pendingTypeChange
      ) { request in
        Button("Keep Rules and Change") {
          apply(request, deletingAllRules: false)
        }
        Button("Delete All Rules and Change", role: .destructive) {
          apply(request, deletingAllRules: true)
        }
        Button("Cancel", role: .cancel) {
          pendingTypeChange = nil
        }
      } message: { request in
        Text(typeChangeMessage(request))
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
        Text(deleteMessage)
      }
  }

  private func presentingSheets(_ view: some View) -> some View {
    view
      .alert("Switch to Protection?", isPresented: $isConfirmingProtection) {
        Button("Switch and Save") {
          Task { await model.switchToProtection(policyID: policyID) }
        }
        Button("Cancel", role: .cancel) {}
      } message: {
        Text(protectionSwitchMessage)
      }
      .sheet(item: $editingRule) { rule in
        AddProgramSheet(model: model, policyID: policyID, editing: rule)
      }
  }

  private var typeChangeTitle: String {
    guard let request = pendingTypeChange else { return "" }
    return String(localized: "Change to \(request.targetType.displayName)?")
  }

  private var deleteMessage: String {
    if model.activePolicy(id: policyID) == nil {
      return String(localized: "This unsaved policy will be discarded.")
    }
    return String(
      localized:
        "The policy and its log files are removed right away."
    )
  }

  // MARK: - Settings form

  private func settingsForm(_ draft: DirectoryPolicyDraft) -> some View {
    Form {
      if let notice {
        Section {
          Label(notice.text, systemImage: notice.systemImage)
            .foregroundStyle(notice.color)
        }
      }
      Section {
        TextField("Name", text: nameBinding, prompt: Text("Policy name"))
        folderRow(draft)
      }
      behaviorSection(draft)
      rulesSection(draft)
      compatibilitySection(draft)
      Section {
        Button("Delete Policy…", role: .destructive) {
          isConfirmingDelete = true
        }
        .foregroundStyle(.red)
        .disabled(model.isBusy)
      }
    }
    .formStyle(.grouped)
  }

  private func folderRow(_ draft: DirectoryPolicyDraft) -> some View {
    FolderPathRow(
      path: draft.protectedRootPath,
      isFocusRequested: model.pendingFolderEntryPolicyID == policyID,
      commit: { text in
        model.updatePolicyDraft(id: policyID) {
          $0.protectedRootPath = ProtectedFolderCheck.path(fromTypedText: text)
        }
      },
      choose: { isChoosingFolder = true },
      onFocus: { model.pendingFolderEntryPolicyID = nil }
    )
    .fileImporter(
      isPresented: $isChoosingFolder,
      allowedContentTypes: [.folder],
      allowsMultipleSelection: false
    ) { result in
      if case .success(let urls) = result, let url = urls.first {
        setFolder(url)
      }
    }
    .dropDestination(for: URL.self) { urls, _ in
      guard let url = urls.first else { return false }
      setFolder(url)
      return true
    }
  }

  private func behaviorSection(_ draft: DirectoryPolicyDraft) -> some View {
    Section {
      LabeledContent {
        Picker("Mode", selection: modeBinding) {
          Text("Protection").tag(PolicyMode.protection)
          Text("Audit").tag(PolicyMode.audit)
        }
        .pickerStyle(.radioGroup)
        .horizontalRadioGroupLayout()
        .labelsHidden()
      } label: {
        Text("Mode")
      }
      LabeledContent {
        Picker("Type", selection: typeBinding) {
          Text("Whitelist").tag(PolicyType.whitelist)
          Text("Blacklist").tag(PolicyType.blacklist)
        }
        .pickerStyle(.radioGroup)
        .horizontalRadioGroupLayout()
        .labelsHidden()
      } label: {
        Text("Type")
      }
    } header: {
      Text("Behavior")
    }
  }

  private func rulesSection(_ draft: DirectoryPolicyDraft) -> some View {
    Section {
      if let warning = emptyRulesWarning(draft) {
        WarningLabel(text: warning)
      } else if draft.rules.isEmpty {
        // A section without rows would let the next section's header collapse into this one.
        Text("No rules")
          .foregroundStyle(.secondary)
      }
      ForEach(draft.rules) { rule in
        RuleRow(
          rule: rule,
          displayName: model.ruleDisplayName(for: rule),
          isEnabled: enabledBinding(for: rule),
          onEdit: { editingRule = rule },
          onRemove: { model.removeRule(policyID: policyID, ruleID: rule.id) }
        )
      }
    } header: {
      HStack {
        Text(PolicyBehaviorText.rulesTitle(draft.policyType))
        if !draft.rules.isEmpty {
          Text(
            RuleCountText.summary(
              active: draft.rules.lazy.filter(\.isEnabled).count, total: draft.rules.count)
          )
          .foregroundStyle(.secondary)
        }
        Spacer()
        Button {
          model.addProgramRequest = AddProgramRequest(policyID: policyID)
        } label: {
          Label("Add Program…", systemImage: "plus")
        }
      }
    }
  }

  /// A Protection whitelist without rules in use denies every open in its folder.
  private func emptyRulesWarning(_ draft: DirectoryPolicyDraft) -> String? {
    guard draft.mode == .protection, draft.policyType == .whitelist,
      !draft.rules.contains(where: \.isEnabled)
    else { return nil }
    return String(
      localized: "No program is allowed. After you save, every open in this folder is denied.")
  }

  @ViewBuilder
  private func compatibilitySection(_ draft: DirectoryPolicyDraft) -> some View {
    if draft.policyType == .whitelist {
      Section {
        let items = model.systemCompatibilityProfileItems(policyID: policyID)
        if items.isEmpty {
          Label("No verified compatibility profiles yet", systemImage: "puzzlepiece.extension")
        } else {
          ForEach(items) { item in
            CompatibilityProfileRow(
              item: item,
              isEditable: compatibilityIsEditable,
              disabledReason: compatibilityDisabledReason
            ) { enabled in
              Task {
                await model.setSystemCompatibilityProfile(
                  policyID: policyID, profileID: item.profile.id, enabled: enabled)
              }
            }
          }
        }
      } header: {
        Text("System Compatibility")
      }
    }
  }

  private var compatibilityIsEditable: Bool {
    !model.isBusy && model.activePolicy(id: policyID) != nil && !model.isPolicyDirty(policyID)
      && model.systemCompatibilityCatalogMatchesExtension
  }

  private var compatibilityDisabledReason: String? {
    if model.activePolicy(id: policyID) == nil || model.isPolicyDirty(policyID) {
      return String(localized: "Save this policy first.")
    }
    if !model.systemCompatibilityCatalogMatchesExtension {
      return String(localized: "The app and extension must use the same built-in definitions.")
    }
    return nil
  }

  // MARK: - Saving

  private var isDirty: Bool { model.isPolicyDirty(policyID) }

  private var validationMessage: String? {
    isDirty ? model.draftValidationMessage(for: policyID) : nil
  }

  private var canSave: Bool {
    !model.isBusy && isDirty && validationMessage == nil
  }

  private var canRevert: Bool {
    !model.isBusy && isDirty
  }

  private func save() {
    Task { await model.savePolicy(id: policyID) }
  }

  /// The prominent Save button when the draft can be saved, otherwise a plain disabled one.
  @ViewBuilder
  private var saveButton: some View {
    if canSave {
      Button("Save") {
        save()
      }
      .buttonStyle(.borderedProminent)
    } else {
      Button(model.isBusy ? "Saving…" : "Save") {}
        .disabled(true)
    }
  }

  private struct Notice {
    let text: String
    let systemImage: String
    let color: Color
  }

  /// Switches to the Log tab when another screen asked to show one of this policy's records.
  private func takePendingLogRequest() {
    guard model.pendingPolicyLogPolicyID == policyID else { return }
    tab = .log
    model.pendingPolicyLogPolicyID = nil
  }

  /// The latest error or a reason the draft can't be saved. Results of extension requests are
  /// shown in Settings, where those requests are made.
  private var notice: Notice? {
    if let error = model.lastError {
      return Notice(text: error, systemImage: "xmark.octagon", color: .red)
    }
    if let validationMessage {
      return Notice(text: validationMessage, systemImage: "exclamationmark.circle", color: .orange)
    }
    return nil
  }

  private var folderPath: String? {
    guard let path = model.policyDraft(id: policyID)?.protectedRootPath, !path.isEmpty else {
      return nil
    }
    return path
  }

  // MARK: - Titles and messages

  private var title: String {
    guard let draft = model.policyDraft(id: policyID) else { return String(localized: "Policy") }
    return draft.name.isEmpty ? String(localized: "Untitled Policy") : draft.name
  }

  private var subtitle: String {
    guard let draft = model.policyDraft(id: policyID) else { return "" }
    if model.activePolicy(id: policyID) == nil {
      return String(localized: "Not saved yet")
    }
    if model.isPolicyDirty(policyID) {
      return String(localized: "Unsaved changes")
    }
    if draft.mode == .audit {
      return String(
        localized:
          "\(draft.mode.displayName) · \(draft.policyType.displayName) · Nothing is blocked")
    }
    return "\(draft.mode.displayName) · \(draft.policyType.displayName)"
  }

  private func typeChangeMessage(_ request: PolicyTypeChangeRequest) -> String {
    switch request.targetType {
    case .blacklist:
      String(
        localized:
          "The \(request.ruleCount) programs in the list will be denied instead of allowed. The change applies when you save."
      )
    case .whitelist:
      String(
        localized:
          "Only the \(request.ruleCount) programs in the list will be allowed. The change applies when you save."
      )
    }
  }

  private var protectionSwitchMessage: String {
    let denied = model.projectedDenials(policyID: policyID)
    var parts: [String] = []
    if denied.isEmpty {
      parts.append(String(localized: "No program in the loaded records would be denied."))
    } else {
      let names = denied.prefix(5).map(\.displayName).joined(separator: ", ")
      let remaining = denied.count - min(denied.count, 5)
      let list =
        remaining > 0 ? String(localized: "\(names) and \(remaining) more") : names
      parts.append(
        String(
          localized:
            "Based on the loaded records, opens from these programs would be denied: \(list)."))
    }
    parts.append(String(localized: "The change is saved and applied right away."))
    if let draft = model.policyDraft(id: policyID),
      let active = model.activePolicy(id: policyID),
      draft.makePolicy() != active
    {
      parts.append(String(localized: "Other unsaved changes to this policy are saved too."))
    }
    return parts.joined(separator: " ")
  }

  // MARK: - Bindings and actions

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

  private var typeBinding: Binding<PolicyType> {
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

  private func enabledBinding(for rule: PolicyRule) -> Binding<Bool> {
    Binding(
      get: { currentRule(rule.id)?.isEnabled ?? rule.isEnabled },
      set: { value in
        guard var updated = currentRule(rule.id) else { return }
        updated.isEnabled = value
        model.updateRule(policyID: policyID, rule: updated)
      }
    )
  }

  private func currentRule(_ ruleID: String) -> PolicyRule? {
    guard let rules = model.policyDraft(id: policyID)?.rules else { return nil }
    return rules.first(where: { $0.id == ruleID })
  }

  private var typeChangeIsPresented: Binding<Bool> {
    Binding(
      get: { pendingTypeChange != nil },
      set: { isPresented in
        if !isPresented { pendingTypeChange = nil }
      }
    )
  }

  private func apply(_ request: PolicyTypeChangeRequest, deletingAllRules: Bool) {
    model.applyPolicyTypeChange(
      policyID: request.policyID,
      to: request.targetType,
      deletingAllRules: deletingAllRules
    )
    pendingTypeChange = nil
  }

  private func setFolder(_ url: URL) {
    let path = ProtectedFolderCheck.canonicalPath(for: url)
    model.updatePolicyDraft(id: policyID) { $0.protectedRootPath = path }
  }

  private func revealFolder() {
    guard let folderPath else { return }
    NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: folderPath)])
  }
}

/// The protected folder's path. It can be typed in place, like the name, or chosen with a panel.
/// Typed text is applied when editing ends; Escape restores the current path.
private struct FolderPathRow: View {
  let path: String
  /// True for a new policy, whose folder is the first thing to enter.
  let isFocusRequested: Bool
  let commit: (String) -> Void
  let choose: () -> Void
  let onFocus: () -> Void

  @State private var text = ""
  @FocusState private var isEditing: Bool

  var body: some View {
    LabeledContent {
      HStack {
        TextField("Protected Folder", text: $text, prompt: Text("No folder chosen"))
          .labelsHidden()
          .textFieldStyle(.plain)
          .multilineTextAlignment(.trailing)
          .focused($isEditing)
          .onSubmit(apply)
          .onExitCommand {
            text = displayText
            isEditing = false
          }
          .help(path)
        Button("Choose…", action: choose)
      }
    } label: {
      Text("Protected Folder")
      if let issue = ProtectedFolderCheck.issue(for: path), issue != .notChosen {
        Text(issue.userFacingMessage)
          .foregroundStyle(.orange)
      }
    }
    .onAppear {
      text = displayText
      if isFocusRequested {
        isEditing = true
        onFocus()
      }
    }
    .onChange(of: path) { text = displayText }
    .onChange(of: isEditing) {
      if !isEditing { apply() }
    }
  }

  private var displayText: String {
    path.isEmpty ? "" : PathText.abbreviated(path)
  }

  private func apply() {
    guard text != displayText else { return }
    commit(text)
  }
}

enum PolicyEditorTab: Hashable {
  case settings
  case log
}

// Keep presentation and its content together so the confirmation can never be empty.
private struct PolicyTypeChangeRequest: Identifiable {
  let id = UUID()
  let policyID: UUID
  let currentType: PolicyType
  let targetType: PolicyType
  let ruleCount: Int
}

// MARK: - Rule row

private struct RuleRow: View {
  let rule: PolicyRule
  let displayName: String
  @Binding var isEnabled: Bool
  let onEdit: () -> Void
  let onRemove: () -> Void

  var body: some View {
    HStack {
      ProgramIcon(signingIdentifier: rule.signingIdentifier, executablePath: nil, size: 32)
      VStack(alignment: .leading) {
        HStack {
          Text(displayName)
            .lineLimit(1)
          if rule.allowsDescendants {
            Text("Includes child processes")
              .font(.caption)
              .foregroundStyle(.orange)
          }
          if !isEnabled {
            Text("Off")
              .font(.caption)
              .foregroundStyle(.secondary)
          }
        }
        SignatureLine(kind: rule.kind.displayName, identifiers: identity)
      }
      .foregroundStyle(isEnabled ? .primary : .secondary)
      Spacer()
      Toggle("Use this rule", isOn: $isEnabled)
        .toggleStyle(.switch)
        .labelsHidden()
      Menu {
        Button("Edit…", action: onEdit)
        Button("Remove", role: .destructive, action: onRemove)
      } label: {
        Label("More actions for \(displayName)", systemImage: "ellipsis.circle")
          .labelStyle(.iconOnly)
      }
      .menuStyle(.borderlessButton)
      .menuIndicator(.hidden)
      .fixedSize()
    }
    .contextMenu {
      Button("Edit…", action: onEdit)
      Button("Remove", role: .destructive, action: onRemove)
    }
  }

  private var identity: String {
    switch rule.kind {
    case .teamSigned:
      "\(rule.teamIdentifier ?? "—") · \(rule.signingIdentifier)"
    case .platformBinary:
      rule.signingIdentifier
    }
  }
}

// MARK: - Compatibility profile row

private struct CompatibilityProfileRow: View {
  let item: SystemCompatibilityProfileItem
  let isEditable: Bool
  let disabledReason: String?
  let setEnabled: (Bool) -> Void

  var body: some View {
    HStack(alignment: .top) {
      Label {
        HStack {
          Text(item.profile.displayName)
          Text(item.state.displayName)
            .foregroundStyle(stateTint)
        }
        Text(item.profile.roleDescription)
        Text(item.profile.consequence)
          .foregroundStyle(.orange)
      } icon: {
        Image(systemName: "puzzlepiece.extension")
      }
      Spacer()
      Button(buttonTitle) {
        setEnabled(item.state.needsReview ? true : !item.isEnabled)
      }
      .disabled(!isEditable)
      .help(disabledReason ?? "")
    }
  }

  private var buttonTitle: String {
    if item.state.needsReview { return String(localized: "Review and Turn On") }
    return item.isEnabled ? String(localized: "Turn Off") : String(localized: "Turn On")
  }

  private var stateTint: Color {
    switch item.state {
    case .active: .green
    case .disabled: .secondary
    case .needsReview, .missingProfile, .unsupportedOS, .policyContextChanged, .policyMissing:
      .orange
    }
  }
}
