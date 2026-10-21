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
  @State private var editingRule: RuleEditRequest?
  @AppStorage(ProgramSortOrder.defaultsKey) private var sortOrder = ProgramSortOrder.default

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
        PolicyLogView(model: model, policyID: policyID)
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
      .toolbarGroups(isShown: needsSaving) {
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
          saveNeedsAuthorization: saveNeedsAuthorization,
          duplicate: canDuplicate ? { model.duplicatePolicy(id: policyID) } : nil,
          revert: canRevert ? { model.revertPolicy(id: policyID) } : nil,
          showInFinder: folderPath == nil ? nil : { revealFolder() }
        ))
  }

  private func presentingDialogs(_ view: some View) -> some View {
    view
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
      .sheet(item: $editingRule) { request in
        AddProgramSheet(
          model: model, policyID: policyID, list: request.list, editing: request.rule)
      }
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
        if !retiredPaths.isEmpty {
          retiredPathsRow
        }
      }
      behaviorSection(draft)
      rulesSection(draft, list: .allow)
      rulesSection(draft, list: .deny)
      if model.supportsSystemCompatibilityProfiles || !draft.systemCompatibilityProfiles.isEmpty {
        compatibilitySection(draft)
      }
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

  /// The folder's former paths that stay reserved for the allowed programs until the policy
  /// is saved.
  private var retiredPathsRow: some View {
    LabeledContent {
      VStack(alignment: .trailing) {
        ForEach(retiredPaths, id: \.self) { path in
          Text(PathText.abbreviated(path))
            .help(path)
            .textSelection(.enabled)
        }
      }
    } label: {
      if retiredPaths.count == 1 {
        Text("Retired Path")
        Text("Saving the policy releases it.")
      } else {
        Text("Retired Paths")
        Text("Saving the policy releases them.")
      }
    }
  }

  private var retiredPaths: [String] { model.retiredFolderPaths(policyID: policyID) }

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
    } header: {
      Text("Behavior")
    }
  }

  /// One of the policy's two lists, in the order chosen in the View menu. Programs to Allow has
  /// a switch that decides whether decisions use it; while it is off, its rules are kept
  /// unchanged and can't be edited.
  private func rulesSection(_ draft: DirectoryPolicyDraft, list: PolicyRuleList) -> some View {
    let rules = sortOrder.sorted(draft[list]) { model.ruleDisplayName(for: $0) }
    let isUsed = draft.uses(list)
    return Section {
      if list == .allow {
        Toggle("Allow Only Programs in This List", isOn: allowListInUseBinding)
      }
      if list == .allow, let warning = emptyAllowListWarning(draft) {
        WarningLabel(text: warning)
      } else if rules.isEmpty, isUsed {
        // A section without rows would let the next section's header collapse into this one.
        Text("No rules")
          .foregroundStyle(.secondary)
      }
      ForEach(rules) { rule in
        RuleRow(
          rule: rule,
          list: list,
          displayName: model.ruleDisplayName(for: rule),
          isEnabled: enabledBinding(for: rule),
          onEdit: { editingRule = RuleEditRequest(rule: rule, list: list) },
          onRemove: { model.removeRule(policyID: policyID, ruleID: rule.id) }
        )
        .disabled(!isUsed)
      }
    } header: {
      HStack {
        Text(PolicyBehaviorText.rulesTitle(list))
        if isUsed, !rules.isEmpty {
          Text(
            RuleCountText.summary(
              active: rules.lazy.filter(\.isEnabled).count, total: rules.count)
          )
          .foregroundStyle(.secondary)
        }
        Spacer()
        Button {
          model.addProgramRequest = AddProgramRequest(policyID: policyID, list: list)
        } label: {
          Label("Add Program…", systemImage: "plus")
        }
        .disabled(!isUsed)
        .accessibilityLabel(PolicyBehaviorText.addToListTitle(list))
      }
    }
  }

  /// The built-in compatibility profiles, each with a switch, and any profile the policy turns
  /// on that this version doesn't offer, so it can be turned off. Turning one on lets the
  /// profile's Apple system processes in and is saved only after administrator authentication.
  private func compatibilitySection(_ draft: DirectoryPolicyDraft) -> some View {
    let offered = Set(model.systemCompatibilityCatalog.profiles.map(\.id))
    let unavailable = draft.systemCompatibilityProfiles.filter {
      !offered.contains($0.profileIdentifier)
    }
    return Section {
      ForEach(model.systemCompatibilityCatalog.profiles) { profile in
        let state = model.systemCompatibilityState(
          policyID: policyID, profileIdentifier: profile.id)
        let isSupported = model.isSupportedOnThisMac(profile)
        Toggle(isOn: compatibilityBinding(profile.id)) {
          Text(SystemCompatibilityText.name(identifier: profile.id))
          if let reason = state?.inactiveReason {
            Text(reason)
              .foregroundStyle(.orange)
          } else if state != nil {
            Text(SystemCompatibilityText.consequence(profile))
          } else if !isSupported {
            Text(SystemCompatibilityProfileState.unsupportedOS.displayName)
          }
        }
        .toggleStyle(.switch)
        .disabled(state == nil && !isSupported)
        .help(SystemCompatibilityText.role(profile))
        .accessibilityLabel(SystemCompatibilityText.name(identifier: profile.id))
      }
      ForEach(unavailable, id: \.profileIdentifier) { entry in
        Toggle(isOn: compatibilityBinding(entry.profileIdentifier)) {
          Text(SystemCompatibilityText.name(identifier: entry.profileIdentifier))
          if let reason = SystemCompatibilityProfileState.missingProfile.inactiveReason {
            Text(reason)
              .foregroundStyle(.orange)
          }
        }
        .toggleStyle(.switch)
        .accessibilityLabel(SystemCompatibilityText.name(identifier: entry.profileIdentifier))
      }
    } header: {
      Text("System Compatibility")
    }
  }

  private func compatibilityBinding(_ identifier: String) -> Binding<Bool> {
    Binding(
      get: {
        model.policyDraft(id: policyID)?.systemCompatibilityProfiles.contains {
          $0.profileIdentifier == identifier
        } ?? false
      },
      set: { model.setSystemCompatibilityProfile(identifier, isOn: $0, policyID: policyID) }
    )
  }

  /// The allow list has no enabled rule, but active compatibility profiles can still allow
  /// requests. The warning speaks of saving only while the draft differs from the saved policy.
  private func emptyAllowListWarning(_ draft: DirectoryPolicyDraft) -> String? {
    guard draft.mode == .protection, !draft.isBlacklistEnabled,
      !draft.allowRules.contains(where: \.isEnabled)
    else { return nil }
    if isDirty {
      return String(
        localized:
          "After saving, no allow rules will be enabled. Active compatibility profiles can still allow requests."
      )
    }
    return String(
      localized:
        "No allow rules are enabled. Active compatibility profiles can still allow requests.")
  }

  // MARK: - Saving

  private var isDirty: Bool { model.isPolicyDirty(policyID) }

  /// Edited, shown from policies the extension no longer has in full, or keeping retired paths
  /// that only a save releases.
  private var needsSaving: Bool {
    isDirty || (model.savedPoliciesNeedSaving && model.activePolicy(id: policyID) != nil)
      || !retiredPaths.isEmpty
  }

  private var validationMessage: String? {
    needsSaving ? model.draftValidationMessage(for: policyID) : nil
  }

  private var canSave: Bool {
    !model.isBusy && needsSaving && validationMessage == nil
  }

  private var canRevert: Bool {
    !model.isBusy && isDirty
  }

  private var canDuplicate: Bool {
    !model.isBusy && model.canCreatePolicy && model.policyDraft(id: policyID) != nil
  }

  /// A change that reduces protection is saved only after the macOS administrator password
  /// dialog; the button says so with an ellipsis.
  private var saveNeedsAuthorization: Bool {
    canSave && model.savingWeakensProtection(policyID: policyID)
  }

  private func save() {
    Task { await model.savePolicy(id: policyID) }
  }

  /// The prominent Save button when the draft can be saved, otherwise a plain disabled one.
  @ViewBuilder
  private var saveButton: some View {
    if canSave {
      Button(saveNeedsAuthorization ? "Save…" : "Save") {
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
    guard model.activePolicy(id: policyID) != nil else { return nil }
    if model.isServingRecoveryPolicies {
      return Notice(
        text: String(
          localized:
            "The programs of this policy were lost. Add them again and save every policy."),
        systemImage: "exclamationmark.triangle", color: .orange)
    }
    if let saved = model.unconfirmedSave, !isDirty {
      return Notice(
        text: String(
          localized:
            "Saved as revision \(saved.acceptedRevision). The extension has not confirmed that it is in effect."
        ),
        systemImage: "clock", color: .orange)
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
      return String(localized: "\(draft.mode.displayName) · Nothing is blocked")
    }
    return draft.mode.displayName
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

  /// The policy's explicit setting, shown as the switch of Programs to Allow. It does not
  /// depend on how many rules the list has, and changing it moves or removes no rule.
  private var allowListInUseBinding: Binding<Bool> {
    Binding(
      get: { !(model.policyDraft(id: policyID)?.isBlacklistEnabled ?? false) },
      set: { model.setAllowListInUse(policyID: policyID, $0) }
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
    guard let draft = model.policyDraft(id: policyID) else { return nil }
    return (draft.allowRules + draft.denyRules).first { $0.id == ruleID }
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
        onFocus()
        // When the policy was created by the keyboard shortcut of a menu command, the key event
        // is still being handled as this screen appears, and a focus request made now is
        // dropped. Requesting it on the next turn of the main queue works in either case.
        Task { @MainActor in isEditing = true }
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

/// A rule being edited, with the list it belongs to.
private struct RuleEditRequest: Identifiable {
  let rule: PolicyRule
  let list: PolicyRuleList

  var id: String { rule.id }
}

// MARK: - Rule row

private struct RuleRow: View {
  let rule: PolicyRule
  let list: PolicyRuleList
  let displayName: String
  @Binding var isEnabled: Bool
  let onEdit: () -> Void
  let onRemove: () -> Void

  /// False while the policy doesn't use this rule's list (see `DirectoryPolicyDraft.uses`).
  @Environment(\.isEnabled) private var isListUsed

  var body: some View {
    HStack {
      ProgramIcon(signingIdentifier: rule.signingIdentifier, executablePath: nil, size: 32)
      VStack(alignment: .leading) {
        HStack {
          Text(displayName)
            .lineLimit(1)
          if !isEnabled {
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
        SignatureLine(kind: rule.kind.displayName, identifiers: identity)
      }
      .foregroundStyle(isEnabled && isListUsed ? .primary : .secondary)
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
