import SwiftUI

/// Actions of the policy shown in the frontmost window, offered as menu bar commands.
struct PolicyCommandActions {
  var save: (() -> Void)?
  /// Saving opens the macOS administrator password dialog, so the items say so.
  var saveNeedsAuthorization = false
  var duplicate: (() -> Void)?
  var revert: (() -> Void)?
  var showInFinder: (() -> Void)?
}

/// Reloads the status or records shown in the frontmost window.
struct RefreshCommandAction {
  /// True while an earlier refresh still runs; the command is then unavailable.
  var isInProgress = false
  let perform: () -> Void
}

/// Shows or hides the inspector of the screen in the frontmost window.
struct InspectorCommandAction {
  let isShown: Bool
  let toggle: () -> Void
}

private struct PolicyCommandActionsKey: FocusedValueKey {
  typealias Value = PolicyCommandActions
}

private struct RefreshCommandActionKey: FocusedValueKey {
  typealias Value = RefreshCommandAction
}

private struct InspectorCommandActionKey: FocusedValueKey {
  typealias Value = InspectorCommandAction
}

extension FocusedValues {
  var policyCommands: PolicyCommandActions? {
    get { self[PolicyCommandActionsKey.self] }
    set { self[PolicyCommandActionsKey.self] = newValue }
  }

  var refreshCommand: RefreshCommandAction? {
    get { self[RefreshCommandActionKey.self] }
    set { self[RefreshCommandActionKey.self] = newValue }
  }

  var inspectorCommand: InspectorCommandAction? {
    get { self[InspectorCommandActionKey.self] }
    set { self[InspectorCommandActionKey.self] = newValue }
  }
}

/// File menu items for the policy in the frontmost window.
struct PolicyMenuCommands: View {
  @FocusedValue(\.policyCommands) private var actions

  var body: some View {
    Button(actions?.saveNeedsAuthorization == true ? "Save Policy…" : "Save Policy") {
      actions?.save?()
    }
    .keyboardShortcut("s", modifiers: .command)
    .disabled(actions?.save == nil)
    Button("Duplicate Policy") {
      actions?.duplicate?()
    }
    .keyboardShortcut("d", modifiers: .command)
    .disabled(actions?.duplicate == nil)
    Button("Revert to Saved") {
      actions?.revert?()
    }
    .disabled(actions?.revert == nil)
    Divider()
    Button("Show Protected Folder in Finder") {
      actions?.showInFinder?()
    }
    .disabled(actions?.showInFinder == nil)
  }
}

/// The View menu's Refresh item.
struct RefreshMenuCommand: View {
  @FocusedValue(\.refreshCommand) private var action

  var body: some View {
    Button("Refresh") {
      action?.perform()
    }
    .keyboardShortcut("r", modifiers: .command)
    .disabled(action == nil || action?.isInProgress == true)
  }
}

/// The View menu's inspector item, with the title and shortcut (⌃⌘I) of SwiftUI's
/// InspectorCommands. InspectorCommands composes its title from separately translated parts, so in
/// Korean it reads "Show 인스펙터"; this item uses whole translated titles instead.
struct InspectorMenuCommand: View {
  @FocusedValue(\.inspectorCommand) private var action

  var body: some View {
    let title: LocalizedStringKey =
      action?.isShown == true ? "Hide Inspector" : "Show Inspector"
    Button(title) {
      action?.toggle()
    }
    .keyboardShortcut("i", modifiers: [.control, .command])
    .disabled(action == nil)
  }
}

/// The View menu's submenu that chooses the order of every policy's program lists. The choice
/// is kept as a preference of the app.
struct ProgramSortMenuCommand: View {
  @AppStorage(ProgramSortOrder.defaultsKey) private var order = ProgramSortOrder.default

  var body: some View {
    Picker("Sort Programs By", selection: $order) {
      ForEach(ProgramSortOrder.allCases) { order in
        Text(order.displayName).tag(order)
      }
    }
  }
}
