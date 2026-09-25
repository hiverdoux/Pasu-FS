import SwiftUI

/// Actions of the policy shown in the frontmost window, offered as menu bar commands.
struct PolicyCommandActions {
  var save: (() -> Void)?
  var revert: (() -> Void)?
  var showInFinder: (() -> Void)?
}

/// Reloads the status or records shown in the frontmost window.
struct RefreshCommandAction {
  let perform: () -> Void
}

private struct PolicyCommandActionsKey: FocusedValueKey {
  typealias Value = PolicyCommandActions
}

private struct RefreshCommandActionKey: FocusedValueKey {
  typealias Value = RefreshCommandAction
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
}

/// File menu items for the policy in the frontmost window.
struct PolicyMenuCommands: View {
  @FocusedValue(\.policyCommands) private var actions

  var body: some View {
    Button("Save Policy") {
      actions?.save?()
    }
    .keyboardShortcut("s", modifiers: .command)
    .disabled(actions?.save == nil)
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
    .disabled(action == nil)
  }
}
