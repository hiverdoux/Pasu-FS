import AppKit
import PasuFSConfiguration
import SwiftUI

struct RootView: View {
  @Bindable var model: AppModel

  var body: some View {
    Group {
      if model.showsOnboarding {
        OnboardingView(model: model)
      } else {
        NavigationSplitView {
          SidebarView(model: model)
            .navigationSplitViewColumnWidth(min: 190, ideal: 216, max: 280)
        } detail: {
          switch model.selectedSection {
          case .overview:
            OverviewView(model: model)
          case .policy(let id):
            PolicyView(
              model: model, policyID: id,
              initialTab: model.pendingPolicyLogPolicyID == id ? .log : .settings
            )
            .id(id)
          }
        }
      }
    }
    .sheet(
      isPresented: $model.isPresentingUninstall,
      onDismiss: {
        guard model.takeUninstallTerminationRequest() else { return }
        model.stop()
        // Defer to the next main-loop turn, after the sheet's presentation teardown.
        DispatchQueue.main.async { NSApplication.shared.terminate(nil) }
      }
    ) {
      UninstallView(model: model)
    }
    .sheet(item: $model.addProgramRequest) { request in
      AddProgramSheet(model: model, request: request)
    }
    .task {
      if model.pendingUninstall != nil || model.uninstallStateError != nil {
        model.isPresentingUninstall = true
      }
    }
  }
}

private struct SidebarView: View {
  @Bindable var model: AppModel

  var body: some View {
    List(selection: $model.selectedSection) {
      Label("Overview", systemImage: "shield")
        .tag(SidebarSelection.overview)

      Section("Policies") {
        ForEach(model.sidebarPolicies) { policy in
          SidebarPolicyRow(policy: policy, isDirty: model.isPolicyDirty(policy.id))
            .listItemTint(policy.mode.tint)
            .tag(SidebarSelection.policy(policy.id))
        }
      }
    }
    .toolbar {
      ToolbarItem {
        Button {
          model.createNewPolicy()
        } label: {
          Label("New Policy", systemImage: "plus")
        }
        .disabled(!model.canCreatePolicy)
        .help("Create a new policy (⌘N)")
      }
    }
  }
}

private struct SidebarPolicyRow: View {
  let policy: DirectoryPolicyDraft
  let isDirty: Bool

  @State private var isHighlighted = false

  // Sidebars draw label icons in the list item tint and switch them to the selection's text color
  // on a highlighted row. The unsaved-changes dot isn't a label icon, so it follows the row itself.
  var body: some View {
    HStack {
      Label {
        Text(policy.name.isEmpty ? String(localized: "Untitled Policy") : policy.name)
          .lineLimit(1)
      } icon: {
        Image(systemName: policy.mode.symbolName)
      }
      Spacer()
      if isDirty {
        Image(systemName: "circle.fill")
          .imageScale(.small)
          .foregroundStyle(isHighlighted ? AnyShapeStyle(.white) : AnyShapeStyle(.orange))
          .help("Unsaved changes")
          .accessibilityLabel("Unsaved changes")
          .background(RowHighlightReader(isHighlighted: $isHighlighted))
      }
    }
  }
}

/// Reports whether the sidebar row containing this view shows the emphasized (accent color)
/// selection, which AppKit draws only while the sidebar is focused in the key window.
private struct RowHighlightReader: NSViewRepresentable {
  @Binding var isHighlighted: Bool

  func makeNSView(context: Context) -> RowHighlightView {
    let view = RowHighlightView()
    view.onChange = { isHighlighted = $0 }
    return view
  }

  func updateNSView(_ nsView: RowHighlightView, context: Context) {
    nsView.onChange = { isHighlighted = $0 }
  }
}

private final class RowHighlightView: NSView {
  var onChange: ((Bool) -> Void)?
  private var observations: [NSKeyValueObservation] = []
  private var reported: Bool?

  override func viewDidMoveToWindow() {
    super.viewDidMoveToWindow()
    observations = []
    var ancestor = superview
    while let view = ancestor, !(view is NSTableRowView) { ancestor = view.superview }
    guard let row = ancestor as? NSTableRowView else { return report(false) }
    // AppKit changes a row's selection state on the main thread.
    observations = [\NSTableRowView.isSelected, \.isEmphasized].map { keyPath in
      row.observe(keyPath) { [weak self] row, _ in
        MainActor.assumeIsolated { self?.update(from: row) }
      }
    }
    update(from: row)
  }

  private func update(from row: NSTableRowView) {
    report(row.isSelected && row.isEmphasized)
  }

  private func report(_ value: Bool) {
    guard value != reported else { return }
    reported = value
    // Not during AppKit's or SwiftUI's own update of the row.
    DispatchQueue.main.async { [weak self] in self?.onChange?(value) }
  }

  override func hitTest(_ point: NSPoint) -> NSView? { nil }
}
