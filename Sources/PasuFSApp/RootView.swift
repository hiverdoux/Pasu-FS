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
          List(selection: $model.selectedSection) {
            Label("Overview", systemImage: "shield")
              .tag(SidebarSelection.protection)
            Label("Audit Log", systemImage: "list.bullet.rectangle")
              .tag(SidebarSelection.auditLog)

            Section("Policies") {
              ForEach(model.sidebarPolicies) { policy in
                HStack(spacing: 7) {
                  Label {
                    Text(policy.name)
                  } icon: {
                    Image(systemName: policy.mode.symbolName)
                      .foregroundStyle(policy.mode.tint)
                  }
                  Spacer(minLength: 4)
                  if model.isPolicyDirty(policy.id) {
                    Circle()
                      .fill(.secondary)
                      .frame(width: 6, height: 6)
                      .help("Unsaved changes")
                  }
                }
                .tag(SidebarSelection.policy(policy.id))
              }
            }
          }
          .navigationSplitViewColumnWidth(min: 180, ideal: 200, max: 240)
          .safeAreaInset(edge: .bottom, alignment: .leading) {
            VStack(alignment: .leading, spacing: 8) {
              Button {
                model.createNewPolicy()
              } label: {
                Label("New Policy", systemImage: "plus.circle")
              }
              .buttonStyle(.borderless)
              .keyboardShortcut("n", modifiers: .command)
              .help("Create a new policy (⌘N)")
              Text("v\(Bundle.main.shortVersionDescription)")
                .font(.caption)
                .foregroundStyle(.tertiary)
            }
            .padding(.horizontal, 16)
            .padding(.bottom, 10)
          }
        } detail: {
          switch model.selectedSection {
          case .protection:
            ProtectionView(model: model)
          case .auditLog:
            AuditLogView(model: model)
          case .policy(let id):
            PolicyView(model: model, policyID: id)
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
    .task {
      if model.pendingUninstall != nil || model.uninstallStateError != nil {
        model.isPresentingUninstall = true
      }
    }
  }
}

extension Bundle {
  var shortVersionDescription: String {
    (infoDictionary?["CFBundleShortVersionString"] as? String) ?? "dev"
  }
}
