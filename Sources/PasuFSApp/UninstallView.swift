import SwiftUI

struct UninstallView: View {
  @Bindable var model: AppModel
  @Environment(\.dismiss) private var dismiss
  @State private var removeData: Bool

  init(model: AppModel) {
    self.model = model
    // A removal deferred until after a restart keeps the choice made before the restart,
    // so the switch shows that choice from the moment the sheet appears.
    _removeData = State(initialValue: model.pendingUninstall?.removeData ?? false)
  }

  var body: some View {
    Form {
      Section {
        Text("Protected folders and their files are not deleted.")
        Toggle("Also delete Pasu FS settings and logs", isOn: $removeData)
          .disabled(model.isUninstalling || model.isFinalizingUninstall)
        if model.hasUnsavedPolicyChanges {
          WarningLabel(
            text: String(
              localized: "Unsaved policy changes will be discarded when Pasu FS quits."))
        }
      } header: {
        SheetTitle(title: title)
      }
      if let error = model.uninstallStateError ?? model.pendingUninstallFailureMessage {
        Section {
          Text(error)
            .foregroundStyle(.red)
            .textSelection(.enabled)
          Text("If this keeps failing, reinstall the same or a newer package and try again.")
        }
      }
      if let error = model.lastError {
        Section {
          Text(error)
            .foregroundStyle(.red)
            .textSelection(.enabled)
        }
      }
      if model.isUninstalling || model.operationMessage != nil {
        Section {
          HStack {
            if model.isUninstalling {
              ProgressView()
                .controlSize(.small)
            }
            if let message = model.operationMessage {
              Text(message)
                .textSelection(.enabled)
            }
          }
        }
      }
    }
    .formStyle(.grouped)
    .toolbar {
      ToolbarItem(placement: .cancellationAction) {
        Button("Cancel") { dismiss() }
          .disabled(model.isUninstalling || model.isFinalizingUninstall)
      }
      ToolbarItem(placement: .destructiveAction) {
        Button(
          model.pendingUninstall == nil ? "Uninstall" : "Continue Uninstalling",
          role: .destructive
        ) {
          Task {
            if await model.uninstall(removeData: removeData) {
              // AppKit may defer termination while a sheet is presented. The root window
              // owns the termination request and handles it after onDismiss has run.
              dismiss()
            }
          }
        }
        .disabled(model.isBusy || model.isUninstalling || model.isFinalizingUninstall)
      }
    }
    .formSheetSizing()
    .interactiveDismissDisabled(model.isUninstalling)
    .onAppear {
      model.lastError = nil
      model.operationMessage = nil
    }
  }

  private var title: String {
    model.pendingUninstall == nil
      ? String(localized: "Uninstall Pasu FS?") : String(localized: "Finish Uninstalling Pasu FS")
  }
}
