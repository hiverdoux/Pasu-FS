import SwiftUI

struct UninstallView: View {
  @Bindable var model: AppModel
  @Environment(\.dismiss) private var dismiss
  @State private var removeData = false

  var body: some View {
    VStack(alignment: .leading, spacing: 16) {
      Text(model.pendingUninstall == nil ? "Uninstall Pasu FS?" : "Finish uninstalling Pasu FS")
        .font(.title2.weight(.semibold))
      Text(
        "This removes Pasu FS from this Mac and stops its protection. macOS may ask for administrator approval or a restart. Your protected folders and their files will not be deleted."
      )
      Toggle("Also delete Pasu FS settings and audit records", isOn: $removeData)
        .disabled(model.isUninstalling || model.isFinalizingUninstall)
      Text(
        "Leave this off to keep your protection rules, compatibility settings, and audit records for a future installation."
      )
      .font(.callout)
      .foregroundStyle(.secondary)
      if model.hasUnsavedPolicyChanges {
        Text("Unsaved policy changes will be discarded when Pasu FS quits.")
          .foregroundStyle(.orange)
      }
      if let error = model.uninstallStateError ?? model.pendingUninstall?.failure {
        Text(error).foregroundStyle(.red).textSelection(.enabled)
        Text(
          "If the app or maintenance service is damaged, quit Pasu FS and reinstall the same or a newer PKG, then retry uninstalling."
        )
        .font(.callout)
      }
      if let error = model.lastError {
        Text(error).foregroundStyle(.red).textSelection(.enabled)
      }
      if let message = model.operationMessage {
        Text(message).font(.callout).textSelection(.enabled)
      }
      HStack {
        if model.isUninstalling { ProgressView().controlSize(.small) }
        Spacer()
        Button("Cancel") { dismiss() }
          .keyboardShortcut(.cancelAction)
          .disabled(model.isUninstalling || model.isFinalizingUninstall)
        Button(
          model.pendingUninstall == nil ? "Uninstall" : "Continue Uninstall", role: .destructive
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
    .padding(24)
    .frame(width: 520)
    .interactiveDismissDisabled(model.isUninstalling)
    .onAppear {
      removeData = model.pendingUninstall?.removeData ?? false
      model.lastError = nil
      model.operationMessage = nil
    }
  }
}
