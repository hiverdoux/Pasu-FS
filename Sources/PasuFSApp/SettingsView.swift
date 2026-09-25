import AppKit
import PasuFSConfiguration
import PasuFSHostCore
import SwiftUI

/// The Settings window (⌘,): app preferences and maintenance that everyday screens don't need.
struct SettingsView: View {
  @Bindable var model: AppModel

  var body: some View {
    TabView(selection: $model.settingsTab) {
      GeneralSettingsView(model: model)
        .tabItem { Label("General", systemImage: "gearshape") }
        .tag(SettingsTab.general)
      ExtensionSettingsView(model: model)
        .tabItem { Label("Extension", systemImage: "puzzlepiece.extension") }
        .tag(SettingsTab.extensionStatus)
      DiagnosticsSettingsView(model: model)
        .tabItem { Label("Diagnostics", systemImage: "waveform.path.ecg") }
        .tag(SettingsTab.diagnostics)
    }
    .frame(width: 640)
  }
}

private struct GeneralSettingsView: View {
  @Bindable var model: AppModel
  @Environment(\.openWindow) private var openWindow

  var body: some View {
    Form {
      Section {
        Toggle("Open at Login", isOn: loginBinding)
          .toggleStyle(.switch)
          .disabled(!model.canChangeOpenAtLogin)
        LabeledContent("Registration with macOS", value: loginItemStatus)
        if model.loginItemState == .requiresApproval {
          HStack {
            Text("macOS needs your approval before Pasu FS can open at login.")
              .foregroundStyle(.orange)
            Spacer()
            Button("Open Login Items…") {
              model.openLoginItemsSettings()
            }
          }
        }
        if let error = model.loginItemError {
          Text(error)
            .foregroundStyle(.red)
        }
      }

      Section {
        LabeledContent {
          Button(
            model.pendingUninstall == nil ? "Uninstall…" : "Continue Uninstall…",
            role: .destructive
          ) {
            openWindow(id: "main")
            NSApplication.shared.activate()
            model.isPresentingUninstall = true
          }
          .disabled(model.isBusy || model.isUninstalling)
        } label: {
          Text("Uninstall Pasu FS")
        }
      }
    }
    .formStyle(.grouped)
    .fixedSize(horizontal: false, vertical: true)
  }

  private var loginBinding: Binding<Bool> {
    Binding(
      get: { model.isOpenAtLoginRegistered },
      set: { model.setOpenAtLogin($0) }
    )
  }

  private var loginItemStatus: String {
    switch model.loginItemState {
    case .notRegistered: String(localized: "Off")
    case .enabled: String(localized: "On")
    case .requiresApproval: String(localized: "Approval required")
    case .notFound: String(localized: "No registration found")
    }
  }
}

private struct ExtensionSettingsView: View {
  @Bindable var model: AppModel
  @State private var isConfirmingDeactivation = false

  var body: some View {
    TimelineView(.periodic(from: .now, by: 2)) { _ in
      let overview = model.extensionVersionOverview(now: Date())
      Form {
        Section {
          LabeledContent("Pasu FS app", value: overview.app.description)
          LabeledContent("Extension included with the app", value: overview.included.description)
          LabeledContent("Running extension", value: overview.active)
          LabeledContent("Comparison") {
            Label(overview.comparison, systemImage: symbol(overview.tone))
              .foregroundStyle(color(overview.tone))
          }
          ForEach(overview.notices) { notice in
            WarningLabel(text: notice.text, systemImage: "exclamationmark.circle")
          }
        } header: {
          Text("Versions")
        }

        Section {
          if !overview.isConfirmed {
            Text("Checking with macOS…")
              .foregroundStyle(.secondary)
          } else if overview.entries.isEmpty {
            Text("macOS reports no installed Pasu FS extension.")
              .foregroundStyle(.secondary)
          }
          ForEach(overview.entries) { entry in
            LabeledContent(entry.version, value: entry.state)
          }
        } header: {
          Text("Installed on This Mac")
        }

        Section("Connection") {
          LabeledContent("Status check", value: model.evidenceSummary)
          LabeledContent("Installation", value: model.installationStateDescription)
          if let identifier = model.installedExtensionIdentifier {
            LabeledContent("Bundle ID") {
              Text(identifier)
                .monospaced()
                .textSelection(.enabled)
            }
          }
        }

        Section {
          LabeledContent {
            Button("Deactivate…", role: .destructive) {
              isConfirmingDeactivation = true
            }
            .disabled(model.isBusy || model.isStoppingProtectionForQuit || model.isUninstalling)
          } label: {
            Text("Deactivate Extension")
          }
          if let message = model.operationMessage {
            Text(message)
              .foregroundStyle(.secondary)
          }
          if let error = model.lastError {
            Text(error)
              .foregroundStyle(.red)
          }
        }
      }
      .formStyle(.grouped)
    }
    .frame(minHeight: 560)
    .confirmationDialog(
      "Deactivate the system extension?",
      isPresented: $isConfirmingDeactivation,
      titleVisibility: .visible
    ) {
      Button("Deactivate", role: .destructive) {
        Task { await model.deactivate() }
      }
      Button("Cancel", role: .cancel) {}
    } message: {
      Text(
        "Protection stops once macOS finishes removing the extension. macOS asks for administrator approval and may require a restart."
      )
    }
  }

  private func color(_ tone: ExtensionVersionOverview.Tone) -> Color {
    switch tone {
    case .neutral: .secondary
    case .matching: .green
    case .attention: .orange
    }
  }

  private func symbol(_ tone: ExtensionVersionOverview.Tone) -> String {
    switch tone {
    case .neutral: "arrow.triangle.2.circlepath"
    case .matching: "checkmark.circle"
    case .attention: "exclamationmark.triangle"
    }
  }
}

private struct DiagnosticsSettingsView: View {
  @Bindable var model: AppModel

  var body: some View {
    Form {
      Section("Runtime") {
        LabeledContent("Status evidence", value: model.runtimeEvidenceDescription)
        LabeledContent("Last update", value: model.evidenceAgeDescription ?? "—")
        LabeledContent("Policy revision") {
          Text(model.activeRevisionFromHealth.map { String($0) } ?? "—")
            .monospacedDigit()
        }
        LabeledContent("Checked requests") {
          Text(model.coveredEventsDescription)
            .monospaced()
        }
      }

      if let history = model.processLineageStatus {
        Section {
          LabeledContent(
            "Status",
            value: history.isTracking
              ? String(localized: "Observing") : String(localized: "Stopped"))
          LabeledContent("Observed process events") {
            Text(history.observedEventCount, format: .number)
              .monospacedDigit()
          }
          ForEach(history.issues) { issue in
            WarningLabel(text: "\(LineageText.explanation(issue)) (\(issue.count))")
          }
          if let warning = LineageText.lossAccountingWarning(
            version: history.deliveryAccountingVersion, issues: history.issues)
          {
            WarningLabel(text: warning)
          }
        } header: {
          Text("Process History")
        }
      }

      Section("Log Storage") {
        if let delivery = model.auditDeliveryMetrics {
          countRow("Records saved without process history", delivery.minimalRecordsStored)
          countRow("Records that couldn’t enter the save queue", delivery.admissionDrops)
          countRow("Save failures", delivery.storageFailures)
        }
        countRow("Lost records", model.droppedAuditEventCount)
      }

      if let responses = model.authorizationMetrics {
        Section {
          countRow("Response failures", responses.failures)
          countRow("Responses finished after the deadline", responses.deadlineExceeded)
        } header: {
          Text("Authorization Responses")
        }
      }
    }
    .formStyle(.grouped)
    .frame(minHeight: 560)
  }

  private func countRow(_ title: LocalizedStringKey, _ value: UInt64) -> some View {
    LabeledContent(title) {
      Text(value, format: .number)
        .monospacedDigit()
        .foregroundStyle(value > 0 ? Color.orange : Color.secondary)
    }
  }
}
