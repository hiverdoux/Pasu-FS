import AppKit
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSPolicy
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
          .accessibilityRowValue(loginItemStatus)
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
    // Every tab has the same minimum height. The window keeps its top edge when a tab grows it,
    // so a shorter General tab would leave a taller tab extending past the bottom of the screen.
    .frame(minHeight: 560)
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
            .accessibilityRowValue(overview.active)
          LabeledContent("Comparison") {
            Label(overview.comparison, systemImage: symbol(overview.tone))
              .foregroundStyle(color(overview.tone))
          }
          .accessibilityRowValue(overview.comparison)
          ForEach(overview.notices) { notice in
            WarningLabel(text: notice.text, systemImage: "exclamationmark.circle")
          }
          if model.installationStatesUnansweredSince != nil,
            let detail = model.answeringExtensionDetail(now: Date())
          {
            Text(detail)
              .foregroundStyle(.secondary)
          }
        } header: {
          Text("Versions")
        }

        Section {
          if overview.isWaitingForFirstReport {
            Text("Checking with macOS…")
              .foregroundStyle(.secondary)
          } else if !overview.isConfirmed {
            Text("Can’t confirm")
              .foregroundStyle(.secondary)
          } else if overview.entries.isEmpty {
            Text("macOS reports no installed Pasu FS extension.")
              .foregroundStyle(.secondary)
          }
          ForEach(overview.entries) { entry in
            LabeledContent(entry.version, value: entry.state)
              .accessibilityRowValue(entry.state)
          }
          if let reportedAt = model.installationStatesReportedAt {
            let age = min(reportedAt, Date()).formatted(
              .relative(presentation: .named, unitsStyle: .abbreviated))
            LabeledContent("Last checked", value: age)
              .accessibilityRowValue(age)
          }
        } header: {
          HStack {
            Text("Installed on This Mac")
            Spacer()
            if model.isRefreshingStatus {
              RefreshProgress()
            }
            Button("Refresh") {
              refresh()
            }
            .buttonStyle(.link)
            .disabled(model.isRefreshingStatus)
          }
        }

        Section("Connection") {
          LabeledContent("Status check", value: model.evidenceSummary)
            .accessibilityRowValue(model.evidenceSummary)
          LabeledContent("Installation", value: model.installationStateDescription)
            .accessibilityRowValue(model.installationStateDescription)
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
            // While macOS removes the extension at the next restart, or reports none installed,
            // there is nothing left to deactivate.
            .disabled(
              model.isBusy || model.isStoppingProtectionForQuit || model.isUninstalling
                || model.extensionRemovalIsPending || model.extensionIsReportedNotInstalled)
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
    .onAppear { model.statusScreen(.extensionSettings, isVisible: true) }
    .onDisappear { model.statusScreen(.extensionSettings, isVisible: false) }
    .focusedSceneValue(
      \.refreshCommand,
      RefreshCommandAction(isInProgress: model.isRefreshingStatus, perform: refresh)
    )
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

  private func refresh() {
    Task { await model.refreshStatusNow() }
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
    // The ages change with time while the extension's report stays the same.
    TimelineView(.periodic(from: .now, by: 2)) { _ in
      Form {
        Section("Runtime") {
          LabeledContent("Status evidence", value: model.runtimeEvidenceDescription)
            .accessibilityRowValue(model.runtimeEvidenceDescription)
          if let lastStatus = model.unresponsiveExtensionLastStatus(now: Date()) {
            // The extension stopped writing its status: show when it last did.
            let lastUpdate =
              "\(lastStatus.formatted(date: .abbreviated, time: .standard)) · \(model.evidenceAgeDescription ?? "")"
            LabeledContent("Last update") {
              Text(verbatim: lastUpdate)
                .foregroundStyle(.orange)
            }
            .accessibilityRowValue(lastUpdate)
          } else {
            LabeledContent("Last update", value: model.evidenceAgeDescription ?? "—")
              .accessibilityRowValue(model.evidenceAgeDescription ?? "—")
          }
          let revision = model.activeRevisionFromHealth.map { String($0) } ?? "—"
          LabeledContent("Policy revision") {
            Text(revision)
              .monospacedDigit()
          }
          .accessibilityRowValue(revision)
          LabeledContent("Checked requests") {
            Text(model.coveredEventsDescription)
              .monospaced()
          }
          .accessibilityRowValue(model.coveredEventsDescription)
          if let delivery = model.targetPathMuting {
            LabeledContent("Request delivery") {
              if delivery.deliversAllRequests {
                Text("All requests")
                  .foregroundStyle(.orange)
              } else {
                Text("Registered paths only")
              }
            }
            .accessibilityRowValue(
              delivery.deliversAllRequests
                ? String(localized: "All requests") : String(localized: "Registered paths only"))
            if delivery.isInverted {
              numberRow("Registered path prefixes", delivery.prefixCount)
              numberRow("Registered exact paths", delivery.literalCount)
            }
            if let error = delivery.lastError {
              WarningLabel(text: String(localized: "Path registration error: \(error)"))
            }
          }
          if let count = model.activeSystemCompatibilityProfileCount {
            numberRow("Active compatibility profiles", count)
          }
          if let count = model.retiredFolderPathCount {
            numberRow("Retired paths", count)
          }
          if let state = model.policyStorageState {
            LabeledContent("Policy storage") {
              Text(PolicyStorageText.displayName(state))
                .foregroundStyle(
                  PolicyStorageText.summary(state) == nil ? Color.primary : Color.orange)
            }
            .accessibilityRowValue(PolicyStorageText.displayName(state))
          }
          if let digest = model.activePolicyDigestDescription {
            LabeledContent("Policy digest") {
              Text(digest)
                .monospaced()
                .lineLimit(1)
                .truncationMode(.middle)
                .textSelection(.enabled)
                .help(digest)
            }
            .accessibilityRowValue(digest)
          }
        }

        if let origin = model.executionOriginStatus {
          Section {
            let processes =
              "\(origin.observedProcessCount.formatted()) / \(origin.maximumProcessCount.formatted())"
            LabeledContent("Tracked processes") {
              Text(verbatim: processes)
                .monospacedDigit()
            }
            .accessibilityRowValue(processes)
            let data =
              "\(byteCount(origin.estimatedDataBytes)) / \(byteCount(origin.maximumEstimatedDataBytes))"
            LabeledContent("Tracked data") {
              Text(verbatim: data)
                .monospacedDigit()
            }
            .accessibilityRowValue(data)
            if let started = origin.observationStartedAt {
              let tracking = trackingStartDescription(
                started,
                secondsAfterStartup: model.endpointConnection?
                  .firstSubscriptionSecondsAfterStartup)
              LabeledContent("Tracking started") {
                Text(verbatim: tracking)
                  .monospacedDigit()
              }
              .accessibilityRowValue(tracking)
            }
            if let count = origin.kernelLaunchdStartHistoryCount {
              numberRow("Started by launchd before tracking", Int(clamping: count))
            }
            countRow("History resets", origin.invalidationCount)
            countRow("Discarded process entries", origin.discardedProcessCount)
            if let reason = origin.lastInvalidation {
              WarningLabel(text: OriginText.uncertainty(reason))
            }
          } header: {
            Text("Execution History")
          }
        }

        if let history = model.processLineageStatus {
          Section {
            let status =
              history.isTracking ? String(localized: "Tracking") : String(localized: "Stopped")
            LabeledContent("Status", value: status)
              .accessibilityRowValue(status)
            LabeledContent("Observed process events") {
              Text(history.observedEventCount, format: .number)
                .monospacedDigit()
            }
            .accessibilityRowValue(history.observedEventCount.formatted(.number))
            countRow(
              "Dropped messages (all kinds)",
              history.issues.first { $0.reason == LineageText.droppedMessagesReason }?.count ?? 0)
            ForEach(history.issues.filter { $0.reason != LineageText.droppedMessagesReason }) {
              issue in
              WarningLabel(text: LineageText.text(issue, alwaysShowingCount: true))
            }
            if let warning = LineageText.lossAccountingWarning(
              version: history.deliveryAccountingVersion, issues: history.issues)
            {
              WarningLabel(text: warning)
            }
          } header: {
            Text("Process Lineage")
          }
        }

        Section("Log Storage") {
          if let delivery = model.auditDeliveryMetrics {
            countRow("Records saved without process lineage", delivery.minimalRecordsStored)
            countRow("Records that couldn’t enter the save queue", delivery.admissionDrops)
            if let denied = delivery.deniedLaneDrops {
              countRow("Denial records among them", denied)
            }
            countRow("Save failures", delivery.storageFailures)
          }
          countRow("Lost records", model.droppedAuditEventCount)
        }

        if let responses = model.authorizationMetrics {
          Section {
            countRow("Response failures", responses.failures)
            countRow("Responses finished after the deadline", responses.deadlineExceeded)
            if let mode = model.deadlineMissMode {
              LabeledContent("On a missed deadline") {
                switch mode.setting {
                case .failClosed:
                  Text("Deny the request")
                case .killUnavailable:
                  Text("Stop the extension")
                case .killAfterFailure:
                  Text("Stop the extension")
                    .foregroundStyle(.orange)
                }
              }
              .accessibilityRowValue(
                mode.setting == .failClosed
                  ? String(localized: "Deny the request") : String(localized: "Stop the extension"))
              if let error = mode.error {
                WarningLabel(text: String(localized: "Deadline setting error: \(error)"))
              }
              if let milliseconds = mode.maximumDeadlineMilliseconds {
                let deadline = Measurement(
                  value: Double(milliseconds), unit: UnitDuration.milliseconds
                ).formatted(.measurement(width: .abbreviated, usage: .asProvided))
                LabeledContent("Maximum deadline", value: deadline)
                  .accessibilityRowValue(deadline)
              }
              if let error = mode.maximumDeadlineError {
                WarningLabel(text: String(localized: "Deadline shortening error: \(error)"))
              }
            }
            if let unchecked = model.uncheckedRequestMetrics {
              countRow("Unchecked requests (upper estimate)", unchecked.estimatedCount)
              if let count = unchecked.lastEstimatedCount, let time = unchecked.lastObservedAt {
                let latest =
                  "\(count.formatted()) · \(time.formatted(date: .abbreviated, time: .standard))"
                LabeledContent("Latest unchecked requests") {
                  Text(verbatim: latest)
                    .monospacedDigit()
                }
                .accessibilityRowValue(latest)
              }
            }
            if let remaining = responses.minimumRemainingTicks {
              LabeledContent(
                "Shortest time left before the deadline", value: MachTime.description(remaining)
              )
              .accessibilityRowValue(MachTime.description(remaining))
            }
            if let count = responses.evaluatedOpenCount, count > 0 {
              LabeledContent("Requests evaluated") {
                Text(count, format: .number)
                  .monospacedDigit()
              }
              .accessibilityRowValue(count.formatted(.number))
              if let total = responses.totalEvaluationTicks {
                LabeledContent("Average check time", value: MachTime.description(total / count))
                  .accessibilityRowValue(MachTime.description(total / count))
              }
              if let longest = responses.maximumEvaluationTicks {
                LabeledContent("Longest check time", value: MachTime.description(longest))
                  .accessibilityRowValue(MachTime.description(longest))
              }
            }
          } header: {
            Text("Authorization Responses")
          }
        }
      }
      .formStyle(.grouped)
    }
    .frame(minHeight: 560)
  }

  private func byteCount(_ bytes: Int) -> String {
    Int64(bytes).formatted(.byteCount(style: .memory))
  }

  /// The time tracking began and, when the extension reports it, how long after the Mac
  /// started.
  private func trackingStartDescription(_ started: Date, secondsAfterStartup: Double?) -> String {
    let time = started.formatted(date: .abbreviated, time: .standard)
    guard let secondsAfterStartup, secondsAfterStartup >= 0 else { return time }
    let elapsed = Measurement(value: secondsAfterStartup, unit: UnitDuration.seconds).formatted(
      .measurement(
        width: .abbreviated, usage: .asProvided,
        numberFormatStyle: .number.precision(.fractionLength(1))))
    return String(localized: "\(time) · \(elapsed) after startup")
  }

  private func numberRow(_ title: LocalizedStringKey, _ value: Int) -> some View {
    LabeledContent(title) {
      Text(value, format: .number)
        .monospacedDigit()
    }
    .accessibilityRowValue(value.formatted(.number))
  }

  private func countRow(_ title: LocalizedStringKey, _ value: UInt64) -> some View {
    LabeledContent(title) {
      Text(value, format: .number)
        .monospacedDigit()
        .foregroundStyle(value > 0 ? Color.orange : Color.secondary)
    }
    .accessibilityRowValue(value.formatted(.number))
  }
}

/// The extension reports durations in ticks of this Mac's Mach clock.
enum MachTime {
  static func milliseconds(_ ticks: UInt64) -> Double {
    var timebase = mach_timebase_info_data_t()
    guard mach_timebase_info(&timebase) == KERN_SUCCESS, timebase.denom != 0 else { return 0 }
    return Double(ticks) * Double(timebase.numer) / Double(timebase.denom) / 1_000_000
  }

  static func description(_ ticks: UInt64) -> String {
    Measurement(value: milliseconds(ticks), unit: UnitDuration.milliseconds).formatted(
      .measurement(
        width: .abbreviated, usage: .asProvided,
        numberFormatStyle: .number.precision(.fractionLength(0...3))))
  }
}
