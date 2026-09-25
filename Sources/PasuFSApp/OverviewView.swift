import AppKit
import PasuFSConfiguration
import PasuFSHostCore
import SwiftUI

struct OverviewView: View {
  @Bindable var model: AppModel
  @Environment(\.openSettings) private var openSettings

  var body: some View {
    Form {
      Section {
        StatusHeader(model: model)
        EvidenceRow(model: model)
      }

      let items = model.attentionItems()
      if !items.isEmpty {
        Section("Needs attention") {
          ForEach(items) { item in
            AttentionRow(item: item, perform: perform)
          }
        }
      }

      policiesSection
      recentDenialsSection
      versionSection
    }
    .formStyle(.grouped)
    .navigationTitle(String(localized: "Overview"))
    .toolbar {
      ToolbarItem {
        Button {
          refresh()
        } label: {
          Label("Refresh", systemImage: "arrow.clockwise")
        }
        .disabled(model.isBusy)
        .help("Refresh the status now")
      }
    }
    .focusedSceneValue(\.refreshCommand, RefreshCommandAction(perform: refresh))
    .task {
      while !Task.isCancelled {
        await model.refreshPolicyAuditLogs()
        try? await Task.sleep(for: .seconds(15))
      }
    }
  }

  private func refresh() {
    Task {
      await model.refreshHealth()
      await model.refreshPolicyAuditLogs()
    }
  }

  // MARK: - Policies

  private var policiesSection: some View {
    Section {
      if model.activePolicies.isEmpty {
        HStack {
          Label("No active policies", systemImage: "lock.doc")
          Spacer()
          Button("New Policy") {
            model.createNewPolicy()
          }
        }
      } else {
        ForEach(model.activePolicies) { policy in
          Button {
            model.selectedSection = .policy(policy.id)
          } label: {
            PolicySummaryRow(policy: policy)
          }
          .buttonStyle(.plain)
        }
      }
    } header: {
      HStack {
        Text("Policies")
        Spacer()
        Button("New Policy") {
          model.createNewPolicy()
        }
        .buttonStyle(.link)
        .disabled(!model.canCreatePolicy)
      }
    }
  }

  // MARK: - Recent denials

  private var recentDenialsSection: some View {
    Section {
      let denials = model.recentDenials(limit: 3)
      if denials.isEmpty {
        Text(
          model.hasLoadedPolicyLogs
            ? String(localized: "No denied requests in the loaded records.")
            : String(localized: "Policy logs have not been loaded yet.")
        )
        .foregroundStyle(.secondary)
      } else {
        ForEach(denials) { denial in
          Button {
            model.showPolicyLogRecord(policyID: denial.policyID, recordID: denial.record.id)
          } label: {
            RecentDenialRow(record: denial.record)
          }
          .buttonStyle(.plain)
        }
      }
      ForEach(model.policyLogErrors, id: \.self) { error in
        WarningLabel(text: error)
      }
    } header: {
      Text("Recent denials")
    }
  }

  // MARK: - Versions

  private var versionSection: some View {
    Section {
      TimelineView(.periodic(from: .now, by: 2)) { _ in
        let overview = model.extensionVersionOverview(now: Date())
        Button {
          open(.extensionStatus)
        } label: {
          HStack {
            Label {
              Text(
                "Pasu FS \(overview.app.description) · Extension \(overview.active) · \(overview.comparison)"
              )
              .foregroundStyle(.secondary)
            } icon: {
              Image(systemName: versionSymbol(overview.tone))
                .foregroundStyle(versionColor(overview.tone))
            }
            Spacer()
            RowChevron()
          }
          .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
      }
    }
  }

  private func versionColor(_ tone: ExtensionVersionOverview.Tone) -> Color {
    switch tone {
    case .neutral: .secondary
    case .matching: .green
    case .attention: .orange
    }
  }

  private func versionSymbol(_ tone: ExtensionVersionOverview.Tone) -> String {
    switch tone {
    case .neutral: "arrow.triangle.2.circlepath"
    case .matching: "checkmark.circle"
    case .attention: "exclamationmark.triangle"
    }
  }

  // MARK: - Actions

  private func perform(_ action: AttentionItem.Action) {
    switch action {
    case .diagnostics:
      open(.diagnostics)
    case .extensionSettings:
      open(.extensionStatus)
    case .generalSettings:
      open(.general)
    case .continueUninstall:
      model.isPresentingUninstall = true
    case .loginItems:
      model.openLoginItemsSettings()
    }
  }

  private func open(_ tab: SettingsTab) {
    model.settingsTab = tab
    openSettings()
    NSApplication.shared.activate()
  }
}

/// The status summary at the top of the Overview.
struct StatusHeader: View {
  let model: AppModel

  var body: some View {
    let status = model.status
    HStack {
      StatusSymbol(systemImage: status.symbolName, tone: status.tone)
      VStack(alignment: .leading) {
        Text(status.title)
          .font(.title2.bold())
        Text(status.detail)
          .foregroundStyle(.secondary)
      }
    }
    .accessibilityElement(children: .combine)
  }
}

/// How the status was obtained, and the active policy revision.
private struct EvidenceRow: View {
  let model: AppModel

  var body: some View {
    LabeledContent {
      if let revision = model.activeRevisionFromHealth {
        Text("Policy revision \(revision)")
      }
    } label: {
      Label {
        Text(model.evidenceSummary)
      } icon: {
        Image(systemName: evidenceSymbol)
          .foregroundStyle(evidenceTint)
      }
    }
  }

  private var evidenceSymbol: String {
    switch model.health.runtimeEvidenceSource {
    case .authenticatedXPC: model.evidenceIsStale ? "clock" : "checkmark.circle"
    case .diagnosticFile: "exclamationmark.triangle"
    case nil: "questionmark.circle"
    }
  }

  private var evidenceTint: Color {
    switch model.health.runtimeEvidenceSource {
    case .authenticatedXPC: model.evidenceIsStale ? .orange : .green
    case .diagnosticFile: .orange
    case nil: .secondary
    }
  }
}

/// The trailing chevron of a row that opens another screen.
struct RowChevron: View {
  var body: some View {
    Image(systemName: "chevron.forward")
      .imageScale(.small)
      .foregroundStyle(.tertiary)
      .accessibilityHidden(true)
  }
}

private struct AttentionRow: View {
  let item: AttentionItem
  let perform: (AttentionItem.Action) -> Void

  var body: some View {
    HStack {
      Label {
        Text(item.text)
        if let detail = item.detail {
          Text(detail)
        }
      } icon: {
        Image(systemName: "exclamationmark.triangle")
          .foregroundStyle(.orange)
      }
      Spacer()
      if let action = item.action {
        Button(actionTitle(action)) {
          perform(action)
        }
      }
    }
  }

  private func actionTitle(_ action: AttentionItem.Action) -> String {
    switch action {
    case .diagnostics: String(localized: "Show Diagnostics…")
    case .extensionSettings: String(localized: "Show Extension Settings…")
    case .generalSettings: String(localized: "Open Settings…")
    case .continueUninstall: String(localized: "Continue Uninstall…")
    case .loginItems: String(localized: "Open Login Items…")
    }
  }
}

struct PolicySummaryRow: View {
  let policy: DirectoryPolicy

  var body: some View {
    HStack {
      Label {
        Text(policy.name)
        Text(PathText.abbreviated(policy.protectedRootPath))
          .lineLimit(1)
          .truncationMode(.middle)
      } icon: {
        Image(systemName: policy.mode.symbolName)
          .foregroundStyle(policy.mode.tint)
      }
      Spacer()
      VStack(alignment: .trailing) {
        Text(verbatim: "\(policy.mode.displayName) · \(policy.policyType.displayName)")
        Text(RuleCountText.summary(active: policy.activeRuleCount, total: policy.rules.count))
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      RowChevron()
    }
    .contentShape(Rectangle())
  }
}

private struct RecentDenialRow: View {
  let record: AuditEventRecord

  var body: some View {
    HStack {
      Label {
        Text(ProcessText.preview(record))
          .lineLimit(1)
          .truncationMode(.middle)
        Text(PathText.abbreviated(record.targetPath ?? String(localized: "No target path")))
          .lineLimit(1)
          .truncationMode(.middle)
      } icon: {
        Image(systemName: "xmark.circle")
          .foregroundStyle(.red)
      }
      Spacer()
      VStack(alignment: .trailing) {
        Text(denyingPolicies)
          .lineLimit(1)
        Text(record.timestamp, format: .dateTime.hour().minute())
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      RowChevron()
    }
    .contentShape(Rectangle())
  }

  private var denyingPolicies: String {
    let names = (record.policyEvaluations ?? []).filter { $0.decision == .deny }.map(\.policyName)
    return names.isEmpty ? String(localized: "Pasu FS") : names.joined(separator: ", ")
  }
}

enum RuleCountText {
  static func summary(active: Int, total: Int) -> String {
    if total == 0 {
      return String(localized: "No rules")
    }
    return String(localized: "\(active) of \(total) rules on")
  }
}
