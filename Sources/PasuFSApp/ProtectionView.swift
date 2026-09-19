import PasuFSConfiguration
import PasuFSHostCore
import SwiftUI

struct ProtectionView: View {
  @Bindable var model: AppModel

  @State private var isConfirmingDeactivation = false

  var body: some View {
    Form {
      statusSection
      versionSection
      coverageSection
      if !attentionItems.isEmpty {
        attentionSection
      }
      policiesSection
      applicationSection
      runtimeSection
      deactivationSection
    }
    .formStyle(.grouped)
    .navigationTitle("Overview")
    .toolbar {
      ToolbarItem {
        Button {
          Task { await model.refreshHealth() }
        } label: {
          Label("Refresh", systemImage: "arrow.clockwise")
        }
        .disabled(model.isBusy)
        .help("Refresh runtime status now")
      }
    }
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
        "Protection stops once macOS completes the removal. macOS asks for administrator approval and may require a restart."
      )
    }
  }

  // MARK: - Status

  private var statusSection: some View {
    Section {
      HStack(spacing: 14) {
        Image(systemName: model.menuBarSymbolName)
          .font(.system(size: 22, weight: .medium))
          .foregroundStyle(statusColor)
          .frame(width: 44, height: 44)
          .background(statusColor.opacity(0.12), in: Circle())
        VStack(alignment: .leading, spacing: 2) {
          Text(model.healthTitle)
            .font(.title3.weight(.semibold))
          Text(statusDetail)
            .font(.caption)
            .foregroundStyle(.secondary)
        }
        Spacer(minLength: 12)
        VStack(alignment: .trailing, spacing: 4) {
          HStack(spacing: 5) {
            Image(systemName: evidenceSymbolName)
              .font(.system(size: 10, weight: .bold))
              .foregroundStyle(evidenceTint)
            Text(evidenceText)
              .font(.caption)
              .foregroundStyle(.secondary)
          }
          if model.health.protectionPolicyCount > 0 || model.health.auditPolicyCount > 0 {
            Text(
              "\(model.health.protectionPolicyCount) Protection · \(model.health.auditPolicyCount) Audit"
            )
            .font(.caption)
            .foregroundStyle(.tertiary)
          }
        }
      }
      .padding(.vertical, 2)
    }
  }

  private var statusDetail: String {
    if let revision = activeRevision {
      return "\(model.healthDetail) · policy-set revision \(revision)"
    }
    return model.healthDetail
  }

  private var versionSection: some View {
    Section {
      TimelineView(.periodic(from: .now, by: 2)) { _ in
        let overview = model.extensionVersionOverview(now: Date())
        VStack(alignment: .leading, spacing: 8) {
          HStack {
            Text("Versions").font(.headline)
            Spacer()
            Label(overview.comparison, systemImage: versionSymbol(overview.tone))
              .font(.caption)
              .foregroundStyle(versionColor(overview.tone))
          }
          LabeledContent("App", value: overview.app.description)
          LabeledContent("Active protection extension", value: overview.active)
          ForEach(overview.notices) { notice in
            Label(notice.text, systemImage: "exclamationmark.circle")
              .font(.caption)
              .foregroundStyle(.orange)
              .fixedSize(horizontal: false, vertical: true)
          }
          DisclosureGroup("Extension details") {
            LabeledContent("Included with app", value: overview.included.description)
            ForEach(overview.entries) { entry in
              LabeledContent(entry.version, value: entry.state)
            }
            Text(
              "Extension versions and installation states are reported by macOS. Protection status is shown above."
            )
            .font(.caption)
            .foregroundStyle(.secondary)
          }
          .font(.caption)
        }
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

  // MARK: - Coverage

  private var coverageSection: some View {
    Section("Coverage") {
      Label {
        coveredText
      } icon: {
        Image(systemName: "checkmark.circle")
          .foregroundStyle(.green)
      }
      Label {
        Text(
          "Not covered: create, rename, delete, hard link, clone, truncate, memory-map, copy, and directory listing."
        )
        .foregroundStyle(.secondary)
      } icon: {
        Image(systemName: "exclamationmark.circle")
          .foregroundStyle(.orange)
      }
    }
  }

  private var coveredText: Text {
    let events = model.health.coveredAuthorizationEvents
    if events.isEmpty {
      return Text("No covered authorization events reported yet.")
    }
    return Text("Covers supported ")
      + Text(events.joined(separator: ", ")).font(.caption.monospaced())
      + Text(" requests — blocking file opens only.")
  }

  // MARK: - Needs attention

  private struct AttentionItem: Identifiable {
    let id: String
    let symbolName: String
    let text: String
  }

  private var attentionItems: [AttentionItem] {
    var items: [AttentionItem] = []
    if case .degraded(let reason) = model.health.protection {
      items.append(
        AttentionItem(id: "degraded", symbolName: "exclamationmark.triangle", text: reason)
      )
    }
    if let warning = model.health.policyWarning {
      items.append(
        AttentionItem(
          id: "policyWarning",
          symbolName: "exclamationmark.triangle",
          text: "Policy update warning: \(warning)"
        )
      )
    }
    if let warning = model.policySynchronizationWarning {
      items.append(
        AttentionItem(
          id: "policySync",
          symbolName: "arrow.triangle.2.circlepath",
          text: warning
        )
      )
    }
    if let warning = model.systemCompatibilitySynchronizationWarning {
      items.append(
        AttentionItem(
          id: "compatibilitySync",
          symbolName: "puzzlepiece.extension",
          text: warning
        )
      )
    }
    return items
  }

  private var attentionSection: some View {
    Section("Needs attention") {
      ForEach(attentionItems) { item in
        Label {
          Text(item.text)
        } icon: {
          Image(systemName: item.symbolName)
            .foregroundStyle(.orange)
        }
      }
    }
  }

  // MARK: - Policies

  private var policiesSection: some View {
    Section {
      if model.activePolicies.isEmpty {
        HStack(spacing: 12) {
          IconTile(systemImage: "lock.doc", tint: .secondary)
          VStack(alignment: .leading, spacing: 2) {
            Text("No active policies")
              .font(.body.weight(.medium))
            Text("One protected folder per policy.")
              .font(.caption)
              .foregroundStyle(.secondary)
          }
          Spacer()
          Button("New Policy") {
            model.createNewPolicy()
          }
          .buttonStyle(.link)
        }
      } else {
        ForEach(model.activePolicies) { policy in
          activePolicyRow(policy)
        }
      }
    } header: {
      HStack {
        Text("Policies")
        Spacer()
        Button("New Policy…") {
          model.createNewPolicy()
        }
        .buttonStyle(.link)
        .font(.callout)
      }
    }
  }

  private func activePolicyRow(_ policy: DirectoryPolicy) -> some View {
    Button {
      model.selectedSection = .policy(policy.id)
    } label: {
      HStack(spacing: 12) {
        IconTile(systemImage: policy.mode.symbolName, tint: policy.mode.tint)
        VStack(alignment: .leading, spacing: 2) {
          Text(policy.name)
            .font(.body.weight(.semibold))
          policySummaryText(policy)
            .font(.caption)
            .foregroundStyle(.secondary)
            .lineLimit(1)
            .truncationMode(.middle)
        }
        Spacer(minLength: 12)
        Text("\(policy.activeRuleCount) of \(policy.rules.count) rules enabled")
          .font(.callout)
          .foregroundStyle(.secondary)
        Image(systemName: "chevron.right")
          .font(.system(size: 11, weight: .semibold))
          .foregroundStyle(.tertiary)
      }
    }
    .buttonStyle(.plain)
    .help("Edit this policy")
  }

  private func policySummaryText(_ policy: DirectoryPolicy) -> Text {
    Text("\(policy.mode.displayName) · \(policy.policyType.displayName) — ")
      + Text(policy.protectedRootPath).font(.caption.monospaced())
  }

  // MARK: - Application

  private var applicationSection: some View {
    Section {
      Button(
        model.pendingUninstall == nil ? "Uninstall Pasu FS…" : "Continue Uninstall…",
        role: .destructive
      ) {
        model.isPresentingUninstall = true
      }
      .disabled(model.isBusy || model.isUninstalling)
      if model.pendingUninstall != nil {
        Text(
          "An uninstall was started. Automatic extension updates are paused until it is resolved."
        )
        .font(.callout)
        .foregroundStyle(.orange)
      }
      Toggle(
        "Open Pasu FS at Login",
        isOn: Binding(
          get: { model.isOpenAtLoginRegistered },
          set: { model.setOpenAtLogin($0) }
        )
      )
      .toggleStyle(.switch)
      .disabled(!model.canChangeOpenAtLogin)

      LabeledContent("Login item", value: loginItemStatusDescription)

      if model.loginItemState == .requiresApproval {
        Text(
          "Pasu FS is registered, but macOS requires approval before it can open at login."
        )
        .font(.callout)
        .foregroundStyle(.orange)
        Button("Open Login Items…") {
          model.openLoginItemsSettings()
        }
      } else if model.loginItemState == .notFound && model.loginItemError == nil {
        Text("Turn on Open at Login to register Pasu FS with macOS.")
          .font(.callout)
          .foregroundStyle(.secondary)
      }
      if let error = model.loginItemError {
        Text(error)
          .font(.callout)
          .foregroundStyle(.red)
      }
    } header: {
      Text("Application")
    } footer: {
      Text(
        "This setting opens only the Pasu FS menu bar app. An activated system extension runs independently."
      )
      .font(.caption)
      .foregroundStyle(.tertiary)
    }
  }

  private var loginItemStatusDescription: String {
    switch model.loginItemState {
    case .notRegistered: "Off"
    case .enabled: "Enabled"
    case .requiresApproval: "Approval required"
    case .notFound: "No registration found"
    }
  }

  // MARK: - Runtime

  private var runtimeSection: some View {
    Section("Runtime") {
      LabeledContent("Runtime evidence", value: evidenceText)
      LabeledContent("System extension", value: model.installationSummary)
      if let history = model.processLineageStatus {
        LabeledContent("Process history", value: history.isTracking ? "Observing" : "Stopped")
        Text(
          "Observes process relationships even without file policies. Only received events are used."
        )
        .font(.caption).foregroundStyle(.secondary)
        LabeledContent("Observed process events", value: "\(history.observedEventCount)")
        ForEach(history.issues) { issue in
          Text("\(issue.explanation) (\(issue.count))")
            .font(.caption).foregroundStyle(.orange)
        }
        if let warning = LineageIssue.lossAccountingWarning(
          version: history.deliveryAccountingVersion, issues: history.issues)
        {
          Text(warning).font(.caption).foregroundStyle(.orange)
        }
      }
      LabeledContent("Dropped audit events") {
        Text("\(model.droppedAuditEventCount)")
          .foregroundStyle(model.droppedAuditEventCount > 0 ? Color.orange : Color.secondary)
      }
    }
  }

  // MARK: - Deactivation

  private var deactivationSection: some View {
    Section {
      Button("Deactivate Extension…", role: .destructive) {
        isConfirmingDeactivation = true
      }
      .disabled(model.isBusy || model.isStoppingProtectionForQuit)
      if let message = model.operationMessage {
        Text(message)
          .font(.callout)
          .foregroundStyle(.secondary)
      }
      if let error = model.lastError {
        Text(error)
          .font(.callout)
          .foregroundStyle(.red)
      }
    } footer: {
      Text(
        "Status polls every 2 seconds. Quit Pasu FS leaves protection running; use Stop Protection and Quit or Deactivate Extension to ask macOS to remove it."
      )
      .font(.caption)
      .foregroundStyle(.tertiary)
    }
  }

  // MARK: - Derived presentation

  private var statusColor: Color {
    switch model.health.protection {
    case .enforcingOpenEvents: .green
    case .monitoringOpenEvents: .blue
    case .degraded: .orange
    default: .secondary
    }
  }

  private var activeRevision: UInt64? {
    switch model.health.protection {
    case .idle(let revision), .enforcingOpenEvents(let revision),
      .monitoringOpenEvents(let revision):
      revision
    default:
      nil
    }
  }

  private var evidenceSymbolName: String {
    switch model.health.runtimeEvidenceSource {
    case .authenticatedXPC: "checkmark"
    case .diagnosticFile: "exclamationmark.triangle"
    case nil: "questionmark"
    }
  }

  private var evidenceTint: Color {
    switch model.health.runtimeEvidenceSource {
    case .authenticatedXPC: .green
    case .diagnosticFile: .orange
    case nil: .secondary
    }
  }

  private var evidenceText: String {
    var parts = [model.runtimeEvidenceDescription]
    if let age = model.evidenceAgeDescription {
      parts.append(age)
    }
    return parts.joined(separator: " · ")
  }
}
