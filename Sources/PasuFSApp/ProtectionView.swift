import PasuFSConfiguration
import PasuFSHostCore
import SwiftUI

struct ProtectionView: View {
  @Bindable var model: AppModel

  @State private var isConfirmingDeactivation = false

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 12) {
        heroCard
        warningBanners
        coverageCard
        activePoliciesSection
        runtimeTiles
        footer
      }
      .padding(20)
    }
    .navigationTitle("Protection")
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

  // MARK: - Hero

  private var heroCard: some View {
    HStack(spacing: 14) {
      Image(systemName: model.menuBarSymbolName)
        .font(.system(size: 26, weight: .medium))
        .foregroundStyle(heroColor)
        .frame(width: 52, height: 52)
        .background(heroColor.opacity(0.12), in: Circle())
      VStack(alignment: .leading, spacing: 3) {
        Text(model.healthTitle)
          .font(.title3.weight(.semibold))
        Text(model.healthDetail)
          .font(.caption)
          .foregroundStyle(.secondary)
      }
      Spacer(minLength: 12)
      VStack(alignment: .trailing, spacing: 6) {
        HStack(spacing: 6) {
          if let revision = activeRevision {
            TagBadge(text: "Revision \(revision)", tint: heroColor)
          }
          if model.health.protectionPolicyCount > 0 || model.health.auditPolicyCount > 0 {
            TagBadge(
              text:
                "\(model.health.protectionPolicyCount) Protection · \(model.health.auditPolicyCount) Audit",
              tint: .secondary
            )
          }
        }
        evidenceLine
      }
    }
    .padding(16)
    .cardStyle()
  }

  private var evidenceLine: some View {
    HStack(spacing: 5) {
      Image(systemName: evidenceSymbolName)
        .font(.system(size: 10, weight: .bold))
        .foregroundStyle(evidenceTint)
      Text(evidenceText)
        .font(.caption)
        .foregroundStyle(.secondary)
    }
  }

  private var warningBanners: some View {
    Group {
      if case .degraded(let reason) = model.health.protection {
        WarningBanner(text: reason)
      }
      if let warning = model.health.policyWarning {
        WarningBanner(text: "Policy update warning: \(warning)")
      }
      if let warning = model.policySynchronizationWarning {
        WarningBanner(text: warning, systemImage: "arrow.triangle.2.circlepath")
      }
    }
  }

  // MARK: - Coverage

  private var coverageCard: some View {
    VStack(alignment: .leading, spacing: 0) {
      HStack(alignment: .firstTextBaseline, spacing: 10) {
        Image(systemName: "checkmark.circle")
          .foregroundStyle(.green)
        coveredText
      }
      .padding(.horizontal, 16)
      .padding(.vertical, 11)
      CardDivider()
      HStack(alignment: .firstTextBaseline, spacing: 10) {
        Image(systemName: "exclamationmark.circle")
          .foregroundStyle(.orange)
        Text(
          "Not covered in v0.2: create, rename, delete, hard link, clone, truncate, memory-map, copy, and directory listing."
        )
        .foregroundStyle(.secondary)
      }
      .padding(.horizontal, 16)
      .padding(.vertical, 11)
    }
    .font(.callout)
    .frame(maxWidth: .infinity, alignment: .leading)
    .cardStyle()
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

  // MARK: - Active policies

  private var activePoliciesSection: some View {
    VStack(alignment: .leading, spacing: 6) {
      HStack {
        SectionHeading("Active policies")
        Spacer()
        Button("New Policy…") {
          model.createNewPolicy()
        }
        .buttonStyle(.link)
        .font(.callout)
      }
      .padding(.horizontal, 4)

      VStack(spacing: 0) {
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
          .padding(.horizontal, 16)
          .padding(.vertical, 12)
        } else {
          ForEach(Array(model.activePolicies.enumerated()), id: \.element.id) { index, policy in
            if index > 0 {
              CardDivider()
            }
            activePolicyRow(policy)
          }
        }
      }
      .cardStyle()
    }
  }

  private func activePolicyRow(_ policy: DirectoryPolicy) -> some View {
    HStack(spacing: 12) {
      IconTile(systemImage: policy.mode.symbolName, tint: policy.mode.tint)
      VStack(alignment: .leading, spacing: 2) {
        HStack(spacing: 8) {
          Text(policy.name)
            .font(.body.weight(.semibold))
          TagBadge(text: policy.mode.displayName, tint: policy.mode.tint)
          TagBadge(text: policy.policyType.displayName, tint: .secondary)
        }
        Text(policy.protectedRootPath)
          .font(.caption.monospaced())
          .foregroundStyle(.secondary)
          .lineLimit(1)
          .truncationMode(.middle)
      }
      Spacer(minLength: 12)
      Text("\(policy.activeRuleCount) of \(policy.rules.count) rules enabled")
        .font(.callout)
        .foregroundStyle(.secondary)
      Button("Edit") {
        model.selectedSection = .policy(policy.id)
      }
      .buttonStyle(.link)
    }
    .padding(.horizontal, 16)
    .padding(.vertical, 12)
  }

  // MARK: - Runtime

  private var runtimeTiles: some View {
    Grid(horizontalSpacing: 10, verticalSpacing: 10) {
      GridRow {
        runtimeTile("Runtime evidence", value: model.runtimeEvidenceDescription)
        runtimeTile("System extension", value: model.installationSummary)
        runtimeTile(
          "Dropped audit events",
          value: "\(model.droppedAuditEventCount)",
          tint: model.droppedAuditEventCount > 0 ? .orange : .primary
        )
      }
    }
  }

  private func runtimeTile(
    _ title: String,
    value: String,
    tint: Color = .primary
  ) -> some View {
    VStack(alignment: .leading, spacing: 3) {
      Text(title)
        .font(.caption)
        .foregroundStyle(.secondary)
      Text(value)
        .font(.callout.weight(.medium))
        .foregroundStyle(tint)
        .lineLimit(2)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(.horizontal, 14)
    .padding(.vertical, 11)
    .cardStyle()
  }

  // MARK: - Footer

  private var footer: some View {
    VStack(alignment: .leading, spacing: 8) {
      HStack {
        Text(
          "Status polls every 2 seconds. Quitting this app does not stop protection — the extension runs on its own."
        )
        .font(.caption)
        .foregroundStyle(.tertiary)
        Spacer()
        Button("Deactivate Extension…", role: .destructive) {
          isConfirmingDeactivation = true
        }
        .disabled(model.isBusy)
      }
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
    }
  }

  // MARK: - Derived presentation

  private var heroColor: Color {
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
