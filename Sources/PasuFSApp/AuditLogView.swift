import PasuFSConfiguration
import SwiftUI

struct AuditLogView: View {
  @Bindable var model: AppModel

  @State private var expandedRecordIDs: Set<String> = []

  var body: some View {
    VStack(alignment: .leading, spacing: 10) {
      if model.auditBatch.droppedEventCount > 0 || model.auditBatch.skippedLineCount > 0
        || model.auditBatch.isTruncated
      {
        WarningBanner(text: honestyBannerText)
      }

      VStack(spacing: 0) {
        columnHeader
        Divider()
        List(model.filteredAuditRecords) { record in
          AuditRecordRow(
            record: record,
            isExpanded: expandedRecordIDs.contains(record.id)
          ) {
            if expandedRecordIDs.contains(record.id) {
              expandedRecordIDs.remove(record.id)
            } else {
              expandedRecordIDs.insert(record.id)
            }
          }
          .listRowSeparator(.visible)
        }
        .listStyle(.plain)
      }
      .cardStyle()
      .clipShape(RoundedRectangle(cornerRadius: 11))

      HStack {
        Text(
          "Newest 500 records, metadata only — no file contents. Storage rotates at 10 MiB, so older history is discarded."
        )
        .font(.caption)
        .foregroundStyle(.tertiary)
        Spacer()
        Text(recordCountDescription)
          .font(.caption)
          .foregroundStyle(.tertiary)
        if let error = model.lastError {
          Text(error)
            .font(.caption)
            .foregroundStyle(.red)
        }
      }
    }
    .padding(20)
    .navigationTitle("Audit Log")
    .searchable(text: $model.auditFilterText, prompt: "Filter loaded records")
    .toolbar {
      ToolbarItem {
        Button {
          Task { await model.refreshAuditLog() }
        } label: {
          Label("Refresh", systemImage: "arrow.clockwise")
        }
        .help("Reload the newest 500 records")
      }
    }
    .task { await model.refreshAuditLog() }
  }

  private var columnHeader: some View {
    HStack(spacing: 10) {
      Text("Time")
        .frame(width: 62, alignment: .leading)
      Text("Response")
        .frame(width: 76, alignment: .leading)
      Text("Process")
        .frame(width: 170, alignment: .leading)
      Text("Target")
        .frame(maxWidth: .infinity, alignment: .leading)
      Text("Policies")
        .frame(width: 96, alignment: .trailing)
    }
    .font(.caption.weight(.semibold))
    .foregroundStyle(.secondary)
    .padding(.horizontal, 16)
    .padding(.vertical, 7)
  }

  private var recordCountDescription: String {
    let loaded = model.auditBatch.records.count
    let shown = model.filteredAuditRecords.count
    if shown == loaded {
      return "\(loaded) records loaded"
    }
    return "\(shown) of \(loaded) shown after filter"
  }

  private var honestyBannerText: String {
    var parts: [String] = []
    if model.auditBatch.droppedEventCount > 0 {
      parts.append("\(model.auditBatch.droppedEventCount) events were dropped under pressure")
    }
    if model.auditBatch.skippedLineCount > 0 {
      parts.append("\(model.auditBatch.skippedLineCount) unreadable lines were skipped")
    }
    if model.auditBatch.isTruncated {
      parts.append("older records were cut at the 500-line limit")
    }
    return parts.joined(separator: " · ")
      + ". This log describes observed events — it is not complete forensic proof."
  }
}

private struct AuditRecordRow: View {
  let record: AuditEventRecord
  let isExpanded: Bool
  let onToggleExpansion: () -> Void

  private var isLegacy: Bool {
    record.schemaVersion == nil || record.schemaVersion == 1
  }

  private var evaluations: [PolicyEvaluationRecord] {
    record.policyEvaluations ?? []
  }

  var body: some View {
    VStack(alignment: .leading, spacing: 4) {
      HStack(spacing: 10) {
        Text(record.timestamp.formatted(date: .omitted, time: .standard))
          .font(.caption.monospaced())
          .foregroundStyle(.secondary)
          .frame(width: 62, alignment: .leading)

        responseBadge
          .frame(width: 76, alignment: .leading)

        VStack(alignment: .leading, spacing: 1) {
          Text(processTitle)
            .font(.callout.weight(.medium))
          if let identity = processIdentity {
            Text(identity)
              .font(.caption2.monospaced())
              .foregroundStyle(.secondary)
              .lineLimit(1)
              .truncationMode(.middle)
          }
        }
        .frame(width: 170, alignment: .leading)

        Text(record.targetPath ?? "No target path")
          .font(.caption.monospaced())
          .lineLimit(1)
          .truncationMode(.middle)
          .frame(maxWidth: .infinity, alignment: .leading)

        policiesCell
          .frame(width: 96, alignment: .trailing)
      }
      .contentShape(Rectangle())
      .onTapGesture {
        if !evaluations.isEmpty {
          onToggleExpansion()
        }
      }

      if isExpanded, !evaluations.isEmpty {
        VStack(alignment: .leading, spacing: 4) {
          ForEach(evaluations) { evaluation in
            PolicyEvaluationRow(evaluation: evaluation)
          }
        }
        .padding(.leading, 82)
        .padding(.bottom, 4)
      } else if isLegacy {
        Text("Legacy audit record — per-policy evaluations are unavailable.")
          .font(.caption2)
          .foregroundStyle(.tertiary)
          .padding(.leading, 82)
      }
    }
    .padding(.vertical, 3)
  }

  private var responseBadge: some View {
    Text(responseLabel)
      .font(.system(size: 10, weight: .bold))
      .kerning(0.4)
      .padding(.horizontal, 7)
      .padding(.vertical, 2)
      .foregroundStyle(responseTint)
      .background(responseTint.opacity(0.12), in: RoundedRectangle(cornerRadius: 4))
      .help("Kernel response: \(record.kernelResponse)")
  }

  private var policiesCell: some View {
    Group {
      if isLegacy {
        Text("legacy v1")
          .font(.caption)
          .foregroundStyle(.tertiary)
      } else if evaluations.isEmpty {
        Text("0 matched")
          .font(.caption)
          .foregroundStyle(.secondary)
      } else {
        HStack(spacing: 5) {
          Text("\(evaluations.count) matched")
            .font(.caption)
            .foregroundStyle(.secondary)
          Image(systemName: "chevron.right")
            .font(.system(size: 9, weight: .bold))
            .foregroundStyle(.secondary)
            .rotationEffect(.degrees(isExpanded ? 90 : 0))
        }
      }
    }
  }

  private var responseLabel: String {
    switch record.kernelResponse {
    case "deny": "DENY"
    case "allow": "ALLOW"
    case "notify-only": "NOTIFY"
    case "response-error": "ERROR"
    default: record.kernelResponse.uppercased()
    }
  }

  private var responseTint: Color {
    switch record.kernelResponse {
    case "deny": .red
    case "allow": .green
    case "notify-only": .blue
    case "response-error": .orange
    default: .secondary
    }
  }

  private var processTitle: String {
    if let path = record.executablePath, !path.isEmpty {
      return (path as NSString).lastPathComponent
    }
    return record.signingIdentifier ?? "Unknown process"
  }

  private var processIdentity: String? {
    guard let signingIdentifier = record.signingIdentifier else { return nil }
    if let team = record.teamIdentifier, !team.isEmpty {
      return "\(team) · \(signingIdentifier)"
    }
    return signingIdentifier
  }
}

private struct PolicyEvaluationRow: View {
  let evaluation: PolicyEvaluationRecord

  var body: some View {
    HStack(alignment: .firstTextBaseline, spacing: 10) {
      Text(evaluation.policyName)
        .font(.caption.weight(.medium))
        .frame(width: 130, alignment: .leading)
      Text("\(evaluation.mode.displayName) · \(evaluation.policyType.displayName)")
        .font(.caption)
        .foregroundStyle(.secondary)
        .frame(width: 140, alignment: .leading)
      Text(matchDescription)
        .font(.caption.monospaced())
        .foregroundStyle(.secondary)
        .lineLimit(1)
      Spacer()
      Text(decisionDescription)
        .font(.caption.weight(.semibold))
        .foregroundStyle(decisionColor)
    }
    .padding(.horizontal, 12)
    .padding(.vertical, 6)
    .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 7))
  }

  private var matchDescription: String {
    var parts: [String] = []
    if let ruleIdentifier = evaluation.ruleIdentifier {
      parts.append("\(evaluation.match.rawValue): \(ruleIdentifier)")
    } else {
      parts.append(evaluation.match.rawValue)
    }
    if evaluation.mode == .audit {
      parts.append("virtual — no kernel effect")
    }
    return parts.joined(separator: " · ")
  }

  private var decisionDescription: String {
    switch evaluation.decision {
    case .allow: "allow"
    case .deny: "deny"
    case .wouldAllow: "would allow"
    case .wouldDeny: "would deny"
    }
  }

  private var decisionColor: Color {
    switch evaluation.decision {
    case .deny, .wouldDeny: .red
    case .allow, .wouldAllow: .green
    }
  }
}
