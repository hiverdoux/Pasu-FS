import Darwin
import Foundation
import PasuFSConfiguration
import SwiftUI

private enum AuditLogPresentation: String, CaseIterable, Identifiable {
  case events = "Events"
  case profileCandidates = "Profile candidates"

  var id: Self { self }
}

private struct AuditEventTableRow: Identifiable {
  let record: AuditEventRecord

  var id: String { record.id }
  var timestamp: Date { record.timestamp }
  var response: String { record.kernelResponse }
  var process: String { record.processPreview }
  var platform: String { record.isPlatformBinary == true ? "Platform" : "Other" }
  var operatingSystemBuild: String { record.operatingSystemBuild ?? "Unavailable" }
  var signingIdentifier: String { record.signingIdentifier ?? "" }
  var requestedFlags: String {
    record.requestedFlags.map { formatOpenFlags(UInt32(bitPattern: $0)) } ?? "Unavailable"
  }
  var target: String { record.targetPath ?? "No target path" }
  var policyCount: String {
    String(format: "%04d", record.policyEvaluations?.count ?? 0)
  }
}

private struct CompatibilityCandidateTableRow: Identifiable {
  let candidate: SystemCompatibilityAuditCandidate

  var id: String { candidate.id }
  var policy: String { candidate.policyName }
  var actor: String { candidate.signingIdentifier }
  var operatingSystemBuild: String { candidate.operatingSystemBuild }
  var requestedFlags: String {
    candidate.requestedFlagValues.map(formatOpenFlags).joined(separator: ", ")
  }
  var codeSigningFlags: String {
    candidate.codeSigningFlagValues.map(formatHex).joined(separator: ", ")
  }
  var observations: String { String(format: "%09d", candidate.observationCount) }
  var lastSeen: Date { candidate.lastSeen }
  var evidence: String {
    candidate.hasCompleteEvidence ? "Fields complete" : "Missing fields"
  }
}

struct AuditLogView: View {
  @Bindable var model: AppModel

  @State private var presentation: AuditLogPresentation = .events
  @State private var showsInspector = true
  @State private var selectedEventIDs: Set<String> = []
  @State private var selectedCandidateIDs: Set<String> = []
  @State private var selectedCandidatePolicyID: UUID?
  @State private var eventSortOrder = [
    KeyPathComparator(\AuditEventTableRow.timestamp, order: .reverse)
  ]
  @State private var candidateSortOrder = [
    KeyPathComparator(\CompatibilityCandidateTableRow.lastSeen, order: .reverse)
  ]

  var body: some View {
    VStack(spacing: 0) {
      if model.auditBatch.droppedEventCount > 0 || model.auditBatch.skippedLineCount > 0
        || model.auditBatch.isTruncated || model.auditBatch.warning != nil
      {
        WarningBanner(text: honestyBannerText)
          .padding(.horizontal, 16)
          .padding(.top, 6)
          .padding(.bottom, 8)
      }

      Group {
        switch presentation {
        case .events:
          eventTable
        case .profileCandidates:
          candidateTable
        }
      }

      Divider()
      footer
    }
    .navigationTitle("Audit Log")
    .searchable(text: $model.auditFilterText, prompt: "Filter loaded records")
    .toolbar {
      ToolbarItem(placement: .principal) {
        Picker("Presentation", selection: $presentation) {
          ForEach(AuditLogPresentation.allCases) { value in
            Text(value.rawValue).tag(value)
          }
        }
        .pickerStyle(.segmented)
        .frame(width: 280)
      }
      if presentation == .profileCandidates {
        ToolbarItem {
          Picker("Whitelist policy", selection: $selectedCandidatePolicyID) {
            Text("All Whitelist policies").tag(Optional<UUID>.none)
            ForEach(whitelistPolicies) { policy in
              Text(policy.name).tag(Optional(policy.id))
            }
          }
          .frame(minWidth: 180)
          .help("Limit candidates to one Whitelist policy")
        }
      }
      ToolbarItem {
        Button {
          Task { await model.refreshAuditLog() }
        } label: {
          Label("Refresh", systemImage: "arrow.clockwise")
        }
        .help("Reload the newest 500 records")
      }
      ToolbarItem {
        Button {
          showsInspector.toggle()
        } label: {
          Label("Details", systemImage: "sidebar.trailing")
        }
        .help(showsInspector ? "Hide the details inspector" : "Show the details inspector")
      }
    }
    .inspector(isPresented: $showsInspector) {
      inspectorContent
        .inspectorColumnWidth(min: 240, ideal: 280, max: 380)
    }
    .task { await model.refreshAuditLog() }
  }

  private var eventTable: some View {
    Table(
      sortedEventRows,
      selection: $selectedEventIDs,
      sortOrder: $eventSortOrder
    ) {
      TableColumn("Time", value: \.timestamp) { row in
        Text(row.timestamp.formatted(date: .omitted, time: .standard))
          .font(.caption.monospaced())
      }
      .width(min: 70, ideal: 86)

      TableColumn("Response", value: \.response) { row in
        ResponseIndicator(response: row.response)
      }
      .width(min: 72, ideal: 82)

      TableColumn("Process", value: \.process) { row in
        VStack(alignment: .leading, spacing: 1) {
          ProcessPreviewLabel(record: row.record)
          if !row.signingIdentifier.isEmpty {
            Text(row.signingIdentifier)
              .font(.caption2.monospaced())
              .foregroundStyle(.secondary)
              .lineLimit(1)
              .truncationMode(.middle)
          }
        }
      }
      .width(min: 170, ideal: 230)

      TableColumn("Platform", value: \.platform)
        .width(min: 68, ideal: 78)

      TableColumn("OS build", value: \.operatingSystemBuild)
        .width(min: 76, ideal: 92)

      TableColumn("Open flags", value: \.requestedFlags) { row in
        Text(row.requestedFlags)
          .font(.caption.monospaced())
      }
      .width(min: 120, ideal: 160)

      TableColumn("Target", value: \.target) { row in
        Text(row.target)
          .font(.caption.monospaced())
          .lineLimit(1)
          .truncationMode(.middle)
      }
      .width(min: 190, ideal: 320)

      TableColumn("Policies", value: \.policyCount) { row in
        Text("\(row.record.policyEvaluations?.count ?? 0)")
      }
      .width(min: 58, ideal: 68)
    }
    .alternatingRowBackgrounds()
  }

  private var candidateTable: some View {
    Group {
      if sortedCandidateRows.isEmpty {
        ContentUnavailableView(
          "No system-profile candidates",
          systemImage: "tablecells",
          description: Text(
            "Candidates require AUTH_OPEN, an exact Apple platform Signing ID, and a Whitelist no-match recorded as deny or would-deny."
          )
        )
        .frame(maxHeight: .infinity)
      } else {
        Table(
          sortedCandidateRows,
          selection: $selectedCandidateIDs,
          sortOrder: $candidateSortOrder
        ) {
          TableColumn("Policy", value: \.policy)
            .width(min: 110, ideal: 150)

          TableColumn("Direct platform actor", value: \.actor) { row in
            VStack(alignment: .leading, spacing: 1) {
              Text(row.candidate.displayName)
              Text(row.actor)
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
            }
          }
          .width(min: 190, ideal: 250)

          TableColumn("Observed open flags", value: \.requestedFlags) { row in
            Text(row.requestedFlags)
              .font(.caption.monospaced())
              .help("Union: \(formatOpenFlags(row.candidate.requestedFlagUnion))")
          }
          .width(min: 180, ideal: 240)

          TableColumn("Code-signing flags", value: \.codeSigningFlags) { row in
            Text(row.codeSigningFlags)
              .font(.caption.monospaced())
          }
          .width(min: 130, ideal: 170)

          TableColumn("OS build", value: \.operatingSystemBuild)
            .width(min: 76, ideal: 92)

          TableColumn("Observations", value: \.observations) { row in
            Text("\(row.candidate.observationCount)")
          }
          .width(min: 78, ideal: 92)

          TableColumn("Last seen", value: \.lastSeen) { row in
            Text(row.lastSeen.formatted(date: .abbreviated, time: .standard))
              .font(.caption)
          }
          .width(min: 120, ideal: 145)

          TableColumn("Evidence", value: \.evidence) { row in
            Text(row.evidence)
              .foregroundStyle(row.candidate.hasCompleteEvidence ? .green : .orange)
          }
          .width(min: 76, ideal: 90)
        }
        .alternatingRowBackgrounds()
      }
    }
  }

  // MARK: - Inspector

  @ViewBuilder
  private var inspectorContent: some View {
    switch presentation {
    case .events:
      if let row = sortedEventRows.first(where: { selectedEventIDs.contains($0.id) }) {
        AuditEventDetails(record: row.record)
      } else {
        noSelectionPlaceholder
      }
    case .profileCandidates:
      if let row = sortedCandidateRows.first(where: {
        selectedCandidateIDs.contains($0.id)
      }) {
        CompatibilityCandidateDetails(candidate: row.candidate)
      } else {
        noSelectionPlaceholder
      }
    }
  }

  private var noSelectionPlaceholder: some View {
    ContentUnavailableView {
      Label("No Selection", systemImage: "sidebar.trailing")
    } description: {
      Text(
        presentation == .events
          ? "Select an event to see its signing identity and per-policy evaluations."
          : "Select a candidate to see its observed evidence."
      )
    }
  }

  private var footer: some View {
    HStack {
      Text(
        presentation == .events
          ? "Newest 500 records, metadata only — no file contents. Storage rotates at 10 MiB."
          : "Candidate evidence uses only the loaded tail. Current OS build: \(SystemCompatibilityOSBuild.current())."
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
    .padding(.horizontal, 16)
    .padding(.vertical, 7)
    .background(.bar)
  }

  private var whitelistPolicies: [DirectoryPolicy] {
    (model.activePolicySet?.policies ?? [])
      .filter { $0.policyType == .whitelist }
      .sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
  }

  private var sortedEventRows: [AuditEventTableRow] {
    model.filteredAuditRecords
      .map(AuditEventTableRow.init)
      .sorted(using: eventSortOrder)
  }

  private var sortedCandidateRows: [CompatibilityCandidateTableRow] {
    let needle = model.auditFilterText.trimmingCharacters(in: .whitespacesAndNewlines)
    return model.systemCompatibilityAuditCandidates(policyID: selectedCandidatePolicyID)
      .filter { candidate in
        needle.isEmpty
          || [candidate.policyName, candidate.signingIdentifier, candidate.displayName]
            .contains { $0.localizedCaseInsensitiveContains(needle) }
      }
      .map(CompatibilityCandidateTableRow.init)
      .sorted(using: candidateSortOrder)
  }

  private var recordCountDescription: String {
    switch presentation {
    case .events:
      "\(sortedEventRows.count) of \(model.auditBatch.records.count) events shown"
    case .profileCandidates:
      "\(sortedCandidateRows.count) policy-specific candidates"
    }
  }

  private var honestyBannerText: String {
    var parts: [String] = []
    if let warning = model.auditBatch.warning { parts.append(warning) }
    if model.auditBatch.droppedEventCount > 0 {
      parts.append(
        "\(model.auditBatch.droppedEventCount) records could not be stored during this run")
    }
    if model.auditBatch.skippedLineCount > 0 {
      parts.append("\(model.auditBatch.skippedLineCount) unreadable lines were skipped")
    }
    if model.auditBatch.isTruncated {
      parts.append("older records were cut at the 500-line limit")
    }
    return parts.joined(separator: " · ")
      + ". Candidate evidence is incomplete when any of these conditions is present."
  }
}

struct ResponseIndicator: View {
  let response: String

  var body: some View {
    HStack(spacing: 5) {
      Circle()
        .fill(tint)
        .frame(width: 6, height: 6)
      Text(label)
        .font(.caption.weight(.semibold))
        .foregroundStyle(tint)
    }
  }

  private var label: String {
    switch response {
    case "deny": "Deny"
    case "allow": "Allow"
    case "notify-only": "Notify"
    case "response-error": "Error"
    default: response
    }
  }

  private var tint: Color {
    switch response {
    case "deny": .red
    case "allow": .green
    case "notify-only": .blue
    case "response-error": .orange
    default: .secondary
    }
  }
}

// MARK: - Inspector details

private struct InspectorRow: View {
  let label: String
  let value: String
  var isMonospaced = false

  var body: some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(label)
        .font(.caption)
        .foregroundStyle(.secondary)
      Text(value)
        .font(isMonospaced ? .callout.monospaced() : .callout)
        .textSelection(.enabled)
    }
    .frame(maxWidth: .infinity, alignment: .leading)
  }
}

struct AuditEventDetails: View {
  let record: AuditEventRecord

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 12) {
        Text("Event Details")
          .font(.headline)
        InspectorRow(label: "Pasu FS response", value: record.kernelResponse)
        InspectorRow(label: "Signing identity", value: identity, isMonospaced: true)
        InspectorRow(
          label: "Code-signing flags",
          value: record.codeSigningFlags.map(formatHex) ?? "Unavailable",
          isMonospaced: true
        )
        InspectorRow(
          label: "Target",
          value: record.targetPath ?? "Unavailable",
          isMonospaced: true
        )
        Divider()
        if let lineage = record.processLineage {
          ProcessLineageDetails(snapshot: lineage)
        } else {
          Text("Process history was not stored in this record.")
            .font(.caption).foregroundStyle(.secondary)
        }
        Divider()
        Text("Policy evaluations")
          .font(.headline)
        if let evaluations = record.policyEvaluations, !evaluations.isEmpty {
          ForEach(evaluations) { evaluation in
            PolicyEvaluationRow(evaluation: evaluation)
          }
          Text("Audit-mode evaluations are virtual — no kernel effect.")
            .font(.caption2)
            .foregroundStyle(.tertiary)
        } else {
          Text("Legacy or non-policy audit record — per-policy evaluations are unavailable.")
            .font(.caption)
            .foregroundStyle(.tertiary)
        }
      }
      .padding(14)
      .frame(maxWidth: .infinity, alignment: .leading)
    }
  }

  private var identity: String {
    if let team = record.teamIdentifier, let signing = record.signingIdentifier {
      return "\(team) · \(signing)"
    }
    return record.signingIdentifier ?? "Unavailable"
  }
}

private struct CompatibilityCandidateDetails: View {
  let candidate: SystemCompatibilityAuditCandidate

  var body: some View {
    ScrollView {
      VStack(alignment: .leading, spacing: 12) {
        Text("Candidate Evidence")
          .font(.headline)
        InspectorRow(
          label: "Policy",
          value: "\(candidate.policyName) · \(candidate.policyMode.displayName)"
        )
        InspectorRow(
          label: "Exact platform Signing ID",
          value: candidate.signingIdentifier,
          isMonospaced: true
        )
        InspectorRow(label: "Observed OS build", value: candidate.operatingSystemBuild)
        InspectorRow(
          label: "Requested flag union",
          value: formatOpenFlags(candidate.requestedFlagUnion),
          isMonospaced: true
        )
        InspectorRow(
          label: "Observed code-signing flags",
          value: candidate.codeSigningFlagValues.map(formatHex).joined(separator: ", "),
          isMonospaced: true
        )
        InspectorRow(
          label: "Observation window",
          value: "\(candidate.firstSeen.formatted()) – \(candidate.lastSeen.formatted())"
        )
        InspectorRow(
          label: "Targets",
          value:
            "\(candidate.uniqueTargetPathCount) unique; samples: \(candidate.targetPathSamples.joined(separator: ", "))"
        )
        if candidate.incompleteObservationCount > 0 {
          Divider()
          Text(
            "\(candidate.incompleteObservationCount) observation(s) lacked flags or a target path and cannot support a profile."
          )
          .font(.caption)
          .foregroundStyle(.orange)
        }
      }
      .padding(14)
      .frame(maxWidth: .infinity, alignment: .leading)
    }
  }
}

private struct PolicyEvaluationRow: View {
  let evaluation: PolicyEvaluationRecord

  var body: some View {
    VStack(alignment: .leading, spacing: 3) {
      HStack(alignment: .firstTextBaseline) {
        Text(evaluation.policyName)
          .font(.caption.weight(.semibold))
        Spacer()
        Text(decisionDescription)
          .font(.caption.weight(.semibold))
          .foregroundStyle(decisionColor)
      }
      Text("\(evaluation.mode.displayName) · \(evaluation.policyType.displayName)")
        .font(.caption)
        .foregroundStyle(.secondary)
      Text(matchDescription)
        .font(.caption2.monospaced())
        .foregroundStyle(.secondary)
    }
    .padding(.horizontal, 10)
    .padding(.vertical, 7)
    .frame(maxWidth: .infinity, alignment: .leading)
    .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 7))
  }

  private var matchDescription: String {
    var parts: [String] = []
    if let ruleIdentifier = evaluation.ruleIdentifier {
      parts.append("\(evaluation.match.rawValue): \(ruleIdentifier)")
    } else if let profileIdentifier = evaluation.systemCompatibilityProfileIdentifier {
      parts.append("system profile: \(profileIdentifier)")
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

private func formatOpenFlags(_ flags: UInt32) -> String {
  var labels: [String] = []
  let read = UInt32(FREAD)
  let write = UInt32(FWRITE)
  if flags & read != 0 { labels.append("FREAD") }
  if flags & write != 0 { labels.append("FWRITE") }
  let unknown = flags & ~(read | write)
  if unknown != 0 { labels.append("other=\(formatHex(unknown))") }
  if labels.isEmpty { labels.append("none") }
  return "\(labels.joined(separator: "+")) [\(formatHex(flags))]"
}

private func formatHex(_ value: UInt32) -> String {
  String(format: "0x%08X", value)
}
