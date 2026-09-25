import Darwin
import Foundation
import PasuFSConfiguration
import SwiftUI

enum OpenFlagsText {
  /// "Read", "Write" or "Read and write" for people; the raw value stays available.
  static func readable(_ flags: UInt32) -> String {
    let read = flags & UInt32(FREAD) != 0
    let write = flags & UInt32(FWRITE) != 0
    switch (read, write) {
    case (true, true): return String(localized: "Read and write")
    case (true, false): return String(localized: "Read")
    case (false, true): return String(localized: "Write")
    case (false, false): return String(localized: "Other")
    }
  }

  static func technical(_ flags: UInt32) -> String {
    var labels: [String] = []
    let read = UInt32(FREAD)
    let write = UInt32(FWRITE)
    if flags & read != 0 { labels.append("FREAD") }
    if flags & write != 0 { labels.append("FWRITE") }
    let unknown = flags & ~(read | write)
    if unknown != 0 { labels.append("other=\(hex(unknown))") }
    if labels.isEmpty { labels.append("none") }
    return "\(labels.joined(separator: "+")) [\(hex(flags))]"
  }

  static func hex(_ value: UInt32) -> String {
    String(format: "0x%08X", value)
  }
}

// MARK: - Event details

/// The details of one log record, shown in a policy log's inspector.
struct AuditEventDetails: View {
  let model: AppModel
  let record: AuditEventRecord

  var body: some View {
    Form {
      Section {
        Label(headline, systemImage: headlineSymbol)
          .font(.headline)
          .foregroundStyle(headlineTint)
        Text(
          verbatim:
            "\(record.timestamp.formatted(date: .abbreviated, time: .standard)) · \(eventDescription)"
        )
        .foregroundStyle(.secondary)
      }
      Section("Request") {
        DetailRows(rows: requestRows)
      }
      Section("Program") {
        DetailRows(rows: programRows)
      }
      Section {
        ExecutionPathView(record: record)
      } header: {
        Text("Execution Path")
      }
      Section {
        if let evaluations = record.policyEvaluations, !evaluations.isEmpty {
          ForEach(evaluations) { evaluation in
            PolicyEvaluationRow(evaluation: evaluation)
          }
        } else {
          Text("This older record has no per-policy decisions.")
            .foregroundStyle(.secondary)
        }
      } header: {
        Text("Policy Decisions")
      }
      if let candidate = ruleCandidate, !model.sidebarPolicies.isEmpty {
        Section {
          Menu("Create Rule From This Program…") {
            ForEach(model.sidebarPolicies) { policy in
              Button(policy.name.isEmpty ? String(localized: "Untitled Policy") : policy.name) {
                model.selectedSection = .policy(policy.id)
                model.addProgramRequest = AddProgramRequest(
                  policyID: policy.id, preselected: candidate)
              }
            }
          }
        }
      }
    }
    .formStyle(.grouped)
  }

  private var headline: String {
    switch record.kernelResponse {
    case "deny": String(localized: "Denied")
    case "allow": String(localized: "Allowed")
    case "notify-only": String(localized: "Notified")
    case "response-error": String(localized: "Response Error")
    default: record.kernelResponse
    }
  }

  private var headlineSymbol: String {
    switch record.kernelResponse {
    case "deny": "xmark.circle"
    case "allow": "checkmark.circle"
    case "response-error": "exclamationmark.triangle"
    default: "bell"
    }
  }

  private var headlineTint: Color {
    switch record.kernelResponse {
    case "deny": .red
    case "allow": .green
    case "response-error": .orange
    default: .blue
    }
  }

  private var eventDescription: String {
    record.eventType == "AUTH_OPEN"
      ? String(localized: "File open (AUTH_OPEN)") : record.eventType
  }

  private var requestRows: [DetailRows.Row] {
    var rows = [
      DetailRows.Row(
        label: String(localized: "Target"),
        value: record.targetPath ?? String(localized: "Unavailable"), isMonospaced: true)
    ]
    if record.pathWasTruncated == true {
      rows.append(
        .init(
          label: String(localized: "Note"),
          value: String(localized: "macOS reported a truncated path.")))
    }
    if let flags = record.requestedFlags {
      let value = UInt32(bitPattern: flags)
      rows.append(
        .init(
          label: String(localized: "Access"),
          value: "\(OpenFlagsText.readable(value)) · \(OpenFlagsText.technical(value))"))
    }
    return rows
  }

  private var programRows: [DetailRows.Row] {
    var rows: [DetailRows.Row] = [
      .init(label: String(localized: "Name"), value: record.directProcessName)
    ]
    if record.isPlatformBinary == true {
      rows.append(
        .init(
          label: String(localized: "Signature"), value: PolicyRuleKind.platformBinary.displayName))
    } else if record.teamIdentifier != nil {
      rows.append(
        .init(label: String(localized: "Signature"), value: PolicyRuleKind.teamSigned.displayName))
    }
    if let team = record.teamIdentifier {
      rows.append(.init(label: String(localized: "Team ID"), value: team, isMonospaced: true))
    }
    rows.append(
      .init(
        label: String(localized: "Signing ID"),
        value: record.signingIdentifier ?? String(localized: "Unavailable"), isMonospaced: true))
    if let flags = record.codeSigningFlags {
      rows.append(
        .init(
          label: String(localized: "Code-Signing Flags"), value: OpenFlagsText.hex(flags),
          isMonospaced: true))
    }
    if let path = record.executablePath {
      rows.append(.init(label: String(localized: "Executable"), value: path, isMonospaced: true))
    }
    if let build = record.operatingSystemBuild {
      rows.append(.init(label: String(localized: "OS Build"), value: build))
    }
    return rows
  }

  private var ruleCandidate: AuditRuleCandidate? {
    PolicyProgramSummarizer.summaries(
      records: [record], policyID: UUID(),
      displayName: { signing, _ in signing }
    ).first?.ruleCandidate
  }
}

private struct PolicyEvaluationRow: View {
  let evaluation: PolicyEvaluationRecord

  var body: some View {
    LabeledContent {
      DecisionText(decision: evaluation.decision)
    } label: {
      Text(evaluation.policyName)
      Text(
        verbatim:
          "\(evaluation.mode.displayName) · \(evaluation.policyType.displayName) · \(matchDescription)"
      )
      if let rule = evaluation.ruleIdentifier {
        Text(rule)
          .monospaced()
      }
    }
  }

  private var matchDescription: String {
    if let profile = evaluation.systemCompatibilityProfileIdentifier {
      return String(localized: "System compatibility profile \(profile)")
    }
    return evaluation.match.displayName
  }
}
