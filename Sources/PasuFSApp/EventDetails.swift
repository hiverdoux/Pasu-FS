import Darwin
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
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

/// The name of a recorded request type, followed by its Endpoint Security event name.
enum RequestKindText {
  static func name(_ eventType: String) -> String {
    switch eventType {
    case "AUTH_OPEN": String(localized: "File open (AUTH_OPEN)")
    case "AUTH_CREATE": String(localized: "Create (AUTH_CREATE)")
    case "AUTH_RENAME": String(localized: "Rename or move (AUTH_RENAME)")
    case "AUTH_UNLINK": String(localized: "Delete (AUTH_UNLINK)")
    case "AUTH_LINK": String(localized: "Hard link (AUTH_LINK)")
    case "AUTH_CLONE": String(localized: "Clone (AUTH_CLONE)")
    case "AUTH_COPYFILE": String(localized: "Copy (AUTH_COPYFILE)")
    case "AUTH_TRUNCATE": String(localized: "Truncate (AUTH_TRUNCATE)")
    case "AUTH_EXCHANGEDATA": String(localized: "Data exchange (AUTH_EXCHANGEDATA)")
    case "AUTH_SETMODE": String(localized: "Permissions change (AUTH_SETMODE)")
    case "AUTH_SETOWNER": String(localized: "Owner change (AUTH_SETOWNER)")
    case "AUTH_SETFLAGS": String(localized: "File flags change (AUTH_SETFLAGS)")
    case "AUTH_SETACL": String(localized: "Access control list change (AUTH_SETACL)")
    case "AUTH_SETEXTATTR": String(localized: "Extended attribute change (AUTH_SETEXTATTR)")
    case "AUTH_DELETEEXTATTR":
      String(localized: "Extended attribute removal (AUTH_DELETEEXTATTR)")
    case "AUTH_SETATTRLIST": String(localized: "Attribute change (AUTH_SETATTRLIST)")
    case "AUTH_UTIMES": String(localized: "Time change (AUTH_UTIMES)")
    case "AUTH_MOUNT": String(localized: "Mount (AUTH_MOUNT)")
    default: eventType
    }
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
        if isMissedDeadline {
          Text("Pasu FS’s answer didn’t reach macOS in time, so macOS decided this request.")
            .foregroundStyle(.secondary)
        }
      }
      Section("Request") {
        DetailRows(rows: requestRows)
      }
      if let evaluations = record.policyEvaluations, !evaluations.isEmpty {
        ForEach(evaluations) { evaluation in
          Section {
            PolicyEvaluationRows(model: model, evaluation: evaluation)
          } header: {
            Text("Decision of “\(evaluation.policyName)”")
          }
        }
      } else {
        Section {
          Text("This older record has no per-policy decisions.")
            .foregroundStyle(.secondary)
        } header: {
          Text("Policy Decisions")
        }
      }
      Section("Access Process") {
        DetailRows(rows: programRows)
      }
      Section {
        ProcessChainView(record: record)
      } header: {
        Text("Process Chain")
      }
      if let candidate = ruleCandidate, !model.sidebarPolicies.isEmpty {
        Section {
          Menu("Create Rule From This Program…") {
            ForEach(model.sidebarPolicies) { policy in
              Button(policy.name.isEmpty ? String(localized: "Untitled Policy") : policy.name) {
                model.selectedSection = .policy(policy.id)
                // Programs to Allow can't be changed while the policy doesn't use it.
                model.addProgramRequest = AddProgramRequest(
                  policyID: policy.id, list: policy.isBlacklistEnabled ? .deny : .allow,
                  preselected: candidate)
              }
            }
          }
        }
      }
    }
    .formStyle(.grouped)
  }

  private var headline: String {
    KernelResponseText.headline(record.kernelResponse, deadlineMissMode: model.deadlineMissMode)
  }

  private var isMissedDeadline: Bool { record.kernelResponse == KernelResponseText.missedDeadline }

  private var headlineSymbol: String {
    switch record.kernelResponse {
    case "deny": "xmark.circle"
    case "allow": "checkmark.circle"
    case KernelResponseText.missedDeadline: "exclamationmark.triangle"
    default: "bell"
    }
  }

  private var headlineTint: Color {
    switch record.kernelResponse {
    case "deny": .red
    case "allow": .green
    case KernelResponseText.missedDeadline: .orange
    default: .blue
    }
  }

  private var eventDescription: String { RequestKindText.name(record.eventType) }

  private var isMount: Bool { record.eventType == "AUTH_MOUNT" }

  /// Whether the record also counts allowed requests for other targets. Its paths are then those
  /// of the first request.
  private var includesOtherTargets: Bool {
    record.representedRequestCount > 1 && record.combinesAnyTarget
  }

  /// A mount names the mount point and the device or share it was mounted from.
  private var requestRows: [DetailRows.Row] {
    let targetLabel =
      isMount
      ? String(localized: "Mount point")
      : (includesOtherTargets ? String(localized: "First target") : String(localized: "Target"))
    var rows = [
      DetailRows.Row(
        label: targetLabel, value: record.targetPath ?? String(localized: "Unavailable"),
        isMonospaced: true)
    ]
    if let destination = record.destinationPath {
      let destinationLabel =
        isMount
        ? String(localized: "Mounted from")
        : (includesOtherTargets
          ? String(localized: "First destination") : String(localized: "Destination"))
      rows.append(.init(label: destinationLabel, value: destination, isMonospaced: true))
    }
    if record.representedRequestCount > 1 {
      rows.append(
        .init(
          label: String(localized: "Requests"),
          value: record.representedRequestCount.formatted(.number)))
      rows.append(
        .init(
          label: String(localized: "Last request"),
          value: record.lastRequestTimestamp.formatted(date: .abbreviated, time: .standard)))
    }
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
    if let revision = record.policyRevision {
      rows.append(.init(label: String(localized: "Policy revision"), value: String(revision)))
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

/// One policy's recorded decision with the evidence the extension used for it: the first
/// program of the observed execution history, the access process and a blocked program found in
/// that history. Nothing here is worked out again from the current rules or the process chain.
private struct PolicyEvaluationRows: View {
  let model: AppModel
  let evaluation: PolicyEvaluationRecord

  var body: some View {
    LabeledContent {
      DecisionText(decision: evaluation.decision)
    } label: {
      Text("Decision")
      Text(evaluation.mode.displayName)
    }
    .accessibilityRowValue(evaluation.decision.displayName)
    if let retired = evaluation.retiredFolderPath {
      WarningLabel(text: String(localized: "Retired path: \(retired)"))
        .textSelection(.enabled)
    }
    if let origin = evaluation.executionOrigin {
      if evaluation.match == .enclosingFolder {
        Text(matchDescription)
      }
      // A profile allows a request the program lists alone would not, so the lists' reason
      // would contradict the decision.
      if evaluation.match == .systemCompatibilityProfile {
        Text(matchDescription)
      } else {
        Text(OriginText.reason(origin.reason))
      }
      if let evidence = origin.historyEvidence, let text = OriginText.evidence(evidence) {
        Text(text)
          .foregroundStyle(.secondary)
      }
      if let denied = origin.deniedProgram {
        OriginProgramRow(
          model: model, title: String(localized: "Blocked Program"), program: denied,
          status: PolicyBehaviorText.inListTitle(.deny))
      }
      OriginProgramRow(
        model: model, title: String(localized: "First Program"), program: origin.origin,
        status: originStatus(origin))
      OriginProgramRow(
        model: model, title: String(localized: "Access Process"), program: origin.actor,
        status: actorStatus(origin))
      if let source = origin.inheritedFrom {
        OriginProgramRow(
          model: model, title: String(localized: "Permission Source"), program: source,
          status: String(localized: "Include descendant processes"))
      }
      if let uncertainty = origin.uncertainty {
        WarningLabel(text: OriginText.uncertainty(uncertainty))
      }
    } else if evaluation.match == .mountPoint || evaluation.match == .enclosingFolder {
      // A mount is decided by its mount point, and renaming a folder that contains the
      // policy folder is allowed for every program; no program takes part in either.
      Text(matchDescription)
    } else {
      // A record without the evidence says nothing about its history, good or bad.
      Text(matchDescription)
      Text("This record has no first-program evidence.")
        .foregroundStyle(.secondary)
    }
    if let detail = evaluation.detail, !detail.isEmpty {
      Text(detail)
        .foregroundStyle(.secondary)
        .textSelection(.enabled)
    }
  }

  /// Allow matches are recorded only for a decision that used Programs to Allow.
  private func originStatus(_ origin: ExecutionOriginDecision) -> String? {
    guard origin.origin != nil, !origin.isBlacklistEnabled else { return nil }
    return origin.originRuleIdentifier != nil
      ? PolicyBehaviorText.inListTitle(.allow) : String(localized: "Not in Programs to Allow")
  }

  private func actorStatus(_ origin: ExecutionOriginDecision) -> String? {
    if let role = origin.actorIntermediaryRole { return OriginText.intermediary(role) }
    guard !origin.isBlacklistEnabled else { return nil }
    if origin.inheritedRuleIdentifier != nil {
      return String(localized: "Allowed as a descendant")
    }
    return origin.actorRuleIdentifier != nil
      ? PolicyBehaviorText.inListTitle(.allow) : String(localized: "Not in Programs to Allow")
  }

  private var matchDescription: String { DecisionReasonText.match(evaluation) }
}

/// One program of a recorded decision. Its identity opens below the row.
private struct OriginProgramRow: View {
  let model: AppModel
  let title: String
  /// Nil when the extension could not establish this program.
  let program: ExecutionProgram?
  let status: String?

  var body: some View {
    if let program {
      DisclosureGroup {
        DetailRows(rows: identityRows(program))
      } label: {
        LabeledContent {
          Text(name(program))
        } label: {
          Text(title)
          if let status {
            Text(status)
          }
        }
      }
    } else {
      LabeledContent(title) {
        Text("Unknown")
          .foregroundStyle(.secondary)
      }
    }
  }

  private func name(_ program: ExecutionProgram) -> String {
    if let signing = program.signingIdentifier, !signing.isEmpty {
      return model.displayName(signingIdentifier: signing, executablePath: program.executablePath)
    }
    return program.executablePath.isEmpty
      ? String(localized: "Unknown program")
      : (program.executablePath as NSString).lastPathComponent
  }

  /// A PID alone is not an identity; it is shown with the execution number macOS assigned.
  private func identityRows(_ program: ExecutionProgram) -> [DetailRows.Row] {
    let unavailable = String(localized: "Unavailable")
    var rows: [DetailRows.Row] = [
      .init(label: "PID", value: String(program.instance.processID), isMonospaced: true),
      .init(
        label: String(localized: "Execution"), value: String(program.instance.processVersion),
        isMonospaced: true),
      .init(
        label: String(localized: "Executable"),
        value: program.executablePath.isEmpty ? unavailable : program.executablePath,
        isMonospaced: !program.executablePath.isEmpty),
    ]
    if program.pathWasTruncated {
      rows.append(
        .init(
          label: String(localized: "Note"),
          value: String(localized: "macOS reported a truncated executable path.")))
    }
    if program.isPlatformBinary {
      rows.append(
        .init(
          label: String(localized: "Signature"), value: PolicyRuleKind.platformBinary.displayName))
    } else if let team = program.teamIdentifier, !team.isEmpty {
      rows.append(
        .init(label: String(localized: "Signature"), value: PolicyRuleKind.teamSigned.displayName))
      rows.append(.init(label: String(localized: "Team ID"), value: team, isMonospaced: true))
    }
    rows.append(
      .init(
        label: String(localized: "Signing ID"), value: program.signingIdentifier ?? unavailable,
        isMonospaced: program.signingIdentifier != nil))
    rows.append(
      .init(
        label: String(localized: "Code-Signing Flags"),
        value: OpenFlagsText.hex(program.codeSigningFlags), isMonospaced: true))
    return rows
  }
}
