import Foundation
import Observation
import PasuFSConfiguration

struct PolicyLogRow: Identifiable {
  let record: AuditEventRecord
  var id: String { record.id }
  var timestamp: Date { record.timestamp }
  var target: String { record.targetPath ?? "Unavailable" }
  var response: String { record.kernelResponse }
  var process: String { record.processPreview }
  var decision: String {
    switch record.policyEvaluations?.first?.decision {
    case .allow: "Allow"
    case .deny: "Deny"
    case .wouldAllow: "Would allow"
    case .wouldDeny: "Would deny"
    case nil: "Unavailable"
    }
  }
}

@Observable
@MainActor
final class PolicyLogState {
  let key: PolicyAuditLogKey
  var batch = AuditLogBatch(records: [])
  var filterText = ""
  var selectedEventIDs: Set<String> = []
  var sortOrder = [KeyPathComparator(\PolicyLogRow.timestamp, order: .reverse)]
  var showsInspector = false
  var isLoading = false
  var hasLoaded = false
  var error: String?
  var requestID: UUID?

  init(key: PolicyAuditLogKey) { self.key = key }

  var rows: [PolicyLogRow] {
    let needle = filterText.trimmingCharacters(in: .whitespacesAndNewlines)
    return batch.records.reversed().map(PolicyLogRow.init).filter { row in
      guard !needle.isEmpty else { return true }
      let evaluation = row.record.policyEvaluations?.first
      return
        ([
          row.process, row.target, row.decision, row.response,
          row.record.signingIdentifier ?? "", row.record.teamIdentifier ?? "",
          evaluation?.policyName ?? "", evaluation?.ruleIdentifier ?? "",
          evaluation?.match.rawValue ?? "",
        ] + row.record.lineageSearchValues).contains { $0.localizedCaseInsensitiveContains(needle) }
    }.sorted(using: sortOrder)
  }

  var warning: String? {
    var parts: [String] = []
    if let warning = batch.warning { parts.append(warning) }
    if batch.droppedEventCount > 0 {
      parts.append("\(batch.droppedEventCount) policy records could not be stored during this run.")
    }
    if batch.skippedLineCount > 0 {
      parts.append("\(batch.skippedLineCount) unreadable or unexpected lines were skipped.")
    }
    if batch.isTruncated { parts.append("Only the newest 500 stored lines are loaded.") }
    return parts.isEmpty ? nil : parts.joined(separator: " ")
  }
}
