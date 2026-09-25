import Foundation
import Observation
import PasuFSConfiguration

struct PolicyLogRow: Identifiable {
  let record: AuditEventRecord
  var id: String { record.id }
  var timestamp: Date { record.timestamp }
  var target: String { record.targetPath ?? String(localized: "Unavailable") }
  var response: String { record.kernelResponse }
  var process: String { record.processPreview }
  var decision: String {
    record.policyEvaluations?.first?.decision.displayName ?? String(localized: "Unavailable")
  }
}

enum PolicyLogPresentation: Hashable {
  case programs
  case events
}

@Observable
@MainActor
final class PolicyLogState {
  let key: PolicyAuditLogKey
  var batch = AuditLogBatch(records: [])
  var filterText = ""
  var isSearching = false
  var selectedEventIDs: Set<String> = []
  var sortOrder = [KeyPathComparator(\PolicyLogRow.timestamp, order: .reverse)]
  /// Whether someone asked for the inspector. The Log tab shows it once the main window has
  /// dropped its minimum width; see MainWindowLayout.
  var wantsInspector = false
  /// Whether the inspector is shown.
  var showsInspector = false
  /// Whether the Log tab showing this log is on screen.
  var isOnScreen = false
  var presentation = PolicyLogPresentation.programs
  var selectedProgramIDs: Set<String> = []
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
    AuditBatchText.limitations(of: batch)
  }
}
