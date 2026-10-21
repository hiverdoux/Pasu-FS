import Foundation
import Observation
import PasuFSConfiguration

struct PolicyLogRow: Identifiable {
  let record: AuditEventRecord
  var id: String { record.id }
  var timestamp: Date { record.timestamp }
  var requestCount: UInt64 { record.representedRequestCount }
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
      let evaluation = row.record.evaluation(for: key.policyIdentifier)
      let origin = evaluation?.executionOrigin
      return
        ([
          row.process, row.target, row.decision, row.response,
          row.record.signingIdentifier ?? "", row.record.teamIdentifier ?? "",
          evaluation?.policyName ?? "", evaluation?.ruleIdentifier ?? "",
          evaluation?.match.rawValue ?? "",
          evaluation.flatMap(DecisionReasonText.summary) ?? "",
          origin?.origin?.executablePath ?? "", origin?.origin?.signingIdentifier ?? "",
          origin?.deniedProgram?.executablePath ?? "",
          origin?.deniedProgram?.signingIdentifier ?? "",
        ] + row.record.lineageSearchValues).contains { $0.localizedCaseInsensitiveContains(needle) }
    }.sorted(using: sortOrder)
  }

  var notices: [PolicyLogNotice] {
    var result: [PolicyLogNotice] = []
    if let error, !error.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      result.append(
        PolicyLogNotice(
          id: "load", severity: .error,
          message: hasLoaded
            ? String(
              localized:
                "The log could not be refreshed: \(error) Showing the records loaded earlier.")
            : String(localized: "The log could not be loaded: \(error)")))
    }
    if let warning = batch.warning,
      !warning.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    {
      result.append(
        PolicyLogNotice(
          id: "runtime", severity: .warning, message: RuntimeText.localized(warning)))
    }
    if batch.droppedEventCount > 0 {
      result.append(
        PolicyLogNotice(
          id: "dropped", severity: .warning,
          message: String(
            localized: "\(batch.droppedEventCount) records couldn’t be saved during this run.")))
    }
    if batch.skippedLineCount > 0 {
      result.append(
        PolicyLogNotice(
          id: "unreadable", severity: .warning,
          message: String(localized: "\(batch.skippedLineCount) unreadable lines were skipped.")))
    }
    return result
  }
}

struct PolicyLogNotice: Identifiable, Equatable {
  enum Severity { case error, warning }
  let id: String
  let severity: Severity
  let message: String
}
