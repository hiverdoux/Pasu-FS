import PasuFSConfiguration
import SwiftUI

/// The observed chain from the oldest known ancestor to the process that opened the file, as
/// rows of a form section.
struct ExecutionPathView: View {
  let record: AuditEventRecord

  var body: some View {
    if let lineage = record.processLineage {
      ProcessChain(snapshot: lineage)
      DisclosureGroup("All Process Details") {
        ProcessLineageDetails(snapshot: lineage)
      }
    } else {
      Text("This record does not include process history.")
        .foregroundStyle(.secondary)
    }
  }
}

private struct ProcessChain: View {
  let snapshot: ProcessLineageSnapshot

  var body: some View {
    let ancestry = snapshot.actorAncestryKeys
    let chain = snapshot.processes.filter { ancestry.contains($0.key) }
    if let responsible = responsibleOutsideChain(chain) {
      ChainStep(
        name: responsible.displayName,
        role: String(localized: "Responsible process · PID \(String(responsible.key.pid))"),
        isActor: false)
    }
    ForEach(chain) { process in
      ChainStep(
        name: process.displayName,
        role: role(of: process),
        isActor: process.key == snapshot.actor)
    }
  }

  private func responsibleOutsideChain(_ chain: [LineageProcess]) -> LineageProcess? {
    guard let key = snapshot.responsible, !chain.contains(where: { $0.key == key }) else {
      return nil
    }
    return snapshot.processes.first { $0.key == key }
  }

  private func role(of process: LineageProcess) -> String {
    if process.key == snapshot.actor {
      return String(localized: "Opened the file · PID \(String(process.key.pid))")
    }
    if process.key == snapshot.responsible {
      return String(localized: "Responsible process · PID \(String(process.key.pid))")
    }
    return "PID \(process.key.pid)"
  }
}

private struct ChainStep: View {
  let name: String
  let role: String
  let isActor: Bool

  var body: some View {
    Label {
      Text(name)
      Text(role)
        .foregroundStyle(.secondary)
    } icon: {
      Image(systemName: isActor ? "largecircle.fill.circle" : "circle")
        .foregroundStyle(isActor ? .red : .secondary)
    }
    .accessibilityElement(children: .combine)
  }
}

/// Every observed process and relation in a record's history.
struct ProcessLineageDetails: View {
  let snapshot: ProcessLineageSnapshot
  private let processes: [LineageProcessKey: LineageProcess]
  private let incoming: [LineageProcessKey: [LineageRelation]]
  private let ancestry: Set<LineageProcessKey>

  init(snapshot: ProcessLineageSnapshot) {
    self.snapshot = snapshot
    processes = snapshot.processes.reduce(into: [:]) { $0[$1.key] = $1 }
    incoming = Dictionary(grouping: snapshot.relations, by: \.target)
    ancestry = snapshot.actorAncestryKeys
  }

  var body: some View {
    LazyVStack(alignment: .leading) {
      Text(
        "Captured \(snapshot.capturedAt.formatted(date: .abbreviated, time: .standard)) · Collection began \(snapshot.collectionStartedAt.formatted(date: .abbreviated, time: .standard))"
      )
      .foregroundStyle(.secondary)
      if snapshot.actor != nil && snapshot.actor == snapshot.responsible {
        Text("macOS reported the process itself as responsible.")
          .foregroundStyle(.secondary)
      } else if snapshot.responsible == nil {
        Text("macOS did not report a responsible process.")
          .foregroundStyle(.secondary)
      }
      ForEach(snapshot.issues.filter { $0.process == nil }) { issue in
        issueView(issue)
      }
      if let warning = LineageText.lossAccountingWarning(
        version: snapshot.deliveryAccountingVersion, issues: snapshot.issues)
      {
        Text(warning)
          .foregroundStyle(.orange)
      }
      ForEach(snapshot.processes.filter { ancestry.contains($0.key) }) { process in
        processView(process)
      }
      if snapshot.processes.contains(where: { !ancestry.contains($0.key) }) {
        Text("Responsibility outside the process’s ancestors")
          .font(.headline)
        ForEach(snapshot.processes.filter { !ancestry.contains($0.key) }) { process in
          processView(process)
        }
      }
    }
    .font(.caption)
  }

  private func processView(_ process: LineageProcess) -> some View {
    VStack(alignment: .leading) {
      Divider()
      Text(process.displayName)
        .font(.headline)
      if process.key == snapshot.actor {
        Text("Opened the file")
      }
      if process.key == snapshot.responsible {
        Text("Responsible process reported by macOS")
      }
      DetailRows(rows: identityRows(process))
      if process.pathWasTruncated {
        Text("macOS reported a truncated executable path.")
          .foregroundStyle(.orange)
      }
      if let started = process.startTime {
        Text("Process created \(started.formatted(date: .abbreviated, time: .standard))")
      }
      if let observed = process.observedAt {
        Text("Last observed \(observed.formatted(date: .abbreviated, time: .standard))")
      }
      if process.exitedAt == nil, let replaced = process.supersededObservedAt,
        let replacement = process.supersededBy
      {
        Text(
          "A different execution \(replacement.id) was observed at \(replaced.formatted(date: .abbreviated, time: .standard)). The exact end time was not observed."
        )
        .foregroundStyle(.secondary)
      }
      if let ended = process.exitedAt {
        Text("Execution ended \(ended.formatted(date: .abbreviated, time: .standard))")
      }
      ForEach(incoming[process.key] ?? []) { relation in
        Text(
          verbatim:
            "\(LineageText.relation(relation.kind)): \(name(relation.source)) [\(relation.source.id)] · \(relation.observedAt.formatted(date: .omitted, time: .standard))"
        )
        .foregroundStyle(.secondary)
      }
      ForEach(snapshot.issues.filter { $0.process == process.key }) { issue in
        issueView(issue)
      }
    }
    .textSelection(.enabled)
    .frame(maxWidth: .infinity, alignment: .leading)
  }

  private func identityRows(_ process: LineageProcess) -> [DetailRows.Row] {
    let unavailable = String(localized: "Unavailable")
    var rows: [DetailRows.Row] = [
      .init(label: "PID", value: String(process.key.pid), isMonospaced: true),
      .init(
        label: String(localized: "Execution"), value: String(process.key.version),
        isMonospaced: true),
      .init(
        label: String(localized: "Executable"),
        value: process.executablePath ?? String(localized: "Not observed"),
        isMonospaced: process.executablePath != nil),
      .init(
        label: String(localized: "Signing ID"), value: process.signingIdentifier ?? unavailable,
        isMonospaced: process.signingIdentifier != nil),
      .init(
        label: String(localized: "Team ID"), value: process.teamIdentifier ?? unavailable,
        isMonospaced: process.teamIdentifier != nil),
    ]
    if let flags = process.codeSigningFlags {
      rows.append(
        .init(
          label: String(localized: "Code-Signing Flags"), value: OpenFlagsText.hex(flags),
          isMonospaced: true))
    }
    return rows
  }

  private func issueView(_ issue: LineageIssue) -> some View {
    Text(
      issue.count > 1
        ? "\(LineageText.explanation(issue)) (\(issue.count))" : LineageText.explanation(issue)
    )
    .foregroundStyle(.orange)
    .textSelection(.enabled)
  }

  private func name(_ key: LineageProcessKey) -> String {
    processes[key]?.displayName ?? "PID \(key.pid)"
  }
}
