import PasuFSConfiguration
import SwiftUI

/// Keep the role separator visible even when either long name is shortened.
struct ProcessPreviewLabel: View {
  let record: AuditEventRecord

  var body: some View {
    HStack(spacing: 4) {
      Text(record.responsibleProcessName).lineLimit(1).truncationMode(.middle)
      Text(">").fixedSize()
      Text(record.directProcessName).lineLimit(1).truncationMode(.middle)
    }
    .help(record.processPreview)
    .accessibilityElement(children: .ignore)
    .accessibilityLabel(record.processPreview)
  }
}

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
    LazyVStack(alignment: .leading, spacing: 12) {
      Text("Full process history").font(.headline)
      Text("Observed at \(snapshot.capturedAt.formatted(date: .abbreviated, time: .standard))")
        .font(.caption).foregroundStyle(.secondary)
      Text(
        "Collection began \(snapshot.collectionStartedAt.formatted(date: .abbreviated, time: .standard)). Earlier or undelivered transitions are not reconstructed."
      )
      .font(.caption).foregroundStyle(.secondary)
      Text(
        "The preview shows macOS responsibility > direct actor; it does not assert a direct parent or a request sender."
      )
      .font(.caption).foregroundStyle(.secondary)
      if snapshot.actor != nil && snapshot.actor == snapshot.responsible {
        Text(
          "macOS reported the actor itself as responsible. This may also happen when no responsible process exists or it has already exited."
        )
        .font(.caption).foregroundStyle(.secondary)
      } else if snapshot.responsible == nil {
        Text("macOS responsibility identity was unavailable.").font(.caption)
      }
      ForEach(snapshot.issues.filter { $0.process == nil }) { issue in
        issueView(issue)
      }
      if let warning = LineageIssue.lossAccountingWarning(
        version: snapshot.deliveryAccountingVersion, issues: snapshot.issues)
      {
        Text(warning).font(.caption).foregroundStyle(.orange)
      }
      ForEach(snapshot.processes.filter { ancestry.contains($0.key) }) { process in
        processView(process)
      }
      if snapshot.processes.contains(where: { !ancestry.contains($0.key) }) {
        Divider()
        Text("Responsibility outside the actor’s ancestry").font(.headline)
        Text("These are responsibility relationships, not additional parent links.")
          .font(.caption).foregroundStyle(.secondary)
        ForEach(snapshot.processes.filter { !ancestry.contains($0.key) }) { process in
          processView(process)
        }
      }
    }
  }

  private func processView(_ process: LineageProcess) -> some View {
    VStack(alignment: .leading, spacing: 5) {
      Text(process.displayName).font(.callout.weight(.semibold))
      if process.key == snapshot.actor { Text("Direct actor").font(.caption.weight(.semibold)) }
      if process.key == snapshot.responsible {
        Text("macOS responsible").font(.caption.weight(.semibold))
      }
      Text("PID \(process.key.pid) · execution version \(process.key.version)")
        .font(.caption.monospaced())
      Text(process.executablePath ?? "Executable path was not observed")
        .font(.caption.monospaced())
      if process.pathWasTruncated {
        Text("macOS reported a truncated executable path.").font(.caption).foregroundStyle(.orange)
      }
      Text("Signing ID: \(process.signingIdentifier ?? "Unavailable")")
        .font(.caption.monospaced())
      Text("Team ID: \(process.teamIdentifier ?? "Unavailable")")
        .font(.caption.monospaced())
      if let flags = process.codeSigningFlags {
        Text("Code-signing flags: \(String(format: "0x%08X", flags))").font(.caption.monospaced())
      }
      if let started = process.startTime {
        Text("Process created: \(started.formatted(date: .abbreviated, time: .standard))").font(
          .caption)
      }
      if let observed = process.observedAt {
        Text("Last observed: \(observed.formatted(date: .abbreviated, time: .standard))").font(
          .caption)
      }
      if let ended = process.exitedAt {
        Text("Execution ended: \(ended.formatted(date: .abbreviated, time: .standard))").font(
          .caption)
      }
      ForEach(incoming[process.key] ?? []) { relation in
        Text(
          "\(relation.kind.displayName): \(name(relation.source)) [\(relation.source.id)] · \(relation.observedAt.formatted(date: .omitted, time: .standard))"
        )
        .font(.caption).foregroundStyle(.secondary)
      }
      ForEach(snapshot.issues.filter { $0.process == process.key }) { issue in
        issueView(issue)
      }
    }
    .textSelection(.enabled)
    .frame(maxWidth: .infinity, alignment: .leading)
    .padding(10)
    .background(.quaternary.opacity(0.4), in: RoundedRectangle(cornerRadius: 7))
  }

  private func issueView(_ issue: LineageIssue) -> some View {
    Text("\(issue.explanation)\(issue.count > 1 ? " (\(issue.count))" : "")")
      .font(.caption).foregroundStyle(.orange).textSelection(.enabled)
  }

  private func name(_ key: LineageProcessKey) -> String {
    processes[key]?.displayName ?? "PID \(key.pid)"
  }
}
