import PasuFSConfiguration
import SwiftUI

struct PolicyLogView: View {
  @Bindable var model: AppModel
  let policyID: UUID

  var body: some View {
    if let policy = model.activePolicy(id: policyID),
      let log = model.policyLogState(policyID: policyID)
    {
      PolicyLogContent(model: model, policy: policy, log: log)
        .id(log.key)
    } else {
      ContentUnavailableView(
        "Save this policy to start its log",
        systemImage: "list.bullet.rectangle",
        description: Text("Policy logs start after the policy is saved and monitoring is active.")
      )
    }
  }
}

private struct PolicyLogContent: View {
  @Bindable var model: AppModel
  let policy: DirectoryPolicy
  @Bindable var log: PolicyLogState

  var body: some View {
    VStack(spacing: 0) {
      controls
      if let error = log.error {
        WarningBanner(
          text: "Log could not be refreshed: \(error)"
            + (log.hasLoaded ? " Showing previously loaded records." : "")
        ).padding(.horizontal, 12).padding(.bottom, 8)
      }
      if let warning = log.warning {
        WarningBanner(text: warning).padding(.horizontal, 12).padding(.bottom, 8)
      }
      if !log.hasLoaded, log.error != nil {
        ContentUnavailableView(
          "Log unavailable", systemImage: "exclamationmark.triangle",
          description: Text("See the message above, then refresh to try again.")
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
      } else if !log.hasLoaded {
        ProgressView("Loading policy log…").frame(maxWidth: .infinity, maxHeight: .infinity)
      } else if log.rows.isEmpty {
        ContentUnavailableView(
          log.filterText.isEmpty ? "No recorded access yet" : "No matching records",
          systemImage: "list.bullet.rectangle",
          description: Text(
            log.filterText.isEmpty
              ? "This log records file and folder opens from when policy logging became available. Earlier records are available in Audit Log while retained."
              : "Search applies only to the loaded records for this policy.")
        )
        .frame(maxWidth: .infinity, maxHeight: .infinity)
      } else {
        eventTable
      }
      Divider()
      VStack(alignment: .leading, spacing: 3) {
        Text("\(log.rows.count) of \(log.batch.records.count) records · Up to 500 loaded")
        Text("Metadata only · 10 MiB per file + one previous file · Older records expire")
        Text(
          "Would allow / Would deny are Audit predictions. Response is Pasu FS’s answer to macOS; other macOS checks can still deny access."
        )
      }
      .font(.caption)
      .foregroundStyle(.secondary)
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(10)
      .background(.bar)
    }
    .inspector(isPresented: $log.showsInspector) {
      if let row = log.rows.first(where: { log.selectedEventIDs.contains($0.id) }) {
        AuditEventDetails(record: row.record)
      } else {
        ContentUnavailableView("Select a record", systemImage: "sidebar.trailing")
      }
    }
    .task(id: log.key) { await model.refreshPolicyAuditLog(policyID: policy.id) }
  }

  private var controls: some View {
    VStack(alignment: .leading, spacing: 8) {
      Text("Saved folder: \(policy.protectedRootPath)")
        .font(.caption.monospaced()).textSelection(.enabled)
      Text("History stays with this policy, including any previously configured folders.")
        .font(.caption).foregroundStyle(.secondary)
      HStack {
        TextField("Filter this policy’s loaded records", text: $log.filterText)
          .textFieldStyle(.roundedBorder)
          .accessibilityLabel("Filter policy log")
        if log.isLoading { ProgressView().controlSize(.small) }
        Button {
          Task { await model.refreshPolicyAuditLog(policyID: policy.id) }
        } label: {
          Label("Refresh", systemImage: "arrow.clockwise")
        }.disabled(log.isLoading)
        Button {
          log.showsInspector.toggle()
        } label: {
          Label("Details", systemImage: "sidebar.trailing")
        }
      }
    }.padding(12)
  }

  private var eventTable: some View {
    Table(log.rows, selection: $log.selectedEventIDs, sortOrder: $log.sortOrder) {
      TableColumn("Time", value: \.timestamp) { row in
        VStack(alignment: .leading, spacing: 2) {
          Text(row.timestamp.formatted(.dateTime.year().month(.twoDigits).day(.twoDigits)))
            .font(.caption2.monospaced()).foregroundStyle(.secondary)
          Text(row.timestamp.formatted(date: .omitted, time: .standard))
            .font(.caption.monospaced())
        }.lineLimit(1)
      }.width(min: 75, ideal: 82, max: 95)
      TableColumn("Program", value: \.process) { row in
        VStack(alignment: .leading) {
          ProcessPreviewLabel(record: row.record)
          if let signing = row.record.signingIdentifier {
            Text(signing).font(.caption2.monospaced()).foregroundStyle(.secondary)
              .lineLimit(1).truncationMode(.middle)
          }
        }
      }.width(min: 100, ideal: 120, max: 180)
      TableColumn("Target", value: \.target) { row in
        Text(row.target).font(.caption.monospaced()).lineLimit(1).truncationMode(.middle)
      }.width(min: 90, ideal: 110)
      TableColumn("This policy", value: \.decision)
        .width(min: 80, ideal: 85, max: 100)
      TableColumn("Response", value: \.response) { row in
        ResponseIndicator(response: row.response)
      }.width(min: 60, ideal: 62, max: 75)
    }.alternatingRowBackgrounds()
  }
}
