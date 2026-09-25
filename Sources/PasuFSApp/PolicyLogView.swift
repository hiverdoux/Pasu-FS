import PasuFSConfiguration
import SwiftUI

struct PolicyLogView: View {
  @Bindable var model: AppModel
  let policyID: UUID
  let onSwitchToProtection: () -> Void

  var body: some View {
    if let policy = model.activePolicy(id: policyID),
      let log = model.policyLogState(policyID: policyID)
    {
      PolicyLogContent(
        model: model, policy: policy, log: log, onSwitchToProtection: onSwitchToProtection
      )
      .id(log.key)
    } else {
      ContentUnavailableView(
        "Save This Policy to Start Its Log", systemImage: "list.bullet.rectangle"
      )
      .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
  }
}

private struct PolicyLogContent: View {
  @Bindable var model: AppModel
  let policy: DirectoryPolicy
  @Bindable var log: PolicyLogState
  let onSwitchToProtection: () -> Void
  @State private var window = WindowReference()

  var body: some View {
    // The segmented picker in the header reports its current width as its minimum. Kept in a
    // safe area bar, or without the zero minimum below, that minimum holds the column at its old
    // width while the inspector opens, so the detail column grows past the window and pushes the
    // sidebar out until the animation ends.
    VStack(spacing: 0) {
      header
      logBody
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .hardScrollEdges()
    }
    .frame(minWidth: 0)
    .toolbarSearch(
      text: $log.filterText, isSearching: $log.isSearching, prompt: "Search this policy’s records"
    )
    .toolbarGroups {
      ToolbarItem {
        Button {
          refresh()
        } label: {
          Label("Refresh", systemImage: "arrow.clockwise")
        }
        .disabled(log.isLoading)
        .help("Load the newest records again")
      }
    } _: {
      ToolbarItem {
        Button {
          log.wantsInspector.toggle()
        } label: {
          Label("Details", systemImage: "sidebar.trailing")
        }
        .help(log.wantsInspector ? "Hide details" : "Show details")
      }
    }
    .inspector(
      isPresented: Binding(get: { log.showsInspector }, set: { log.wantsInspector = $0 })
    ) {
      inspector
        .inspectorColumnWidth(min: 260, ideal: 320, max: 420)
    }
    .background(WindowReader(reference: window))
    .onAppear {
      log.isOnScreen = true
      updateInspector()
    }
    .onDisappear {
      log.isOnScreen = false
      log.showsInspector = false
    }
    .onChange(of: log.wantsInspector) { updateInspector() }
    .task(id: log.key) { await model.refreshPolicyAuditLog(policyID: policy.id) }
    .focusedSceneValue(\.refreshCommand, RefreshCommandAction(perform: refresh))
  }

  /// Shows the inspector only after the main window has dropped its minimum width, and hides it
  /// right away. See MainWindowLayout.
  private func updateInspector() {
    guard log.wantsInspector else {
      log.showsInspector = false
      return
    }
    guard !log.showsInspector else { return }
    Task {
      await MainWindowLayout.minimumWidthReleased(in: window.window)
      if log.wantsInspector, log.isOnScreen {
        log.showsInspector = true
      }
    }
  }

  private func refresh() {
    Task { await model.refreshPolicyAuditLog(policyID: policy.id) }
  }

  // MARK: - Header

  private var header: some View {
    VStack(alignment: .leading) {
      if policy.mode == .audit {
        AuditModeCallout(onSwitch: onSwitchToProtection)
      }
      HStack {
        Picker("Show", selection: $log.presentation) {
          Text("By Program").tag(PolicyLogPresentation.programs)
          Text("All Events").tag(PolicyLogPresentation.events)
        }
        .pickerStyle(.segmented)
        .labelsHidden()
        .fixedSize()
        if log.isLoading {
          ProgressView()
            .controlSize(.small)
        }
        Spacer()
        Text(
          "\(PathText.abbreviated(policy.protectedRootPath)) · \(log.batch.records.count) records loaded (up to 500)"
        )
        .font(.caption)
        .foregroundStyle(.secondary)
        .lineLimit(1)
        .truncationMode(.middle)
      }
      notices
    }
    .padding()
  }

  @ViewBuilder
  private var notices: some View {
    if let error = log.error {
      WarningLabel(
        text: log.hasLoaded
          ? String(
            localized:
              "The log could not be refreshed: \(error) Showing the records loaded earlier.")
          : String(localized: "The log could not be loaded: \(error)")
      )
    }
    if let warning = log.warning {
      WarningLabel(text: warning)
    }
  }

  // MARK: - Body

  @ViewBuilder
  private var logBody: some View {
    if !log.hasLoaded, log.error != nil {
      ContentUnavailableView("Log Unavailable", systemImage: "exclamationmark.triangle")
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    } else if !log.hasLoaded {
      ProgressView("Loading the policy log…")
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    } else {
      switch log.presentation {
      case .programs:
        programTable
      case .events:
        eventTable
      }
    }
  }

  private var programs: [PolicyProgramSummary] {
    let summaries = model.policyProgramSummaries(policyID: policy.id)
    let needle = log.filterText.trimmingCharacters(in: .whitespacesAndNewlines)
    guard !needle.isEmpty else { return summaries }
    return summaries.filter { summary in
      [summary.displayName, summary.processPreview, summary.id, summary.executablePath ?? ""]
        .contains { $0.localizedCaseInsensitiveContains(needle) }
    }
  }

  @ViewBuilder
  private var programTable: some View {
    let rows = programs
    if rows.isEmpty {
      emptyState
    } else {
      Table(rows, selection: $log.selectedProgramIDs) {
        TableColumn("Program") { summary in
          HStack {
            ProgramIcon(
              signingIdentifier: signingIdentifier(summary), executablePath: summary.executablePath,
              size: 32)
            VStack(alignment: .leading) {
              Text(summary.displayName)
                .lineLimit(1)
              if summary.processPreview != summary.displayName {
                Text(summary.processPreview)
                  .font(.caption)
                  .foregroundStyle(.secondary)
                  .lineLimit(1)
                  .truncationMode(.middle)
              }
            }
          }
        }
        .width(min: 160, ideal: 220)

        TableColumn("Code Signature") { summary in
          VStack(alignment: .leading) {
            Text(signatureHeadline(summary))
              .font(.caption)
              .foregroundStyle(.secondary)
            Text(signatureDetail(summary))
              .font(.caption.monospaced())
              .lineLimit(1)
              .truncationMode(.middle)
          }
        }
        .width(min: 150, ideal: 210)

        TableColumn("This Policy") { summary in
          VStack(alignment: .leading) {
            if let decision = summary.latestDecision {
              DecisionText(decision: decision)
            }
            Text("Denied \(summary.deniedCount) · Allowed \(summary.allowedCount)")
              .font(.caption)
              .foregroundStyle(.secondary)
          }
        }
        .width(min: 110, ideal: 140)

        TableColumn("Last Access") { summary in
          Text(summary.lastSeen, format: .dateTime.month(.defaultDigits).day().hour().minute())
            .font(.caption)
        }
        .width(min: 80, ideal: 100)

        TableColumn("Rule") { summary in
          ProgramRuleAction(model: model, policy: policy, summary: summary)
        }
        .width(min: 120, ideal: 150)
      }
      .alternatingRowBackgrounds()
    }
  }

  @ViewBuilder
  private var eventTable: some View {
    if log.rows.isEmpty {
      emptyState
    } else {
      Table(log.rows, selection: $log.selectedEventIDs, sortOrder: $log.sortOrder) {
        TableColumn("Time", value: \.timestamp) { row in
          VStack(alignment: .leading) {
            Text(row.timestamp, format: .dateTime.month(.defaultDigits).day())
              .font(.caption2)
              .foregroundStyle(.secondary)
            Text(row.timestamp, format: .dateTime.hour().minute().second())
              .font(.caption)
              .monospacedDigit()
          }
        }
        .width(min: 90, ideal: 100, max: 120)

        TableColumn("Program", value: \.process) { row in
          VStack(alignment: .leading) {
            Text(ProcessText.preview(row.record))
              .lineLimit(1)
              .truncationMode(.middle)
            if let signing = row.record.signingIdentifier {
              Text(signing)
                .font(.caption2.monospaced())
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .truncationMode(.middle)
            }
          }
        }
        .width(min: 120, ideal: 180)

        TableColumn("Target", value: \.target) { row in
          Text(PathText.abbreviated(row.target))
            .font(.caption.monospaced())
            .lineLimit(1)
            .truncationMode(.middle)
        }
        .width(min: 120, ideal: 220)

        TableColumn("This Policy", value: \.decision) { row in
          if let decision = row.record.policyEvaluations?.first(where: {
            $0.policyIdentifier == policy.id
          })?.decision ?? row.record.policyEvaluations?.first?.decision {
            DecisionText(decision: decision)
          } else {
            Text("Unavailable")
              .foregroundStyle(.secondary)
          }
        }
        .width(min: 80, ideal: 100)

        TableColumn("Response", value: \.response) { row in
          ResponseText(response: row.response)
        }
        .width(min: 60, ideal: 70)
      }
      .alternatingRowBackgrounds()
    }
  }

  @ViewBuilder
  private var emptyState: some View {
    let query = log.filterText.trimmingCharacters(in: .whitespacesAndNewlines)
    if query.isEmpty {
      ContentUnavailableView("No Recorded Access Yet", systemImage: "list.bullet.rectangle")
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    } else {
      ContentUnavailableView.search(text: query)
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
  }

  // MARK: - Inspector

  @ViewBuilder
  private var inspector: some View {
    switch log.presentation {
    case .events:
      if let row = log.rows.first(where: { log.selectedEventIDs.contains($0.id) }) {
        AuditEventDetails(model: model, record: row.record)
      } else {
        ContentUnavailableView("Select a Record", systemImage: "sidebar.trailing")
      }
    case .programs:
      if let summary = programs.first(where: { log.selectedProgramIDs.contains($0.id) }) {
        ProgramDetails(summary: summary)
      } else {
        ContentUnavailableView("Select a Program", systemImage: "sidebar.trailing")
      }
    }
  }

  // MARK: - Text

  private func signingIdentifier(_ summary: PolicyProgramSummary) -> String? {
    switch summary.identity {
    case .teamSigned(_, let signing), .platformBinary(let signing): signing
    case .unsigned: nil
    }
  }

  private func signatureHeadline(_ summary: PolicyProgramSummary) -> String {
    switch summary.identity {
    case .teamSigned(let team, _):
      "\(summary.kindDescription) · \(team)"
    case .platformBinary, .unsigned:
      summary.kindDescription
    }
  }

  private func signatureDetail(_ summary: PolicyProgramSummary) -> String {
    switch summary.identity {
    case .teamSigned(_, let signing), .platformBinary(let signing): signing
    case .unsigned(let path): path.map(PathText.abbreviated) ?? "—"
    }
  }
}

/// Tells the user an Audit policy blocks nothing and offers the next step.
private struct AuditModeCallout: View {
  let onSwitch: () -> Void

  var body: some View {
    HStack {
      Label {
        Text("This Audit policy blocks nothing.")
      } icon: {
        Image(systemName: "eye")
          .foregroundStyle(.blue)
      }
      Spacer()
      Button("Switch to Protection…", action: onSwitch)
    }
  }

}

/// The rule action for one program row: add it, show that it is listed, or explain why not.
private struct ProgramRuleAction: View {
  let model: AppModel
  let policy: DirectoryPolicy
  let summary: PolicyProgramSummary

  var body: some View {
    if let rule = model.draftContainsRule(policyID: policy.id, summary: summary) {
      Text(
        rule.isEnabled
          ? PolicyBehaviorText.inListTitle(listType)
          : String(localized: "\(PolicyBehaviorText.inListTitle(listType)) · Off")
      )
      .font(.caption)
      .foregroundStyle(.secondary)
    } else if let candidate = summary.ruleCandidate {
      Button(PolicyBehaviorText.addToListTitle(listType)) {
        do {
          try model.addRule(policyID: policy.id, from: candidate)
        } catch {
          model.lastError = UserFacingError.message(error)
        }
      }
      .buttonStyle(.bordered)
      .controlSize(.small)
    } else {
      Label("Can’t Add", systemImage: "info.circle")
        .font(.caption)
        .foregroundStyle(.secondary)
        .help("No signing information")
    }
  }

  private var listType: PolicyType {
    model.policyDraft(id: policy.id)?.policyType ?? policy.policyType
  }
}

/// Details for one program in a policy log.
private struct ProgramDetails: View {
  let summary: PolicyProgramSummary

  var body: some View {
    Form {
      Section {
        Label {
          Text(summary.displayName)
          Text(summary.kindDescription)
        } icon: {
          ProgramIcon(signingIdentifier: signing, executablePath: summary.executablePath, size: 32)
        }
        DetailRows(rows: identityRows)
      }
      Section {
        Text(
          "\(summary.observationCount) opens · Denied \(summary.deniedCount) · Allowed \(summary.allowedCount)"
        )
        Text("Last access \(summary.lastSeen.formatted(date: .abbreviated, time: .standard))")
          .foregroundStyle(.secondary)
      } header: {
        Text("Observed in This Policy")
      }
      if !summary.targetSamples.isEmpty {
        Section("Recent Targets") {
          ForEach(summary.targetSamples, id: \.self) { target in
            Text(PathText.abbreviated(target))
              .monospaced()
              .textSelection(.enabled)
          }
        }
      }
    }
    .formStyle(.grouped)
  }

  private var signing: String? {
    switch summary.identity {
    case .teamSigned(_, let value), .platformBinary(let value): value
    case .unsigned: nil
    }
  }

  private var identityRows: [DetailRows.Row] {
    var rows: [DetailRows.Row] = []
    switch summary.identity {
    case .teamSigned(let team, let signing):
      rows.append(.init(label: String(localized: "Team ID"), value: team, isMonospaced: true))
      rows.append(.init(label: String(localized: "Signing ID"), value: signing, isMonospaced: true))
    case .platformBinary(let signing):
      rows.append(.init(label: String(localized: "Signing ID"), value: signing, isMonospaced: true))
    case .unsigned:
      break
    }
    if let path = summary.executablePath {
      rows.append(.init(label: String(localized: "Executable"), value: path, isMonospaced: true))
    }
    rows.append(.init(label: String(localized: "Process"), value: summary.processPreview))
    return rows
  }
}
