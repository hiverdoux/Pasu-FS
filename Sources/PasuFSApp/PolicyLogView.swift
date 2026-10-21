import AppKit
import PasuFSConfiguration
import SwiftUI

struct PolicyLogView: View {
  @Bindable var model: AppModel
  let policyID: UUID

  var body: some View {
    if let policy = model.activePolicy(id: policyID),
      let log = model.policyLogState(policyID: policyID)
    {
      PolicyLogContent(
        model: model, policy: policy, log: log
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
      bottomBar
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
    .focusedSceneValue(
      \.inspectorCommand,
      InspectorCommandAction(isShown: log.wantsInspector) { log.wantsInspector.toggle() })
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
    HStack(spacing: 12) {
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
      Spacer(minLength: 0)
      PolicyLogNotices(notices: log.notices)
    }
    .padding()
  }

  private var bottomBar: some View {
    VStack(spacing: 0) {
      Divider()
      HStack(spacing: 8) {
        Text(PathText.abbreviated(policy.protectedRootPath))
          .lineLimit(1)
          .truncationMode(.middle)
          .help(policy.protectedRootPath)
        Text("·")
        Text("\(log.batch.records.count) records loaded (up to 500)")
          .fixedSize()
        Spacer(minLength: 0)
      }
      .font(.caption)
      .foregroundStyle(.secondary)
      .padding(.horizontal)
      .padding(.vertical, 8)
      .frame(maxWidth: .infinity, alignment: .leading)
      .background(.bar)
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
          .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
          .contentShape(Rectangle())
          .contextMenu {
            LogCopyButton("Copy Program Name", value: summary.displayName)
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
          .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
          .contentShape(Rectangle())
          .contextMenu {
            LogCopyButton("Copy Signing Identifier", value: signingIdentifier(summary))
          }
        }
        .width(min: 150, ideal: 210)

        TableColumn("This Policy") { summary in
          VStack(alignment: .leading) {
            if let decision = summary.latestDecision {
              LatestDecisionText(summary: summary, decision: decision)
            }
            Text("Denied \(summary.deniedCount) · Allowed \(summary.allowedCount)")
              .font(.caption)
              .foregroundStyle(.secondary)
          }
        }
        .width(min: 110, ideal: 180)

        TableColumn("Last Access") { summary in
          Text(summary.lastSeen, format: .dateTime.month(.defaultDigits).day().hour().minute())
            .font(.caption)
        }
        .width(min: 80, ideal: 100)

        TableColumn("Rule") { summary in
          ProgramRuleAction(model: model, policy: policy, summary: summary)
        }
        .width(min: 150, ideal: 190)
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

        TableColumn("Access Process", value: \.process) { row in
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
          .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
          .contentShape(Rectangle())
          .contextMenu {
            LogCopyButton(
              "Copy Responsible Process Name", value: responsibleProcessName(row.record))
            LogCopyButton("Copy Access Process Name", value: row.record.directProcessName)
            LogCopyButton("Copy Signing Identifier", value: row.record.signingIdentifier)
          }
        }
        .width(min: 120, ideal: 180)

        TableColumn("Target", value: \.target) { row in
          Text(PathText.abbreviated(row.target))
            .font(.caption.monospaced())
            .lineLimit(1)
            .truncationMode(.middle)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
            .contentShape(Rectangle())
            .contextMenu {
              LogCopyButton("Copy Path", value: row.record.targetPath)
            }
        }
        .width(min: 120, ideal: 180)

        TableColumn("This Policy", value: \.decision) { row in
          if let evaluation = row.record.evaluation(for: policy.id) {
            VStack(alignment: .leading) {
              DecisionText(decision: evaluation.decision)
              if evaluation.retiredFolderPath != nil {
                Text("Retired path")
                  .font(.caption)
                  .foregroundStyle(.orange)
              }
              // The recorded reason. It is not worked out again from the current rules. It wraps
              // to a second line when the column is narrow, such as while the inspector is open.
              if let reason = DecisionReasonText.summary(evaluation) {
                Text(reason)
                  .font(.caption)
                  .foregroundStyle(.secondary)
                  .lineLimit(2)
                  .help(reason)
              }
            }
          } else {
            Text("Unavailable")
              .foregroundStyle(.secondary)
          }
        }
        .width(min: 80, ideal: 190)

        TableColumn("Response", value: \.response) { row in
          ResponseText(response: row.response, deadlineMissMode: model.deadlineMissMode)
        }
        .width(min: 60, ideal: 70)

        // How many requests the record stands for, and when the last of them came.
        TableColumn("Requests", value: \.requestCount) { row in
          VStack(alignment: .trailing) {
            Text(row.requestCount, format: .number)
              .monospacedDigit()
            if row.requestCount > 1 {
              Text(
                "Last \(row.record.lastRequestTimestamp.formatted(date: .omitted, time: .standard))"
              )
              .font(.caption2)
              .foregroundStyle(.secondary)
              .monospacedDigit()
            }
          }
          .frame(maxWidth: .infinity, alignment: .trailing)
        }
        .width(min: 60, ideal: 90, max: 130)
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

  private func responsibleProcessName(_ record: AuditEventRecord) -> String? {
    guard let lineage = record.processLineage, let responsible = lineage.responsible else {
      return nil
    }
    return lineage.processes.first { $0.key == responsible }?.displayName
  }

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

private struct LogCopyButton: View {
  let title: LocalizedStringKey
  let value: String?

  init(_ title: LocalizedStringKey, value: String?) {
    self.title = title
    self.value = value
  }

  var body: some View {
    Button(title) {
      guard let value, !value.isEmpty else { return }
      NSPasteboard.general.clearContents()
      NSPasteboard.general.setString(value, forType: .string)
    }
    .disabled(value?.isEmpty ?? true)
  }
}

/// The rule action for one program row: add it to a list, show the lists it is in, or explain
/// why it can't be added.
private struct ProgramRuleAction: View {
  let model: AppModel
  let policy: DirectoryPolicy
  let summary: PolicyProgramSummary

  var body: some View {
    let allow = model.draftRule(policyID: policy.id, list: .allow, summary: summary)
    let deny = model.draftRule(policyID: policy.id, list: .deny, summary: summary)
    if allow != nil, deny != nil {
      Text("In Both Lists")
        .font(.caption)
        .foregroundStyle(.secondary)
    } else if let candidate = summary.ruleCandidate {
      Menu(menuTitle(allow: allow, deny: deny)) {
        if allow == nil {
          Button(PolicyBehaviorText.addToListTitle(.allow)) {
            add(candidate, to: .allow)
          }
          // Programs to Allow stays as it is while the policy doesn't use it.
          .disabled(draft?.isBlacklistEnabled ?? policy.isBlacklistEnabled)
        }
        if deny == nil {
          Button(PolicyBehaviorText.addToListTitle(.deny)) {
            add(candidate, to: .deny)
          }
        }
      }
      .controlSize(.small)
      .fixedSize()
    } else {
      Label("Can’t Add", systemImage: "info.circle")
        .font(.caption)
        .foregroundStyle(.secondary)
        .help("No signing information")
    }
  }

  private var draft: DirectoryPolicyDraft? { model.policyDraft(id: policy.id) }

  private func menuTitle(allow: PolicyRule?, deny: PolicyRule?) -> String {
    guard
      let (rule, list) = allow.map({ ($0, PolicyRuleList.allow) })
        ?? deny.map({ ($0, PolicyRuleList.deny) })
    else { return String(localized: "Add Rule") }
    let title = PolicyBehaviorText.inListTitle(list)
    return rule.isEnabled ? title : String(localized: "\(title) · Off")
  }

  private func add(_ candidate: AuditRuleCandidate, to list: PolicyRuleList) {
    do {
      try model.addRule(policyID: policy.id, to: list, from: candidate)
    } catch {
      model.lastError = UserFacingError.message(error)
    }
  }
}

/// A program's latest decision. One made under an earlier policy revision than the policies in
/// use is shown in the secondary color and marked, so it isn't read as what the current rules
/// decide.
private struct LatestDecisionText: View {
  let summary: PolicyProgramSummary
  let decision: PolicyEvaluationDecision

  var body: some View {
    if summary.latestDecisionPrecedesCurrentRevision,
      let revision = summary.latestDecisionRevision, let current = summary.currentRevision
    {
      // The mark moves below the decision when the column is too narrow for both, such as while
      // the inspector is open.
      ViewThatFits(in: .horizontal) {
        HStack(alignment: .firstTextBaseline, spacing: 4) {
          Text(decision.displayName)
          Text("·")
          Text("Earlier revision")
            .font(.caption)
        }
        VStack(alignment: .leading, spacing: 0) {
          Text(decision.displayName)
          Text("Earlier revision")
            .font(.caption)
        }
      }
      .lineLimit(1)
      .foregroundStyle(.secondary)
      .help(String(localized: "Decided under revision \(revision) · Current revision \(current)"))
    } else {
      DecisionText(decision: decision)
    }
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
          "\(summary.observationCount) requests · Denied \(summary.deniedCount) · Allowed \(summary.allowedCount)"
        )
        Text("Last access \(summary.lastSeen.formatted(date: .abbreviated, time: .standard))")
          .foregroundStyle(.secondary)
        if let revision = summary.latestDecisionRevision {
          LabeledContent("Latest decision revision") {
            Text(revisionText(revision))
              .textSelection(.enabled)
          }
          .accessibilityRowValue(revisionText(revision))
        }
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

  private func revisionText(_ revision: UInt64) -> String {
    guard let current = summary.currentRevision else { return String(revision) }
    if revision < current {
      return String(localized: "\(revision) (current \(current))")
    }
    return revision == current ? String(localized: "\(revision) (current)") : String(revision)
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
    rows.append(.init(label: String(localized: "Access Process"), value: summary.processPreview))
    return rows
  }
}
