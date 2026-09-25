import PasuFSHostCore
import SwiftUI

private enum OnboardingStepID: CaseIterable {
  case activate
  case approve
  case fullDiskAccess
  case policy
}

struct OnboardingView: View {
  @Bindable var model: AppModel
  @FocusState private var isPrimaryActionFocused: Bool

  var body: some View {
    let states = model.setupStepStates
    let steps = OnboardingStepID.allCases
    let current = steps.first { state(of: $0, in: states) == .active } ?? .activate
    let doneCount = steps.filter { state(of: $0, in: states) == .done }.count
    Form {
      Section {
        ForEach(Array(steps.enumerated()), id: \.offset) { index, step in
          StepRow(
            number: index + 1,
            title: title(of: step),
            status: statusText(step, state: state(of: step, in: states)),
            state: state(of: step, in: states))
        }
      }
      Section {
        detail(current)
      } header: {
        Text(title(of: current))
      }
      Section {
        WarningLabel(text: String(localized: "Nothing is protected until setup is finished."))
        if let error = model.lastError {
          Label(error, systemImage: "xmark.octagon")
            .foregroundStyle(.red)
        }
        if let message = model.operationMessage {
          Label(message, systemImage: "info.circle")
        }
      }
      Section {
        Button("Uninstall Pasu FS…", role: .destructive) {
          model.isPresentingUninstall = true
        }
        .disabled(model.isBusy || model.isUninstalling)
      }
    }
    .formStyle(.grouped)
    .defaultFocus($isPrimaryActionFocused, true)
    .navigationTitle(String(localized: "Set Up Pasu FS"))
    .navigationSubtitle(String(localized: "Step \(min(doneCount + 1, 4)) of 4"))
  }

  @ViewBuilder
  private func detail(_ step: OnboardingStepID) -> some View {
    switch step {
    case .activate:
      HStack {
        Button("Activate Extension") {
          Task { await model.activate() }
        }
        .buttonStyle(.borderedProminent)
        .disabled(model.isBusy)
        .focused($isPrimaryActionFocused)
        Spacer()
      }
    case .approve:
      LabeledContent("Location", value: approvalPath.joined(separator: " › "))
      HStack {
        Button("Open System Settings…") {
          model.openExtensionApprovalSettings()
        }
        .buttonStyle(.borderedProminent)
        .focused($isPrimaryActionFocused)
        Spacer()
        WaitingLabel(text: String(localized: "Waiting for your approval"))
      }
    case .fullDiskAccess:
      Text("Turn on “Pasu FS Endpoint Security”.")
      LabeledContent(
        "Location",
        value: [
          String(localized: "System Settings"),
          String(localized: "Privacy & Security"),
          String(localized: "Full Disk Access"),
        ].joined(separator: " › "))
      HStack {
        Button("Open System Settings…") {
          model.openFullDiskAccessSettings()
        }
        .buttonStyle(.borderedProminent)
        .focused($isPrimaryActionFocused)
        Spacer()
        WaitingLabel(text: String(localized: "Waiting for access"))
      }
    case .policy:
      HStack {
        Button("Create Policy") {
          model.createNewPolicy()
        }
        .buttonStyle(.borderedProminent)
        .focused($isPrimaryActionFocused)
        Spacer()
      }
    }
  }

  private var approvalPath: [String] {
    if ProcessInfo.processInfo.operatingSystemVersion.majorVersion >= 15 {
      return [
        String(localized: "System Settings"),
        String(localized: "General"),
        String(localized: "Login Items & Extensions"),
        String(localized: "Endpoint Security Extensions"),
      ]
    }
    return [String(localized: "System Settings"), String(localized: "Privacy & Security")]
  }

  private func state(of step: OnboardingStepID, in states: SetupStepStates) -> SetupStepState {
    switch step {
    case .activate: states.activateExtension
    case .approve: states.approveExtension
    case .fullDiskAccess: states.grantFullDiskAccess
    case .policy: states.configurePolicy
    }
  }

  private func title(of step: OnboardingStepID) -> String {
    switch step {
    case .activate: String(localized: "Activate the system extension")
    case .approve: String(localized: "Approve in System Settings")
    case .fullDiskAccess: String(localized: "Allow Full Disk Access")
    case .policy: String(localized: "Create your first policy")
    }
  }

  private func statusText(_ step: OnboardingStepID, state: SetupStepState) -> String {
    switch state {
    case .done:
      return String(localized: "Done")
    case .pending:
      return String(localized: "Waiting")
    case .active:
      switch step {
      case .approve: return String(localized: "Waiting for your approval")
      case .fullDiskAccess: return String(localized: "Waiting for access")
      case .activate, .policy: return String(localized: "Current step")
      }
    }
  }
}

private struct StepRow: View {
  let number: Int
  let title: String
  let status: String
  let state: SetupStepState

  var body: some View {
    Label {
      Text(title)
        .foregroundStyle(state == .pending ? .secondary : .primary)
      Text(status)
    } icon: {
      indicator
    }
    .accessibilityElement(children: .combine)
  }

  @ViewBuilder
  private var indicator: some View {
    switch state {
    case .done:
      Image(systemName: "checkmark.circle.fill")
        .foregroundStyle(.green)
    case .active:
      Image(systemName: "\(number).circle.fill")
        .foregroundStyle(.tint)
    case .pending:
      Image(systemName: "\(number).circle")
        .foregroundStyle(.secondary)
    }
  }
}

private struct WaitingLabel: View {
  let text: String

  var body: some View {
    HStack {
      ProgressView()
        .controlSize(.small)
      Text(text)
        .foregroundStyle(.secondary)
    }
  }
}
