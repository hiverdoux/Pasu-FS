import PasuFSHostCore
import SwiftUI

private struct OnboardingStep: Identifiable {
  let id: String
  let title: String
  let detail: String
  let state: SetupStepState
  let actionTitle: String?
  let action: (() -> Void)?
  let waitsForUser: Bool
}

struct OnboardingView: View {
  @Bindable var model: AppModel

  private var steps: [OnboardingStep] {
    let states = model.setupStepStates
    return [
      OnboardingStep(
        id: "activate",
        title: "Activate the system extension",
        detail: states.activateExtension == .done
          ? "The activation request was submitted to macOS."
          : "Submit the Endpoint Security extension to macOS.",
        state: states.activateExtension,
        actionTitle: states.activateExtension == .active ? "Activate Extension" : nil,
        action: { Task { await model.activate() } },
        waitsForUser: false
      ),
      OnboardingStep(
        id: "approve",
        title: "Approve the extension in System Settings",
        detail:
          "macOS requires you to approve the Endpoint Security extension yourself. "
          + "Pasu FS cannot approve it for you, and macOS may ask for a restart.",
        state: states.approveExtension,
        actionTitle: states.approveExtension == .active ? "Open System Settings…" : nil,
        action: { model.openExtensionApprovalSettings() },
        waitsForUser: true
      ),
      OnboardingStep(
        id: "fullDiskAccess",
        title: "Grant Full Disk Access",
        detail: "The extension needs Full Disk Access before it can start.",
        state: states.grantFullDiskAccess,
        actionTitle: states.grantFullDiskAccess == .active ? "Open System Settings…" : nil,
        action: { model.openFullDiskAccessSettings() },
        waitsForUser: true
      ),
      OnboardingStep(
        id: "policy",
        title: "Create the first policy",
        detail: "Choose one folder, Protection or Audit mode, and a Whitelist or Blacklist.",
        state: states.configurePolicy,
        actionTitle: states.configurePolicy == .active ? "Set Up Policy…" : nil,
        action: { model.beginFirstPolicySetup() },
        waitsForUser: false
      ),
    ]
  }

  var body: some View {
    VStack(spacing: 14) {
      VStack(spacing: 8) {
        Image(systemName: "lock.shield")
          .font(.system(size: 30, weight: .medium))
          .foregroundStyle(.blue)
          .frame(width: 62, height: 62)
          .background(.blue.opacity(0.12), in: Circle())
        Text("Set up Pasu FS")
          .font(.title2.weight(.semibold))
        Text("Four steps — macOS requires you to approve two of them yourself.")
          .font(.callout)
          .foregroundStyle(.secondary)
      }
      .padding(.top, 30)

      VStack(spacing: 0) {
        ForEach(Array(steps.enumerated()), id: \.element.id) { index, step in
          if index > 0 {
            CardDivider()
          }
          OnboardingStepRow(step: step, number: index + 1, isBusy: model.isBusy)
        }
      }
      .cardStyle()
      .frame(maxWidth: 560)

      WarningBanner(
        text:
          "Until setup finishes, nothing is protected. Coverage after setup: supported \(model.coveredEventsDescription) requests only."
      )
      .frame(maxWidth: 560)

      if let error = model.lastError {
        Text(error)
          .font(.callout)
          .foregroundStyle(.red)
          .frame(maxWidth: 560, alignment: .leading)
      }
      if let message = model.operationMessage {
        Text(message)
          .font(.callout)
          .foregroundStyle(.secondary)
          .frame(maxWidth: 560, alignment: .leading)
      }

      Spacer(minLength: 0)

      Text("This checklist advances automatically — status is checked every 2 seconds.")
        .font(.caption)
        .foregroundStyle(.tertiary)
        .padding(.bottom, 16)
    }
    .frame(maxWidth: .infinity, maxHeight: .infinity)
    .padding()
  }
}

private struct OnboardingStepRow: View {
  let step: OnboardingStep
  let number: Int
  let isBusy: Bool

  var body: some View {
    HStack(alignment: .top, spacing: 14) {
      stateIndicator
      VStack(alignment: .leading, spacing: 4) {
        Text(step.title)
          .font(.body.weight(step.state == .active ? .semibold : .medium))
          .foregroundStyle(step.state == .pending ? .secondary : .primary)
          .strikethrough(step.state == .done, color: .secondary)
        Text(step.detail)
          .font(.callout)
          .foregroundStyle(step.state == .pending ? .tertiary : .secondary)
        if let actionTitle = step.actionTitle, let action = step.action {
          Button(actionTitle, action: action)
            .buttonStyle(.borderedProminent)
            .controlSize(.small)
            .disabled(isBusy)
            .padding(.top, 3)
        }
      }
      Spacer(minLength: 0)
      if step.state == .active, step.waitsForUser {
        HStack(spacing: 5) {
          Circle()
            .fill(.blue)
            .frame(width: 7, height: 7)
          Text("Waiting for you")
            .font(.caption.weight(.medium))
            .foregroundStyle(.blue)
        }
        .padding(.top, 4)
      }
    }
    .padding(.horizontal, 18)
    .padding(.vertical, 13)
    .background(step.state == .active ? Color.blue.opacity(0.05) : Color.clear)
  }

  @ViewBuilder
  private var stateIndicator: some View {
    switch step.state {
    case .done:
      Image(systemName: "checkmark")
        .font(.system(size: 12, weight: .bold))
        .foregroundStyle(.green)
        .frame(width: 26, height: 26)
        .background(.green.opacity(0.13), in: Circle())
    case .active:
      Text("\(number)")
        .font(.system(size: 12.5, weight: .semibold))
        .foregroundStyle(.white)
        .frame(width: 26, height: 26)
        .background(.blue, in: Circle())
    case .pending:
      Text("\(number)")
        .font(.system(size: 12.5, weight: .medium))
        .foregroundStyle(.tertiary)
        .frame(width: 26, height: 26)
        .overlay(Circle().strokeBorder(.quaternary, lineWidth: 1.5))
    }
  }
}
