import AppKit
import PasuFSHostCore
import SwiftUI

@main
private enum PasuFSApplicationEntry {
  @MainActor
  static func main() async {
    if CommandLine.arguments.dropFirst().first == "--pasu-fs-host" {
      await HostCommandRunner.run(
        arguments: Array(CommandLine.arguments.dropFirst(2)),
        hostBundleURL: Bundle.main.bundleURL
      )
    } else {
      PasuFSApp.main()
    }
  }
}

struct PasuFSApp: App {
  @NSApplicationDelegateAdaptor(AppWindowLifecycle.self) private var windowLifecycle
  @State private var model = AppModel()

  var body: some Scene {
    Window("Pasu FS", id: "main") {
      RootView(model: model)
        .frame(minWidth: 780, minHeight: 560)
        .background(MainWindowObserver(lifecycle: windowLifecycle))
        .task { model.start() }
    }
    .defaultSize(width: 780, height: 560)
    .commands {
      CommandGroup(replacing: .appTermination) {
        QuitPasuFSButton(model: model)
          .keyboardShortcut("q", modifiers: .command)
      }
    }

    MenuBarExtra {
      MenuBarContentView(model: model, windowLifecycle: windowLifecycle)
        .task { model.start() }
    } label: {
      Label("Pasu FS", systemImage: model.menuBarSymbolName)
    }
  }
}

private struct MenuBarContentView: View {
  let model: AppModel
  let windowLifecycle: AppWindowLifecycle
  @Environment(\.openWindow) private var openWindow

  var body: some View {
    Text(model.healthTitle)
    Text(model.menuBarPolicySummary)
      .font(.caption)
      .foregroundStyle(.secondary)
    Text("Covers \(model.coveredEventsDescription)")
      .font(.caption)
      .foregroundStyle(.secondary)
    if let warning = model.health.policyWarning {
      Text(warning)
        .font(.caption)
        .foregroundStyle(.orange)
    }
    Divider()
    Button("Open Pasu FS…") {
      windowLifecycle.prepareToOpenWindow()
      openWindow(id: "main")
      NSApplication.shared.activate()
    }
    Button("Refresh Status") {
      Task { await model.refreshHealth() }
    }
    Divider()
    if model.isStoppingProtectionForQuit {
      Text("Stopping Protection…")
    } else {
      Button("Stop Protection and Quit…", role: .destructive) {
        guard
          MenuBarAlerts.confirmStopProtectionAndQuit(
            hasUnsavedPolicyChanges: model.hasUnsavedPolicyChanges
          )
        else {
          return
        }
        Task {
          switch await model.stopProtectionForQuit() {
          case .stopped:
            model.stop()
            NSApplication.shared.terminate(nil)
          case .requiresRestart:
            MenuBarAlerts.showRestartRequired()
          case .failed(let description):
            MenuBarAlerts.showStopFailure(description: description)
          }
        }
      }
      .disabled(model.isBusy || model.isUninstalling)
    }
    QuitPasuFSButton(model: model)
  }
}

private struct QuitPasuFSButton: View {
  let model: AppModel

  var body: some View {
    Button("Quit Pasu FS") {
      guard
        MenuBarAlerts.confirmQuit(
          hasUnsavedPolicyChanges: model.hasUnsavedPolicyChanges
        )
      else {
        return
      }
      model.stop()
      NSApplication.shared.terminate(nil)
    }
    .disabled(model.isBusy || model.isStoppingProtectionForQuit || model.isUninstalling)
  }
}

@MainActor
private enum MenuBarAlerts {
  static func confirmQuit(hasUnsavedPolicyChanges: Bool) -> Bool {
    var message =
      "The menu bar app will close, but the system extension and protection will continue."
    if hasUnsavedPolicyChanges {
      message += " Unsaved policy changes will be discarded."
    }
    return runConfirmation(
      title: "Quit Pasu FS?",
      message: message,
      confirmTitle: "Quit"
    )
  }

  static func confirmStopProtectionAndQuit(hasUnsavedPolicyChanges: Bool) -> Bool {
    var message =
      "Pasu FS will ask macOS to deactivate the system extension. Protection stops only after macOS completes the request. Administrator approval or a restart may be required."
    if hasUnsavedPolicyChanges {
      message += " Unsaved policy changes will be discarded if Pasu FS quits."
    }
    return runConfirmation(
      title: "Stop Protection and Quit?",
      message: message,
      confirmTitle: "Stop Protection and Quit"
    )
  }

  static func showRestartRequired() {
    showMessage(
      title: "Restart Required",
      message:
        "macOS accepted the deactivation request, but the system extension may keep protecting files until the Mac restarts. Pasu FS will remain open."
    )
  }

  static func showStopFailure(description: String) {
    showMessage(
      title: "Protection Is Still Running",
      message: description
    )
  }

  private static func runConfirmation(
    title: String,
    message: String,
    confirmTitle: String
  ) -> Bool {
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = title
    alert.informativeText = message
    alert.addButton(withTitle: confirmTitle)
    let cancelButton = alert.addButton(withTitle: "Cancel")
    cancelButton.keyEquivalent = "\u{1b}"
    return alert.runModal() == .alertFirstButtonReturn
  }

  private static func showMessage(title: String, message: String) {
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = title
    alert.informativeText = message
    alert.addButton(withTitle: "OK")
    _ = alert.runModal()
  }
}
