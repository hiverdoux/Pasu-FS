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
  @State private var model: AppModel

  init() {
    _model = State(initialValue: AppModel())
  }

  var body: some Scene {
    Window("Pasu FS", id: "main") {
      RootView(model: model)
        .frame(
          minWidth: model.relaxesMainWindowMinimumWidth ? nil : MainWindowLayout.minimumWidth,
          minHeight: 600
        )
        .background(MainWindowObserver(lifecycle: windowLifecycle))
        .task { model.start() }
    }
    .defaultSize(width: 1080, height: 740)
    .commands {
      SidebarCommands()
      InspectorCommands()
      CommandGroup(replacing: .newItem) {
        Button("New Policy") {
          model.createNewPolicy()
        }
        .keyboardShortcut("n", modifiers: .command)
        .disabled(!model.canCreatePolicy)
      }
      CommandGroup(replacing: .saveItem) {
        PolicyMenuCommands()
      }
      CommandGroup(before: .sidebar) {
        RefreshMenuCommand()
        Divider()
      }
      CommandGroup(replacing: .appTermination) {
        StopProtectionAndQuitButton(model: model)
        QuitPasuFSButton(model: model)
          .keyboardShortcut("q", modifiers: .command)
      }
    }

    Settings {
      SettingsView(model: model)
        .background(AuxiliaryWindowObserver(lifecycle: windowLifecycle))
    }

    MenuBarExtra {
      MenuBarContentView(model: model, windowLifecycle: windowLifecycle)
        .task { model.start() }
    } label: {
      // The status item reads the symbol's own description unless a label is set. The label
      // names the app and repeats the status that the symbol shows.
      Label("Pasu FS", systemImage: model.menuBarSymbolName)
        .accessibilityLabel(Text("Pasu FS, \(model.status.title)"))
    }
  }
}

/// The native menu shown from the menu bar icon.
private struct MenuBarContentView: View {
  let model: AppModel
  let windowLifecycle: AppWindowLifecycle
  @Environment(\.openWindow) private var openWindow
  @Environment(\.openSettings) private var openSettings

  var body: some View {
    let status = model.status
    Text(status.title)
    Text(model.menuBarPolicySummary)
    if let item = model.attentionItems().first {
      Text(item.text)
    }
    Divider()
    Button("Open Pasu FS…") {
      windowLifecycle.prepareToOpenWindow()
      openWindow(id: "main")
      NSApplication.shared.activate()
    }
    Button("Settings…") {
      windowLifecycle.prepareToOpenWindow()
      openSettings()
      NSApplication.shared.activate()
    }
    Button("Refresh Status") {
      Task { await model.refreshHealth() }
    }
    Divider()
    StopProtectionAndQuitButton(model: model)
    QuitPasuFSButton(model: model)
  }
}

private struct StopProtectionAndQuitButton: View {
  let model: AppModel

  var body: some View {
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
    var message = String(
      localized:
        "Only the menu bar app quits. The system extension and protection keep running.")
    if hasUnsavedPolicyChanges {
      message += " " + String(localized: "Unsaved policy changes will be discarded.")
    }
    return runConfirmation(
      title: String(localized: "Quit Pasu FS?"),
      message: message,
      confirmTitle: String(localized: "Quit")
    )
  }

  static func confirmStopProtectionAndQuit(hasUnsavedPolicyChanges: Bool) -> Bool {
    var message = String(
      localized:
        "Pasu FS asks macOS to deactivate the system extension. Protection stops only after macOS completes the request, which may need administrator approval or a restart."
    )
    if hasUnsavedPolicyChanges {
      message +=
        " " + String(localized: "Unsaved policy changes will be discarded if Pasu FS quits.")
    }
    return runConfirmation(
      title: String(localized: "Stop Protection and Quit?"),
      message: message,
      confirmTitle: String(localized: "Stop Protection and Quit")
    )
  }

  static func showRestartRequired() {
    showMessage(
      title: String(localized: "Restart Required"),
      message: String(
        localized:
          "macOS accepted the deactivation request, but the system extension may keep protecting files until the Mac restarts. Pasu FS stays open."
      )
    )
  }

  static func showStopFailure(description: String) {
    showMessage(
      title: String(localized: "Protection Is Still Running"),
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
    let cancelButton = alert.addButton(withTitle: String(localized: "Cancel"))
    cancelButton.keyEquivalent = "\u{1b}"
    return alert.runModal() == .alertFirstButtonReturn
  }

  private static func showMessage(title: String, message: String) {
    let alert = NSAlert()
    alert.alertStyle = .warning
    alert.messageText = title
    alert.informativeText = message
    alert.addButton(withTitle: String(localized: "OK"))
    _ = alert.runModal()
  }
}
