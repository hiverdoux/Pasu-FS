import AppKit
import SwiftUI

@main
struct PasuFSApp: App {
  @State private var model = AppModel()

  var body: some Scene {
    Window("Pasu FS", id: "main") {
      RootView(model: model)
        .frame(minWidth: 780, minHeight: 560)
        .task { model.start() }
    }
    .defaultSize(width: 780, height: 560)

    MenuBarExtra {
      MenuBarContentView(model: model)
        .task { model.start() }
    } label: {
      Label("Pasu FS", systemImage: model.menuBarSymbolName)
    }
  }
}

private struct MenuBarContentView: View {
  let model: AppModel
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
      openWindow(id: "main")
      NSApplication.shared.activate()
    }
    Button("Refresh Status") {
      Task { await model.refreshHealth() }
    }
    Divider()
    Button("Quit Pasu FS (protection continues)") {
      model.stop()
      NSApplication.shared.terminate(nil)
    }
  }
}
