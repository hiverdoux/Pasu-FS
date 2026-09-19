import AppKit
import SwiftUI

@MainActor
final class AppWindowLifecycle: NSObject, NSApplicationDelegate {
  private weak var mainWindow: NSWindow?
  private var openMainWindow: (() -> Void)?

  func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
    false
  }

  func applicationShouldHandleReopen(
    _ sender: NSApplication, hasVisibleWindows flag: Bool
  ) -> Bool {
    guard let openMainWindow else { return true }
    prepareToOpenWindow()
    // Use the SwiftUI scene action even after the previous NSWindow was released.
    openMainWindow()
    mainWindow?.deminiaturize(nil)
    sender.activate()
    return false
  }

  func prepareToOpenWindow() {
    if NSApplication.shared.activationPolicy() != .regular {
      NSApplication.shared.setActivationPolicy(.regular)
    }
  }

  func observe(_ window: NSWindow, openMainWindow: @escaping () -> Void) {
    self.openMainWindow = openMainWindow
    guard mainWindow !== window else { return }
    NotificationCenter.default.removeObserver(
      self, name: NSWindow.didBecomeKeyNotification, object: mainWindow
    )
    NotificationCenter.default.removeObserver(
      self, name: NSWindow.willCloseNotification, object: mainWindow
    )
    mainWindow = window
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(windowDidBecomeKey(_:)),
      name: NSWindow.didBecomeKeyNotification,
      object: window
    )
    NotificationCenter.default.addObserver(
      self,
      selector: #selector(windowWillClose(_:)),
      name: NSWindow.willCloseNotification,
      object: window
    )
    prepareToOpenWindow()
  }

  @objc private func windowDidBecomeKey(_ notification: Notification) {
    prepareToOpenWindow()
  }

  @objc private func windowWillClose(_ notification: Notification) {
    guard let window = notification.object as? NSWindow else { return }
    // Let AppKit finish closing before removing the app from the Dock.
    Task { @MainActor [weak self, window] in
      guard let self, self.mainWindow === window, !window.isVisible else {
        return
      }
      NSApplication.shared.setActivationPolicy(.accessory)
    }
  }
}

struct MainWindowObserver: NSViewRepresentable {
  let lifecycle: AppWindowLifecycle
  @Environment(\.openWindow) private var openWindow

  func makeNSView(context: Context) -> MainWindowObservationView {
    let view = MainWindowObservationView()
    view.onWindowAvailable = { [weak lifecycle, openWindow] window in
      lifecycle?.observe(window) { openWindow(id: "main") }
    }
    return view
  }

  func updateNSView(_ nsView: MainWindowObservationView, context: Context) {
    if let window = nsView.window {
      lifecycle.observe(window) { [openWindow] in openWindow(id: "main") }
    }
  }
}

final class MainWindowObservationView: NSView {
  var onWindowAvailable: ((NSWindow) -> Void)?

  override func viewDidMoveToWindow() {
    super.viewDidMoveToWindow()
    if let window {
      onWindowAvailable?(window)
    }
  }
}
