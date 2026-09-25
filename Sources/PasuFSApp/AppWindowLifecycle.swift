import AppKit
import SwiftUI

@MainActor
final class AppWindowLifecycle: NSObject, NSApplicationDelegate {
  private weak var mainWindow: NSWindow?
  private var auxiliaryWindows: [ObjectIdentifier: WeakWindow] = [:]
  private var openMainWindow: (() -> Void)?

  private struct WeakWindow {
    weak var window: NSWindow?
  }

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
    stopObserving(mainWindow)
    mainWindow = window
    startObserving(window)
    prepareToOpenWindow()
  }

  /// Windows such as Settings keep the app in the Dock while they are open.
  func observeAuxiliary(_ window: NSWindow) {
    let key = ObjectIdentifier(window)
    guard auxiliaryWindows[key]?.window !== window else { return }
    auxiliaryWindows[key] = WeakWindow(window: window)
    startObserving(window)
    prepareToOpenWindow()
  }

  private func startObserving(_ window: NSWindow) {
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
  }

  private func stopObserving(_ window: NSWindow?) {
    guard let window else { return }
    NotificationCenter.default.removeObserver(
      self, name: NSWindow.didBecomeKeyNotification, object: window
    )
    NotificationCenter.default.removeObserver(
      self, name: NSWindow.willCloseNotification, object: window
    )
  }

  @objc private func windowDidBecomeKey(_ notification: Notification) {
    prepareToOpenWindow()
  }

  @objc private func windowWillClose(_ notification: Notification) {
    // Let AppKit finish closing before removing the app from the Dock.
    Task { @MainActor [weak self] in
      guard let self else { return }
      auxiliaryWindows = auxiliaryWindows.filter { Self.isOpen($0.value.window) }
      guard !Self.isOpen(mainWindow), auxiliaryWindows.isEmpty else { return }
      NSApplication.shared.setActivationPolicy(.accessory)
    }
  }

  /// A minimized window still counts as open, so the app keeps its Dock item.
  private static func isOpen(_ window: NSWindow?) -> Bool {
    guard let window else { return false }
    return window.isVisible || window.isMiniaturized
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

struct AuxiliaryWindowObserver: NSViewRepresentable {
  let lifecycle: AppWindowLifecycle

  func makeNSView(context: Context) -> MainWindowObservationView {
    let view = MainWindowObservationView()
    view.onWindowAvailable = { [weak lifecycle] window in
      lifecycle?.observeAuxiliary(window)
    }
    return view
  }

  func updateNSView(_ nsView: MainWindowObservationView, context: Context) {
    if let window = nsView.window {
      lifecycle.observeAuxiliary(window)
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
