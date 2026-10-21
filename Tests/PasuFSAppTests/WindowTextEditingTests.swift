import AppKit
import XCTest

@testable import PasuFSApp

/// The main window ends text editing before it shows the setup assistant, so the toolbar search
/// field is no longer editing when SwiftUI removes the toolbar. See `RootView`.
@MainActor
final class WindowTextEditingTests: XCTestCase {
  func testEndsEditingInATextField() throws {
    let (window, field) = makeWindow()
    defer { window.close() }
    XCTAssertTrue(window.makeFirstResponder(field))
    // A text field edits through the window's field editor, which becomes first responder.
    XCTAssertTrue(window.firstResponder is NSText)

    XCTAssertTrue(window.endTextEditing())
    XCTAssertFalse(window.firstResponder is NSText)
    XCTAssertNil(field.currentEditor())
  }

  func testLeavesOtherFirstRespondersAlone() throws {
    let (window, _) = makeWindow()
    defer { window.close() }
    let button = NSButton(title: "Example", target: nil, action: nil)
    window.contentView?.addSubview(button)
    window.makeFirstResponder(button)
    let responder = window.firstResponder

    XCTAssertFalse(window.endTextEditing())
    XCTAssertTrue(window.firstResponder === responder)
  }

  private func makeWindow() -> (NSWindow, NSTextField) {
    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 320, height: 120), styleMask: [.titled],
      backing: .buffered, defer: false)
    window.isReleasedWhenClosed = false
    let field = NSTextField(string: "example")
    field.frame = NSRect(x: 20, y: 40, width: 200, height: 24)
    window.contentView?.addSubview(field)
    return (window, field)
  }
}
