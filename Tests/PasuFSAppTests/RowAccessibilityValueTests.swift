import AppKit
import ApplicationServices
import SwiftUI
import XCTest

@testable import PasuFSApp

/// A `LabeledContent` row in a grouped form exposes its value as an accessibility element after
/// the label. On macOS 27.0.1 that element holds a second one with the text the row shows, and
/// without `accessibilityRowValue(_:)` it kept the value the row first showed after the text
/// changed. On macOS 26.6.2 the row has one value element, and on macOS 27.2 both follow the
/// text without it.
@MainActor
final class RowAccessibilityValueTests: XCTestCase {
  func testRowValueFollowsTheTextItShows() throws {
    try XCTSkipUnless(
      CGSessionCopyCurrentDictionary() != nil, "Needs a login session with a window server.")
    // macOS answers accessibility queries for the windows of a launched application.
    let application = NSApplication.shared
    application.setActivationPolicy(.accessory)
    application.finishLaunching()
    let model = RowValueModel()
    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 480, height: 240), styleMask: [.titled],
      backing: .buffered, defer: false)
    window.isReleasedWhenClosed = false
    window.contentView = NSHostingView(rootView: RowValueForm(model: model))
    window.orderFront(nil)
    defer { window.close() }

    // Accessibility queries to this process need no permission. The first one builds the
    // elements, so the row has them before its text changes.
    XCTAssertEqual(Set(rowValues(labeled: "Installation", settlingOn: "Enabled")), ["Enabled"])
    model.value = "Uninstalling"
    XCTAssertEqual(
      Set(rowValues(labeled: "Installation", settlingOn: "Uninstalling")), ["Uninstalling"])
  }

  /// The values of the row's value elements, read once they all show `expected` or after about
  /// 2.5 seconds.
  private func rowValues(labeled label: String, settlingOn expected: String) -> [String] {
    var values: [String] = []
    for _ in 0..<50 {
      RunLoop.main.run(until: Date().addingTimeInterval(0.05))
      values = rowValues(labeled: label)
      if !values.isEmpty, values.allSatisfy({ $0 == expected }) { break }
    }
    return values
  }

  /// The label is a static text; the element after it holds the value, and on macOS 27 another
  /// element inside it holds the text.
  ///
  /// The search visits each element once, doesn't enter the application element and stops after
  /// 2,000 elements: on macOS 27.2 an element in the window can list the application among its
  /// children, and following it would make the search loop through the windows without end.
  private func rowValues(labeled label: String) -> [String] {
    let application = AXUIElementCreateApplication(getpid())
    var pending = (attribute(application, kAXWindowsAttribute) as? [AXUIElement]) ?? []
    var visited = [application]
    while !pending.isEmpty, visited.count < 2_000 {
      let element = pending.removeFirst()
      guard !visited.contains(where: { CFEqual($0, element) }),
        attribute(element, kAXRoleAttribute) as? String != kAXApplicationRole
      else { continue }
      visited.append(element)
      let children = (attribute(element, kAXChildrenAttribute) as? [AXUIElement]) ?? []
      for (index, child) in children.enumerated()
      where attribute(child, kAXValueAttribute) as? String == label && index + 1 < children.count {
        let row = children[index + 1]
        let text = (attribute(row, kAXChildrenAttribute) as? [AXUIElement])?.first
        return [row, text].compactMap { $0.flatMap { attribute($0, kAXValueAttribute) as? String } }
      }
      pending.append(contentsOf: children)
    }
    return []
  }

  private func attribute(_ element: AXUIElement, _ name: String) -> CFTypeRef? {
    var value: CFTypeRef?
    return AXUIElementCopyAttributeValue(element, name as CFString, &value) == .success
      ? value : nil
  }
}

@Observable
@MainActor
private final class RowValueModel {
  var value = "Enabled"
}

private struct RowValueForm: View {
  let model: RowValueModel

  var body: some View {
    Form {
      LabeledContent("Installation", value: model.value)
        .accessibilityRowValue(model.value)
    }
    .formStyle(.grouped)
  }
}
