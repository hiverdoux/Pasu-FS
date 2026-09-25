import AppKit
import PasuFSConfiguration
import SwiftUI
import UniformTypeIdentifiers

// Shared pieces for the main screens. Screens use grouped Forms, tables and standard controls,
// and status is shown with colored text and SF Symbols rather than custom badges or
// backgrounds, so the app adopts the system design, including Liquid Glass on macOS 26 and later.

enum MainWindowLayout {
  /// The narrowest main window. The toolbar still fits the policy tabs next to an expanded
  /// search field, with the sidebar at up to its widest.
  ///
  /// The window drops this minimum while a policy log shows its inspector, and the log opens the
  /// inspector only after the window has done so. When a minimum width is in place as the
  /// inspector opens in a window narrower than about that minimum plus the sidebar, the detail
  /// column grows past the window and pushes the sidebar out until the animation ends. Dropping
  /// the minimum in the same update as opening the inspector has the same effect, and setting the
  /// minimum on a screen instead adds the sidebar's width to it.
  static let minimumWidth: CGFloat = 900

  /// Waits, for at most a quarter of a second, until `window` no longer holds the minimum width.
  @MainActor
  static func minimumWidthReleased(in window: NSWindow?) async {
    for _ in 0..<60 {
      guard let window, window.contentMinSize.width >= minimumWidth else { return }
      try? await Task.sleep(for: .milliseconds(4))
    }
  }
}

/// A weak reference to the window a view is shown in, kept up to date by `WindowReader`.
@MainActor
final class WindowReference {
  weak var window: NSWindow?
}

/// Records the window its view is shown in.
struct WindowReader: NSViewRepresentable {
  let reference: WindowReference

  func makeNSView(context: Context) -> MainWindowObservationView {
    let view = MainWindowObservationView()
    view.onWindowAvailable = { [reference] window in reference.window = window }
    return view
  }

  func updateNSView(_ nsView: MainWindowObservationView, context: Context) {
    if let window = nsView.window {
      reference.window = window
    }
  }
}

extension PolicyMode {
  var tint: Color {
    switch self {
    case .protection: .green
    case .audit: .blue
    }
  }
}

extension StatusTone {
  var color: Color {
    switch self {
    case .protecting: .green
    case .auditing: .blue
    case .attention: .orange
    case .neutral: .secondary
    }
  }
}

extension PolicyEvaluationDecision {
  var tint: Color {
    switch self {
    case .deny: .red
    case .wouldDeny: .orange
    case .allow, .wouldAllow: .green
    }
  }
}

/// A status symbol for the Overview header and the setup assistant.
struct StatusSymbol: View {
  let systemImage: String
  let tone: StatusTone

  var body: some View {
    Image(systemName: systemImage)
      .symbolRenderingMode(.hierarchical)
      .foregroundStyle(tone.color)
      .font(.largeTitle)
      .accessibilityHidden(true)
  }
}

/// The installed app's icon for a signing identity, or a generic program icon.
struct ProgramIcon: View {
  let signingIdentifier: String?
  let executablePath: String?
  var size: CGFloat = 26

  var body: some View {
    Image(
      nsImage: ProgramIconCache.icon(signingIdentifier: signingIdentifier, path: executablePath)
    )
    .resizable()
    .interpolation(.high)
    .frame(width: size, height: size)
    .accessibilityHidden(true)
  }
}

@MainActor
enum ProgramIconCache {
  private static var icons: [String: NSImage] = [:]

  static func icon(signingIdentifier: String?, path: String?) -> NSImage {
    let key = "\(signingIdentifier ?? ""):\(path ?? "")"
    if let cached = icons[key] { return cached }
    let icon: NSImage
    if let signingIdentifier,
      let url = NSWorkspace.shared.urlForApplication(withBundleIdentifier: signingIdentifier)
    {
      icon = NSWorkspace.shared.icon(forFile: url.path)
    } else if let path, FileManager.default.fileExists(atPath: path) {
      icon = NSWorkspace.shared.icon(forFile: path)
    } else {
      icon = NSWorkspace.shared.icon(for: .unixExecutable)
    }
    icons[key] = icon
    return icon
  }
}

/// A policy decision as colored text. "Would" decisions are Audit predictions.
struct DecisionText: View {
  let decision: PolicyEvaluationDecision

  var body: some View {
    Text(decision.displayName)
      .foregroundStyle(decision.tint)
  }
}

/// The final answer Pasu FS gave macOS for a request.
struct ResponseText: View {
  let response: String

  var body: some View {
    Text(KernelResponseText.label(response))
      .fontWeight(.semibold)
      .foregroundStyle(tint)
  }

  private var tint: Color {
    switch response {
    case "deny": .red
    case "allow": .green
    case "notify-only": .blue
    case "response-error": .orange
    default: .secondary
    }
  }
}

/// A notice that must stay visible, such as records that could not be saved.
struct WarningLabel: View {
  let text: String
  var systemImage = "exclamationmark.triangle"

  var body: some View {
    Label {
      Text(text)
    } icon: {
      Image(systemName: systemImage)
        .foregroundStyle(.orange)
    }
  }
}

/// The title of a sheet, shown in the header of the first section of its form, above that
/// section's own header if it has one. See `formSheetSizing()`.
struct SheetTitle: View {
  let title: String
  var subtitle: String?

  var body: some View {
    VStack(alignment: .leading, spacing: 2) {
      Text(title)
        .font(.title3.weight(.semibold))
        .foregroundStyle(.primary)
        .accessibilityAddTraits(.isHeader)
      if let subtitle, !subtitle.isEmpty {
        Text(subtitle)
          .font(.subheadline)
          .foregroundStyle(.secondary)
      }
    }
    .textCase(nil)
    .padding(.bottom, 8)
  }
}

/// A path shown with the home folder abbreviated, as Finder does.
enum PathText {
  static func abbreviated(_ path: String) -> String {
    (path as NSString).abbreviatingWithTildeInPath
  }
}

/// A code-signature caption. The kind uses the system font; identifiers use a monospaced font.
struct SignatureLine: View {
  let kind: String
  let identifiers: String

  var body: some View {
    HStack {
      Text(kind)
        .layoutPriority(1)
      Text(verbatim: "·")
      Text(identifiers)
        .monospaced()
        .truncationMode(.middle)
    }
    .lineLimit(1)
    .font(.caption)
    .foregroundStyle(.secondary)
  }
}

/// Label and value rows for inspectors. Values can be selected and copied.
struct DetailRows: View {
  struct Row: Identifiable {
    let label: String
    let value: String
    var isMonospaced = false

    var id: String { label }
  }

  let rows: [Row]

  var body: some View {
    ForEach(rows) { row in
      LabeledContent(row.label) {
        Text(row.value)
          .monospaced(row.isMonospaced)
          .multilineTextAlignment(.trailing)
          .textSelection(.enabled)
      }
    }
  }
}

extension View {
  /// Searches the records a screen has loaded with the system toolbar search item. When the
  /// toolbar is short of room, the system shows it as a button that expands into the field, moves
  /// the other items aside and puts those that no longer fit in the overflow menu.
  func toolbarSearch(
    text: Binding<String>, isSearching: Binding<Bool>, prompt: LocalizedStringKey
  ) -> some View {
    searchable(text: text, isPresented: isSearching, placement: .toolbar, prompt: Text(prompt))
  }

  /// Uses the hard scroll edge effect under the top and bottom bars on macOS 26 and later, the
  /// style Apple recommends on macOS so bar content stays legible over scrolling rows.
  @ViewBuilder
  func hardScrollEdges() -> some View {
    #if compiler(>=6.2)
      if #available(macOS 26.0, *) {
        scrollEdgeEffectStyle(.hard, for: .vertical)
      } else {
        self
      }
    #else
      self
    #endif
  }

  /// Gives a sheet that contains a form the system's form width on macOS 15 and later, with the
  /// height of its content.
  ///
  /// Sheets don't use a NavigationStack title: macOS draws it in a toolbar band that keeps room
  /// on the leading side for window buttons a sheet doesn't have. `SheetTitle` goes at the top
  /// of the form instead, and the Cancel and confirm buttons stay in the sheet's bottom bar.
  @ViewBuilder
  func formSheetSizing() -> some View {
    if #available(macOS 15.0, *) {
      presentationSizing(.form.fitted(horizontal: false, vertical: true))
    } else {
      frame(minWidth: 520, minHeight: 520)
    }
  }

  /// Adds two groups of toolbar items with the system's fixed space between them on macOS 26
  /// and later, as the toolbar guidelines recommend for separate groups.
  @ViewBuilder
  func toolbarGroups(
    isShown: Bool = true,
    @ToolbarContentBuilder _ first: () -> some ToolbarContent,
    @ToolbarContentBuilder _ second: () -> some ToolbarContent
  ) -> some View {
    #if compiler(>=6.2)
      if #available(macOS 26.0, *) {
        toolbar {
          if isShown {
            first()
            ToolbarSpacer(.fixed)
            second()
          }
        }
      } else {
        toolbar {
          if isShown {
            first()
            second()
          }
        }
      }
    #else
      toolbar {
        if isShown {
          first()
          second()
        }
      }
    #endif
  }
}
