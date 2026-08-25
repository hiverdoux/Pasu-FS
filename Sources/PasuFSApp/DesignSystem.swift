import PasuFSConfiguration
import SwiftUI

/// Shared visual vocabulary for the mockup-derived redesign: white cards on the
/// window background, uppercase section headings, tinted mini badges, and
/// tinted icon tiles. Colors stay semantic so dark mode keeps working.
struct CardStyle: ViewModifier {
  func body(content: Content) -> some View {
    content
      .background(
        Color(nsColor: .textBackgroundColor),
        in: RoundedRectangle(cornerRadius: 11)
      )
      .overlay(
        RoundedRectangle(cornerRadius: 11)
          .strokeBorder(.quaternary, lineWidth: 1)
      )
      .shadow(color: .black.opacity(0.04), radius: 1, y: 1)
  }
}

extension View {
  func cardStyle() -> some View {
    modifier(CardStyle())
  }
}

struct CardDivider: View {
  var body: some View {
    Divider()
      .padding(.horizontal, 16)
  }
}

struct SectionHeading: View {
  let title: String

  init(_ title: String) {
    self.title = title
  }

  var body: some View {
    Text(title.uppercased())
      .font(.caption.weight(.semibold))
      .kerning(0.4)
      .foregroundStyle(.secondary)
  }
}

struct TagBadge: View {
  let text: String
  let tint: Color

  var body: some View {
    Text(text.uppercased())
      .font(.system(size: 10, weight: .semibold))
      .kerning(0.3)
      .padding(.horizontal, 6)
      .padding(.vertical, 2)
      .foregroundStyle(tint)
      .background(tint.opacity(0.13), in: RoundedRectangle(cornerRadius: 4))
  }
}

struct IconTile: View {
  let systemImage: String
  let tint: Color
  var size: CGFloat = 34

  var body: some View {
    Image(systemName: systemImage)
      .font(.system(size: size * 0.5, weight: .medium))
      .foregroundStyle(tint)
      .frame(width: size, height: size)
      .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: size * 0.24))
  }
}

struct WarningBanner: View {
  let text: String
  var systemImage = "exclamationmark.triangle"

  var body: some View {
    Label(text, systemImage: systemImage)
      .font(.callout)
      .foregroundStyle(.orange)
      .frame(maxWidth: .infinity, alignment: .leading)
      .padding(.horizontal, 13)
      .padding(.vertical, 8)
      .background(.orange.opacity(0.1), in: RoundedRectangle(cornerRadius: 9))
      .overlay(
        RoundedRectangle(cornerRadius: 9)
          .strokeBorder(.orange.opacity(0.25), lineWidth: 1)
      )
  }
}

extension PolicyMode {
  var displayName: String {
    switch self {
    case .protection: "Protection"
    case .audit: "Audit"
    }
  }

  var tint: Color {
    switch self {
    case .protection: .green
    case .audit: .blue
    }
  }

  var symbolName: String {
    switch self {
    case .protection: "checkmark.shield"
    case .audit: "eye"
    }
  }
}

extension PolicyType {
  var displayName: String {
    switch self {
    case .whitelist: "Whitelist"
    case .blacklist: "Blacklist"
    }
  }
}

extension PolicyRuleKind {
  var displayName: String {
    switch self {
    case .teamSigned: "Team signed"
    case .platformBinary: "Apple platform"
    }
  }

  var symbolName: String {
    switch self {
    case .teamSigned: "app.badge.checkmark"
    case .platformBinary: "apple.terminal"
    }
  }
}
