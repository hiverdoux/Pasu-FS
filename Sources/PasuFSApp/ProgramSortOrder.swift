import Foundation
import PasuFSConfiguration

/// The order in which the program lists of every policy are shown. The choice is a preference
/// of the app and changes only the display: the saved policies keep their rules in the order
/// they were added, which has no effect on decisions.
enum ProgramSortOrder: String, CaseIterable, Identifiable {
  case name
  case signingIdentifier
  /// Developer-signed programs grouped by Team ID, then Apple platform binaries.
  case signature
  case orderAdded

  static let defaultsKey = "programSortOrder"
  static let `default` = Self.name

  var id: Self { self }

  var displayName: String {
    switch self {
    case .name: String(localized: "Name")
    case .signingIdentifier: String(localized: "Signing ID")
    case .signature: String(localized: "Signature Kind and Team ID")
    case .orderAdded: String(localized: "Order Added")
    }
  }

  /// The rules in this order. `displayName` gives the name a rule's row shows. Names and
  /// identifiers are compared as Finder compares file names, and rules that compare the same
  /// keep their order in the list.
  func sorted(_ rules: [PolicyRule], displayName: (PolicyRule) -> String) -> [PolicyRule] {
    let keys = self.keys
    guard !keys.isEmpty else { return rules }
    let entries = rules.enumerated().map { offset, rule in
      Entry(offset: offset, rule: rule, name: displayName(rule))
    }
    return entries.sorted { lhs, rhs in
      for key in keys {
        let result = key.compare(lhs, rhs)
        if result != .orderedSame { return result == .orderedAscending }
      }
      return lhs.offset < rhs.offset
    }
    .map(\.rule)
  }

  private struct Entry {
    let offset: Int
    let rule: PolicyRule
    let name: String
  }

  private enum Key {
    case name
    case signingIdentifier
    case teamIdentifier
    /// Developer-signed programs before Apple platform binaries.
    case kind

    func compare(_ lhs: Entry, _ rhs: Entry) -> ComparisonResult {
      switch self {
      case .name:
        return lhs.name.localizedStandardCompare(rhs.name)
      case .signingIdentifier:
        return lhs.rule.signingIdentifier.localizedStandardCompare(rhs.rule.signingIdentifier)
      case .teamIdentifier:
        return (lhs.rule.teamIdentifier ?? "").localizedStandardCompare(
          rhs.rule.teamIdentifier ?? "")
      case .kind:
        let (left, right) = (Self.rank(lhs.rule.kind), Self.rank(rhs.rule.kind))
        if left == right { return .orderedSame }
        return left < right ? .orderedAscending : .orderedDescending
      }
    }

    private static func rank(_ kind: PolicyRuleKind) -> Int {
      kind == .teamSigned ? 0 : 1
    }
  }

  private var keys: [Key] {
    switch self {
    case .name: [.name, .signingIdentifier, .teamIdentifier]
    case .signingIdentifier: [.signingIdentifier, .teamIdentifier, .name]
    case .signature: [.kind, .teamIdentifier, .name, .signingIdentifier]
    case .orderAdded: []
    }
  }
}
