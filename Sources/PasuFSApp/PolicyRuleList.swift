import PasuFSConfiguration

/// One of a policy's two independent program lists. Both are kept when the policy stops or
/// starts using its allow list.
enum PolicyRuleList: Hashable, CaseIterable {
  case allow
  case deny
}

extension DirectoryPolicyDraft {
  subscript(list: PolicyRuleList) -> [PolicyRule] {
    get {
      switch list {
      case .allow: allowRules
      case .deny: denyRules
      }
    }
    set {
      switch list {
      case .allow: allowRules = newValue
      case .deny: denyRules = newValue
      }
    }
  }

  /// Whether decisions use this list. The deny list always applies.
  func uses(_ list: PolicyRuleList) -> Bool {
    list == .deny || !isBlacklistEnabled
  }
}

extension DirectoryPolicy {
  /// The number of rules that take part in decisions, per list. An allow list the policy keeps
  /// without using is not counted.
  var rulesInUse: (allow: Int, deny: Int) {
    (
      isBlacklistEnabled ? 0 : allowRules.lazy.filter(\.isEnabled).count,
      denyRules.lazy.filter(\.isEnabled).count
    )
  }
}

extension DirectoryPolicy {
  /// Whether the policy blocks a program because its execution history is incomplete, as it is
  /// for programs started before the running extension began tracking processes. Audit policies
  /// block nothing. A Protection policy whose allow list is in use but has no rule in effect
  /// denies every program anyway, so the history doesn't change its decisions.
  var deniesProgramsWithIncompleteHistory: Bool {
    mode == .protection && (isBlacklistEnabled || allowRules.contains(where: \.isEnabled))
  }
}
