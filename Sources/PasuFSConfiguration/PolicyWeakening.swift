import Foundation

/// Decides whether a policy-set save must be authorized by an administrator.
///
/// A change weakens protection when a policy in Protection mode would deny fewer requests
/// afterwards, including when it turns on a system-compatibility profile, or when a policy
/// disappears. The stored set is the baseline. A set
/// stored for the first time, a new policy, a switch from Audit to Protection and every
/// edit of a policy that is in Audit mode are not weakening: an Audit policy denies
/// nothing, and leaving Protection mode is itself a weakening change, so the contents of
/// an Audit policy can never have reached Protection mode without authorization.
public enum PolicyWeakeningAnalyzer {
  public static func weakens(
    candidate: PolicySetDocument, comparedTo active: PolicySetDocument?
  ) -> Bool {
    guard let active else { return false }
    let candidates = Dictionary(
      candidate.policies.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    return active.policies.contains { policy in
      guard let replacement = candidates[policy.id] else { return true }
      return weakens(candidate: replacement, comparedTo: policy)
    }
  }

  /// Whether replacing `active` with `candidate` reduces protection. Both describe the
  /// same policy; the name and disabled rules never matter.
  public static func weakens(candidate: DirectoryPolicy, comparedTo active: DirectoryPolicy)
    -> Bool
  {
    guard active.mode == .protection else { return false }
    if candidate.mode != .protection { return true }
    if candidate.protectedRootPath != active.protectedRootPath { return true }
    if !active.isBlacklistEnabled {
      // Turning the allow-list switch off lets every program that is not blocked open the
      // files. While the switch stays on, a program allowed for the first time or newly
      // allowed to pass its permission on to the programs it starts reduces protection.
      if candidate.isBlacklistEnabled { return true }
      let before = effectiveRules(active.allowRules)
      for (identity, allowsDescendants) in effectiveRules(candidate.allowRules) {
        guard let previous = before[identity] else { return true }
        if allowsDescendants && !previous { return true }
      }
    }
    // The block list applies with the switch in either position.
    let remaining = effectiveRules(candidate.denyRules)
    if effectiveRules(active.denyRules).keys.contains(where: { remaining[$0] == nil }) {
      return true
    }
    // A compatibility profile lets Apple system processes in without an observed history or a
    // rule. Turning one on, or turning it on again after the catalog changed what it allows,
    // reduces protection; turning one off does not.
    let approved = Set(active.systemCompatibilityProfiles)
    return candidate.systemCompatibilityProfiles.contains { !approved.contains($0) }
  }

  /// The rules in use, by program identity, with whether any of them passes its permission
  /// on to descendant processes. A rule that is off has no effect, so turning a rule off
  /// and removing it are the same change.
  private static func effectiveRules(_ rules: [PolicyRule]) -> [String: Bool] {
    var result: [String: Bool] = [:]
    for rule in rules where rule.isEnabled {
      result[rule.identityKey] = (result[rule.identityKey] ?? false) || rule.allowsDescendants
    }
    return result
  }
}
