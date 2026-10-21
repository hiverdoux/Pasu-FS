import Foundation
import XCTest

@testable import PasuFSConfiguration

final class PolicyWeakeningTests: XCTestCase {
  func testFirstStoredSetAndNewPoliciesNeedNoAuthorization() {
    let policy = protection()
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: set([policy]), comparedTo: nil))
    XCTAssertFalse(
      PolicyWeakeningAnalyzer.weakens(
        candidate: set([policy, protection(path: "/Users/example/Other")]),
        comparedTo: set([policy])))
    XCTAssertFalse(
      PolicyWeakeningAnalyzer.weakens(candidate: set([policy]), comparedTo: set([policy])))
  }

  func testDeletingAPolicyWeakens() {
    let kept = protection()
    let removed = protection(path: "/Users/example/Other")
    XCTAssertTrue(
      PolicyWeakeningAnalyzer.weakens(candidate: set([kept]), comparedTo: set([kept, removed])))
    let audit = protection(mode: .audit)
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: set([]), comparedTo: set([audit])))
  }

  func testModeChanges() {
    let active = protection()
    var candidate = active
    candidate.mode = .audit
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: candidate, comparedTo: active))
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: active, comparedTo: candidate))
  }

  func testEditsOfAnAuditPolicyNeedNoAuthorization() {
    let active = protection(mode: .audit)
    var candidate = active
    candidate.protectedRootPath = "/Users/example/Elsewhere"
    candidate.isBlacklistEnabled = true
    candidate.allowRules.append(
      .teamSigned(
        id: "rule.new", teamIdentifier: "TEAM000002", signingIdentifier: "com.example.new",
        allowsDescendants: true))
    candidate.denyRules = []
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: candidate, comparedTo: active))
  }

  func testNameChangeAndDisabledRulesAreNeutral() {
    let active = protection()
    var candidate = active
    candidate.name = "Renamed"
    candidate.allowRules.append(
      .teamSigned(
        id: "rule.off", teamIdentifier: "TEAM000002", signingIdentifier: "com.example.off",
        isEnabled: false, allowsDescendants: true))
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: candidate, comparedTo: active))
  }

  func testProtectedFolderChangeWeakens() {
    let active = protection()
    var candidate = active
    candidate.protectedRootPath = "/Users/example/Secrets/"
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: candidate, comparedTo: active))
  }

  func testAllowListSwitch() {
    let active = protection()
    var off = active
    off.isBlacklistEnabled = true
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: off, comparedTo: active))
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: active, comparedTo: off))

    // While the switch was off, the allow list was not in use: turning the switch on with
    // more allow rules than before still only strengthens.
    var onWithMore = active
    onWithMore.allowRules.append(newAllowRule())
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: onWithMore, comparedTo: off))
    var offWithMore = off
    offWithMore.allowRules.append(newAllowRule())
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: offWithMore, comparedTo: off))
  }

  func testAllowRules() {
    let active = protection()
    var added = active
    added.allowRules.append(newAllowRule())
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: added, comparedTo: active))
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: active, comparedTo: added))

    // Turning a rule on counts as adding it; turning it off counts as removing it.
    var disabled = added
    disabled.allowRules[1].isEnabled = false
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: disabled, comparedTo: active))
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: added, comparedTo: disabled))

    // The rule ID does not matter, the program identity does; Team IDs compare ignoring case.
    var renamed = active
    renamed.allowRules[0].id = "rule.other"
    renamed.allowRules[0].teamIdentifier = "team000001"
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: renamed, comparedTo: active))
    var replaced = active
    replaced.allowRules[0].signingIdentifier = "com.example.replacement"
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: replaced, comparedTo: active))
  }

  func testDescendantOption() {
    let active = protection()
    var delegated = active
    delegated.allowRules[0].allowsDescendants = true
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: delegated, comparedTo: active))
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: active, comparedTo: delegated))

    // The option on a block rule has no effect, so changing it is neutral.
    var denyDelegated = active
    denyDelegated.denyRules[0].allowsDescendants = true
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: denyDelegated, comparedTo: active))
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: active, comparedTo: denyDelegated))
  }

  func testBlockRulesApplyWithTheSwitchInEitherPosition() {
    for switchOff in [false, true] {
      var active = protection()
      active.isBlacklistEnabled = switchOff
      var removed = active
      removed.denyRules = []
      XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: removed, comparedTo: active))
      XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: active, comparedTo: removed))
      var disabled = active
      disabled.denyRules[0].isEnabled = false
      XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: disabled, comparedTo: active))
      var added = active
      added.denyRules.append(
        .platformBinary(
          id: "rule.deny2", signingIdentifier: "com.apple.cat", allowsDescendants: false))
      XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: added, comparedTo: active))
    }
  }

  func testSetLevelAnalysisMatchesPoliciesByIdentifier() {
    let first = protection()
    let second = protection(path: "/Users/example/Other")
    var weakenedSecond = second
    weakenedSecond.mode = .audit
    XCTAssertTrue(
      PolicyWeakeningAnalyzer.weakens(
        candidate: set([first, weakenedSecond]), comparedTo: set([first, second])))
    XCTAssertFalse(
      PolicyWeakeningAnalyzer.weakens(
        candidate: set([second, first]), comparedTo: set([first, second])))
  }

  func testTurningOnACompatibilityProfileWeakens() {
    let entry = PolicySystemCompatibilityProfile(
      profileIdentifier: "container-management",
      authorizationDigest: String(repeating: "a", count: 64))
    let active = protection()
    var candidate = active
    candidate.systemCompatibilityProfiles = [entry]
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: candidate, comparedTo: active))
    // Turning it off, or keeping it, does not.
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: active, comparedTo: candidate))
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: candidate, comparedTo: candidate))
    // Turning it on again after the catalog changed what it allows does.
    var renewed = candidate
    renewed.systemCompatibilityProfiles = [
      PolicySystemCompatibilityProfile(
        profileIdentifier: entry.profileIdentifier,
        authorizationDigest: String(repeating: "b", count: 64))
    ]
    XCTAssertTrue(PolicyWeakeningAnalyzer.weakens(candidate: renewed, comparedTo: candidate))
    // The whole-set check finds it too.
    XCTAssertTrue(
      PolicyWeakeningAnalyzer.weakens(candidate: set([candidate]), comparedTo: set([active])))
  }

  func testCompatibilityProfilesOfAuditAndNewPoliciesNeedNoAuthorization() {
    let entry = PolicySystemCompatibilityProfile(
      profileIdentifier: "xprotect-remediation",
      authorizationDigest: String(repeating: "a", count: 64))
    let audit = protection(mode: .audit)
    var auditCandidate = audit
    auditCandidate.systemCompatibilityProfiles = [entry]
    XCTAssertFalse(PolicyWeakeningAnalyzer.weakens(candidate: auditCandidate, comparedTo: audit))
    let existing = protection()
    var added = protection(path: "/Users/example/Library/Containers/com.example.App")
    added.systemCompatibilityProfiles = [entry]
    XCTAssertFalse(
      PolicyWeakeningAnalyzer.weakens(
        candidate: set([existing, added]), comparedTo: set([existing])))
  }

  // MARK: - Helpers

  private func protection(mode: PolicyMode = .protection, path: String = "/Users/example/Secrets")
    -> DirectoryPolicy
  {
    DirectoryPolicy(
      id: UUID(
        uuidString: "00000000-0000-0000-0000-"
          + String(format: "%012x", path.hashValue & 0xffff_ffff_ffff))!,
      name: "Policy " + path, mode: mode, isBlacklistEnabled: false, protectedRootPath: path,
      allowRules: [
        .teamSigned(
          id: "rule.allow", teamIdentifier: "TEAM000001", signingIdentifier: "com.example.editor",
          allowsDescendants: false)
      ],
      denyRules: [
        .teamSigned(
          id: "rule.deny", teamIdentifier: "TEAM000001", signingIdentifier: "com.example.sync",
          allowsDescendants: false)
      ])
  }

  private func newAllowRule() -> PolicyRule {
    .teamSigned(
      id: "rule.new", teamIdentifier: "TEAM000002", signingIdentifier: "com.example.new",
      allowsDescendants: false)
  }

  private func set(_ policies: [DirectoryPolicy]) -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(uuidString: "00000000-0000-0000-0000-000000000099")!, revision: 1,
      policies: policies)
  }
}
