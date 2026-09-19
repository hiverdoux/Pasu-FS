import Foundation
import XCTest

@testable import PasuFSHostCore

final class AdministrativeAuthorizationTests: XCTestCase {
  func testStateChangingOperationsUseSeparateRightsAndExplicitPrompts() {
    XCTAssertEqual(
      AdministrativeAuthorizationOperation.extensionActivate.rightName,
      "com.example.pasu.fs.extension.activate"
    )
    XCTAssertEqual(
      AdministrativeAuthorizationOperation.extensionDeactivate.rightName,
      "com.example.pasu.fs.extension.deactivate"
    )
    XCTAssertEqual(
      AdministrativeAuthorizationOperation.policyModify.rightName,
      "com.example.pasu.fs.policy.modify"
    )
    XCTAssertEqual(
      AdministrativeAuthorizationOperation.compatibilityModify.rightName,
      "com.example.pasu.fs.compatibility.modify"
    )
    XCTAssertTrue(
      AdministrativeAuthorizationOperation.extensionActivate.prompt.contains("activate")
    )
    XCTAssertTrue(
      AdministrativeAuthorizationOperation.extensionDeactivate.prompt.contains("deactivate")
    )
    XCTAssertEqual(
      AdministrativeAuthorizationRule.authenticationRuleName,
      "authenticate-admin"
    )
  }

  func testRightDefinitionRequiresFreshNonSharedAdminAuthentication() {
    let definition =
      AdministrativeAuthorizationRule.definition(
        for: .extensionDeactivate
      ) as CFDictionary

    XCTAssertTrue(AdministrativeAuthorizationRule.isSecure(definition))
    let values = definition as! [String: Any]
    XCTAssertEqual(values["class"] as? String, "user")
    XCTAssertEqual(values["group"] as? String, "admin")
    XCTAssertEqual((values["authenticate-user"] as? NSNumber)?.boolValue, true)
    XCTAssertEqual((values["allow-root"] as? NSNumber)?.boolValue, false)
    XCTAssertEqual((values["shared"] as? NSNumber)?.boolValue, false)
    XCTAssertEqual((values["timeout"] as? NSNumber)?.intValue, 0)
  }

  func testRightDefinitionRejectsCachedOrIdentityOnlyRules() {
    let base = AdministrativeAuthorizationRule.definition(
      for: .extensionActivate
    )
    for mutation in [
      ["shared": true],
      ["timeout": 300],
      ["allow-root": true],
      ["authenticate-user": false],
      ["class": "rule"],
      ["group": "staff"],
      ["tries": 1],
      ["rule": "allow"],
    ] {
      var changed = base
      for (key, value) in mutation {
        changed[key] = value
      }
      XCTAssertFalse(
        AdministrativeAuthorizationRule.isSecure(changed as CFDictionary)
      )
    }
  }
}
