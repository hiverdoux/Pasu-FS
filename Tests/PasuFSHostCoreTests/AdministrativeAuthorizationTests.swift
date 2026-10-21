import Foundation
import PasuFSIPC
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
      AdministrativeAuthorizationOperation.uninstall.rightName,
      "com.example.pasu.fs.uninstall"
    )
    XCTAssertEqual(
      AdministrativeAuthorizationOperation.policyWeaken.rightName,
      "com.example.pasu.fs.policy.weaken"
    )
    XCTAssertEqual(AdministrativeAuthorizationOperation.allCases.count, 4)
    XCTAssertTrue(
      AdministrativeAuthorizationOperation.extensionActivate.prompt.contains("activate")
    )
    XCTAssertTrue(
      AdministrativeAuthorizationOperation.extensionDeactivate.prompt.contains("deactivate")
    )
    XCTAssertTrue(AdministrativeAuthorizationOperation.uninstall.prompt.contains("uninstall"))
    XCTAssertTrue(
      AdministrativeAuthorizationOperation.policyWeaken.prompt.contains("reduce the protection"))
    XCTAssertEqual(
      AdministrativeAuthorizationRule.authenticationRuleName,
      "authenticate-admin"
    )
  }

  func testPromptsAreTranslatedInTheAppCatalog() throws {
    // macOS reads each prompt from the app's Localizable.strings when the right is
    // registered, so every prompt must be a catalog key with a manual extraction state.
    let repository = URL(fileURLWithPath: #filePath)
      .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    let catalog = repository.appendingPathComponent(
      "Product/Localization/App/Localizable.xcstrings")
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: Data(contentsOf: catalog)) as? [String: Any])
    let strings = try XCTUnwrap(object["strings"] as? [String: [String: Any]])
    for operation in AdministrativeAuthorizationOperation.allCases {
      let entry = try XCTUnwrap(strings[operation.prompt], operation.prompt)
      XCTAssertEqual(entry["extractionState"] as? String, "manual", operation.prompt)
      let korean = (entry["localizations"] as? [String: Any])?["ko"] as? [String: Any]
      let unit = korean?["stringUnit"] as? [String: Any]
      XCTAssertEqual(unit?["state"] as? String, "translated", operation.prompt)
      XCTAssertFalse((unit?["value"] as? String ?? "").isEmpty, operation.prompt)
    }
  }

  func testFabricatedExternalAuthorizationsAreRejectedBeforeAnyPrompt() {
    XCTAssertEqual(ExternalAuthorizationVerifier.externalFormSize, 32)
    XCTAssertThrowsError(
      try ExternalAuthorizationVerifier.verify(Data(), grants: .policyWeaken)
    ) { error in
      XCTAssertEqual(error as? ExternalAuthorizationError, .malformed)
    }
    XCTAssertThrowsError(
      try ExternalAuthorizationVerifier.verify(
        Data(repeating: 0, count: 4096), grants: .policyWeaken)
    ) { error in
      XCTAssertEqual(error as? ExternalAuthorizationError, .malformed)
    }
    // A fabricated session cannot be imported, so no password dialog is reached.
    XCTAssertThrowsError(
      try ExternalAuthorizationVerifier.verify(Data(repeating: 0, count: 32), grants: .policyWeaken)
    ) { error in
      switch error as? ExternalAuthorizationError {
      case .invalid, .ruleUnexpected: break
      default: XCTFail("\(error)")
      }
    }
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
