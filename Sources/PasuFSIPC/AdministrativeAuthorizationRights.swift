import Foundation
import Security

/// The operations that need a fresh administrator authentication. Each one has its own
/// entry in the macOS authorization database; the names are shared by the app, the
/// command-line tool, the maintenance service and the system extension.
public enum AdministrativeAuthorizationOperation: String, CaseIterable, Sendable {
  case extensionActivate = "com.example.pasu.fs.extension.activate"
  case extensionDeactivate = "com.example.pasu.fs.extension.deactivate"
  case uninstall = "com.example.pasu.fs.uninstall"
  /// A policy save that reduces protection; see `PolicyWeakeningAnalyzer`.
  case policyWeaken = "com.example.pasu.fs.policy.weaken"

  public var rightName: String { rawValue }

  /// The sentence macOS shows when it asks for an administrator password.
  ///
  /// The sentence is registered as the right's description key. For every language
  /// folder of the app bundle, the authorization database stores the entry with this
  /// key from `Localizable.strings`, or the key itself where the table has no entry.
  /// The key therefore stays English and each translation lives in the app's String
  /// Catalog.
  public var prompt: String {
    switch self {
    case .extensionActivate:
      "Administrator authentication is required to activate the Pasu FS protection system extension."
    case .extensionDeactivate:
      "Administrator authentication is required to deactivate the Pasu FS protection system extension."
    case .uninstall:
      "Administrator authentication is required to uninstall Pasu FS from this Mac."
    case .policyWeaken:
      "Administrator authentication is required to reduce the protection of a Pasu FS policy."
    }
  }

  fileprivate var comment: String {
    switch self {
    case .extensionActivate:
      "Authorizes one Pasu FS system-extension activation request."
    case .extensionDeactivate:
      "Authorizes one Pasu FS system-extension deactivation request."
    case .uninstall:
      "Authorizes one Pasu FS uninstall transaction."
    case .policyWeaken:
      "Authorizes one Pasu FS policy change that reduces protection."
    }
  }
}

public enum AdministrativeAuthorizationRule {
  /// The public rule whose values the entries copy (`security authorizationdb read
  /// authenticate-admin` prints them).
  public static let authenticationRuleName = String(kAuthorizationRuleAuthenticateAsAdmin)

  /// The entry for one operation: the public `authenticate-admin` rule written out as a user
  /// rule with the same values, except that `shared` is false, so the credential is not shared
  /// with other rights in the same authorization session, and that the comment names the
  /// operation. `timeout = 0`, which keeps an earlier authentication from satisfying the check,
  /// and `tries = 10000` are the public rule's own values.
  public static func definition(
    for operation: AdministrativeAuthorizationOperation
  ) -> [String: Any] {
    [
      "class": "user",
      "group": "admin",
      "authenticate-user": true,
      "allow-root": false,
      "session-owner": false,
      "shared": false,
      "timeout": 0,
      // How many password attempts one dialog allows; the public rule's value, kept unchanged.
      "tries": 10_000,
      kAuthorizationComment: operation.comment,
    ]
  }

  /// Whether an entry read from the authorization database still has the registered values for
  /// every key that decides who is authorized, and neither delegates to another rule nor names
  /// mechanisms. An entry that was changed in any of these, `tries` included, is refused.
  public static func isSecure(_ definition: CFDictionary) -> Bool {
    guard let values = definition as? [String: Any] else { return false }
    return values["class"] as? String == "user"
      && values["group"] as? String == "admin"
      && bool(values["authenticate-user"]) == true
      && bool(values["allow-root"]) == false
      && bool(values["session-owner"]) == false
      && bool(values["shared"]) == false
      && integer(values["timeout"]) == 0
      && integer(values["tries"]) == 10_000
      && values["rule"] == nil
      && values["mechanisms"] == nil
  }

  private static func bool(_ value: Any?) -> Bool? {
    (value as? NSNumber)?.boolValue
  }

  private static func integer(_ value: Any?) -> Int? {
    (value as? NSNumber)?.intValue
  }
}

public enum ExternalAuthorizationError: Error, Equatable, CustomStringConvertible, Sendable {
  case malformed
  case invalid(OSStatus)
  case ruleUnexpected
  case canceled
  case denied(OSStatus)

  public var description: String {
    switch self {
    case .malformed:
      "The administrator authorization is missing or malformed."
    case .invalid(let status):
      "The administrator authorization is invalid (OSStatus \(status))."
    case .ruleUnexpected:
      "The authorization entry does not require a fresh, non-shared administrator authentication."
    case .canceled:
      "Administrator authentication was canceled."
    case .denied(let status):
      "Administrator authentication was not granted (OSStatus \(status))."
    }
  }
}

/// Verifies, in a privileged process, that a transferred authorization session grants one
/// operation.
///
/// The app creates a fresh session in the user's login session and sends its external
/// form. The privileged process imports it, checks that the entry still requires a
/// one-time administrator authentication, and then asks macOS for the right exactly once
/// with interaction allowed: the password dialog appears in the user's session while
/// this call waits. `timeout = 0` on the entry means an earlier authentication can never
/// satisfy the check.
public enum ExternalAuthorizationVerifier {
  public static let externalFormSize = MemoryLayout<AuthorizationExternalForm>.size

  public static func verify(
    _ data: Data, grants operation: AdministrativeAuthorizationOperation
  ) throws {
    guard data.count == externalFormSize else {
      throw ExternalAuthorizationError.malformed
    }
    var external = AuthorizationExternalForm()
    _ = withUnsafeMutableBytes(of: &external) { data.copyBytes(to: $0) }
    var reference: AuthorizationRef?
    let importStatus = AuthorizationCreateFromExternalForm(&external, &reference)
    guard importStatus == errAuthorizationSuccess, let reference else {
      throw ExternalAuthorizationError.invalid(importStatus)
    }
    defer { AuthorizationFree(reference, []) }
    var definition: CFDictionary?
    let lookup = operation.rightName.withCString {
      AuthorizationRightGet($0, &definition)
    }
    guard lookup == errAuthorizationSuccess, let definition,
      AdministrativeAuthorizationRule.isSecure(definition)
    else {
      throw ExternalAuthorizationError.ruleUnexpected
    }
    let status = operation.rightName.withCString { name in
      var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
      return withUnsafeMutablePointer(to: &item) { itemPointer in
        var rights = AuthorizationRights(count: 1, items: itemPointer)
        return AuthorizationCopyRights(
          reference, &rights, nil, [.extendRights, .interactionAllowed], nil)
      }
    }
    if status == errAuthorizationCanceled {
      throw ExternalAuthorizationError.canceled
    }
    guard status == errAuthorizationSuccess else {
      throw ExternalAuthorizationError.denied(status)
    }
  }
}
