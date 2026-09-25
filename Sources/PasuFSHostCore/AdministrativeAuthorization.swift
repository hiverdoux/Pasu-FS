import Foundation
import Security

public enum AdministrativeAuthorizationOperation: String, CaseIterable, Sendable {
  case extensionActivate = "com.example.pasu.fs.extension.activate"
  case extensionDeactivate = "com.example.pasu.fs.extension.deactivate"
  case uninstall = "com.example.pasu.fs.uninstall"

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
    }
  }
}

public enum AdministrativeAuthorizationRule {
  /// This is the public `authenticate-admin` rule expanded into a user rule so
  /// Pasu FS can additionally require `shared = false` and `timeout = 0`.
  public static let authenticationRuleName = String(kAuthorizationRuleAuthenticateAsAdmin)

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
      "tries": 10_000,
      kAuthorizationComment: operation.comment,
    ]
  }

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

public enum AdministrativeAuthorizationError: Error, CustomStringConvertible, Sendable {
  case authorizationCreationFailed(OSStatus)
  case rightLookupFailed(name: String, status: OSStatus)
  case rightRegistrationFailed(name: String, status: OSStatus)
  case rightRemovalFailed(name: String, status: OSStatus)
  case rightDefinitionMismatch(String)
  case canceled
  case denied
  case interactionUnavailable
  case authorizationFailed(OSStatus)

  public var description: String {
    switch self {
    case .authorizationCreationFailed(let status):
      "Could not create a fresh administrator authorization session: \(statusDescription(status))."
    case .rightLookupFailed(let name, let status):
      "Could not read authorization right \(name): \(statusDescription(status))."
    case .rightRegistrationFailed(let name, let status):
      "Could not register authorization right \(name): \(statusDescription(status))."
    case .rightRemovalFailed(let name, let status):
      "Could not remove authorization right \(name): \(statusDescription(status))."
    case .rightDefinitionMismatch(let name):
      "Authorization right \(name) does not require the expected one-time, non-shared administrator authentication. The request was not submitted."
    case .canceled:
      "Administrator authentication was canceled. The request was not submitted."
    case .denied:
      "Administrator authentication was denied. The request was not submitted."
    case .interactionUnavailable:
      "Administrator authentication requires an interactive macOS login session. The request was not submitted."
    case .authorizationFailed(let status):
      "Administrator authentication failed: \(statusDescription(status)). The request was not submitted."
    }
  }

  private func statusDescription(_ status: OSStatus) -> String {
    if let message = SecCopyErrorMessageString(status, nil) as String? {
      return "\(message) (\(status))"
    }
    return "OSStatus \(status)"
  }
}

/// Creates, replaces and removes the product's entries in the authorization database.
///
/// macOS lets any user add a missing right, but only root or an authenticated
/// administrator may change or remove an existing one. The installer therefore
/// registers every right as root after each installation, so the definitions and
/// prompts always match the installed app, and the maintenance service removes them
/// as root during uninstall. The app and the command-line tool only add a right that
/// is still missing.
public enum AdministrativeAuthorizationRegistry {
  enum Lookup {
    case found(CFDictionary)
    case missing
    case failed(OSStatus)
  }

  static func lookup(_ operation: AdministrativeAuthorizationOperation) -> Lookup {
    var definition: CFDictionary?
    let status = operation.rightName.withCString {
      AuthorizationRightGet($0, &definition)
    }
    if status == errAuthorizationSuccess, let definition { return .found(definition) }
    return status == errAuthorizationDenied ? .missing : .failed(status)
  }

  /// Registers every operation's definition and prompt translations from `bundle`,
  /// replacing existing entries.
  public static func register(localizationsFrom bundle: CFBundle) throws {
    for operation in AdministrativeAuthorizationOperation.allCases {
      try register(operation, localizationsFrom: bundle)
    }
  }

  /// Registers one operation's definition and prompt translations from `bundle`.
  public static func register(
    _ operation: AdministrativeAuthorizationOperation, localizationsFrom bundle: CFBundle
  ) throws {
    let authorization = try freshAuthorization()
    defer { AuthorizationFree(authorization, .destroyRights) }
    let definition = AdministrativeAuthorizationRule.definition(for: operation) as CFDictionary
    let status = operation.rightName.withCString {
      AuthorizationRightSet(
        authorization, $0, definition, operation.prompt as CFString, bundle,
        "Localizable" as CFString)
    }
    guard status == errAuthorizationSuccess else {
      throw AdministrativeAuthorizationError.rightRegistrationFailed(
        name: operation.rightName, status: status)
    }
  }

  /// Removes every operation's entry. Entries that do not exist are skipped.
  public static func remove() throws {
    for operation in AdministrativeAuthorizationOperation.allCases {
      switch lookup(operation) {
      case .missing:
        continue
      case .failed(let status):
        throw AdministrativeAuthorizationError.rightLookupFailed(
          name: operation.rightName, status: status)
      case .found:
        let authorization = try freshAuthorization()
        defer { AuthorizationFree(authorization, .destroyRights) }
        let status = operation.rightName.withCString { AuthorizationRightRemove(authorization, $0) }
        guard status == errAuthorizationSuccess else {
          throw AdministrativeAuthorizationError.rightRemovalFailed(
            name: operation.rightName, status: status)
        }
      }
    }
  }

  static func freshAuthorization() throws -> AuthorizationRef {
    var authorization: AuthorizationRef?
    let status = AuthorizationCreate(nil, nil, [], &authorization)
    guard status == errAuthorizationSuccess, let authorization else {
      throw AdministrativeAuthorizationError.authorizationCreationFailed(status)
    }
    return authorization
  }
}

public struct OneShotAdministrativeAuthorizer: Sendable {
  public init() {}

  /// Transfer a fresh GUI-session reference; the helper performs the actual one-shot authorization.
  /// Authenticating here and then checking again in the helper cannot work with timeout = 0.
  @MainActor
  public func withExternalAuthorization<T>(
    _ operation: AdministrativeAuthorizationOperation,
    submitting body: @MainActor (Data) async throws -> T
  ) async throws -> T {
    try ensureRight(operation)
    let reference = try AdministrativeAuthorizationRegistry.freshAuthorization()
    defer { AuthorizationFree(reference, .destroyRights) }
    var external = AuthorizationExternalForm()
    let exportStatus = AuthorizationMakeExternalForm(reference, &external)
    guard exportStatus == errAuthorizationSuccess else {
      throw AdministrativeAuthorizationError.authorizationFailed(exportStatus)
    }
    let data = withUnsafeBytes(of: &external) { Data($0) }
    return try await body(data)
  }

  /// The closure must synchronously submit the protected operation. The fresh
  /// authorization reference is destroyed immediately after the closure returns.
  public func perform<T>(
    _ operation: AdministrativeAuthorizationOperation,
    submitting body: () throws -> T
  ) throws -> T {
    try ensureRight(operation)
    let authorization = try AdministrativeAuthorizationRegistry.freshAuthorization()
    defer {
      AuthorizationFree(authorization, .destroyRights)
    }
    try request(operation, authorization: authorization)
    return try body()
  }

  /// A missing right is added with the prompts of this process's bundle. An existing
  /// right is used as it is, because changing it would need a separate administrator
  /// authentication; the installer refreshes existing rights as root.
  private func ensureRight(_ operation: AdministrativeAuthorizationOperation) throws {
    switch AdministrativeAuthorizationRegistry.lookup(operation) {
    case .found(let definition):
      guard AdministrativeAuthorizationRule.isSecure(definition) else {
        throw AdministrativeAuthorizationError.rightDefinitionMismatch(operation.rightName)
      }
    case .missing:
      try AdministrativeAuthorizationRegistry.register(
        operation, localizationsFrom: CFBundleGetMainBundle())
      guard case .found(let definition) = AdministrativeAuthorizationRegistry.lookup(operation),
        AdministrativeAuthorizationRule.isSecure(definition)
      else {
        throw AdministrativeAuthorizationError.rightDefinitionMismatch(operation.rightName)
      }
    case .failed(let status):
      throw AdministrativeAuthorizationError.rightLookupFailed(
        name: operation.rightName,
        status: status
      )
    }
  }

  private func request(
    _ operation: AdministrativeAuthorizationOperation,
    authorization: AuthorizationRef
  ) throws {
    let status = operation.rightName.withCString { rightName in
      var right = AuthorizationItem(
        name: rightName,
        valueLength: 0,
        value: nil,
        flags: 0
      )
      return withUnsafeMutablePointer(to: &right) { rightPointer in
        var rights = AuthorizationRights(count: 1, items: rightPointer)
        // AuthorizationRightSet already registered the action-specific text as
        // this right's description. Repeating it as an invocation prompt makes
        // SecurityAgent render the same sentence twice.
        return AuthorizationCopyRights(
          authorization,
          &rights,
          nil,
          [.interactionAllowed, .extendRights],
          nil
        )
      }
    }
    switch status {
    case errAuthorizationSuccess:
      return
    case errAuthorizationCanceled:
      throw AdministrativeAuthorizationError.canceled
    case errAuthorizationDenied:
      throw AdministrativeAuthorizationError.denied
    case errAuthorizationInteractionNotAllowed:
      throw AdministrativeAuthorizationError.interactionUnavailable
    default:
      throw AdministrativeAuthorizationError.authorizationFailed(status)
    }
  }
}
