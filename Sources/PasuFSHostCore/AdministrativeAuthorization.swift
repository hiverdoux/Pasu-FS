import Foundation
import Security

public enum AdministrativeAuthorizationOperation: String, CaseIterable, Sendable {
  case extensionActivate = "com.example.pasu.fs.extension.activate"
  case extensionDeactivate = "com.example.pasu.fs.extension.deactivate"
  case policyModify = "com.example.pasu.fs.policy.modify"
  case compatibilityModify = "com.example.pasu.fs.compatibility.modify"
  case uninstall = "com.example.pasu.fs.uninstall"

  public var rightName: String { rawValue }

  public var prompt: String {
    switch self {
    case .extensionActivate:
      "Administrator authentication is required to activate the Pasu FS protection system extension."
    case .extensionDeactivate:
      "Administrator authentication is required to deactivate the Pasu FS protection system extension."
    case .policyModify:
      "Administrator authentication is required to modify Pasu FS protection policies from the command line."
    case .compatibilityModify:
      "Administrator authentication is required to modify Pasu FS system-compatibility profiles from the command line."
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
    case .policyModify:
      "Authorizes one command-line Pasu FS policy modification."
    case .compatibilityModify:
      "Authorizes one command-line Pasu FS system-compatibility modification."
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
    case .rightDefinitionMismatch(let name):
      "Authorization right \(name) does not require the expected one-time, non-shared administrator authentication. The system-extension request was not submitted."
    case .canceled:
      "Administrator authentication was canceled. The system-extension request was not submitted."
    case .denied:
      "Administrator authentication was denied. The system-extension request was not submitted."
    case .interactionUnavailable:
      "Administrator authentication requires an interactive macOS login session. The system-extension request was not submitted."
    case .authorizationFailed(let status):
      "Administrator authentication failed: \(statusDescription(status)). The system-extension request was not submitted."
    }
  }

  private func statusDescription(_ status: OSStatus) -> String {
    if let message = SecCopyErrorMessageString(status, nil) as String? {
      return "\(message) (\(status))"
    }
    return "OSStatus \(status)"
  }
}

public struct OneShotAdministrativeAuthorizer: Sendable {
  private enum RightLookup {
    case found(CFDictionary)
    case failed(OSStatus)
  }

  public init() {}

  /// Transfer a fresh GUI-session reference; the helper performs the actual one-shot authorization.
  /// Authenticating here and then checking again in the helper cannot work with timeout = 0.
  @MainActor
  public func withExternalAuthorization<T>(
    _ operation: AdministrativeAuthorizationOperation,
    submitting body: @MainActor (Data) async throws -> T
  ) async throws -> T {
    try ensureRight(operation)
    var reference: AuthorizationRef?
    let status = AuthorizationCreate(nil, nil, [], &reference)
    guard status == errAuthorizationSuccess, let reference else {
      throw AdministrativeAuthorizationError.authorizationCreationFailed(status)
    }
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

    var authorization: AuthorizationRef?
    let createStatus = AuthorizationCreate(
      nil,
      nil,
      [],
      &authorization
    )
    guard createStatus == errAuthorizationSuccess, let authorization else {
      throw AdministrativeAuthorizationError.authorizationCreationFailed(createStatus)
    }
    defer {
      AuthorizationFree(authorization, .destroyRights)
    }

    try request(operation, authorization: authorization)
    return try body()
  }

  private func ensureRight(_ operation: AdministrativeAuthorizationOperation) throws {
    let lookup = rightDefinition(named: operation.rightName)
    switch lookup {
    case .found(let definition):
      guard AdministrativeAuthorizationRule.isSecure(definition) else {
        throw AdministrativeAuthorizationError.rightDefinitionMismatch(operation.rightName)
      }
    case .failed(let status) where status == errAuthorizationDenied:
      try registerRight(operation)
      guard case .found(let definition) = rightDefinition(named: operation.rightName),
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

  private func rightDefinition(named name: String) -> RightLookup {
    var definition: CFDictionary?
    let status = name.withCString {
      AuthorizationRightGet($0, &definition)
    }
    guard status == errAuthorizationSuccess, let definition else {
      return .failed(status)
    }
    return .found(definition)
  }

  private func registerRight(_ operation: AdministrativeAuthorizationOperation) throws {
    var authorization: AuthorizationRef?
    let createStatus = AuthorizationCreate(nil, nil, [], &authorization)
    guard createStatus == errAuthorizationSuccess, let authorization else {
      throw AdministrativeAuthorizationError.authorizationCreationFailed(createStatus)
    }
    defer {
      AuthorizationFree(authorization, .destroyRights)
    }

    let definition = AdministrativeAuthorizationRule.definition(for: operation) as CFDictionary
    let status = operation.rightName.withCString {
      AuthorizationRightSet(
        authorization,
        $0,
        definition,
        operation.prompt as CFString,
        nil,
        nil
      )
    }
    guard status == errAuthorizationSuccess else {
      throw AdministrativeAuthorizationError.rightRegistrationFailed(
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
