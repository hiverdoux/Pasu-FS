import Foundation
import PasuFSConfiguration

/// Sends a policy set to the extension, with a fresh administrator authorization when the
/// change reduces protection. `savedPolicyIdentifier` names the policy the user saved.
@MainActor
public protocol PolicyChangeAuthorizing {
  func apply(
    _ document: PolicySetDocument, weakening: Bool, savedPolicyIdentifier: UUID?,
    using client: any ExtensionRuntimeControlling
  ) async throws -> PolicyApplyReceipt
}

/// Transfers a fresh authorization session for a weakening change; the extension performs
/// the actual one-shot authorization and macOS shows the password dialog meanwhile.
public struct SystemPolicyChangeAuthorizer: PolicyChangeAuthorizing {
  public init() {}

  public func apply(
    _ document: PolicySetDocument, weakening: Bool, savedPolicyIdentifier: UUID?,
    using client: any ExtensionRuntimeControlling
  ) async throws -> PolicyApplyReceipt {
    guard weakening else {
      return try await client.applyPolicySet(
        document, authorization: nil, savedPolicyIdentifier: savedPolicyIdentifier)
    }
    return try await OneShotAdministrativeAuthorizer().withExternalAuthorization(.policyWeaken) {
      data in
      try await client.applyPolicySet(
        document, authorization: data, savedPolicyIdentifier: savedPolicyIdentifier)
    }
  }
}
