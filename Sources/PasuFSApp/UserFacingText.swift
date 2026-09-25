import Foundation
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSIPC
import PasuFSMaintenanceCore

// User-facing wording lives here so every screen names the same concept the same way.
// Messages produced by the system extension or shared libraries stay in English there,
// because those components do not run in the user's language. The app translates the
// messages it recognizes and shows any other message unchanged.

extension PolicyMode {
  var displayName: String {
    switch self {
    case .protection: String(localized: "Protection")
    case .audit: String(localized: "Audit")
    }
  }

  var symbolName: String {
    switch self {
    case .protection: "checkmark.shield"
    case .audit: "eye"
    }
  }
}

extension PolicyType {
  var displayName: String {
    switch self {
    case .whitelist: String(localized: "Whitelist")
    case .blacklist: String(localized: "Blacklist")
    }
  }
}

extension PolicyRuleKind {
  var displayName: String {
    switch self {
    case .teamSigned: String(localized: "Developer signed")
    case .platformBinary: String(localized: "Apple platform binary")
    }
  }
}

extension PolicyEvaluationDecision {
  var displayName: String {
    switch self {
    case .allow: String(localized: "Allow")
    case .deny: String(localized: "Deny")
    case .wouldAllow: String(localized: "Would allow")
    case .wouldDeny: String(localized: "Would deny")
    }
  }

  var isDenial: Bool { self == .deny || self == .wouldDeny }
}

extension PolicyRuleMatchKind {
  var displayName: String {
    switch self {
    case .direct: String(localized: "Matched a rule")
    case .inherited: String(localized: "Inherited from an observed parent process")
    case .systemCompatibilityProfile: String(localized: "System compatibility profile")
    case .none: String(localized: "No matching rule")
    case .decodeError: String(localized: "Process details could not be read")
    case .truncatedPath: String(localized: "The path was truncated")
    }
  }
}

extension SystemCompatibilityProfileState {
  var displayName: String {
    switch self {
    case .active: String(localized: "On")
    case .disabled: String(localized: "Off")
    case .needsReview: String(localized: "Review needed")
    case .missingProfile: String(localized: "Unavailable")
    case .unsupportedOS: String(localized: "Not supported on this macOS")
    case .policyContextChanged: String(localized: "Policy changed")
    case .policyMissing: String(localized: "Policy unavailable")
    }
  }

  var needsReview: Bool {
    self == .needsReview || self == .policyContextChanged
  }
}

enum KernelResponseText {
  static func label(_ response: String) -> String {
    switch response {
    case "allow": String(localized: "Allow")
    case "deny": String(localized: "Deny")
    case "notify-only": String(localized: "Notify")
    case "response-error": String(localized: "Error")
    default: response
    }
  }
}

enum PolicyBehaviorText {
  static func rulesTitle(_ type: PolicyType) -> String {
    switch type {
    case .whitelist: String(localized: "Programs to Allow")
    case .blacklist: String(localized: "Programs to Block")
    }
  }

  static func addToListTitle(_ type: PolicyType) -> String {
    switch type {
    case .whitelist: String(localized: "Add to Whitelist")
    case .blacklist: String(localized: "Add to Blacklist")
    }
  }

  static func inListTitle(_ type: PolicyType) -> String {
    switch type {
    case .whitelist: String(localized: "In Whitelist")
    case .blacklist: String(localized: "In Blacklist")
    }
  }

  static func descendantsWarning(_ type: PolicyType) -> String {
    switch type {
    case .whitelist:
      String(
        localized:
          "Everything this program starts can open the files too, including commands run in a shell."
      )
    case .blacklist:
      String(
        localized:
          "Everything this program starts is blocked too, including helpers other apps share."
      )
    }
  }
}

enum LineageText {
  static func explanation(_ issue: LineageIssue) -> String {
    switch issue.reason {
    case "unobserved": String(localized: "Identity reported, but this execution was not observed.")
    case "parentUnavailable":
      String(
        localized:
          "The parent execution identity was not available, so the chain cannot continue here.")
    case "kernelEventLoss":
      String(
        localized:
          "macOS event delivery had gaps. Transitions that were not observed cannot be reconstructed."
      )
    case "sequenceRestarted":
      String(localized: "The event sequence restarted within this collection.")
    case "queueOverflow":
      String(localized: "The process history queue could not accept some observations.")
    case "historyOmitted":
      String(localized: "Process history was left out to keep the access record under load.")
    case "historyBudgetExceeded":
      String(localized: "Process history did not fit within the pending-work budget.")
    case "resourceLimit":
      String(
        localized:
          "The process history data budget ran out, so some observations were not kept.")
    case "decodeError": String(localized: "Some process event fields could not be read.")
    case "cycle":
      String(
        localized:
          "Conflicting circular relationships were observed and were not treated as a single line of ancestors."
      )
    case "oversizedRecord":
      String(
        localized:
          "The complete process history exceeded the log file limit and could not be stored.")
    case "mutedLifecycle":
      String(localized: "macOS excludes some process lifecycle events from this client.")
    case "muteInspectionFailed":
      String(localized: "The macOS event exclusion list could not be inspected.")
    case "versionUnavailable":
      String(
        localized: "This event version did not include parent and responsibility identities.")
    case "executionMismatch":
      String(
        localized:
          "The execution change did not identify the same process, so it was not linked.")
    default: issue.explanation
    }
  }

  static func relation(_ kind: LineageRelationKind) -> String {
    switch kind {
    case .fork: String(localized: "Child creation observed")
    case .exec: String(localized: "Program replaced in the same process")
    case .parent: String(localized: "Parent reported by macOS")
    case .responsible: String(localized: "Responsibility reported by macOS")
    }
  }

  static func lossAccountingWarning(version: Int?, issues: [LineageIssue]) -> String? {
    guard LineageIssue.lossAccountingWarning(version: version, issues: issues) != nil else {
      return nil
    }
    return String(
      localized:
        "This older collector could count local queue losses again as macOS delivery gaps. These two counts may overlap."
    )
  }
}

enum AuditBatchText {
  /// Everything that makes the loaded records incomplete. These notes are never hidden. The
  /// 500-record load limit isn't repeated here because the log header always states it.
  static func limitations(of batch: AuditLogBatch) -> String? {
    var parts: [String] = []
    if let warning = batch.warning {
      parts.append(RuntimeText.localized(warning))
    }
    if batch.droppedEventCount > 0 {
      parts.append(
        String(localized: "\(batch.droppedEventCount) records couldn’t be saved during this run."))
    }
    if batch.skippedLineCount > 0 {
      parts.append(String(localized: "\(batch.skippedLineCount) unreadable lines were skipped."))
    }
    return parts.isEmpty ? nil : parts.joined(separator: " ")
  }
}

/// Translates recognized English messages from the host library and the system extension.
enum RuntimeText {
  static func localized(_ message: String) -> String {
    if let exact = exactTranslation(message) {
      return exact
    }
    let storage = SystemCompatibilityWarningState.storageRejectionMessage
    if message.hasPrefix(storage + " ") {
      return localized(storage) + " " + localized(String(message.dropFirst(storage.count + 1)))
    }
    if let profileWarning = profileWarningTranslation(message) {
      return profileWarning
    }
    if let revisionMessage = revisionTranslation(message) {
      return revisionMessage
    }
    for (prefix, translate) in prefixedTranslations where message.hasPrefix(prefix) {
      return translate(String(message.dropFirst(prefix.count)))
    }
    return message
  }

  private static func exactTranslation(_ message: String) -> String? {
    switch message {
    case "Authenticated runtime status is stale.":
      String(
        localized:
          "The extension status has not been updated for more than 15 seconds. Pasu FS cannot confirm that protection is still running."
      )
    case "Only an unauthenticated diagnostic status file is available.":
      String(
        localized:
          "The authenticated connection is unavailable, so only the diagnostic file was read. The diagnostic file cannot confirm protection."
      )
    case "The extension reported idle without a policy-set revision.",
      "The extension reported enforcement without a policy revision.",
      "The extension reported monitoring without a policy revision.":
      String(
        localized:
          "The extension reported its state without a policy revision, so the state cannot be trusted."
      )
    case "The extension is degraded.":
      String(localized: "The extension reported that it is not working normally.")
    case SetupProgress.awaitingFirstPolicyReason:
      String(localized: "No saved policy yet.")
    case "Process history event subscription failed.":
      String(localized: "The extension could not subscribe to process history events.")
    case "Full Disk Access is required.":
      String(localized: "Full Disk Access is required.")
    case "Creating the Endpoint Security client.":
      String(localized: "Starting the Endpoint Security client.")
    case "Endpoint Security client stopped.":
      String(localized: "The Endpoint Security client stopped.")
    case "An unrecognized legacy policy file was not removed or activated.":
      String(localized: "An unrecognized old policy file was neither removed nor applied.")
    case "The schema v1 policy was permanently removed. Create new policies.":
      String(
        localized:
          "The old single-policy file was permanently removed. Create the policies again.")
    case SystemCompatibilityWarningState.storageRejectionMessage:
      String(
        localized:
          "Saved system compatibility settings could not be read, validated or trusted. No compatibility profile is active."
      )
    case "The audit log is unavailable.":
      String(localized: "Logs are unavailable.")
    default:
      nil
    }
  }

  private static let prefixedTranslations: [(String, @Sendable (String) -> String)] = [
    (
      "Stored policy set could not be activated: ",
      { String(localized: "The saved policies could not be applied: \($0)") }
    ),
    (
      "Authenticated XPC unavailable: ",
      { String(localized: "The authenticated connection is unavailable: \($0)") }
    ),
    (
      "The legacy policy could not be retired and was not activated: ",
      {
        String(
          localized: "The old single-policy file could not be removed and was not applied: \($0)")
      }
    ),
    (
      "Stored policy set rejected: ",
      { String(localized: "The saved policies were rejected: \($0)") }
    ),
    (
      "Status persistence failed: ",
      { String(localized: "The status file could not be saved: \($0)") }
    ),
    (
      "es_new_client failed: ",
      { String(localized: "The Endpoint Security client could not be created: \($0)") }
    ),
  ]

  private static func profileWarningTranslation(_ message: String) -> String? {
    let prefix = "System-compatibility profile "
    let separator = " is inactive: "
    if message.hasPrefix(prefix), message.hasSuffix("."),
      let range = message.range(of: separator)
    {
      let identifier = String(
        message[message.index(message.startIndex, offsetBy: prefix.count)..<range.lowerBound])
      let rawState = String(message[range.upperBound...].dropLast())
      let state = SystemCompatibilityProfileState(rawValue: rawState)?.displayName ?? rawState
      return String(localized: "Compatibility profile \(identifier) is inactive: \(state)")
    }
    let suffix = " enabled system-compatibility profiles are inactive."
    if message.hasSuffix(suffix), let count = Int(message.dropLast(suffix.count)) {
      return String(localized: "\(count) turned-on compatibility profiles are inactive.")
    }
    return nil
  }

  private static func revisionTranslation(_ message: String) -> String? {
    let prefix = "Policy-set revision "
    guard message.hasPrefix(prefix) else { return nil }
    let rest = message.dropFirst(prefix.count)
    let digits = rest.prefix { $0.isASCII && $0.isNumber }
    guard let revision = UInt64(digits) else { return nil }
    let tail = String(rest.dropFirst(digits.count))
    let activationFailure = " was accepted but could not be activated: "
    if tail.hasPrefix(activationFailure) {
      let detail = String(tail.dropFirst(activationFailure.count))
      return String(
        localized: "Policy revision \(revision) was accepted but could not be applied: \(detail)")
    }
    if tail == " is accepted but Endpoint Security is unavailable." {
      return String(
        localized:
          "Policy revision \(revision) was accepted, but Endpoint Security is unavailable.")
    }
    return nil
  }
}

/// A message suitable for the screen, for errors from any layer.
enum UserFacingError {
  static func message(_ error: any Error) -> String {
    switch error {
    case let error as UserFacingErrorConvertible:
      return error.userFacingMessage
    case let error as PolicyValidationError:
      return policyValidation(error)
    case let error as ExtensionControlClientError:
      return extensionClient(error)
    case let error as MaintenanceError:
      return maintenance(error.code, detail: error.detail)
    case let error as AdministrativeAuthorizationError:
      return authorization(error)
    default:
      break
    }
    let nsError = error as NSError
    if nsError.domain == MaintenanceContract.errorDomain,
      let rawCode = nsError.userInfo[MaintenanceContract.errorCodeKey] as? String,
      let code = MaintenanceErrorCode(rawValue: rawCode)
    {
      return maintenance(
        code, detail: nsError.userInfo[MaintenanceContract.errorDetailKey] as? String)
    }
    if nsError.domain == PasuFSXPCError.domain {
      let detail = RuntimeText.localized(nsError.localizedDescription)
      switch PasuFSXPCErrorCode(rawValue: nsError.code) {
      case .policyRejected:
        return String(localized: "The extension rejected the policies: \(detail)")
      case .systemCompatibilitySettingsRejected:
        return String(
          localized: "The extension rejected the system compatibility settings: \(detail)")
      case .timeout:
        return String(localized: "The extension did not reply in time: \(detail)")
      default:
        return String(localized: "The extension reported an error: \(detail)")
      }
    }
    if let described = nsError.userInfo[NSLocalizedDescriptionKey] as? String {
      return described
    }
    if let localized = (error as? LocalizedError)?.errorDescription {
      return localized
    }
    return String(describing: error)
  }

  static func authorization(_ error: AdministrativeAuthorizationError) -> String {
    switch error {
    case .authorizationCreationFailed(let status):
      let code = String(status)
      return String(
        localized:
          "A fresh administrator authorization session could not be created (OSStatus \(code)).")
    case .rightLookupFailed(let name, let status):
      let code = String(status)
      return String(
        localized: "The authorization right \(name) could not be read (OSStatus \(code)).")
    case .rightRegistrationFailed(let name, let status):
      let code = String(status)
      return String(
        localized: "The authorization right \(name) could not be registered (OSStatus \(code)).")
    case .rightRemovalFailed(let name, let status):
      let code = String(status)
      return String(
        localized: "The authorization right \(name) could not be removed (OSStatus \(code)).")
    case .rightDefinitionMismatch(let name):
      return String(
        localized:
          "The authorization right \(name) does not require a fresh, non-shared administrator authentication. Reinstall the Pasu FS package."
      )
    case .canceled:
      return String(localized: "Administrator authentication was canceled. Nothing was changed.")
    case .denied:
      return String(localized: "Administrator authentication was denied. Nothing was changed.")
    case .interactionUnavailable:
      return String(
        localized: "Administrator authentication needs an interactive macOS login session.")
    case .authorizationFailed(let status):
      let code = String(status)
      return String(localized: "Administrator authentication failed (OSStatus \(code)).")
    }
  }

  static func policyValidation(_ error: PolicyValidationError) -> String {
    switch error {
    case .unsupportedSchemaVersion(let version):
      return String(localized: "This policy format (version \(version)) is not supported.")
    case .invalidRevision:
      return String(localized: "The policy revision must be greater than zero.")
    case .tooManyPolicies:
      return String(
        localized: "You can create up to \(PolicySetDocument.maximumPolicyCount) policies.")
    case .tooManyRules:
      return String(
        localized:
          "All policies together can contain up to \(PolicySetDocument.maximumRuleCount) rules.")
    case .duplicatePolicyID:
      return String(localized: "Two policies have the same internal ID.")
    case .invalidPolicyName:
      return String(
        localized:
          "Enter a policy name of up to \(PolicySetDocument.maximumPolicyNameLength) characters without leading or trailing spaces or control characters."
      )
    case .duplicatePolicyName(let name):
      return String(localized: "Another policy is already named “\(name)”.")
    case .protectedRootMustBeAbsolute(let name):
      return String(localized: "Choose the folder for “\(name)”.")
    case .duplicateModeAndDirectory(let mode, let path):
      return String(
        localized: "Another \(mode.displayName) policy already uses this folder: \(path)")
    case .invalidIdentifier(let field):
      switch field {
      case "signing identifier":
        return String(
          localized:
            "Check every program’s Signing ID. It can’t be empty, longer than 512 characters, padded with spaces or contain control characters."
        )
      case "team identifier":
        return String(
          localized:
            "Check every program’s Team ID. It can’t be empty, longer than 512 characters, padded with spaces or contain control characters."
        )
      default:
        return String(localized: "A rule has an invalid internal ID.")
      }
    case .teamIdentifierRequired:
      return String(localized: "Enter a Team ID for every developer-signed program.")
    case .teamIdentifierForbidden:
      return String(localized: "An Apple platform binary rule can’t have a Team ID.")
    case .duplicateRuleID(let policy, _):
      return String(localized: "“\(policy)” has two rules with the same internal ID.")
    case .duplicateIdentity(let policy, _):
      return String(localized: "“\(policy)” already has a rule for this program.")
    }
  }

  static func extensionClient(_ error: ExtensionControlClientError) -> String {
    switch error {
    case .interfaceUnavailable:
      String(localized: "Pasu FS can’t connect to the extension.")
    case .invalidReply:
      String(localized: "The extension returned an invalid reply.")
    case .handshakeMismatch:
      String(localized: "The extension connection check failed.")
    case .configurationProtocolMismatch(let expected, let actual):
      String(
        localized:
          "The app and extension use different configuration versions (app \(expected), extension \(actual)). Install a matching package."
      )
    case .requestTimedOut:
      String(localized: "The extension did not reply in time.")
    case .policyAuditLogUnsupported:
      String(
        localized:
          "The running extension can’t show policy logs. Update the extension to view this tab.")
    }
  }

  /// Failures reported by the maintenance service, its client and the removal code. The code
  /// travels across XPC and through the uninstall state file; the detail is the variable part.
  static func maintenance(_ code: MaintenanceErrorCode, detail: String?) -> String {
    let detail = detail ?? ""
    switch code {
    case .messageTooLarge:
      return String(localized: "A message to the maintenance service was too large.")
    case .unknownStateFormat:
      return String(localized: "The uninstall progress file has an unknown format.")
    case .invalidPackageBuildVersion:
      return String(localized: "The package build number is invalid.")
    case .installedBuildVersionUnknown:
      return String(
        localized:
          "The installed build number could not be determined. The installation was not changed."
      )
    case .downgradeNotSupported:
      return String(
        localized:
          "A newer Pasu FS build is installed. Going back to an older build is not supported.")
    case .approvalExpired:
      return String(
        localized: "The uninstall approval expired or belongs to another request. Try again.")
    case .unsafeRemovalPath:
      return String(localized: "The removal path is not safe.")
    case .removalTargetUntrusted:
      return String(
        localized: "The removal target has an unexpected owner or is a symbolic link: \(detail)")
    case .unexpectedOwner:
      return String(
        localized: "An item with an unexpected owner was found during removal: \(detail)")
    case .mountCrossingRefused:
      return String(localized: "Items on another volume are not removed.")
    case .removalTargetChanged:
      return String(localized: "The removal target changed during removal, so removal stopped.")
    case .systemCallFailed:
      return String(localized: "A file operation failed: \(detail).")
    case .authorizationMalformed:
      return String(localized: "The uninstall approval is missing or damaged.")
    case .authorizationInvalid:
      return String(localized: "The uninstall approval is invalid (OSStatus \(detail)).")
    case .authorizationRuleUnexpected:
      return String(
        localized: "The uninstall approval rule is not the expected one-time administrator rule.")
    case .authorizationCanceled:
      return String(localized: "Administrator authentication was canceled. No files were removed.")
    case .authorizationDenied:
      return String(
        localized: "Administrator approval for uninstalling was not granted (OSStatus \(detail)).")
    case .invalidHandshake:
      return String(localized: "The maintenance service connection check is invalid.")
    case .requestInProgress:
      return String(localized: "Another uninstall request is already in progress.")
    case .noCurrentApproval:
      return String(localized: "There is no current uninstall approval.")
    case .notRunningAsRoot:
      return String(
        localized: "The maintenance executable must be started by macOS Installer or launchd.")
    case .unsupportedOperation:
      return String(localized: "The maintenance operation is not supported.")
    case .commandFailed:
      return String(localized: "A command failed: \(detail)")
    case .runningApplicationsUnknown:
      return String(localized: "Running Pasu FS apps could not be checked.")
    case .applicationRunning:
      return String(
        localized:
          "Quit Pasu FS normally, then run the installer or uninstaller again. Protection continues when the app quits. Another login session may also have Pasu FS open."
      )
    case .installationPathUnreadable:
      return String(localized: "The installation path could not be inspected.")
    case .installationPathNotDirectory:
      return String(
        localized: "The Pasu FS installation path is not a real folder. No files were changed.")
    case .installationPathOccupied:
      return String(
        localized: "Another app or an unrecognized folder occupies the installation path.")
    case .installedVersionUnreadable:
      return String(localized: "The existing app has no readable build number or package receipt.")
    case .componentPermissionsUnsafe:
      return String(
        localized: "The installed maintenance component has unsafe ownership or permissions.")
    case .helperSignatureMismatch:
      return String(localized: "The maintenance service signature does not match this app.")
    case .helperMismatch:
      return String(
        localized:
          "The installed maintenance service does not match this app. Reinstall the package.")
    case .applicationDidNotExit:
      return String(localized: "Pasu FS did not quit. Open the app and try uninstalling again.")
    case .receiptUnverifiable:
      return String(
        localized: "The package receipt could not be verified during removal: \(detail)")
    case .dataDirectoryNotRemoved:
      return String(localized: "The product data folder could not be removed.")
    case .authorizationRightsNotRegistered:
      return String(
        localized: "The Pasu FS authorization rights could not be registered: \(detail)")
    case .authorizationRightsNotRemoved:
      return String(localized: "The Pasu FS authorization rights could not be removed: \(detail)")
    case .handshakeMismatch:
      return String(localized: "The maintenance service reply did not match this app.")
    case .connectionLost:
      return String(localized: "The uninstall connection was lost. Try again.")
    case .requestNotAccepted:
      return String(localized: "The uninstall request was not accepted.")
    case .serviceUnavailable:
      return String(
        localized: "The maintenance service is unavailable. Reinstall the Pasu FS package.")
    case .serviceNoReply:
      return String(
        localized:
          "The maintenance service did not reply. Check its background-item permission or reinstall the package."
      )
    case .invalidReply:
      return String(localized: "The maintenance service sent an invalid reply.")
    case .internalFailure:
      return String(localized: "The maintenance operation failed: \(detail)")
    }
  }
}

/// Errors defined by the app provide their own screen text.
protocol UserFacingErrorConvertible: Error {
  var userFacingMessage: String { get }
}

/// A step of the uninstall flow that the app itself refused, with text already localized.
struct UninstallFlowError: UserFacingErrorConvertible {
  let userFacingMessage: String
  init(_ message: String) { userFacingMessage = message }
}
