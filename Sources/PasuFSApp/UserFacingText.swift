import Foundation
import PasuFSConfiguration
import PasuFSHostCore
import PasuFSIPC
import PasuFSMaintenanceCore
import PasuFSPolicy

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
    case .inherited: String(localized: "Inherited from an observed ancestor process")
    case .systemCompatibilityProfile: String(localized: "System compatibility profile")
    case .none: String(localized: "No matching rule")
    case .decodeError: String(localized: "Process details could not be read")
    case .truncatedPath: String(localized: "The path was truncated")
    case .mountPoint: String(localized: "The mount point covers this policy’s folder")
    case .enclosingFolder:
      String(localized: "The request acts on a folder that contains this policy’s folder")
    }
  }
}

extension SystemCompatibilityProfileState {
  var displayName: String {
    switch self {
    case .active: String(localized: "On")
    case .needsReview: String(localized: "Review needed")
    case .missingProfile: String(localized: "Unavailable")
    case .unsupportedOS: String(localized: "Not supported on this macOS")
    }
  }

  /// Why a profile that is turned on does nothing, or nil while it is active.
  var inactiveReason: String? {
    switch self {
    case .active: nil
    case .needsReview:
      String(localized: "Inactive because the profile changed. Turn it off and on again.")
    case .missingProfile: String(localized: "Inactive because this version doesn’t offer it.")
    case .unsupportedOS: String(localized: "Inactive on this version of macOS.")
    }
  }
}

/// Names and descriptions of the built-in compatibility profiles in the app's language.
enum SystemCompatibilityText {
  static func name(identifier: String) -> String {
    switch identifier {
    case BuiltInSystemCompatibilityCatalog.containerManagementIdentifier:
      String(localized: "App Container Management")
    case BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier:
      String(localized: "XProtect Malware Scanning")
    case BuiltInSystemCompatibilityCatalog.finderCopyIdentifier:
      String(localized: "Finder Copy")
    default:
      identifier
    }
  }

  static func role(_ profile: SystemCompatibilityProfile) -> String {
    switch profile.id {
    case BuiltInSystemCompatibilityCatalog.containerManagementIdentifier:
      String(
        localized:
          "Lets the macOS services that prepare an app’s container, some running as your user account, read it so the app can start."
      )
    case BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier:
      String(
        localized:
          "Lets the macOS malware scanner XProtect read this folder: its remediator plug-ins, running as root or as your user account, while they scan it, and its analysis service, running as root, when Gatekeeper checks an item."
      )
    case BuiltInSystemCompatibilityCatalog.finderCopyIdentifier:
      String(
        localized:
          "Lets the macOS service that carries out Finder’s copies, duplicates and restores from the Time Machine screen, running as root or as your user account, copy files and folders into and out of this folder."
      )
    default:
      profile.roleDescription
    }
  }

  static func consequence(_ profile: SystemCompatibilityProfile) -> String {
    switch profile.id {
    case BuiltInSystemCompatibilityCatalog.containerManagementIdentifier:
      String(localized: "Apple’s container services can read this app container.")
    case BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier:
      String(localized: "Apple’s malware scanner can read this folder.")
    case BuiltInSystemCompatibilityCatalog.finderCopyIdentifier:
      String(
        localized:
          "Finder can copy items into this folder, and copy its items or the whole folder out of it."
      )
    default:
      profile.consequence
    }
  }
}

/// What macOS did with a request whose answer from Pasu FS failed to reach it. macOS decides such
/// a request itself at its deadline, according to the deadline miss mode the extension reports.
/// The mode is the current one, not the one in effect when the record was made.
enum MissedDeadlineOutcome: Equatable {
  case denied
  case allowed
  /// The status names no mode.
  case unknown

  init(_ mode: DeadlineMissModeStatus?) {
    switch mode?.setting {
    case .failClosed: self = .denied
    case .killUnavailable, .killAfterFailure: self = .allowed
    case nil: self = .unknown
    }
  }
}

enum KernelResponseText {
  static let missedDeadline = "response-error"

  /// The answer in the log list. For a request whose answer failed, the answer macOS gave itself.
  static func label(_ response: String, deadlineMissMode: DeadlineMissModeStatus?) -> String {
    switch response {
    case "allow": String(localized: "Allow")
    case "deny": String(localized: "Deny")
    case "notify-only": String(localized: "Notify")
    case missedDeadline:
      switch MissedDeadlineOutcome(deadlineMissMode) {
      case .denied: String(localized: "Deny")
      case .allowed: String(localized: "Allow")
      case .unknown: String(localized: "Missed deadline")
      }
    default: response
    }
  }

  /// The title of a record's details.
  static func headline(_ response: String, deadlineMissMode: DeadlineMissModeStatus?) -> String {
    switch response {
    case "deny": String(localized: "Denied")
    case "allow": String(localized: "Allowed")
    case "notify-only": String(localized: "Notified")
    case missedDeadline:
      switch MissedDeadlineOutcome(deadlineMissMode) {
      case .denied: String(localized: "Denied (missed deadline)")
      case .allowed: String(localized: "Allowed (missed deadline)")
      case .unknown: String(localized: "Missed deadline")
      }
    default: response
    }
  }
}

/// The reason shown with a recorded decision.
enum DecisionReasonText {
  /// The line under a decision in the log list: the profile that allowed the request, or the
  /// recorded reason from the program lists. A profile allows a request the program lists alone
  /// would not, so the lists' reason would contradict the decision.
  static func summary(_ evaluation: PolicyEvaluationRecord) -> String? {
    if evaluation.match == .systemCompatibilityProfile { return match(evaluation) }
    return evaluation.executionOrigin.map { OriginText.reason($0.reason) }
  }

  /// The profile that allowed the request, or how the request matched the policy.
  static func match(_ evaluation: PolicyEvaluationRecord) -> String {
    if let profile = evaluation.systemCompatibilityProfileIdentifier {
      let name = SystemCompatibilityText.name(identifier: profile)
      return String(localized: "Allowed by the compatibility profile “\(name)”")
    }
    return evaluation.match.displayName
  }
}

enum PolicyBehaviorText {
  static func rulesTitle(_ list: PolicyRuleList) -> String {
    switch list {
    case .allow: String(localized: "Programs to Allow")
    case .deny: String(localized: "Programs to Block")
    }
  }

  static func addToListTitle(_ list: PolicyRuleList) -> String {
    switch list {
    case .allow: String(localized: "Add to Programs to Allow")
    case .deny: String(localized: "Add to Programs to Block")
    }
  }

  static func inListTitle(_ list: PolicyRuleList) -> String {
    switch list {
    case .allow: String(localized: "In Programs to Allow")
    case .deny: String(localized: "In Programs to Block")
    }
  }
}

/// Wording for the decision evidence the extension records with each checked open.
enum OriginText {
  static func reason(_ reason: ExecutionOriginDecisionReason) -> String {
    switch reason {
    case .allowed: String(localized: "First program and access process are allowed")
    case .allowedInherited: String(localized: "Access allowed by a descendant rule")
    case .blacklistAllowed: String(localized: "No blocked program in the execution history")
    case .emptyAllowList: String(localized: "No program is allowed")
    case .originNotAllowed: String(localized: "First program is not allowed")
    case .actorNotAllowed: String(localized: "Access process is not allowed")
    case .deniedInHistory: String(localized: "Blocked program in the execution history")
    case .incompleteHistory: String(localized: "Execution history is incomplete")
    case .noFirstProgram: String(localized: "First program is unknown")
    }
  }

  /// Why the history a decision needs could not be established.
  static func uncertainty(_ uncertainty: ExecutionOriginUncertainty) -> String {
    switch uncertainty {
    case .beforeObservation:
      String(localized: "This execution began before the extension started tracking processes.")
    case .eventLoss:
      String(localized: "macOS did not deliver some process events.")
    case .stateLimit:
      String(localized: "The tracked execution history reached its limit and was reset.")
    case .policyChanged:
      String(
        localized:
          "A program was added to a block list, so the earlier execution history can’t be used.")
    case .identityChanged:
      String(localized: "The program changed without an observed execution change.")
    case .decodeFailure:
      String(localized: "A process event could not be read.")
    case .unavailableEventVersion:
      String(localized: "This macOS event version does not number its process events.")
    }
  }

  static func intermediary(_ role: SystemIntermediaryRole) -> String {
    String(localized: "System intermediary (\(role.rawValue))")
  }

  /// How a complete history began, when that differs from an observed launch.
  static func evidence(_ evidence: ExecutionHistoryEvidence) -> String? {
    switch evidence {
    case .observed:
      nil
    case .kernelLaunchdStart:
      String(
        localized:
          "This history begins with a process that launchd started before the extension started tracking processes."
      )
    }
  }
}

enum InstallationStateText {
  /// The notice while macOS doesn't answer requests for the installation states, with what
  /// restarts the system extension daemon that answers them.
  static func unanswered(since: Date, now: Date) -> String {
    let duration = Duration.seconds(max(0, now.timeIntervalSince(since))).formatted(
      .units(allowed: [.hours, .minutes, .seconds], width: .wide, maximumUnitCount: 1))
    return String(
      localized:
        "macOS isn’t reporting the system extension state (for \(duration)). In Terminal, run “sudo killall sysextd”, or restart this Mac."
    )
  }

  /// Why a query produced no installation states. macOS's own error keeps its text.
  static func failureDetail(_ failure: InstallationStateQueryFailure) -> String {
    switch failure {
    case .requestFailed(_, _, let description):
      description
    case .endedWithoutAnswer:
      String(
        localized: "macOS finished the extension query without returning version information.")
    case .launchFailed(let description):
      String(localized: "The installation state check could not start: \(description)")
    case .exited(let status):
      String(
        localized:
          "The installation state check ended with status \(Int(status)) without an answer.")
    case .signaled(let signal):
      String(localized: "The installation state check was ended by signal \(Int(signal)).")
    case .invalidOutput:
      String(localized: "The installation state check returned an unreadable result.")
    }
  }
}

enum PolicyStorageText {
  static func displayName(_ state: PolicyStorageState) -> String {
    switch state {
    case .notConfigured: String(localized: "No saved policies")
    case .ready: String(localized: "Normal")
    case .migrated: String(localized: "Converted from an earlier format")
    case .recovered: String(localized: "Restored from the verified copy")
    case .denyAllRecovery: String(localized: "Damaged; denying every request")
    case .unavailable: String(localized: "Unavailable")
    }
  }

  /// What a state other than the normal ones means for protection.
  static func summary(_ state: PolicyStorageState) -> String? {
    switch state {
    case .notConfigured, .ready:
      nil
    case .migrated:
      String(
        localized:
          "The saved policies were converted from an earlier format. Programs started by an allowed program are no longer allowed automatically."
      )
    case .recovered:
      String(localized: "The saved policies were restored from their verified copy.")
    case .denyAllRecovery:
      String(
        localized:
          "The saved policies are damaged. Protection policies deny every request in their folders until the policies are saved again."
      )
    case .unavailable:
      String(
        localized:
          "The saved policies could not be recovered, so their folders are not protected.")
    }
  }
}

enum LineageText {
  /// The reason of the issue that counts every message number macOS skipped, whatever the kind
  /// of the message, not only process events.
  static let droppedMessagesReason = "kernelEventLoss"

  /// The issue with its count. The count of dropped messages is named as such; the other
  /// issues show it after their explanation, and only above one unless `alwaysShowingCount`.
  static func text(_ issue: LineageIssue, alwaysShowingCount: Bool) -> String {
    if issue.reason == droppedMessagesReason {
      return String(
        localized:
          "Dropped messages (all kinds): \(issue.count). Process changes among them can’t be reconstructed."
      )
    }
    let explanation = explanation(issue)
    return alwaysShowingCount || issue.count > 1 ? "\(explanation) (\(issue.count))" : explanation
  }

  static func explanation(_ issue: LineageIssue) -> String {
    switch issue.reason {
    case "unobserved": String(localized: "Identity reported, but this execution was not observed.")
    case "parentUnavailable":
      String(
        localized:
          "The parent execution identity was not available, so the chain cannot continue here.")
    case "sequenceRestarted":
      String(localized: "The event sequence restarted within this collection.")
    case "queueOverflow":
      String(localized: "The process lineage queue could not accept some observations.")
    case "historyOmitted":
      String(localized: "Process lineage was left out to keep the access record under load.")
    case "historyBudgetExceeded":
      String(localized: "Process lineage did not fit within the pending-work budget.")
    case "resourceLimit":
      String(
        localized:
          "The process lineage data budget ran out, so some observations were not kept.")
    case "decodeError": String(localized: "Some process event fields could not be read.")
    case "cycle":
      String(
        localized:
          "Conflicting circular relationships were observed and were not treated as a single line of ancestors."
      )
    case "oversizedRecord":
      String(
        localized:
          "The complete process lineage exceeded the log file limit and could not be stored.")
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
    case .parent: String(localized: "Parent process reported by macOS")
    case .responsible: String(localized: "Responsibility reported by macOS")
    }
  }

  static func lossAccountingWarning(version: Int?, issues: [LineageIssue]) -> String? {
    guard LineageIssue.lossAccountingWarning(version: version, issues: issues) != nil else {
      return nil
    }
    return String(
      localized:
        "This older collector could count local queue losses again as dropped messages. These two counts may overlap."
    )
  }
}

/// Translates recognized English messages from the host library and the system extension.
enum RuntimeText {
  static func localized(_ message: String) -> String {
    // The extension reports separate warnings on separate lines.
    if message.contains("\n") {
      return message.split(separator: "\n").map { localized(String($0)) }.joined(separator: "\n")
    }
    if let exact = exactTranslation(message) {
      return exact
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
    case HealthStateReducer.installationStatesUnreportedReason:
      String(localized: "macOS isn’t reporting the system extension state.")
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
      String(localized: "The extension could not subscribe to process lineage events.")
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
    case "The audit log is unavailable.":
      String(localized: "Logs are unavailable.")
    case "Policy storage migrated. Review and enable descendant access for each allowed program.":
      String(
        localized:
          "Previous descendant settings are off. Enable them for each program you trust."
      )
    case "The latest committed policy was recovered from its verified copy.":
      String(localized: "The primary copy was unreadable and has been repaired.")
    case "Both current policy copies are unavailable. Known Protection scopes deny all access until a newer valid policy is saved.",
      "Recovery protection denies access in known Protection scopes until a newer valid policy is saved.":
      String(
        localized:
          "Both copies of the saved policies are unreadable. Their programs can’t be restored.")
    case "The protected root must be an absolute path.":
      ProtectedFolderIssue.notAbsolute.userFacingMessage
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
    // The form that extension versions before 0.9.0 sent.
    (
      "Stored policy set rejected: ",
      { String(localized: "The saved policies were rejected: \($0)") }
    ),
    (
      "Stored policy set rejected; protected scopes could not be recovered: ",
      { String(localized: "The saved policies were rejected: \($0)") }
    ),
    (
      "The current policy copy is active, but repairing its primary failed: ",
      { String(localized: "The primary copy could not be repaired: \($0)") }
    ),
    (
      "The protected root does not exist: ",
      { "\(ProtectedFolderIssue.missing.userFacingMessage) \($0)" }
    ),
    (
      "The protected root is not a directory: ",
      { "\(ProtectedFolderIssue.notDirectory.userFacingMessage) \($0)" }
    ),
    (
      "Choose a folder below the home or system directory: ",
      { "\(ProtectedFolderIssue.tooBroad($0).userFacingMessage) \($0)" }
    ),
    (
      "Policy-set identifier ",
      { _ in
        String(
          localized:
            "The extension stores a different policy set. Pasu FS is loading the saved policies again."
        )
      }
    ),
    (
      "Status persistence failed: ",
      { String(localized: "The status file could not be saved: \($0)") }
    ),
    (
      "Protected volume unmounted: ",
      {
        String(
          localized:
            "A volume at \($0) was unmounted. Check the protected folders there, then save the policies again to clear this notice."
        )
      }
    ),
    (
      "Protected folder missing: ",
      {
        String(
          localized:
            "A protected folder can’t be found: \($0). Its last path stays protected.")
      }
    ),
    (
      "Protected folder moved but not followed: ",
      {
        String(
          localized: "A protected folder moved, but its policy could not be updated: \($0)")
      }
    ),
    (
      "Protected folder check failed: ",
      { String(localized: "The protected folders could not be checked: \($0)") }
    ),
    (
      "es_new_client failed: ",
      { String(localized: "The Endpoint Security client could not be created: \($0)") }
    ),
  ]

  private static func profileWarningTranslation(_ message: String) -> String? {
    let prefix = "System-compatibility profile "
    for (separator, inactive) in [(" is inactive: ", true), (" cannot be turned on: ", false)] {
      guard message.hasPrefix(prefix), message.hasSuffix("."),
        let range = message.range(of: separator)
      else { continue }
      let identifier = String(
        message[message.index(message.startIndex, offsetBy: prefix.count)..<range.lowerBound])
      let name = SystemCompatibilityText.name(identifier: identifier)
      let rawState = String(message[range.upperBound...].dropLast())
      let state = SystemCompatibilityProfileState(rawValue: rawState)?.displayName ?? rawState
      return inactive
        ? String(localized: "Compatibility profile “\(name)” is inactive: \(state)")
        : String(localized: "Compatibility profile “\(name)” can’t be turned on: \(state)")
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
    if tail.hasPrefix(" is older than active revision ")
      || tail == " has different contents from the active policy set."
    {
      return String(
        localized: "The saved policies changed after they were loaded. Save again once they reload."
      )
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
    case let error as ProgramRuleReaderError:
      return programRuleReader(error)
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
      case .timeout:
        return String(localized: "The extension did not reply in time: \(detail)")
      case .authorizationRequired:
        return String(
          localized:
            "This change reduces protection and needs administrator authentication: \(detail)")
      case .authorizationCanceled:
        return String(
          localized: "Administrator authentication was canceled. The policies were not changed.")
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
    case .tooManyCompatibilityProfiles(let policy, _):
      return String(
        localized:
          "“\(policy)” can turn on up to \(PolicySetDocument.maximumCompatibilityProfilesPerPolicy) compatibility profiles."
      )
    case .invalidCompatibilityProfileDigest(let policy, _),
      .duplicateCompatibilityProfile(let policy, _):
      return String(localized: "“\(policy)” has an invalid compatibility profile entry.")
    }
  }

  static func programRuleReader(_ error: ProgramRuleReaderError) -> String {
    switch error {
    case .invalidSignature:
      return String(localized: "The program’s code signature is invalid.")
    case .unsupportedIdentity:
      return String(
        localized:
          "This program is unsigned or ad-hoc signed. Only developer-signed programs and Apple platform binaries can be added."
      )
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
    case .connectionInterrupted:
      String(localized: "The connection to the extension was interrupted before it replied.")
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
          "Quit Pasu FS normally, then run the installer again or start uninstalling again from the app. Protection continues when the app quits. Another login session may also have Pasu FS open."
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
