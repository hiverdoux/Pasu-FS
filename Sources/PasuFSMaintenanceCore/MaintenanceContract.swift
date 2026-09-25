import Darwin
import Foundation
import PasuFSConfiguration

public enum MaintenanceContract {
  public static let service = "com.example.pasu.fs.maintenance"
  public static let packageIdentifier = "com.example.pasu.fs.pkg"
  public static let appPath = "/Applications/Pasu FS.app"
  public static let helperPath = "/Library/PrivilegedHelperTools/\(service)"
  public static let daemonPath = "/Library/LaunchDaemons/\(service).plist"
  public static let embeddedHelperPath = "Contents/Library/LaunchServices/\(service)"
  public static let stateFilename = "uninstall-state.json"
  public static let protocolVersion = 1
  public static let maximumMessageSize = 16 * 1024
  public static let errorDomain = "com.example.pasu.fs.maintenance"
  /// User-info keys that carry a `MaintenanceError` across XPC so the app can show it in the
  /// user's language. String values survive secure archiving; the English description stays in
  /// `NSLocalizedDescriptionKey` for logs and for clients that do not know the code.
  public static let errorCodeKey = "PasuFSMaintenanceErrorCode"
  public static let errorDetailKey = "PasuFSMaintenanceErrorDetail"

  public static func remoteError(_ error: any Error) -> NSError {
    // Swift error user-info providers do not survive an XPC archive. Materialize the message here.
    var userInfo: [String: Any] = [NSLocalizedDescriptionKey: String(describing: error)]
    if let error = error as? MaintenanceError {
      userInfo[errorCodeKey] = error.code.rawValue
      if let detail = error.detail {
        userInfo[errorDetailKey] = detail
      }
    }
    return NSError(domain: errorDomain, code: 1, userInfo: userInfo)
  }

  public static func encode<T: Encodable>(_ value: T) throws -> Data {
    let data = try JSONEncoder().encode(value)
    guard data.count <= maximumMessageSize else { throw MaintenanceError(.messageTooLarge) }
    return data
  }

  public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    guard data.count <= maximumMessageSize else { throw MaintenanceError(.messageTooLarge) }
    return try JSONDecoder().decode(type, from: data)
  }
}

/// Every failure the maintenance service, its client and the removal code can report. The
/// code is stable across releases so the app can translate it; `detail` carries the variable
/// part, such as a path, a system error text or a command's output.
///
/// The raw values are written to the uninstall state file and sent across XPC, so renaming a
/// case changes a persisted format. Readers treat an unknown value as "no code" and fall back
/// to the English description.
public enum MaintenanceErrorCode: String, CaseIterable, Codable, Sendable {
  case messageTooLarge
  case unknownStateFormat
  case invalidPackageBuildVersion
  case installedBuildVersionUnknown
  case downgradeNotSupported
  case approvalExpired
  case unsafeRemovalPath
  case removalTargetUntrusted
  case unexpectedOwner
  case mountCrossingRefused
  case removalTargetChanged
  case systemCallFailed
  case authorizationMalformed
  case authorizationInvalid
  case authorizationRuleUnexpected
  case authorizationCanceled
  case authorizationDenied
  case invalidHandshake
  case requestInProgress
  case noCurrentApproval
  case notRunningAsRoot
  case unsupportedOperation
  case commandFailed
  case runningApplicationsUnknown
  case applicationRunning
  case installationPathUnreadable
  case installationPathNotDirectory
  case installationPathOccupied
  case installedVersionUnreadable
  case componentPermissionsUnsafe
  case helperSignatureMismatch
  case helperMismatch
  case applicationDidNotExit
  case receiptUnverifiable
  case dataDirectoryNotRemoved
  case authorizationRightsNotRegistered
  case authorizationRightsNotRemoved
  case handshakeMismatch
  case connectionLost
  case requestNotAccepted
  case serviceUnavailable
  case serviceNoReply
  case invalidReply
  case internalFailure

  /// The English text used in logs, in Installer output and by clients without a translation.
  public func message(detail: String?) -> String {
    let detail = detail ?? ""
    switch self {
    case .messageTooLarge: return "Message too large."
    case .unknownStateFormat: return "Unknown uninstall state format."
    case .invalidPackageBuildVersion: return "Invalid package build version."
    case .installedBuildVersionUnknown:
      return "Cannot determine the installed build version. Installation was not changed."
    case .downgradeNotSupported:
      return "A newer Pasu FS build is installed. Downgrades are not supported."
    case .approvalExpired:
      return "The uninstall approval expired or belongs to another request. Please try again."
    case .unsafeRemovalPath: return "Unsafe removal path."
    case .removalTargetUntrusted:
      return "The removal target has an unexpected owner or is a symbolic link: \(detail)"
    case .unexpectedOwner: return "Unexpected owner during removal: \(detail)"
    case .mountCrossingRefused: return "Refusing to cross a mounted filesystem."
    case .removalTargetChanged: return "The removal target changed \(detail)."
    case .systemCallFailed: return "\(detail)."
    case .authorizationMalformed: return "Missing or malformed uninstall authorization."
    case .authorizationInvalid: return "Invalid uninstall authorization (OSStatus \(detail))."
    case .authorizationRuleUnexpected:
      return "The uninstall authorization rule is not the expected one-time administrator rule."
    case .authorizationCanceled:
      return "Administrator authentication was canceled. No files were removed."
    case .authorizationDenied:
      return "Administrator approval for uninstalling was not granted (OSStatus \(detail))."
    case .invalidHandshake: return "Invalid maintenance handshake."
    case .requestInProgress: return "Another uninstall request is already in progress."
    case .noCurrentApproval: return "No current uninstall approval."
    case .notRunningAsRoot:
      return "This maintenance executable must be started by macOS Installer or launchd."
    case .unsupportedOperation: return "Unsupported maintenance operation."
    case .commandFailed: return detail
    case .runningApplicationsUnknown: return "Could not check running Pasu FS applications."
    case .applicationRunning:
      return
        "Quit Pasu FS normally, then run the installer or uninstaller again. Protection continues when the app quits. Another login session may also have Pasu FS open."
    case .installationPathUnreadable: return "Cannot inspect the installation path."
    case .installationPathNotDirectory:
      return "The Pasu FS installation path is not a real directory. No files were changed."
    case .installationPathOccupied:
      return "Another application or an unrecognized directory occupies the installation path."
    case .installedVersionUnreadable:
      return "The existing application has no readable build version or package receipt."
    case .componentPermissionsUnsafe:
      return "The installed maintenance component has unsafe ownership or permissions."
    case .helperSignatureMismatch:
      return "The maintenance service signature does not match this application."
    case .helperMismatch:
      return "The installed helper does not match the application. Reinstall the package."
    case .applicationDidNotExit: return "Pasu FS did not exit. Open the app and retry uninstalling."
    case .receiptUnverifiable:
      return "Could not verify the package receipt during removal: \(detail)"
    case .dataDirectoryNotRemoved: return "The product data directory could not be removed."
    case .authorizationRightsNotRegistered:
      return "Could not register the Pasu FS authorization rights: \(detail)"
    case .authorizationRightsNotRemoved:
      return "Could not remove the Pasu FS authorization rights: \(detail)"
    case .handshakeMismatch: return "The maintenance service handshake did not match this app."
    case .connectionLost: return "The uninstall connection was lost. Please try again."
    case .requestNotAccepted: return "The uninstall request was not accepted."
    case .serviceUnavailable:
      return "The maintenance service is unavailable. Reinstall the Pasu FS package."
    case .serviceNoReply:
      return
        "The maintenance service did not reply. Check its background-item permission or reinstall the package."
    case .invalidReply: return "Invalid maintenance reply."
    case .internalFailure: return "Maintenance failed: \(detail)"
    }
  }
}

public struct MaintenanceError: Error, LocalizedError, CustomStringConvertible, Sendable {
  public let code: MaintenanceErrorCode
  public let detail: String?

  public init(_ code: MaintenanceErrorCode, detail: String? = nil) {
    self.code = code
    self.detail = detail
  }

  public var description: String { code.message(detail: detail) }
  public var errorDescription: String? { description }
}

public enum UninstallPhase: String, Codable, Sendable {
  case prepared, awaitingRestart, removing, failed
}

public struct UninstallState: Codable, Equatable, Sendable {
  public let formatVersion: Int
  public let phase: UninstallPhase
  public let removeData: Bool
  /// The English description of the failure, kept for logs and for older app versions.
  public let failure: String?
  /// The failure's code and variable part, so the app can show it in the user's language.
  /// Absent in state files written before these fields existed, and nil when the file names a
  /// code this version does not know.
  public let failureCode: MaintenanceErrorCode?
  public let failureDetail: String?
  public let bootSession: String?

  public init(phase: UninstallPhase, removeData: Bool, failure: MaintenanceError? = nil) {
    self.formatVersion = 1
    self.phase = phase
    self.removeData = removeData
    self.failure = failure?.description
    self.failureCode = failure?.code
    self.failureDetail = failure?.detail
    self.bootSession = BootSession.identifier()
  }

  private enum CodingKeys: String, CodingKey {
    case formatVersion, phase, removeData, failure, failureCode, failureDetail, bootSession
  }

  public init(from decoder: any Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    formatVersion = try container.decode(Int.self, forKey: .formatVersion)
    phase = try container.decode(UninstallPhase.self, forKey: .phase)
    removeData = try container.decode(Bool.self, forKey: .removeData)
    failure = try container.decodeIfPresent(String.self, forKey: .failure)
    // A newer maintenance service may record a code this app does not know yet.
    failureCode = try container.decodeIfPresent(String.self, forKey: .failureCode)
      .flatMap(MaintenanceErrorCode.init(rawValue:))
    failureDetail = try container.decodeIfPresent(String.self, forKey: .failureDetail)
    bootSession = try container.decodeIfPresent(String.self, forKey: .bootSession)
  }

  public func encode(to encoder: any Encoder) throws {
    var container = encoder.container(keyedBy: CodingKeys.self)
    try container.encode(formatVersion, forKey: .formatVersion)
    try container.encode(phase, forKey: .phase)
    try container.encode(removeData, forKey: .removeData)
    try container.encodeIfPresent(failure, forKey: .failure)
    try container.encodeIfPresent(failureCode?.rawValue, forKey: .failureCode)
    try container.encodeIfPresent(failureDetail, forKey: .failureDetail)
    try container.encodeIfPresent(bootSession, forKey: .bootSession)
  }
}

public enum BootSession {
  public static func identifier() -> String? {
    var size = 0
    guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1, size < 256 else {
      return nil
    }
    var bytes = [CChar](repeating: 0, count: size)
    guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0 else { return nil }
    return String(
      decoding: bytes.prefix(while: { $0 != 0 }).map { UInt8(bitPattern: $0) }, as: UTF8.self)
  }
}

public final class UninstallStateStore: @unchecked Sendable {
  private let store: SecureAtomicFileStore

  public init(root: URL? = nil, owner: UInt32 = 0) throws {
    let directory = try root ?? ExtensionStorageLocations.localSystemDefault().rootDirectory
    store = SecureAtomicFileStore(rootDirectory: directory, requiredOwnerUserID: owner)
  }

  /// The marker contains no credentials or user file paths. Reading it does not start the helper.
  public func read() throws -> UninstallState? {
    do {
      let data = try store.read(
        MaintenanceContract.stateFilename, maximumSize: MaintenanceContract.maximumMessageSize)
      let state = try MaintenanceContract.decode(UninstallState.self, from: data)
      guard state.formatVersion == 1 else {
        throw MaintenanceError(.unknownStateFormat)
      }
      return state
    } catch SecureFileStoreError.fileNotFound {
      return nil
    } catch SecureFileStoreError.systemCall(_, let code) where code == ENOENT {
      return nil
    }
  }

  public func write(_ state: UninstallState) throws {
    try store.prepareDirectory()
    try store.write(
      MaintenanceContract.encode(state), to: MaintenanceContract.stateFilename, mode: 0o644)
  }

  public func clear() throws {
    try SafeRemoval.remove(
      store.rootDirectory.appendingPathComponent(MaintenanceContract.stateFilename),
      requiredOwner: store.requiredOwnerUserID ?? 0)
  }
}

public struct MaintenanceStatus: Codable, Sendable {
  public let version: Int
  public let nonce: Data
  public let state: UninstallState?
  public init(nonce: Data, state: UninstallState?) {
    version = MaintenanceContract.protocolVersion
    self.nonce = nonce
    self.state = state
  }
}

public struct UninstallPreparation: Codable, Sendable {
  public let authorization: Data
  public let removeData: Bool
  public init(authorization: Data, removeData: Bool) {
    self.authorization = authorization
    self.removeData = removeData
  }
}

public struct UninstallTicket: Codable, Sendable {
  public let identifier: UUID
  public init(identifier: UUID) { self.identifier = identifier }
}

public enum UninstallCommitAction: String, Codable, Sendable {
  case cancel, awaitRestart, removeFiles
}

public struct UninstallCommit: Codable, Sendable {
  public let ticket: UUID
  public let action: UninstallCommitAction
  public init(ticket: UUID, action: UninstallCommitAction) {
    self.ticket = ticket
    self.action = action
  }
}

public struct MaintenanceAcknowledgement: Codable, Sendable {
  public let accepted: Bool
  public init() { accepted = true }
}

@objc(PasuFSMaintenanceXPCProtocol)
public protocol PasuFSMaintenanceXPCProtocol: NSObjectProtocol {
  func status(_ nonce: Data, withReply reply: @escaping @Sendable (Data?, NSError?) -> Void)
  func prepare(_ request: Data, withReply reply: @escaping @Sendable (Data?, NSError?) -> Void)
  func commit(_ request: Data, withReply reply: @escaping @Sendable (Data?, NSError?) -> Void)
}

public struct ProductBuildVersion: Comparable, Equatable, Sendable {
  private let components: [UInt64]
  public init?(_ string: String) {
    let parts = string.split(separator: ".", omittingEmptySubsequences: false)
    guard (1...3).contains(parts.count) else { return nil }
    var values: [UInt64] = []
    for part in parts {
      guard !part.isEmpty, part.allSatisfy({ $0.isASCII && $0.isNumber }),
        let value = UInt64(part)
      else { return nil }
      values.append(value)
    }
    components = values + Array(repeating: 0, count: 3 - values.count)
  }
  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.components.lexicographicallyPrecedes(rhs.components)
  }
  public static func validateUpgrade(incoming: String, installed: String?) throws {
    guard let candidate = Self(incoming) else {
      throw MaintenanceError(.invalidPackageBuildVersion)
    }
    if let installed {
      guard let current = Self(installed) else {
        throw MaintenanceError(.installedBuildVersionUnknown)
      }
      guard candidate >= current else {
        throw MaintenanceError(.downgradeNotSupported)
      }
    }
  }
}

/// Authority exists only in memory and is bound to the authenticated XPC connection.
public struct UninstallSession: Sendable {
  public let ticket = UUID()
  public let connection: UUID
  public let processID: Int32
  public let removeData: Bool
  public let expires: Date
  public let previousState: UninstallState?
  public init(
    connection: UUID, processID: Int32, removeData: Bool, previousState: UninstallState? = nil,
    now: Date = Date()
  ) {
    self.connection = connection
    self.processID = processID
    self.removeData = removeData
    self.previousState = previousState
    expires = now.addingTimeInterval(600)
  }
  public func validate(ticket: UUID, connection: UUID, now: Date = Date()) throws {
    guard self.ticket == ticket, self.connection == connection, now < expires else {
      throw MaintenanceError(.approvalExpired)
    }
  }
}
