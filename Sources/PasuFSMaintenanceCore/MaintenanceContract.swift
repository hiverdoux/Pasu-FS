import Darwin
import Foundation
import PasuFSConfiguration

public enum MaintenanceContract {
  public static let service = "com.example.pasu.fs.maintenance"
  public static let packageIdentifier = "com.example.pasu.fs.pkg"
  public static let uninstallRight = "com.example.pasu.fs.uninstall"
  public static let appPath = "/Applications/Pasu FS.app"
  public static let helperPath = "/Library/PrivilegedHelperTools/\(service)"
  public static let daemonPath = "/Library/LaunchDaemons/\(service).plist"
  public static let embeddedHelperPath = "Contents/Library/LaunchServices/\(service)"
  public static let stateFilename = "uninstall-state.json"
  public static let protocolVersion = 1
  public static let maximumMessageSize = 16 * 1024

  public static func remoteError(_ error: any Error) -> NSError {
    // Swift error user-info providers do not survive an XPC archive. Materialize the message here.
    NSError(
      domain: "com.example.pasu.fs.maintenance", code: 1,
      userInfo: [NSLocalizedDescriptionKey: String(describing: error)])
  }

  public static func encode<T: Encodable>(_ value: T) throws -> Data {
    let data = try JSONEncoder().encode(value)
    guard data.count <= maximumMessageSize else { throw MaintenanceError("Message too large.") }
    return data
  }

  public static func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
    guard data.count <= maximumMessageSize else { throw MaintenanceError("Message too large.") }
    return try JSONDecoder().decode(type, from: data)
  }
}

public struct MaintenanceError: Error, LocalizedError, CustomStringConvertible, Sendable {
  public let description: String
  public init(_ description: String) { self.description = description }
  public var errorDescription: String? { description }
}

public enum UninstallPhase: String, Codable, Sendable {
  case prepared, awaitingRestart, removing, failed
}

public struct UninstallState: Codable, Equatable, Sendable {
  public let formatVersion: Int
  public let phase: UninstallPhase
  public let removeData: Bool
  public let failure: String?
  public let bootSession: String?

  public init(phase: UninstallPhase, removeData: Bool, failure: String? = nil) {
    self.formatVersion = 1
    self.phase = phase
    self.removeData = removeData
    self.failure = failure
    self.bootSession = BootSession.identifier()
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
        throw MaintenanceError("Unknown uninstall state format.")
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
      throw MaintenanceError("Invalid package build version.")
    }
    if let installed {
      guard let current = Self(installed) else {
        throw MaintenanceError(
          "Cannot determine the installed build version. Installation was not changed.")
      }
      guard candidate >= current else {
        throw MaintenanceError("A newer Pasu FS build is installed. Downgrades are not supported.")
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
      throw MaintenanceError(
        "The uninstall approval expired or belongs to another request. Please try again.")
    }
  }
}
