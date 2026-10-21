import Darwin
import EndpointSecurity
import Foundation
import PasuFSConfiguration

/// The values of `es_deadline_miss_mode_t`, as `ESTypes.h` in the macOS 27 SDK declares them. The
/// SDK type is not referenced, so the package still builds with SDKs that predate it.
public enum DeadlineMissMode: UInt32, Sendable {
  /// macOS stops the client when it misses a deadline. The default.
  case kill = 0
  /// macOS denies a request whose deadline passes and keeps the client running. A request
  /// dropped because the client's queue is full is denied instead of allowed.
  case failClosed = 1
  /// macOS allows a request whose deadline passes. The extension never sets this mode.
  case failOpen = 2
}

/// `es_set_deadline_miss_mode` and `es_get_deadline_miss_mode`, which macOS 27 added, as the
/// running system provides them. They are looked up by name at run time, so the extension links
/// and runs on systems that lack them.
public struct DeadlineMissModeFunctions {
  /// The first macOS version the SDK declares the functions for. macOS 26 already exports them,
  /// but there both return an error and the kill mode stays in effect.
  public static let firstSupportedMajorVersion = 27

  /// `es_return_t es_set_deadline_miss_mode(es_client_t *client, es_deadline_miss_mode_t mode)`
  public typealias Set = @convention(c) (OpaquePointer, UInt32) -> es_return_t
  /// `es_return_t es_get_deadline_miss_mode(es_client_t *client, es_deadline_miss_mode_t *mode)`
  public typealias Get = @convention(c) (OpaquePointer, UnsafeMutablePointer<UInt32>) -> es_return_t

  public static let setSymbol = "es_set_deadline_miss_mode"
  public static let getSymbol = "es_get_deadline_miss_mode"

  public var set: Set?
  public var get: Get?

  /// - Parameter lookUp: Returns the address of the named function, or nil when it is missing.
  public init(lookUp: (String) -> UnsafeMutableRawPointer?) {
    set = lookUp(Self.setSymbol).map { unsafeBitCast($0, to: Set.self) }
    get = lookUp(Self.getSymbol).map { unsafeBitCast($0, to: Get.self) }
  }

  /// The functions in the images loaded into this process, which include Endpoint Security, or
  /// none before macOS 27.
  public static func system(
    operatingSystemVersion: OperatingSystemVersion = ProcessInfo.processInfo.operatingSystemVersion
  ) -> DeadlineMissModeFunctions {
    DeadlineMissModeFunctions(
      lookUp: lookUpSystemFunction(operatingSystemVersion: operatingSystemVersion))
  }

  /// Finds a function that macOS 27 added to Endpoint Security by name in the images loaded into
  /// this process, or finds nothing before macOS 27.
  static func lookUpSystemFunction(
    operatingSystemVersion: OperatingSystemVersion
  ) -> (String) -> UnsafeMutableRawPointer? {
    guard operatingSystemVersion.majorVersion >= firstSupportedMajorVersion else {
      return { _ in nil }
    }
    // `RTLD_DEFAULT` from `dlfcn.h`, a macro Swift doesn't import.
    let searchAllImages = UnsafeMutableRawPointer(bitPattern: -2)
    return { dlsym(searchAllImages, $0) }
  }
}

public enum DeadlineMissModeConfiguration {
  /// Asks Endpoint Security to deny the requests that `client` doesn't answer in time, and reads
  /// the mode back to confirm it. Call it before subscribing to any event.
  ///
  /// Where the functions are missing or the system predates them, the client keeps the kill mode. Where setting or confirming
  /// fails, the extension asks for the kill mode again unless Endpoint Security already reports
  /// it, so the client never runs in a mode the extension didn't choose.
  public static func configure(
    client: OpaquePointer, functions: DeadlineMissModeFunctions
  ) -> DeadlineMissModeStatus {
    guard let set = functions.set, let get = functions.get else {
      let missing = [
        functions.set == nil ? DeadlineMissModeFunctions.setSymbol : nil,
        functions.get == nil ? DeadlineMissModeFunctions.getSymbol : nil,
      ].compactMap { $0 }
      // On a system without either function this is the normal state, not an error.
      return DeadlineMissModeStatus(
        setting: .killUnavailable,
        error: missing.count == 1 ? "\(missing[0]) is missing." : nil)
    }
    let requested = set(client, DeadlineMissMode.failClosed.rawValue) == ES_RETURN_SUCCESS
    let reported = mode(of: client, get: get)
    if reported == DeadlineMissMode.failClosed.rawValue {
      return DeadlineMissModeStatus(setting: .failClosed)
    }
    var problem: String
    if !requested {
      problem = "\(DeadlineMissModeFunctions.setSymbol) failed."
    } else if let reported {
      problem = "Endpoint Security reported mode \(reported) after the fail-closed mode was set."
    } else {
      problem = "\(DeadlineMissModeFunctions.getSymbol) failed."
    }
    if reported != DeadlineMissMode.kill.rawValue {
      let restored =
        set(client, DeadlineMissMode.kill.rawValue) == ES_RETURN_SUCCESS
        && mode(of: client, get: get) == DeadlineMissMode.kill.rawValue
      problem +=
        restored ? " The kill mode was set again." : " The kill mode could not be confirmed either."
    }
    return DeadlineMissModeStatus(setting: .killAfterFailure, error: problem)
  }

  /// The mode `get` reports for `client`, or nil when it fails.
  private static func mode(
    of client: OpaquePointer, get: DeadlineMissModeFunctions.Get
  ) -> UInt32? {
    var mode = UInt32.max
    return get(client, &mode) == ES_RETURN_SUCCESS ? mode : nil
  }
}
