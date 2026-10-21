import EndpointSecurity
import Foundation
import PasuFSConfiguration

/// `es_set_deadline_max_milliseconds` and `es_get_deadline_max_milliseconds`, which macOS 27
/// added, as the running system provides them. Like the deadline miss mode functions, they are
/// looked up by name at run time and only on macOS 27 and later.
public struct DeadlineMaximumFunctions {
  /// `es_return_t es_set_deadline_max_milliseconds(es_client_t *client,
  /// const es_event_type_t *events, uint32_t event_count, uint32_t milliseconds)`
  public typealias Set =
    @convention(c) (OpaquePointer, UnsafePointer<es_event_type_t>, UInt32, UInt32) -> es_return_t
  /// `es_return_t es_get_deadline_max_milliseconds(es_client_t *client, es_event_type_t event,
  /// uint32_t *milliseconds)`
  public typealias Get =
    @convention(c) (OpaquePointer, es_event_type_t, UnsafeMutablePointer<UInt32>) -> es_return_t

  public static let setSymbol = "es_set_deadline_max_milliseconds"
  public static let getSymbol = "es_get_deadline_max_milliseconds"

  public var set: Set?
  public var get: Get?

  /// - Parameter lookUp: Returns the address of the named function, or nil when it is missing.
  public init(lookUp: (String) -> UnsafeMutableRawPointer?) {
    set = lookUp(Self.setSymbol).map { unsafeBitCast($0, to: Set.self) }
    get = lookUp(Self.getSymbol).map { unsafeBitCast($0, to: Get.self) }
  }

  /// The functions in the images loaded into this process, or none before macOS 27.
  public static func system(
    operatingSystemVersion: OperatingSystemVersion = ProcessInfo.processInfo.operatingSystemVersion
  ) -> DeadlineMaximumFunctions {
    DeadlineMaximumFunctions(
      lookUp: DeadlineMissModeFunctions.lookUpSystemFunction(
        operatingSystemVersion: operatingSystemVersion))
  }
}

/// The outcome of shortening the deadlines of the authorization events.
public struct DeadlineMaximumResult: Equatable, Sendable {
  /// The maximum deadline confirmed for every event, or nil when the default deadlines apply.
  public var milliseconds: UInt32?
  public var error: String?

  public init(milliseconds: UInt32? = nil, error: String? = nil) {
    self.milliseconds = milliseconds
    self.error = error
  }
}

public enum DeadlineMaximumConfiguration {
  /// The longest macOS waits for the extension's answer to an authorization request before it
  /// denies the request in the fail-closed mode. Without shortening the deadline, a stalled
  /// extension leaves each affected request waiting until macOS's default deadline.
  ///
  /// A three-second maximum bounds how long an unresponsive extension delays each affected
  /// request. It changes how long macOS waits, not the fail-closed decision at the deadline.
  public static let milliseconds: UInt32 = 3_000

  /// Shortens the deadline of `status`'s client to `milliseconds` for every event in `events`,
  /// once the fail-closed mode is confirmed. In any other mode macOS stops an extension that
  /// misses a deadline, so the default deadlines stay. A failure leaves the default deadlines and
  /// the fail-closed mode in effect and is reported in the returned status.
  public static func apply(
    to status: DeadlineMissModeStatus, client: OpaquePointer, events: [es_event_type_t],
    milliseconds: UInt32 = milliseconds, functions: DeadlineMaximumFunctions
  ) -> DeadlineMissModeStatus {
    guard status.setting == .failClosed else { return status }
    let result = configure(
      client: client, events: events, milliseconds: milliseconds, functions: functions)
    var status = status
    status.maximumDeadlineMilliseconds = result.milliseconds
    status.maximumDeadlineError = result.error
    return status
  }

  /// Sets the maximum deadline of every event in `events` and reads each one back to confirm it.
  /// Where confirming fails, the extension sets each event that changed, or whose deadline it
  /// can't read, back to the deadline it reported before.
  public static func configure(
    client: OpaquePointer, events: [es_event_type_t], milliseconds: UInt32,
    functions: DeadlineMaximumFunctions
  ) -> DeadlineMaximumResult {
    guard let set = functions.set, let get = functions.get else {
      // Both functions came with the fail-closed mode, so a missing one is unexpected here.
      let missing = [
        functions.set == nil ? DeadlineMaximumFunctions.setSymbol : nil,
        functions.get == nil ? DeadlineMaximumFunctions.getSymbol : nil,
      ].compactMap { $0 }
      return DeadlineMaximumResult(
        error: "\(missing.joined(separator: " and ")) \(missing.count == 1 ? "is" : "are") missing."
      )
    }
    guard !events.isEmpty else {
      return DeadlineMaximumResult(error: "No event was given.")
    }
    let defaults = events.map { maximum(of: client, event: $0, get: get) }
    let requested =
      events.withUnsafeBufferPointer {
        set(client, $0.baseAddress!, UInt32($0.count), milliseconds)
      } == ES_RETURN_SUCCESS
    let reported = events.map { maximum(of: client, event: $0, get: get) }
    if requested, reported.allSatisfy({ $0 == milliseconds }) {
      return DeadlineMaximumResult(milliseconds: milliseconds)
    }

    var problem: String
    if !requested {
      problem = "\(DeadlineMaximumFunctions.setSymbol) failed for \(milliseconds) ms."
    } else if let index = reported.firstIndex(where: { $0 == nil }) {
      problem =
        "\(DeadlineMaximumFunctions.getSymbol) failed for event type \(events[index].rawValue)."
    } else {
      let index = reported.firstIndex { $0 != milliseconds }!
      problem =
        "Endpoint Security reported \(reported[index]!) ms for event type "
        + "\(events[index].rawValue) after \(milliseconds) ms was set."
    }
    var restored = true
    for (index, event) in events.enumerated()
    where reported[index] == nil || reported[index] != defaults[index] {
      guard let original = defaults[index] else {
        restored = false
        continue
      }
      let reset =
        withUnsafePointer(to: event) { set(client, $0, 1, original) } == ES_RETURN_SUCCESS
        && maximum(of: client, event: event, get: get) == original
      restored = restored && reset
    }
    if !restored {
      problem += " The default deadlines could not be confirmed."
    } else if zip(reported, defaults).contains(where: { $0 != $1 }) {
      problem += " The default deadlines were set again."
    }
    return DeadlineMaximumResult(error: problem)
  }

  /// The maximum deadline `get` reports for `event`, or nil when it fails.
  private static func maximum(
    of client: OpaquePointer, event: es_event_type_t, get: DeadlineMaximumFunctions.Get
  ) -> UInt32? {
    var milliseconds = UInt32.max
    return get(client, event, &milliseconds) == ES_RETURN_SUCCESS ? milliseconds : nil
  }
}
