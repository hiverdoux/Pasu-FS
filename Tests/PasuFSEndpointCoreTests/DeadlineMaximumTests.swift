import EndpointSecurity
import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSEndpointCore

final class DeadlineMaximumTests: XCTestCase {
  private let events = [
    ES_EVENT_TYPE_AUTH_OPEN, ES_EVENT_TYPE_AUTH_RENAME, ES_EVENT_TYPE_AUTH_MOUNT,
  ]

  func testLookUpUsesTheSymbolNames() {
    var names: [String] = []
    let functions = DeadlineMaximumFunctions { name in
      names.append(name)
      return nil
    }
    XCTAssertEqual(names, ["es_set_deadline_max_milliseconds", "es_get_deadline_max_milliseconds"])
    XCTAssertNil(functions.set)
    XCTAssertNil(functions.get)
  }

  func testEveryAnsweredEventIsShortened() {
    let client = FakeDeadlineClient()
    let answered = FileOperationKind.subscribedEventTypes
    XCTAssertEqual(answered.count, AuthorizationEventCatalog.supportedEventNames.count)
    XCTAssertEqual(
      client.configure(events: answered), DeadlineMaximumResult(milliseconds: 3_000))
    XCTAssertEqual(client.requests.count, 1)
    XCTAssertEqual(client.requests.first?.events, answered.map(\.rawValue))
    XCTAssertEqual(client.requests.first?.milliseconds, 3_000)
    for event in answered {
      XCTAssertEqual(client.maxima[event.rawValue], 3_000)
    }
  }

  func testDefaultValueIsThreeSeconds() {
    XCTAssertEqual(DeadlineMaximumConfiguration.milliseconds, 3_000)
  }

  func testRefusedSettingKeepsTheDefaults() {
    let client = FakeDeadlineClient()
    client.refusesSetting = true
    XCTAssertEqual(
      client.configure(events: events),
      DeadlineMaximumResult(error: "es_set_deadline_max_milliseconds failed for 3000 ms."))
    XCTAssertEqual(client.requests.count, 1)
    XCTAssertEqual(client.maxima, [:])
  }

  func testUnconfirmedEventIsSetBackToItsDefault() {
    let client = FakeDeadlineClient()
    client.misreported = [ES_EVENT_TYPE_AUTH_RENAME.rawValue: 5_000]
    let result = client.configure(events: events)
    XCTAssertNil(result.milliseconds)
    XCTAssertEqual(
      result.error,
      "Endpoint Security reported 5000 ms for event type \(ES_EVENT_TYPE_AUTH_RENAME.rawValue) "
        + "after 3000 ms was set. The default deadlines were set again.")
    // The first request covers every event; then each changed event is set back on its own.
    XCTAssertEqual(client.requests.count, 1 + events.count)
    XCTAssertEqual(
      client.requests.dropFirst().map(\.milliseconds),
      Array(repeating: FakeDeadlineClient.systemDefault, count: events.count))
    for event in events {
      XCTAssertEqual(client.maxima[event.rawValue], FakeDeadlineClient.systemDefault)
    }
  }

  func testUnreadableDeadlineIsReported() {
    let client = FakeDeadlineClient()
    client.refusesReading = true
    let result = client.configure(events: events)
    XCTAssertNil(result.milliseconds)
    XCTAssertEqual(
      result.error,
      "es_get_deadline_max_milliseconds failed for event type \(ES_EVENT_TYPE_AUTH_OPEN.rawValue)."
        + " The default deadlines could not be confirmed.")
  }

  func testMissingFunctionsAreReported() {
    let withoutGet = FakeDeadlineClient()
    XCTAssertEqual(
      withoutGet.configure(events: events, set: true, get: false),
      DeadlineMaximumResult(error: "es_get_deadline_max_milliseconds is missing."))
    XCTAssertEqual(withoutGet.requests.count, 0)

    let withoutBoth = FakeDeadlineClient()
    XCTAssertEqual(
      withoutBoth.configure(events: events, set: false, get: false),
      DeadlineMaximumResult(
        error:
          "es_set_deadline_max_milliseconds and es_get_deadline_max_milliseconds are missing."))
  }

  func testOnlyTheFailClosedModeIsShortened() {
    for setting in [DeadlineMissModeStatus.Setting.killUnavailable, .killAfterFailure] {
      let client = FakeDeadlineClient()
      let status = DeadlineMissModeStatus(setting: setting, error: "kept")
      XCTAssertEqual(client.apply(to: status, events: events), status)
      XCTAssertEqual(client.requests.count, 0, setting.rawValue)
    }
    let client = FakeDeadlineClient()
    XCTAssertEqual(
      client.apply(to: DeadlineMissModeStatus(setting: .failClosed), events: events),
      DeadlineMissModeStatus(setting: .failClosed, maximumDeadlineMilliseconds: 3_000))
  }

  func testFailureKeepsTheFailClosedMode() {
    let client = FakeDeadlineClient()
    client.refusesSetting = true
    XCTAssertEqual(
      client.apply(to: DeadlineMissModeStatus(setting: .failClosed), events: events),
      DeadlineMissModeStatus(
        setting: .failClosed,
        maximumDeadlineError: "es_set_deadline_max_milliseconds failed for 3000 ms."))
  }

  func testFunctionsAreNotUsedBeforeMacOS27() {
    let earlier = DeadlineMaximumFunctions.system(
      operatingSystemVersion: OperatingSystemVersion(
        majorVersion: 26, minorVersion: 6, patchVersion: 2))
    XCTAssertNil(earlier.set)
    XCTAssertNil(earlier.get)
  }

  func testThisSystemsFunctionsAreFoundTogether() {
    let functions = DeadlineMaximumFunctions.system(
      operatingSystemVersion: OperatingSystemVersion(
        majorVersion: 27, minorVersion: 0, patchVersion: 0))
    XCTAssertEqual(functions.set == nil, functions.get == nil)
  }

  func testStatusWithoutMaximumDeadlineStillDecodes() throws {
    let status = DeadlineMissModeStatus(
      setting: .failClosed, maximumDeadlineMilliseconds: 3_000, maximumDeadlineError: nil)
    let data = try JSONEncoder().encode(status)
    let object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    XCTAssertEqual(object["maximumDeadlineMilliseconds"] as? Int, 3_000)
    XCTAssertNil(object["maximumDeadlineError"])
    XCTAssertEqual(try JSONDecoder().decode(DeadlineMissModeStatus.self, from: data), status)
    let older = try JSONDecoder().decode(
      DeadlineMissModeStatus.self, from: Data(#"{"setting":"failClosed"}"#.utf8))
    XCTAssertEqual(older, DeadlineMissModeStatus(setting: .failClosed))
  }
}

/// Stands in for an Endpoint Security client's deadlines. The functions below receive its address
/// as the client pointer, as C functions can't capture state.
private final class FakeDeadlineClient {
  static let systemDefault: UInt32 = 15_000

  /// Maximum deadlines by event type; events not listed have the system default.
  var maxima: [UInt32: UInt32] = [:]
  var requests: [(events: [UInt32], milliseconds: UInt32)] = []
  /// `es_set_deadline_max_milliseconds` fails and changes nothing.
  var refusesSetting = false
  /// `es_get_deadline_max_milliseconds` fails.
  var refusesReading = false
  /// Events whose next read after a change reports this value instead.
  var misreported: [UInt32: UInt32] = [:]

  private static let set: DeadlineMaximumFunctions.Set = { client, events, count, milliseconds in
    let fake = FakeDeadlineClient.from(client)
    let types = UnsafeBufferPointer(start: events, count: Int(count)).map(\.rawValue)
    fake.requests.append((types, milliseconds))
    if fake.refusesSetting || milliseconds > systemDefault { return ES_RETURN_ERROR }
    for type in types { fake.maxima[type] = milliseconds }
    return ES_RETURN_SUCCESS
  }

  private static let get: DeadlineMaximumFunctions.Get = { client, event, milliseconds in
    let fake = FakeDeadlineClient.from(client)
    if fake.refusesReading { return ES_RETURN_ERROR }
    let value = fake.maxima[event.rawValue] ?? systemDefault
    if value != systemDefault, let reported = fake.misreported.removeValue(forKey: event.rawValue) {
      milliseconds.pointee = reported
    } else {
      milliseconds.pointee = value
    }
    return ES_RETURN_SUCCESS
  }

  private static func from(_ client: OpaquePointer) -> FakeDeadlineClient {
    Unmanaged<FakeDeadlineClient>.fromOpaque(UnsafeRawPointer(client)).takeUnretainedValue()
  }

  private func functions(set hasSet: Bool, get hasGet: Bool) -> DeadlineMaximumFunctions {
    DeadlineMaximumFunctions { name in
      switch name {
      case DeadlineMaximumFunctions.setSymbol where hasSet:
        unsafeBitCast(Self.set, to: UnsafeMutableRawPointer.self)
      case DeadlineMaximumFunctions.getSymbol where hasGet:
        unsafeBitCast(Self.get, to: UnsafeMutableRawPointer.self)
      default:
        nil
      }
    }
  }

  private var pointer: OpaquePointer { OpaquePointer(Unmanaged.passUnretained(self).toOpaque()) }

  /// Configures this client through functions found by name, as the extension does.
  func configure(
    events: [es_event_type_t], set hasSet: Bool = true, get hasGet: Bool = true
  ) -> DeadlineMaximumResult {
    withExtendedLifetime(self) {
      DeadlineMaximumConfiguration.configure(
        client: pointer, events: events, milliseconds: DeadlineMaximumConfiguration.milliseconds,
        functions: functions(set: hasSet, get: hasGet))
    }
  }

  func apply(to status: DeadlineMissModeStatus, events: [es_event_type_t])
    -> DeadlineMissModeStatus
  {
    withExtendedLifetime(self) {
      DeadlineMaximumConfiguration.apply(
        to: status, client: pointer, events: events, functions: functions(set: true, get: true))
    }
  }
}
