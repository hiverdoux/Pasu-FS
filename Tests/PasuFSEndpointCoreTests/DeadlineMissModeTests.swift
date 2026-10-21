import EndpointSecurity
import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSEndpointCore

final class DeadlineMissModeTests: XCTestCase {
  func testHeaderValues() {
    XCTAssertEqual(DeadlineMissMode.kill.rawValue, 0)
    XCTAssertEqual(DeadlineMissMode.failClosed.rawValue, 1)
    XCTAssertEqual(DeadlineMissMode.failOpen.rawValue, 2)
  }

  func testLookUpUsesTheSymbolNames() {
    var names: [String] = []
    let functions = DeadlineMissModeFunctions { name in
      names.append(name)
      return nil
    }
    XCTAssertEqual(names, ["es_set_deadline_miss_mode", "es_get_deadline_miss_mode"])
    XCTAssertNil(functions.set)
    XCTAssertNil(functions.get)
  }

  func testMissingFunctionsKeepKillWithoutAnError() {
    let client = FakeEndpointClient()
    let status = client.configure(set: false, get: false)
    XCTAssertEqual(status, DeadlineMissModeStatus(setting: .killUnavailable))
    XCTAssertFalse(status.deniesUnansweredRequests)
    XCTAssertEqual(client.requestedModes, [])
  }

  func testOneMissingFunctionKeepsKillAndNamesIt() {
    let withoutGet = FakeEndpointClient()
    XCTAssertEqual(
      withoutGet.configure(set: true, get: false),
      DeadlineMissModeStatus(
        setting: .killUnavailable, error: "es_get_deadline_miss_mode is missing."))
    XCTAssertEqual(withoutGet.requestedModes, [])

    let withoutSet = FakeEndpointClient()
    XCTAssertEqual(
      withoutSet.configure(set: false, get: true),
      DeadlineMissModeStatus(
        setting: .killUnavailable, error: "es_set_deadline_miss_mode is missing."))
    XCTAssertEqual(withoutSet.requestedModes, [])
  }

  func testConfirmedFailClosed() {
    let client = FakeEndpointClient()
    let status = client.configure()
    XCTAssertEqual(status, DeadlineMissModeStatus(setting: .failClosed))
    XCTAssertTrue(status.deniesUnansweredRequests)
    XCTAssertEqual(client.requestedModes, [DeadlineMissMode.failClosed.rawValue])
    XCTAssertEqual(client.mode, DeadlineMissMode.failClosed.rawValue)
  }

  func testRefusedSettingKeepsKill() {
    let client = FakeEndpointClient()
    client.refusesSetting = true
    XCTAssertEqual(
      client.configure(),
      DeadlineMissModeStatus(
        setting: .killAfterFailure, error: "es_set_deadline_miss_mode failed."))
    XCTAssertEqual(client.requestedModes, [DeadlineMissMode.failClosed.rawValue])
    XCTAssertEqual(client.mode, DeadlineMissMode.kill.rawValue)
  }

  func testIgnoredSettingIsReportedAsKill() {
    let client = FakeEndpointClient()
    client.ignoresSetting = true
    XCTAssertEqual(
      client.configure(),
      DeadlineMissModeStatus(
        setting: .killAfterFailure,
        error: "Endpoint Security reported mode 0 after the fail-closed mode was set."))
    XCTAssertEqual(client.requestedModes, [DeadlineMissMode.failClosed.rawValue])
  }

  func testUnreadableModeSetsKillAgain() {
    let client = FakeEndpointClient()
    client.refusesReading = true
    let status = client.configure()
    XCTAssertEqual(status.setting, .killAfterFailure)
    XCTAssertEqual(
      status.error,
      "es_get_deadline_miss_mode failed. The kill mode could not be confirmed either.")
    XCTAssertEqual(
      client.requestedModes, [DeadlineMissMode.failClosed.rawValue, DeadlineMissMode.kill.rawValue])
    XCTAssertEqual(client.mode, DeadlineMissMode.kill.rawValue)
  }

  func testUnexpectedReportedModeSetsKillAgain() {
    let client = FakeEndpointClient()
    client.reportsOnce = DeadlineMissMode.failOpen.rawValue
    let status = client.configure()
    XCTAssertEqual(
      status,
      DeadlineMissModeStatus(
        setting: .killAfterFailure,
        error:
          "Endpoint Security reported mode 2 after the fail-closed mode was set. The kill mode was set again."
      ))
    XCTAssertEqual(
      client.requestedModes, [DeadlineMissMode.failClosed.rawValue, DeadlineMissMode.kill.rawValue])
    XCTAssertEqual(client.mode, DeadlineMissMode.kill.rawValue)
  }

  func testFailOpenIsNeverRequested() {
    let cases: [(FakeEndpointClient) -> Void] = [
      { _ in }, { $0.refusesSetting = true }, { $0.ignoresSetting = true },
      { $0.refusesReading = true }, { $0.reportsOnce = 7 },
    ]
    for prepare in cases {
      let client = FakeEndpointClient()
      prepare(client)
      _ = client.configure()
      XCTAssertFalse(client.requestedModes.contains(DeadlineMissMode.failOpen.rawValue))
    }
  }

  func testFunctionsAreNotUsedBeforeMacOS27() {
    // macOS 26 exports both functions, but they fail there.
    let earlier = DeadlineMissModeFunctions.system(
      operatingSystemVersion: OperatingSystemVersion(
        majorVersion: 26, minorVersion: 6, patchVersion: 2))
    XCTAssertNil(earlier.set)
    XCTAssertNil(earlier.get)
    let client = FakeEndpointClient()
    XCTAssertEqual(
      DeadlineMissModeConfiguration.configure(
        client: OpaquePointer(Unmanaged.passUnretained(client).toOpaque()), functions: earlier),
      DeadlineMissModeStatus(setting: .killUnavailable))
  }

  func testThisSystemsFunctionsAreFoundTogether() {
    // Whichever system runs the tests, both functions are found or neither is.
    let functions = DeadlineMissModeFunctions.system(
      operatingSystemVersion: OperatingSystemVersion(
        majorVersion: 27, minorVersion: 0, patchVersion: 0))
    XCTAssertEqual(functions.set == nil, functions.get == nil)
    let current = DeadlineMissModeFunctions.system()
    if ProcessInfo.processInfo.operatingSystemVersion.majorVersion < 27 {
      XCTAssertNil(current.set)
    } else {
      XCTAssertEqual(current.set == nil, functions.set == nil)
    }
  }

  func testStatusWithoutDeadlineMissModeStillDecodes() throws {
    var snapshot = ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(), phase: .idle,
      timestamp: Date(timeIntervalSince1970: 1_800_000_000))
    snapshot.deadlineMissMode = DeadlineMissModeStatus(
      setting: .killAfterFailure, error: "es_set_deadline_miss_mode failed.")
    let data = try JSONEncoder().encode(snapshot)
    XCTAssertEqual(try JSONDecoder().decode(ExtensionStatusSnapshot.self, from: data), snapshot)
    var object = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    XCTAssertEqual(
      object["deadlineMissMode"] as? [String: String],
      ["setting": "killAfterFailure", "error": "es_set_deadline_miss_mode failed."])
    object.removeValue(forKey: "deadlineMissMode")
    let older = try JSONDecoder().decode(
      ExtensionStatusSnapshot.self, from: JSONSerialization.data(withJSONObject: object))
    XCTAssertNil(older.deadlineMissMode)
  }
}

/// Stands in for an Endpoint Security client. The functions below receive its address as the
/// client pointer, as C functions can't capture state.
private final class FakeEndpointClient {
  var mode = DeadlineMissMode.kill.rawValue
  var requestedModes: [UInt32] = []
  /// `es_set_deadline_miss_mode` fails and changes nothing.
  var refusesSetting = false
  /// `es_set_deadline_miss_mode` succeeds but changes nothing.
  var ignoresSetting = false
  /// `es_get_deadline_miss_mode` fails.
  var refusesReading = false
  /// The next read reports this mode instead of the current one.
  var reportsOnce: UInt32?

  private static let set: DeadlineMissModeFunctions.Set = { client, mode in
    let fake = FakeEndpointClient.from(client)
    fake.requestedModes.append(mode)
    if fake.refusesSetting { return ES_RETURN_ERROR }
    if !fake.ignoresSetting { fake.mode = mode }
    return ES_RETURN_SUCCESS
  }

  private static let get: DeadlineMissModeFunctions.Get = { client, mode in
    let fake = FakeEndpointClient.from(client)
    if fake.refusesReading { return ES_RETURN_ERROR }
    mode.pointee = fake.reportsOnce ?? fake.mode
    fake.reportsOnce = nil
    return ES_RETURN_SUCCESS
  }

  private static func from(_ client: OpaquePointer) -> FakeEndpointClient {
    Unmanaged<FakeEndpointClient>.fromOpaque(UnsafeRawPointer(client)).takeUnretainedValue()
  }

  /// Configures this client through functions found by name, as the extension does.
  func configure(set hasSet: Bool = true, get hasGet: Bool = true) -> DeadlineMissModeStatus {
    let functions = DeadlineMissModeFunctions { name in
      switch name {
      case DeadlineMissModeFunctions.setSymbol where hasSet:
        unsafeBitCast(Self.set, to: UnsafeMutableRawPointer.self)
      case DeadlineMissModeFunctions.getSymbol where hasGet:
        unsafeBitCast(Self.get, to: UnsafeMutableRawPointer.self)
      default:
        nil
      }
    }
    return withExtendedLifetime(self) {
      DeadlineMissModeConfiguration.configure(
        client: OpaquePointer(Unmanaged.passUnretained(self).toOpaque()), functions: functions)
    }
  }
}
