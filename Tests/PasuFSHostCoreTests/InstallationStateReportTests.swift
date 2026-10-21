import Foundation
import XCTest

@testable import PasuFSHostCore

final class InstallationStateReportTests: XCTestCase {
  private let installed = ExtensionInstallationProperties(
    bundleIdentifier: ActivationController.extensionIdentifier, bundleVersion: "123",
    bundleShortVersion: "1.2.3", isEnabled: false, isAwaitingUserApproval: true,
    isUninstalling: false)

  /// Every outcome survives the round trip with the exit status that names it.
  func testReportsSurviveEncodingWithTheirExitStatus() {
    let reports: [InstallationStateReport] = [
      .reported([installed]),
      .reported([]),
      .requestFailed(domain: "OSSystemExtensionErrorDomain", code: 4, description: "Not found"),
      .endedWithoutAnswer,
      .timedOut(seconds: 30),
    ]
    XCTAssertEqual(reports.map(\.exitStatus), [0, 0, 2, 2, 3])
    for report in reports {
      let data = report.encoded()
      XCTAssertEqual(data.last, 0x0A, "one line")
      XCTAssertEqual(
        InstallationStateReport(decoding: data, exitStatus: report.exitStatus), report)
    }
  }

  /// The format is plain JSON that names each field, so other tools can read it too.
  func testEncodedFieldsAreNamed() throws {
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: InstallationStateReport.reported([installed]).encoded())
        as? [String: Any])
    XCTAssertEqual(object["formatVersion"] as? Int, 1)
    XCTAssertEqual(object["outcome"] as? String, "reported")
    let first = try XCTUnwrap((object["installations"] as? [[String: Any]])?.first)
    XCTAssertEqual(first["bundleVersion"] as? String, "123")
    XCTAssertEqual(first["isAwaitingUserApproval"] as? Bool, true)

    let failure = try XCTUnwrap(
      JSONSerialization.jsonObject(
        with: InstallationStateReport.requestFailed(domain: "D", code: 7, description: "E")
          .encoded()) as? [String: Any])
    XCTAssertEqual(failure["outcome"] as? String, "failed")
    XCTAssertEqual(
      failure["failure"] as? [String: AnyHashable],
      ["kind": "requestFailed", "domain": "D", "code": 7, "description": "E"])
  }

  /// Anything other than one object in this format, with the matching exit status, is rejected.
  func testUnreadableOrInconsistentOutputIsRejected() {
    let reported = InstallationStateReport.reported([installed]).encoded()
    XCTAssertNil(InstallationStateReport(decoding: reported, exitStatus: 2), "status mismatch")
    XCTAssertNil(InstallationStateReport(decoding: reported, exitStatus: 1))
    XCTAssertNil(InstallationStateReport(decoding: reported.prefix(20), exitStatus: 0))
    XCTAssertNil(InstallationStateReport(decoding: reported + reported, exitStatus: 0))
    XCTAssertNil(InstallationStateReport(decoding: Data(), exitStatus: 0))
    XCTAssertNil(InstallationStateReport(decoding: Data("Usage: …\n".utf8), exitStatus: 0))
    for json in [
      #"{"formatVersion":2,"outcome":"reported","installations":[]}"#,
      #"{"formatVersion":1,"outcome":"reported"}"#,
      #"{"formatVersion":1,"outcome":"reported","installations":[],"timeoutSeconds":1}"#,
      #"{"formatVersion":1,"outcome":"later","installations":[]}"#,
      #"{"formatVersion":1,"outcome":"reported","installations":[{"bundleVersion":"1"}]}"#,
    ] {
      XCTAssertNil(InstallationStateReport(decoding: Data(json.utf8), exitStatus: 0), json)
    }
    for json in [
      #"{"formatVersion":1,"outcome":"failed","failure":{"kind":"requestFailed","code":1}}"#,
      #"{"formatVersion":1,"outcome":"failed","failure":{"kind":"other"}}"#,
      #"{"formatVersion":1,"outcome":"failed","failure":{"kind":"endedWithoutAnswer","code":1}}"#,
      #"{"formatVersion":1,"outcome":"failed"}"#,
    ] {
      XCTAssertNil(InstallationStateReport(decoding: Data(json.utf8), exitStatus: 2), json)
    }
    XCTAssertNil(
      InstallationStateReport(
        decoding: Data(#"{"formatVersion":1,"outcome":"timedOut","timeoutSeconds":-1}"#.utf8),
        exitStatus: 3))
    let oversized = Data(repeating: 0x20, count: InstallationStateReport.maximumEncodedSize)
    XCTAssertNil(InstallationStateReport(decoding: reported + oversized, exitStatus: 0))
  }

  // MARK: - The request in the child process

  func testProbeReturnsTheAnswer() async {
    let reported = await InstallationStateProbe.query(
      StreamLifecycle(events: [.submitted(action: "properties"), .properties([installed])]),
      timeout: 5)
    XCTAssertEqual(reported, .reported([installed]))

    let failed = await InstallationStateProbe.query(
      StreamLifecycle(events: [.failed(domain: "D", code: 3, description: "E")]), timeout: 5)
    XCTAssertEqual(failed, .requestFailed(domain: "D", code: 3, description: "E"))

    let ended = await InstallationStateProbe.query(
      StreamLifecycle(events: [.submitted(action: "properties")]), timeout: 5)
    XCTAssertEqual(ended, .endedWithoutAnswer)
  }

  /// A request that macOS never answers ends at the timeout, as `--status` and the child do.
  func testProbeStopsWaitingAtTheTimeout() async {
    let lifecycle = StreamLifecycle(events: [.submitted(action: "properties")], finishes: false)
    let started = Date()
    let report = await InstallationStateProbe.query(lifecycle, timeout: 0.2)
    XCTAssertEqual(report, .timedOut(seconds: 1))
    XCTAssertLessThan(Date().timeIntervalSince(started), 5)
  }
}

/// Yields fixed events to properties requests, and finishes the stream or leaves it open.
private struct StreamLifecycle: ExtensionLifecycleControlling {
  let events: [ActivationEvent]
  var finishes = true

  func activationEvents() -> AsyncStream<ActivationEvent> { AsyncStream { $0.finish() } }
  func deactivationEvents() -> AsyncStream<ActivationEvent> { AsyncStream { $0.finish() } }
  func propertiesEvents() -> AsyncStream<ActivationEvent> {
    AsyncStream { continuation in
      for event in events { continuation.yield(event) }
      if finishes { continuation.finish() }
    }
  }
  func installationStateLauncher() -> any InstallationStateChildLaunching {
    InstallationStateChildProcessLauncher(executableURL: nil)
  }
}
