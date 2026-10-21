import Darwin
import Foundation
import XCTest

@testable import PasuFSHostCore

/// The process the app starts for a query, with system tools in place of the app's executable.
final class SpawnedInstallationStateChildTests: XCTestCase {
  func testOutputAndExitStatusAreRead() async throws {
    let child = try SpawnedInstallationStateChild(
      executablePath: "/bin/echo", arguments: ["sample output"])
    let termination = await child.waitForTermination()
    XCTAssertEqual(termination.reason, .exited(0))
    XCTAssertEqual(String(decoding: termination.standardOutput, as: UTF8.self), "sample output\n")
    XCTAssertFalse(termination.outputWasTruncated)

    let failing = try SpawnedInstallationStateChild(executablePath: "/usr/bin/false", arguments: [])
    let failed = await failing.waitForTermination()
    XCTAssertEqual(failed.reason, .exited(1))
    XCTAssertTrue(failed.standardOutput.isEmpty)
  }

  /// The child gets no input and no error output, and none of the parent's other descriptors.
  func testChildInheritsNoOtherDescriptors() async throws {
    // A descriptor without close-on-exec, which a plain exec would pass on.
    let unrelated = open("/dev/null", O_RDONLY)
    XCTAssertGreaterThan(unrelated, 2)
    defer { close(unrelated) }
    XCTAssertEqual(fcntl(unrelated, F_GETFD) & FD_CLOEXEC, 0)

    let child = try SpawnedInstallationStateChild(
      executablePath: "/bin/sh",
      arguments: [
        "-c",
        "read line; echo read=$?; [ -e /dev/fd/\(unrelated) ] && echo inherited || echo closed; echo error >&2",
      ])
    let termination = await child.waitForTermination()
    XCTAssertEqual(
      String(decoding: termination.standardOutput, as: UTF8.self), "read=1\nclosed\n")
  }

  /// A killed child is reported as ended by SIGKILL, once it has ended; a kill after the end
  /// sends nothing.
  func testKillEndsTheChildAndWaitsForIt() async throws {
    let child = try SpawnedInstallationStateChild(executablePath: "/bin/sleep", arguments: ["30"])
    let started = Date()
    child.kill()
    let termination = await child.waitForTermination()
    XCTAssertEqual(termination.reason, .signaled(SIGKILL))
    XCTAssertLessThan(Date().timeIntervalSince(started), 5)
    XCTAssertEqual(Darwin.kill(child.processIdentifier, 0), -1, "the process is gone")
    child.kill()
    let again = await child.waitForTermination()
    XCTAssertEqual(again, termination)
  }

  func testOutputBeyondTheLimitIsTruncated() async throws {
    let size = InstallationStateReport.maximumEncodedSize + 10
    let child = try SpawnedInstallationStateChild(
      executablePath: "/bin/sh", arguments: ["-c", "head -c \(size) /dev/zero"])
    let termination = await child.waitForTermination()
    XCTAssertEqual(termination.reason, .exited(0))
    XCTAssertTrue(termination.outputWasTruncated)
    XCTAssertEqual(termination.standardOutput.count, InstallationStateReport.maximumEncodedSize)
  }

  func testMissingExecutableFailsToLaunch() {
    XCTAssertThrowsError(
      try SpawnedInstallationStateChild(
        executablePath: "/nonexistent/sample.app/Contents/MacOS/sample", arguments: []))
  }
}
