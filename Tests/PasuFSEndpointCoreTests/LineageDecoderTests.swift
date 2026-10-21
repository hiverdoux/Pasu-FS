import Darwin
import EndpointSecurity
import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSEndpointCore

final class LineageDecoderTests: XCTestCase {
  func testMessageVersionGuardsAndExecutionIdentityExtraction() throws {
    var file = es_file_t()
    try withUnsafeMutablePointer(to: &file) { filePointer in
      let rawProcess = UnsafeMutablePointer<es_process_t>.allocate(capacity: 1)
      defer { rawProcess.deallocate() }
      memset(rawProcess, 0, MemoryLayout<es_process_t>.stride)
      rawProcess.pointee.executable = filePointer
      rawProcess.pointee.audit_token = audit_token_t(val: (0, 0, 0, 0, 0, 20, 0, 7))
      rawProcess.pointee.parent_audit_token = audit_token_t(val: (0, 0, 0, 0, 0, 10, 0, 3))
      rawProcess.pointee.responsible_audit_token = audit_token_t(val: (0, 0, 0, 0, 0, 5, 0, 2))
      rawProcess.pointee.start_time.tv_sec = 1_800_000_000
      rawProcess.pointee.original_ppid = 10
      let processPointer = rawProcess
      do {
        let old = try EndpointDecoder.lineageProcess(processPointer, version: 2, at: Date())
        XCTAssertEqual(old.key, LineageProcessKey(pid: 20, version: 7))
        XCTAssertNil(old.startTime)
        XCTAssertNil(old.parent)
        XCTAssertNil(old.responsible)
        let intermediate = try EndpointDecoder.lineageProcess(
          processPointer, version: 3, at: Date())
        XCTAssertNotNil(intermediate.startTime)
        XCTAssertNil(intermediate.parent)
        let current = try EndpointDecoder.lineageProcess(processPointer, version: 4, at: Date())
        XCTAssertEqual(current.parent, LineageProcessKey(pid: 10, version: 3))
        XCTAssertEqual(current.responsible, LineageProcessKey(pid: 5, version: 2))
        let message = UnsafeMutablePointer<es_message_t>.allocate(capacity: 1)
        defer { message.deallocate() }
        memset(message, 0, MemoryLayout<es_message_t>.stride)
        message.pointee.process = processPointer
        message.pointee.event_type = ES_EVENT_TYPE_AUTH_OPEN
        message.pointee.seq_num = 123
        message.pointee.global_seq_num = 456
        message.pointee.version = 1
        var event = EndpointDecoder.lineageObservation(message)
        XCTAssertNil(event.sequence)
        XCTAssertNil(event.globalSequence)
        XCTAssertTrue(event.issues.contains("versionUnavailable"))
        message.pointee.version = 2
        event = EndpointDecoder.lineageObservation(message)
        XCTAssertEqual(event.sequence, 123)
        XCTAssertNil(event.globalSequence)
        message.pointee.version = 4
        event = EndpointDecoder.lineageObservation(message)
        XCTAssertEqual(event.globalSequence, 456)
        XCTAssertTrue(event.issues.isEmpty)
        XCTAssertEqual(event.actor?.responsible, current.responsible)
      }
    }
  }

  /// The facts a history can begin with when launchd started a process before observation:
  /// the start time from version 3 and the current parent from version 4.
  func testProcessFactsCarryTheStartTimeAndTheCurrentParentByMessageVersion() throws {
    var file = es_file_t()
    try withUnsafeMutablePointer(to: &file) { filePointer in
      let rawProcess = UnsafeMutablePointer<es_process_t>.allocate(capacity: 1)
      defer { rawProcess.deallocate() }
      memset(rawProcess, 0, MemoryLayout<es_process_t>.stride)
      rawProcess.pointee.executable = filePointer
      rawProcess.pointee.audit_token = audit_token_t(val: (0, 0, 0, 0, 0, 20, 0, 7))
      rawProcess.pointee.parent_audit_token = audit_token_t(val: (0, 0, 0, 0, 0, 1, 0, 3))
      rawProcess.pointee.start_time = timeval(tv_sec: 1_800_000_000, tv_usec: 250_000)
      rawProcess.pointee.original_ppid = 1
      rawProcess.pointee.ppid = 1

      let old = try EndpointDecoder.process(rawProcess, messageVersion: 2)
      XCTAssertNil(old.facts.startTime)
      XCTAssertNil(old.facts.parentProcessInstance)
      XCTAssertNil(old.executionProgram.parentProcessID)
      XCTAssertEqual(old.executionProgram.originalParentProcessID, 1)

      let intermediate = try EndpointDecoder.process(rawProcess, messageVersion: 3)
      XCTAssertEqual(
        intermediate.facts.startTime, Date(timeIntervalSince1970: 1_800_000_000.25))
      XCTAssertNil(intermediate.executionProgram.parentProcessID)

      let current = try EndpointDecoder.process(rawProcess, messageVersion: 4)
      XCTAssertEqual(current.executionProgram.parentProcessID, 1)
      XCTAssertEqual(current.executionProgram.startTime, intermediate.facts.startTime)

      // A start time the kernel left empty is not reported as the epoch.
      rawProcess.pointee.start_time = timeval()
      XCTAssertNil(try EndpointDecoder.process(rawProcess, messageVersion: 4).facts.startTime)
    }
  }
}
