import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest

@testable import PasuFSEndpointCore

final class ProcessLineageLoadTests: XCTestCase {
  /// Compares the same pure-facts authorization and persistence workload with
  /// history disabled/enabled. This is not a measurement of kernel deadlines.
  func testNormalLoadHasIdenticalDecisionsAndNoDroppedRecords() throws {
    for enabled in [false, true] {
      let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
      let protected = root.appendingPathComponent("protected")
      try FileManager.default.createDirectory(at: protected, withIntermediateDirectories: true)
      defer { try? FileManager.default.removeItem(at: root) }
      let budget = AuditWorkBudget()
      let logger = try PolicyAuditLogStore(
        directoryURL: root.appendingPathComponent("logs"), budget: budget)
      defer { logger.flushAndClose() }
      let tracker =
        enabled
        ? ProcessLineageTracker(bootIdentifier: "example", sink: logger, budget: budget) : nil
      defer { tracker?.close() }
      let policy = DirectoryPolicy(
        name: "Example", mode: .audit, policyType: .whitelist,
        protectedRootPath: protected.path, rules: [])
      let document = PolicySetDocument(setIdentifier: UUID(), revision: 1, policies: [policy])
      logger.updatePolicySet(document)
      let coordinator = EndpointEventCoordinator(
        policySetIdentifier: document.setIdentifier,
        policies: [
          EndpointPolicyConfiguration(
            id: policy.id, name: policy.name, mode: policy.mode, policyType: policy.policyType,
            scope: try ProtectedPathScope(root: protected.path, homeDirectory: root.path),
            rules: PolicySnapshot(rules: []))
        ], policyRevision: 1, sink: logger)
      let owner = LineageProcessKey(pid: 1, version: 1)
      var actor = LineageProcess(
        key: owner, executablePath: "/example/root", responsible: owner, originalParentPID: 0)
      let date = Date(timeIntervalSince1970: 1_800_000_000)
      for pid: Int32 in 2...17 {
        let child = LineageProcess(
          key: LineageProcessKey(pid: pid, version: 1),
          executablePath: "/example/tool\(pid)", parent: actor.key,
          responsible: owner, originalParentPID: actor.key.pid)
        tracker?.submit(
          LineageObservation(
            eventType: "NOTIFY_FORK", timestamp: date,
            source: actor, target: child), record: nil)
        actor = child
      }
      let facts = ProcessFacts(
        auditToken: try AuditTokenKey(words: Array(repeating: 1, count: 8)),
        processInstance: ProcessInstanceKey(processID: actor.key.pid, processVersion: 1),
        teamIdentifier: nil, signingIdentifier: nil)
      let observation = LineageObservation(eventType: "AUTH_OPEN", timestamp: date, source: actor)
      var samples: [Double] = []
      let start = DispatchTime.now().uptimeNanoseconds
      for index: UInt64 in 0..<1_000 {
        let before = DispatchTime.now().uptimeNanoseconds
        let decision = coordinator.evaluateOpen(
          path: protected.appendingPathComponent("sample").path,
          pathWasTruncated: false, process: facts, requestedOpenFlags: 1)
        samples.append(Double(DispatchTime.now().uptimeNanoseconds - before) / 1_000)
        XCTAssertEqual(decision.authorizedFlags, UInt32.max)
        XCTAssertEqual(decision.policyEvaluations.first?.decision, .wouldDeny)
        let record = EndpointEventRecord(
          timestamp: date, policySetIdentifier: document.setIdentifier, policyRevision: 1,
          eventSequence: index, eventType: "AUTH_OPEN", processID: actor.key.pid,
          executablePath: actor.executablePath,
          targetPath: protected.appendingPathComponent("sample").path,
          policyDecision: decision.policyDecision, kernelResponse: "allow",
          policyEvaluations: decision.policyEvaluations)
        if let tracker {
          tracker.submit(observation, record: record)
        } else {
          logger.record(record)
        }
        // Bounded batches model normal load separately from queue-overload tests.
        if index % 50 == 49 {
          tracker?.flush()
          _ = try logger.readAuditLog(maximumLineCount: 1)
        }
      }
      tracker?.flush()
      logger.flushAndClose()
      let elapsed = Double(DispatchTime.now().uptimeNanoseconds - start) / 1_000_000
      samples.sort()
      XCTAssertEqual(logger.droppedEventCount, 0)
      XCTAssertFalse(
        tracker?.status.issues.contains {
          $0.reason == "queueOverflow" || $0.reason == "resourceLimit"
        } == true)
      let files = try FileManager.default.contentsOfDirectory(
        at: root.appendingPathComponent("logs"), includingPropertiesForKeys: [.fileSizeKey])
      let bytes = try files.reduce(0) {
        $0 + (try $1.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0)
      }
      print(
        "LINEAGE_LOAD history=\(enabled) count=1000 evaluation_p50_us=\(samples[500]) evaluation_p99_us=\(samples[990]) total_ms=\(elapsed) retained_graph_bytes=\(tracker?.status.retainedDataBytes ?? 0) retained_log_bytes=\(bytes) dropped=\(logger.droppedEventCount)"
      )
    }
  }
}
