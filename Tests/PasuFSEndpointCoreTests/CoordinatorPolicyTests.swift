import Darwin
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest

@testable import PasuFSEndpointCore

final class CoordinatorPolicyTests: XCTestCase {
  func testPolicyTypeDecisionMatrix() {
    XCTAssertEqual(
      EndpointEventCoordinator.evaluationDecision(
        mode: .protection,
        policyType: .whitelist,
        match: .direct(ruleID: "rule")
      ),
      .allow
    )
    XCTAssertEqual(
      EndpointEventCoordinator.evaluationDecision(
        mode: .protection,
        policyType: .whitelist,
        match: .none
      ),
      .deny
    )
    XCTAssertEqual(
      EndpointEventCoordinator.evaluationDecision(
        mode: .protection,
        policyType: .blacklist,
        match: .inherited(ruleID: "rule")
      ),
      .deny
    )
    XCTAssertEqual(
      EndpointEventCoordinator.evaluationDecision(
        mode: .protection,
        policyType: .blacklist,
        match: .none
      ),
      .allow
    )
    XCTAssertEqual(
      EndpointEventCoordinator.evaluationDecision(
        mode: .audit,
        policyType: .whitelist,
        match: .none
      ),
      .wouldDeny
    )
    XCTAssertEqual(
      EndpointEventCoordinator.evaluationDecision(
        mode: .audit,
        policyType: .blacklist,
        match: .direct(ruleID: "rule")
      ),
      .wouldDeny
    )
  }

  func testOverlappingProtectionPoliciesRequireAllToAllowAndAuditNeverDenies() throws {
    let fixture = try makeScopeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let parentScope = try ProtectedPathScope(
      root: fixture.parent.path,
      homeDirectory: fixture.home.path
    )
    let childScope = try ProtectedPathScope(
      root: fixture.child.path,
      homeDirectory: fixture.home.path
    )
    let editorRule = AllowRule(
      id: "rule.editor",
      program: SignedProgramIdentity(
        teamIdentifier: "TEAM123456",
        signingIdentifier: "com.example.Editor"
      ),
      allowsDescendants: false
    )
    let otherRule = AllowRule(
      id: "rule.other",
      program: SignedProgramIdentity(
        teamIdentifier: "OTHERTEAM1",
        signingIdentifier: "com.example.Other"
      ),
      allowsDescendants: false
    )
    let parent = configuration(
      id: 1,
      name: "Parent whitelist",
      mode: .protection,
      type: .whitelist,
      scope: parentScope,
      rules: [editorRule]
    )
    let childBlacklist = configuration(
      id: 2,
      name: "Child blacklist",
      mode: .protection,
      type: .blacklist,
      scope: childScope,
      rules: [otherRule]
    )
    let childAudit = configuration(
      id: 3,
      name: "Child audit",
      mode: .audit,
      type: .whitelist,
      scope: childScope,
      rules: []
    )
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [parent, childBlacklist, childAudit],
      policyRevision: 7,
      sink: NoopSink(),
      decodeFailurePolicy: .failClosed
    )
    let target = fixture.child.appendingPathComponent("sample.txt").path
    let editor = try processFacts(team: "TEAM123456", signing: "com.example.Editor")

    let allowed = coordinator.evaluateOpen(
      path: target,
      pathWasTruncated: false,
      process: editor
    )
    XCTAssertEqual(allowed.authorizedFlags, UInt32.max)
    XCTAssertEqual(allowed.policyDecision, "allowed")
    XCTAssertEqual(allowed.policyEvaluations.count, 3)
    XCTAssertTrue(allowed.policyEvaluations.contains { $0.decision == .wouldDeny })

    let denyingBlacklist = configuration(
      id: 2,
      name: "Child blacklist",
      mode: .protection,
      type: .blacklist,
      scope: childScope,
      rules: [editorRule]
    )
    coordinator.replacePolicySet(
      setIdentifier: uuid(100),
      policies: [parent, denyingBlacklist, childAudit],
      revision: 8
    )
    let denied = coordinator.evaluateOpen(
      path: target,
      pathWasTruncated: false,
      process: editor
    )
    XCTAssertEqual(denied.authorizedFlags, 0)
    XCTAssertEqual(denied.policyDecision, "denied")
    XCTAssertEqual(
      denied.policyEvaluations.filter { $0.mode == .protection }.map(\.decision),
      [.allow, .deny]
    )
  }

  func testDecodeFailureFailsClosedForProtectionButNotAuditOnly() throws {
    let fixture = try makeScopeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let scope = try ProtectedPathScope(
      root: fixture.parent.path,
      homeDirectory: fixture.home.path
    )
    let audit = configuration(
      id: 1,
      name: "Audit",
      mode: .audit,
      type: .blacklist,
      scope: scope,
      rules: []
    )
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [audit],
      policyRevision: 1,
      sink: NoopSink(),
      decodeFailurePolicy: .failClosed
    )
    let target = fixture.parent.appendingPathComponent("sample.txt").path
    let auditOnly = coordinator.evaluateOpen(
      path: target,
      pathWasTruncated: false,
      process: nil,
      decodeErrorDescription: "test decode failure"
    )
    XCTAssertEqual(auditOnly.authorizedFlags, UInt32.max)
    XCTAssertEqual(auditOnly.policyEvaluations.map(\.decision), [.wouldDeny])

    let protection = configuration(
      id: 2,
      name: "Protection",
      mode: .protection,
      type: .blacklist,
      scope: scope,
      rules: []
    )
    coordinator.replacePolicySet(
      setIdentifier: uuid(100),
      policies: [audit, protection],
      revision: 2
    )
    let protected = coordinator.evaluateOpen(
      path: target,
      pathWasTruncated: false,
      process: nil,
      decodeErrorDescription: "test decode failure"
    )
    XCTAssertEqual(protected.authorizedFlags, 0)
    XCTAssertEqual(protected.policyDecision, "denied")
  }

  func testTypeChangeFlipsRetainedLineageAndRuleRemovalRevokesIt() throws {
    let fixture = try makeScopeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let scope = try ProtectedPathScope(
      root: fixture.parent.path,
      homeDirectory: fixture.home.path
    )
    let inheritableRule = AllowRule(
      id: "rule.editor",
      program: SignedProgramIdentity(
        teamIdentifier: "TEAM123456",
        signingIdentifier: "com.example.Editor"
      ),
      allowsDescendants: true
    )
    let whitelist = configuration(
      id: 1,
      name: "Policy",
      mode: .protection,
      type: .whitelist,
      scope: scope,
      rules: [inheritableRule]
    )
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [whitelist],
      policyRevision: 1,
      sink: NoopSink(),
      decodeFailurePolicy: .failClosed
    )
    let root = try processFacts(
      seed: 1,
      team: "TEAM123456",
      signing: "com.example.Editor"
    )
    let child = try processFacts(seed: 2, team: "OTHERTEAM1", signing: "com.example.Shell")
    coordinator.observeExec(root)
    coordinator.observeFork(parent: root.processInstance, child: child.processInstance)
    let target = fixture.parent.appendingPathComponent("sample.txt").path

    let inheritedAllow = coordinator.evaluateOpen(
      path: target,
      pathWasTruncated: false,
      process: child
    )
    XCTAssertEqual(inheritedAllow.authorizedFlags, UInt32.max)
    XCTAssertEqual(inheritedAllow.policyEvaluations[0].match, .inherited)

    let blacklist = configuration(
      id: 1,
      name: "Policy",
      mode: .protection,
      type: .blacklist,
      scope: scope,
      rules: [inheritableRule]
    )
    coordinator.replacePolicySet(
      setIdentifier: uuid(100),
      policies: [blacklist],
      revision: 2
    )
    let inheritedDeny = coordinator.evaluateOpen(
      path: target,
      pathWasTruncated: false,
      process: child
    )
    XCTAssertEqual(inheritedDeny.authorizedFlags, 0)
    XCTAssertEqual(inheritedDeny.policyEvaluations[0].match, .inherited)

    let disabled = configuration(
      id: 1,
      name: "Policy",
      mode: .protection,
      type: .blacklist,
      scope: scope,
      rules: []
    )
    coordinator.replacePolicySet(
      setIdentifier: uuid(100),
      policies: [disabled],
      revision: 3
    )
    let revoked = coordinator.evaluateOpen(
      path: target,
      pathWasTruncated: false,
      process: child
    )
    XCTAssertEqual(revoked.authorizedFlags, UInt32.max)
    XCTAssertEqual(revoked.policyEvaluations[0].match, .none)
  }

  func testDecodeFailureDecisionMatrix() {
    XCTAssertEqual(
      EndpointEventCoordinator.failureDecision(mode: .enforce, policy: .failClosed),
      OpenFailureDecision(authorizedFlags: 0, kernelResponse: "deny")
    )
    XCTAssertEqual(
      EndpointEventCoordinator.failureDecision(mode: .enforce, policy: .failOpen),
      OpenFailureDecision(authorizedFlags: UInt32.max, kernelResponse: "allow")
    )
    XCTAssertEqual(
      EndpointEventCoordinator.failureDecision(mode: .audit, policy: .failClosed),
      OpenFailureDecision(authorizedFlags: UInt32.max, kernelResponse: "allow")
    )
  }

  func testJSONLineLoggerRotatesAndProducesDecodableCurrentFile() throws {
    let directory = FileManager.default.temporaryDirectory
      .appendingPathComponent("pasu-fs-logger-test-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: directory) }
    let logger = try JSONLineEventLogger(
      directoryURL: directory,
      requiredOwnerUserID: getuid(),
      maximumPendingRecords: 8,
      maximumFileSize: 280
    )

    for index in 0..<8 {
      logger.record(
        EndpointEventRecord(
          policyRevision: 3,
          eventSequence: UInt64(index),
          eventType: "AUTH_OPEN",
          targetPath: "/Users/example/Protected/file-\(index).txt",
          policyDecision: "denied",
          kernelResponse: "deny"
        )
      )
    }
    logger.flushAndClose()

    let data = try Data(contentsOf: logger.fileURL)
    let lines = data.split(separator: 0x0A)
    XCTAssertFalse(lines.isEmpty)
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    XCTAssertNoThrow(try decoder.decode(EndpointEventRecord.self, from: Data(lines.last!)))
    XCTAssertTrue(
      FileManager.default.fileExists(atPath: logger.fileURL.appendingPathExtension("1").path)
    )
  }

  private func configuration(
    id: Int,
    name: String,
    mode: PolicyMode,
    type: PolicyType,
    scope: ProtectedPathScope,
    rules: [AllowRule]
  ) -> EndpointPolicyConfiguration {
    EndpointPolicyConfiguration(
      id: uuid(id),
      name: name,
      mode: mode,
      policyType: type,
      scope: scope,
      rules: PolicySnapshot(rules: rules)
    )
  }

  private func processFacts(
    seed: Int32 = 1,
    team: String,
    signing: String
  ) throws -> ProcessFacts {
    ProcessFacts(
      auditToken: try AuditTokenKey(words: Array(repeating: UInt32(seed), count: 8)),
      processInstance: ProcessInstanceKey(processID: seed, processVersion: 1),
      teamIdentifier: team,
      signingIdentifier: signing
    )
  }

  private func makeScopeFixture() throws -> (
    base: URL, home: URL, parent: URL, child: URL
  ) {
    let base = FileManager.default.temporaryDirectory
      .appendingPathComponent("PasuFSMultiPolicyTests-\(UUID().uuidString)")
    let home = base.appendingPathComponent("home")
    let parent = home.appendingPathComponent("Protected")
    let child = parent.appendingPathComponent("Nested")
    try FileManager.default.createDirectory(at: child, withIntermediateDirectories: true)
    return (base, home, parent, child)
  }

  private func uuid(_ value: Int) -> UUID {
    UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", value))!
  }
}

private struct NoopSink: EndpointEventSink {
  func record(_: EndpointEventRecord) {}
}
