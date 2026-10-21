import Darwin
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest

@testable import PasuFSEndpointCore

/// After a policy follows its folder, the folder's former path stays reserved for the programs
/// the policy allows until the policy is saved: other programs are denied there, and allowed
/// programs are recorded with a warning.
final class RetiredFolderPathTests: XCTestCase {
  private let current = "/Users/example/Moved/Secret"
  private let retired = "/Users/example/Parent/Secret"

  private struct Harness {
    let coordinator: EndpointEventCoordinator
    let allowed: ProcessFacts
    let unlisted: ProcessFacts
  }

  // MARK: - At the retired path and below it

  func testOtherProgramsAreDeniedAtTheRetiredPathAndBelowIt() throws {
    let harness = try makeHarness()
    let inside = retired + "/report.txt"
    let requests: [FileOperationRequest] = [
      .open(path: inside, flags: UInt32(FREAD)),
      .open(path: inside, flags: UInt32(FREAD | FWRITE)),
      .open(path: retired, flags: UInt32(FREAD)),
      .create(in: file(retired), name: "report.txt"),
      .create(in: file("/Users/example/Parent"), name: "Secret"),
      .rename(source: file("/Users/example/Outside/a.txt"), destination: CheckedPath(path: inside)),
      .rename(source: file(inside), destination: CheckedPath(path: "/Users/example/Outside/a.txt")),
      .unlink(target: file(inside)),
      .truncate(target: file(inside)),
      .link(
        source: file("/Users/example/Outside/a.txt"), targetDirectory: file(retired), name: "b"),
      .clone(
        source: file("/Users/example/Outside/a.txt"), targetDirectory: file(retired), name: "b"),
      .copyFile(
        source: file("/Users/example/Outside/a.txt"), existingTarget: nil,
        targetDirectory: file(retired), name: "b"),
      .exchangeData(file(inside), file("/Users/example/Outside/a.txt")),
    ]
    for request in requests {
      let result = harness.coordinator.evaluate(request, process: harness.unlisted)
      XCTAssertTrue(result.isInScope, "\(request.kind)")
      XCTAssertTrue(result.isDenied, "\(request.kind) \(request.primaryPath.path)")
      let evaluation = try XCTUnwrap(result.policyEvaluations.first)
      XCTAssertEqual(evaluation.retiredFolderPath, retired)
      XCTAssertEqual(evaluation.decision, .deny)
      XCTAssertNotNil(evaluation.executionOrigin)
    }
  }

  func testAllowedProgramsAreAllowedAndRecordedWithTheRetiredPath() throws {
    let harness = try makeHarness()
    let inside = retired + "/report.txt"
    for request in [
      FileOperationRequest.create(in: file(retired), name: "report.txt"),
      .open(path: inside, flags: UInt32(FREAD | FWRITE)),
      .create(in: file("/Users/example/Parent"), name: "Secret"),
    ] {
      let result = harness.coordinator.evaluate(request, process: harness.allowed)
      XCTAssertTrue(result.isInScope)
      XCTAssertFalse(result.isDenied)
      XCTAssertEqual(result.policyDecision, "allowed")
      let evaluation = try XCTUnwrap(result.policyEvaluations.first)
      XCTAssertEqual(evaluation.retiredFolderPath, retired)
      XCTAssertEqual(evaluation.decision, .allow)
      XCTAssertEqual(evaluation.match, .direct)
      XCTAssertEqual(evaluation.ruleIdentifier, "rule.editor")
    }
  }

  /// A metadata change at the retired path or below it is decided like any other request
  /// there; a change to a folder that leads to the retired path changes nothing inside it.
  func testMetadataChangesAtTheRetiredPathFollowTheSameRules() throws {
    let harness = try makeHarness()
    for kind in FileOperationKind.allCases where kind.changesMetadata {
      for target in [retired, retired + "/report.txt"] {
        let request = FileOperationRequest.metadataChange(kind, target: file(target))
        let denied = harness.coordinator.evaluate(request, process: harness.unlisted)
        XCTAssertTrue(denied.isDenied, "\(kind.rawValue) \(target)")
        XCTAssertEqual(denied.policyEvaluations.first?.retiredFolderPath, retired)
        let allowed = harness.coordinator.evaluate(request, process: harness.allowed)
        XCTAssertFalse(allowed.isDenied, "\(kind.rawValue) \(target)")
        XCTAssertEqual(allowed.policyEvaluations.first?.decision, .allow)
        XCTAssertEqual(allowed.policyEvaluations.first?.retiredFolderPath, retired)
      }
      let parent = harness.coordinator.evaluate(
        .metadataChange(kind, target: file("/Users/example/Parent")), process: harness.unlisted)
      XCTAssertFalse(parent.isInScope, kind.rawValue)
    }
  }

  func testRequestsInTheFolderItselfCarryNoRetiredPath() throws {
    let harness = try makeHarness()
    let result = harness.coordinator.evaluate(
      .open(path: current + "/report.txt", flags: UInt32(FREAD)), process: harness.allowed)
    XCTAssertFalse(result.isDenied)
    XCTAssertNil(result.policyEvaluations.first?.retiredFolderPath)
  }

  func testAnAuditPolicyRecordsWouldDenyAtTheRetiredPath() throws {
    let harness = try makeHarness(mode: .audit)
    let result = harness.coordinator.evaluate(
      .create(in: file(retired), name: "report.txt"), process: harness.unlisted)
    XCTAssertTrue(result.isInScope)
    XCTAssertFalse(result.isDenied)
    XCTAssertEqual(result.policyDecision, "audit-only")
    XCTAssertEqual(result.policyEvaluations.first?.decision, .wouldDeny)
    XCTAssertEqual(result.policyEvaluations.first?.retiredFolderPath, retired)
  }

  func testUnrelatedPathsAndTheRetiredPathsSiblingsAreOutsideTheScope() throws {
    let harness = try makeHarness()
    for request in [
      FileOperationRequest.open(path: "/Users/example/Parent", flags: UInt32(FREAD)),
      .open(path: "/Users/example/Parent/Secretive/a.txt", flags: UInt32(FREAD)),
      .create(in: file("/Users/example/Parent"), name: "Other"),
      .create(in: file("/Users/example"), name: "Unrelated"),
      .unlink(target: file("/Users/example/Parent/Other")),
    ] {
      let result = harness.coordinator.evaluate(request, process: harness.unlisted)
      XCTAssertFalse(result.isInScope, "\(request.kind) \(request.primaryPath.path)")
      XCTAssertFalse(result.isDenied)
    }
  }

  // MARK: - Folders leading to the retired path

  func testOtherProgramsCannotMoveRemoveOrCopyAFolderThatContainsTheRetiredPath() throws {
    let harness = try makeHarness()
    for request in [
      FileOperationRequest.rename(
        source: file("/Users/example/Parent"),
        destination: CheckedPath(path: "/Users/example/Elsewhere")),
      .unlink(target: file("/Users/example/Parent")),
      .clone(source: file("/Users/example/Parent"), targetDirectory: file("/tmp"), name: "copy"),
    ] {
      let result = harness.coordinator.evaluate(request, process: harness.unlisted)
      XCTAssertTrue(result.isDenied, "\(request.kind)")
      XCTAssertEqual(result.policyEvaluations.first?.retiredFolderPath, retired)
    }
    let allowed = harness.coordinator.evaluate(
      .rename(
        source: file("/Users/example/Parent"),
        destination: CheckedPath(path: "/Users/example/Elsewhere")),
      process: harness.allowed)
    XCTAssertFalse(allowed.isDenied)
    XCTAssertEqual(allowed.policyEvaluations.first?.retiredFolderPath, retired)
    // Nothing of the policy folder moved, so nothing is followed.
    XCTAssertTrue(harness.coordinator.pendingFolderMoves.isEmpty)
  }

  func testOtherProgramsCannotPlaceAnItemOnAFolderLeadingToTheRetiredPath() throws {
    let harness = try makeHarness(retired: "/Users/example/Old/Parent/Secret")
    // The folders leading to the retired path no longer exist after the parent was renamed.
    for request in [
      FileOperationRequest.create(in: file("/Users/example"), name: "Old"),
      .create(in: file("/Users/example/Old"), name: "Parent"),
      .rename(
        source: file("/private/tmp/prepared"), destination: CheckedPath(path: "/Users/example/Old")),
      .clone(
        source: file("/private/tmp/prepared"), targetDirectory: file("/Users/example/Old"),
        name: "Parent"),
      .link(source: file("/private/tmp/a"), targetDirectory: file("/Users/example"), name: "Old"),
    ] {
      let result = harness.coordinator.evaluate(request, process: harness.unlisted)
      XCTAssertTrue(result.isDenied, "\(request.kind) \(request.newObjectPath?.path ?? "")")
      XCTAssertEqual(
        result.policyEvaluations.first?.retiredFolderPath, "/Users/example/Old/Parent/Secret")
    }
  }

  func testMovingThePolicyFolderBackOntoTheRetiredPathIsARenameOfItsParent() throws {
    let harness = try makeHarness()
    // Finder renames the folder's new parent back to the old name.
    let result = harness.coordinator.evaluate(
      .rename(
        source: file("/Users/example/Moved"),
        destination: CheckedPath(path: "/Users/example/Parent")
      ),
      process: harness.unlisted)
    XCTAssertFalse(result.isDenied)
    let evaluation = try XCTUnwrap(result.policyEvaluations.first)
    XCTAssertEqual(evaluation.match, .enclosingFolder)
    XCTAssertNil(evaluation.retiredFolderPath)
    XCTAssertEqual(harness.coordinator.pendingFolderMoves.map(\.scope.root), [retired])
    // While the move is pending, the retired path is protected as the folder's location.
    let inside = harness.coordinator.evaluate(
      .open(path: retired + "/report.txt", flags: UInt32(FREAD)), process: harness.allowed)
    XCTAssertFalse(inside.isDenied)
    XCTAssertNil(inside.policyEvaluations.first?.retiredFolderPath)
  }

  func testAProtectedFolderMovedOntoTheRetiredPathByAnAllowedProgramIsNotAWarning() throws {
    let harness = try makeHarness()
    let result = harness.coordinator.evaluate(
      .rename(source: file(current), destination: CheckedPath(path: retired)),
      process: harness.allowed)
    XCTAssertFalse(result.isDenied)
    XCTAssertNil(result.policyEvaluations.first?.retiredFolderPath)
  }

  func testMovingAnotherFolderOntoAParentOfTheRetiredPathIsDenied() throws {
    let harness = try makeHarness()
    // A rename of the current parent that does not land the folder on the retired path.
    let result = harness.coordinator.evaluate(
      .rename(
        source: file("/Users/example/Outside"),
        destination: CheckedPath(path: "/Users/example/Parent")
      ),
      process: harness.unlisted)
    XCTAssertTrue(result.isDenied)
    XCTAssertEqual(result.policyEvaluations.first?.retiredFolderPath, retired)
  }

  // MARK: - Folders that contain both the policy folder and a retired path

  func testRenamingAFolderThatAlsoContainsThePolicyFolderMovesTheRetiredPathAlong() throws {
    let base = "/Users/example/Base"
    let harness = try makeHarness(current: base + "/B/Secret", retired: base + "/A/Secret")
    let result = harness.coordinator.evaluate(
      .rename(source: file(base), destination: CheckedPath(path: "/Users/example/Base2")),
      process: harness.unlisted)
    XCTAssertFalse(result.isDenied)
    let evaluation = try XCTUnwrap(result.policyEvaluations.first)
    XCTAssertEqual(evaluation.match, .enclosingFolder)
    XCTAssertNil(evaluation.retiredFolderPath)
    let move = try XCTUnwrap(harness.coordinator.pendingFolderMoves.first)
    XCTAssertEqual(move.scope.root, "/Users/example/Base2/B/Secret")
    XCTAssertEqual(move.retiredScopes.map(\.root), ["/Users/example/Base2/A/Secret"])
    // Until the move is confirmed, both the retired path and its new location are reserved.
    for directory in [base + "/A/Secret", "/Users/example/Base2/A/Secret"] {
      let create = harness.coordinator.evaluate(
        .create(in: file(directory), name: "x"), process: harness.unlisted)
      XCTAssertTrue(create.isDenied, directory)
      XCTAssertEqual(create.policyEvaluations.first?.retiredFolderPath, directory)
    }
  }

  func testDeletingOrCopyingAFolderThatAlsoContainsThePolicyFolderIsDecidedByTheLists() throws {
    let base = "/Users/example/Base"
    let harness = try makeHarness(current: base + "/B/Secret", retired: base + "/A/Secret")
    for request in [
      FileOperationRequest.unlink(target: file(base)),
      .clone(source: file(base), targetDirectory: file("/Users/example"), name: "Copy"),
    ] {
      let denied = harness.coordinator.evaluate(request, process: harness.unlisted)
      XCTAssertTrue(denied.isDenied, "\(request.kind)")
      XCTAssertEqual(denied.policyEvaluations.first?.match, .enclosingFolder)
      XCTAssertEqual(denied.policyEvaluations.first?.retiredFolderPath, base + "/A/Secret")
      let allowed = harness.coordinator.evaluate(request, process: harness.allowed)
      XCTAssertFalse(allowed.isDenied, "\(request.kind)")
    }
  }

  func testRenamingAParentOfThePolicyFolderOntoAFolderLeadingToARetiredPathIsDenied() throws {
    // The policy folder moves, but the destination recreates the folder above a retired path
    // without bringing the policy folder there.
    let harness = try makeHarness(
      current: "/Users/example/Work/Secret", retired: "/Users/example/Old/Other/Secret")
    let result = harness.coordinator.evaluate(
      .rename(
        source: file("/Users/example/Work"), destination: CheckedPath(path: "/Users/example/Old")),
      process: harness.unlisted)
    XCTAssertTrue(result.isDenied)
    XCTAssertEqual(
      result.policyEvaluations.first?.retiredFolderPath, "/Users/example/Old/Other/Secret")
    XCTAssertTrue(harness.coordinator.pendingFolderMoves.isEmpty)
  }

  // MARK: - Mounts and truncated paths

  func testAMountCoveringTheRetiredPathIsDeniedForEveryone() throws {
    let harness = try makeHarness()
    for mountPoint in [retired, retired + "/Inner", "/Users/example/Parent"] {
      let result = harness.coordinator.evaluate(
        .mount(mountPoint: mountPoint, volumeSource: "/dev/disk9s1"), process: harness.allowed)
      XCTAssertTrue(result.isDenied, mountPoint)
      let evaluation = try XCTUnwrap(result.policyEvaluations.first)
      XCTAssertEqual(evaluation.match, .mountPoint)
      XCTAssertEqual(evaluation.retiredFolderPath, retired)
      XCTAssertEqual(
        evaluation.detail, "A volume mounted here would cover a retired path of this policy.")
    }
  }

  func testATruncatedPathAtTheRetiredPathFailsClosed() throws {
    let harness = try makeHarness()
    let result = harness.coordinator.evaluate(
      .open(path: retired + "/deep", wasTruncated: true), process: harness.allowed)
    XCTAssertTrue(result.isDenied)
    XCTAssertEqual(result.policyEvaluations.first?.match, .truncatedPath)
    XCTAssertEqual(result.policyEvaluations.first?.retiredFolderPath, retired)
  }

  // MARK: - Policy changes and records

  func testReplacingThePolicySetReplacesTheRetiredPaths() throws {
    let harness = try makeHarness()
    let request = FileOperationRequest.create(in: file(retired), name: "report.txt")
    XCTAssertTrue(harness.coordinator.evaluate(request, process: harness.unlisted).isDenied)
    harness.coordinator.replacePolicySet(
      setIdentifier: uuid(100), policies: [configuration(retired: [])], revision: 3)
    let released = harness.coordinator.evaluate(request, process: harness.unlisted)
    XCTAssertFalse(released.isInScope)
    XCTAssertFalse(released.isDenied)
  }

  func testRecordsAtARetiredPathAreCombinedOnlyWithIdenticalRequests() {
    var evaluation = PolicyEvaluationRecord(
      policyIdentifier: uuid(1), policyName: "Policy", mode: .protection, policyType: .whitelist,
      match: .direct, decision: .allow)
    let allowed = AuditEventRecord(
      eventType: "AUTH_CREATE", targetPath: current + "/a", policyDecision: "allowed",
      kernelResponse: "allow", policyEvaluations: [evaluation])
    XCTAssertTrue(allowed.combinesAnyTarget)
    evaluation.retiredFolderPath = retired
    let warned = AuditEventRecord(
      eventType: "AUTH_CREATE", targetPath: retired + "/a", policyDecision: "allowed",
      kernelResponse: "allow", policyEvaluations: [evaluation])
    XCTAssertFalse(warned.combinesAnyTarget)
    XCTAssertTrue(warned.touchesRetiredFolderPath)
    XCTAssertNotEqual(RecordGroupKey(allowed), RecordGroupKey(warned))
  }

  func testTheRecordFieldIsOptionalInStoredRecords() throws {
    let evaluation = PolicyEvaluationRecord(
      policyIdentifier: uuid(1), policyName: "Policy", mode: .protection, policyType: .whitelist,
      match: .none, decision: .deny, retiredFolderPath: retired)
    let encoded = try JSONEncoder().encode(evaluation)
    XCTAssertEqual(try JSONDecoder().decode(PolicyEvaluationRecord.self, from: encoded), evaluation)
    var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    object.removeValue(forKey: "retiredFolderPath")
    let older = try JSONDecoder().decode(
      PolicyEvaluationRecord.self, from: JSONSerialization.data(withJSONObject: object))
    XCTAssertNil(older.retiredFolderPath)
  }

  // MARK: - Helpers

  private func makeHarness(
    mode: PolicyMode = .protection, current: String? = nil, retired: String? = nil
  ) throws -> Harness {
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        configuration(mode: mode, current: current, retired: [retired ?? self.retired])
      ],
      policyRevision: 2, sink: NoopSink(), decodeFailurePolicy: .failClosed)
    let allowed = try processFacts(seed: 10, team: "TEAM123456", signing: "com.example.Editor")
    let unlisted = try processFacts(seed: 20, team: "OTHERTEAM1", signing: "com.example.Other")
    try observeLaunch(allowed, in: coordinator)
    try observeLaunch(unlisted, in: coordinator)
    return Harness(coordinator: coordinator, allowed: allowed, unlisted: unlisted)
  }

  private func configuration(
    mode: PolicyMode = .protection, current: String? = nil, retired: [String]
  ) -> EndpointPolicyConfiguration {
    EndpointPolicyConfiguration(
      id: uuid(1), name: "Policy", mode: mode, policyType: .whitelist,
      scope: ProtectedPathScope(canonicalRoot: current ?? self.current, caseSensitive: false),
      rules: PolicySnapshot(rules: [
        AllowRule(
          id: "rule.editor",
          program: SignedProgramIdentity(
            teamIdentifier: "TEAM123456", signingIdentifier: "com.example.Editor"),
          allowsDescendants: false)
      ]),
      retiredScopes: retired.map {
        ProtectedPathScope(retired: RetiredFolderPath(path: $0, caseSensitive: false))
      })
  }

  private func observeLaunch(_ actor: ProcessFacts, in coordinator: EndpointEventCoordinator) throws
  {
    let launchd = ExecutionProgram(
      facts: try processFacts(
        seed: 1, team: "", signing: "com.apple.xpc.launchd", isPlatformBinary: true),
      executablePath: "/sbin/launchd")
    var child = launchd
    child.instance = ProcessInstanceKey(
      processID: actor.processInstance.processID, processVersion: 0)
    coordinator.observeFork(parent: launchd, child: child)
    coordinator.observeExec(from: child, to: ExecutionProgram(facts: actor, executablePath: ""))
  }

  private func processFacts(
    seed: Int32, team: String, signing: String, isPlatformBinary: Bool = false
  ) throws -> ProcessFacts {
    ProcessFacts(
      auditToken: try AuditTokenKey(words: Array(repeating: UInt32(seed), count: 8)),
      processInstance: ProcessInstanceKey(processID: seed, processVersion: 1),
      teamIdentifier: team, signingIdentifier: signing,
      isPlatformBinary: isPlatformBinary, codeSigningFlags: 1)
  }

  private func file(_ path: String) -> EndpointFileSnapshot {
    EndpointFileSnapshot(path: path, pathWasTruncated: false)
  }

  private func uuid(_ value: Int) -> UUID {
    UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", value))!
  }
}

private struct NoopSink: EndpointEventSink {
  func record(_: EndpointEventRecord) {}
}
