import Darwin
import EndpointSecurity
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import XCTest
import os

@testable import PasuFSEndpointCore

/// Every supported authorization event uses the same folder and program rules as a file open.
final class FileOperationPolicyTests: XCTestCase {
  private struct Fixture {
    let base: URL
    let home: URL
    let root: URL
    let nested: URL
    let outside: URL
    var inside: String { root.appendingPathComponent("sample.txt").path }
    var elsewhere: String { outside.appendingPathComponent("sample.txt").path }
  }

  private struct Harness {
    let coordinator: EndpointEventCoordinator
    let allowed: ProcessFacts
    let unlisted: ProcessFacts
  }

  /// With policies to apply, a new client's first subscription names every event the policies
  /// need together with the process events: under NSEndpointSecurityEarlyBoot it ends macOS's
  /// hold on mounts and on programs other than Apple platform binaries.
  func testFirstSubscriptionNamesThePolicyEventsWithTheProcessEvents() {
    let process = EndpointEventCoordinator.processEventTypes.map(\.rawValue)
    XCTAssertEqual(
      process,
      [ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT].map(
        \.rawValue))
    XCTAssertEqual(
      EndpointEventCoordinator.firstSubscriptionEventTypes(withPolicies: false).map(\.rawValue),
      process)
    let first = EndpointEventCoordinator.firstSubscriptionEventTypes(withPolicies: true).map(
      \.rawValue)
    XCTAssertEqual(Set(first).count, first.count, "no event type is named twice")
    XCTAssertEqual(
      Set(first),
      Set(
        process + FileOperationKind.subscribedEventTypes.map(\.rawValue)
          + EndpointEventCoordinator.policyNotificationEventTypes.map(\.rawValue)))
    XCTAssertEqual(first.count, 3 + AuthorizationEventCatalog.supportedEventNames.count + 2)
    XCTAssertEqual(
      Set(EndpointEventCoordinator.policyEventTypes.map(\.rawValue)).subtracting(first), [])
  }

  func testSupportedEventsMatchTheCatalogAndSubscription() {
    XCTAssertEqual(
      FileOperationKind.allCases.map(\.rawValue).sorted(),
      AuthorizationEventCatalog.supportedEventNames.sorted())
    XCTAssertEqual(
      FileOperationKind.subscribedEventTypes.count,
      AuthorizationEventCatalog.supportedEventNames.count)
    for kind in FileOperationKind.allCases {
      XCTAssertEqual(FileOperationKind(eventType: kind.eventType), kind)
      XCTAssertTrue(AuthorizationEventCatalog.isAuthorizationEvent(kind.rawValue))
      XCTAssertEqual(kind.answersWithFlags, kind == .open)
    }
    XCTAssertNil(FileOperationKind(eventType: ES_EVENT_TYPE_NOTIFY_EXEC))
    XCTAssertFalse(AuthorizationEventCatalog.isAuthorizationEvent("NOTIFY_EXEC"))
    XCTAssertEqual(ExecutionOriginCapabilities().authorizationEvents.count, 18)
    XCTAssertEqual(AuthorizationEventCatalog.supportedEventNames.last, "AUTH_MOUNT")
    XCTAssertEqual(FileOperationKind.allCases.filter(\.isDecidedByPathAlone), [.mount])
    XCTAssertEqual(
      FileOperationKind.allCases.filter(\.changesMetadata).map(\.rawValue),
      [
        "AUTH_SETMODE", "AUTH_SETOWNER", "AUTH_SETFLAGS", "AUTH_SETACL", "AUTH_SETEXTATTR",
        "AUTH_DELETEEXTATTR", "AUTH_SETATTRLIST", "AUTH_UTIMES",
      ])
    // Setting the system clock names no file, so it is not subscribed.
    XCTAssertNil(FileOperationKind(eventType: ES_EVENT_TYPE_AUTH_SETTIME))
    XCTAssertFalse(FileOperationKind.subscribedEventTypes.contains(ES_EVENT_TYPE_AUTH_SETTIME))
    // Reading metadata is not checked.
    for reading in [
      ES_EVENT_TYPE_AUTH_GETATTRLIST, ES_EVENT_TYPE_AUTH_GETEXTATTR,
      ES_EVENT_TYPE_AUTH_LISTEXTATTR, ES_EVENT_TYPE_AUTH_READDIR, ES_EVENT_TYPE_AUTH_READLINK,
      ES_EVENT_TYPE_AUTH_SEARCHFS,
    ] {
      XCTAssertNil(FileOperationKind(eventType: reading))
    }
    // A compatibility profile can name every request kind except a mount.
    XCTAssertEqual(
      Set(SystemCompatibilityRequestKind.allCases.map(\.rawValue)),
      Set(FileOperationKind.allCases.filter { !$0.isDecidedByPathAlone }.map(\.rawValue)))
    XCTAssertEqual(
      EndpointEventCoordinator.policyNotificationEventTypes,
      [ES_EVENT_TYPE_NOTIFY_UNMOUNT, ES_EVENT_TYPE_NOTIFY_RENAME])
  }

  func testProtectedFolderLiesInsideItselfAndItsParents() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let scope = try ProtectedPathScope(root: fixture.root.path, homeDirectory: fixture.home.path)
    XCTAssertTrue(scope.rootIsInside(fixture.root.path))
    XCTAssertTrue(scope.rootIsInside(fixture.home.path))
    XCTAssertTrue(scope.rootIsInside(fixture.base.path))
    XCTAssertTrue(scope.rootIsInside("/"))
    XCTAssertFalse(scope.rootIsInside(fixture.nested.path))
    XCTAssertFalse(scope.rootIsInside(fixture.outside.path))
    XCTAssertFalse(scope.rootIsInside(fixture.root.path + "-other"))
    XCTAssertFalse(scope.rootIsInside("relative"))
    XCTAssertTrue(scope.rootIsInside(fixture.home.path + "/./Protected/Nested/.."))
  }

  func testCheckedPathJoinsADirectoryAndName() {
    XCTAssertEqual(
      CheckedPath(directory: EndpointFileSnapshot(path: "/a/b", pathWasTruncated: false), name: "c")
        .path, "/a/b/c")
    XCTAssertEqual(
      CheckedPath(directory: EndpointFileSnapshot(path: "/", pathWasTruncated: false), name: "c")
        .path, "/c")
    let truncated = CheckedPath(
      directory: EndpointFileSnapshot(path: "/a", pathWasTruncated: true), name: nil)
    XCTAssertEqual(truncated.path, "/a/")
    XCTAssertTrue(truncated.wasTruncated)
    XCTAssertFalse(truncated.affectsEnclosedFolders)
  }

  func testRenameChecksSourceAndDestination() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let outward = FileOperationRequest.rename(
      source: file(fixture.inside), destination: CheckedPath(path: fixture.elsewhere))
    assertDecisions(outward, harness, kind: .rename)
    let inward = FileOperationRequest.rename(
      source: file(fixture.elsewhere), destination: CheckedPath(path: fixture.inside))
    assertDecisions(inward, harness, kind: .rename)
    let unrelated = FileOperationRequest.rename(
      source: file(fixture.elsewhere),
      destination: CheckedPath(path: fixture.outside.appendingPathComponent("renamed").path))
    assertOutsideScope(unrelated, harness)
    XCTAssertEqual(outward.primaryPath.path, fixture.inside)
    XCTAssertEqual(outward.destinationPath?.path, fixture.elsewhere)
    XCTAssertTrue(outward.primaryPath.affectsEnclosedFolders)
    XCTAssertFalse(outward.destinationPath?.affectsEnclosedFolders ?? true)
  }

  func testRenamingTheProtectedFolderIsCheckedAndRenamingItsParentsIsAllowed() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let itself = FileOperationRequest.rename(
      source: file(fixture.root.path),
      destination: CheckedPath(path: fixture.outside.appendingPathComponent("moved").path))
    assertDecisions(itself, harness, kind: .rename)
    for source in [fixture.home.path, fixture.base.path] {
      let request = FileOperationRequest.rename(
        source: file(source),
        destination: CheckedPath(path: fixture.base.path + "-renamed-\(source.count)"))
      let result = harness.coordinator.evaluate(request, process: harness.unlisted)
      XCTAssertTrue(result.isInScope, source)
      XCTAssertFalse(result.isDenied, source)
      XCTAssertEqual(result.policyEvaluations.map(\.match), [.enclosingFolder], source)
      XCTAssertEqual(result.policyEvaluations.map(\.decision), [.allow], source)
    }
    // The allowed renames above also protect the folder's possible new locations, so a fresh
    // coordinator shows that a sibling folder is unrelated.
    let sibling = FileOperationRequest.rename(
      source: file(fixture.outside.path),
      destination: CheckedPath(path: fixture.home.appendingPathComponent("moved").path))
    assertOutsideScope(sibling, try makeHarness(fixture))
  }

  func testUnlinkChecksTargetAndEnclosingFolders() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    for target in [fixture.inside, fixture.nested.path, fixture.root.path, fixture.home.path] {
      assertDecisions(.unlink(target: file(target)), harness, kind: .unlink, message: target)
    }
    assertOutsideScope(.unlink(target: file(fixture.elsewhere)), harness)
    assertOutsideScope(.unlink(target: file(fixture.outside.path)), harness)
  }

  func testLinkChecksSourceFileAndNewLinkLocation() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let outward = FileOperationRequest.link(
      source: file(fixture.inside), targetDirectory: file(fixture.outside.path), name: "alias")
    assertDecisions(outward, harness, kind: .link)
    XCTAssertEqual(
      outward.destinationPath?.path, fixture.outside.appendingPathComponent("alias").path)
    let inward = FileOperationRequest.link(
      source: file(fixture.elsewhere), targetDirectory: file(fixture.root.path), name: "alias")
    assertDecisions(inward, harness, kind: .link)
    assertOutsideScope(
      .link(
        source: file(fixture.elsewhere), targetDirectory: file(fixture.outside.path), name: "x"),
      harness)
    // A folder cannot be hard linked, so a parent folder as the source is not a folder operation.
    assertOutsideScope(
      .link(
        source: file(fixture.home.path), targetDirectory: file(fixture.outside.path), name: "x"),
      harness)
  }

  func testCloneChecksSourceAndDestination() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    assertDecisions(
      .clone(source: file(fixture.inside), targetDirectory: file(fixture.outside.path), name: "c"),
      harness, kind: .clone)
    assertDecisions(
      .clone(
        source: file(fixture.elsewhere), targetDirectory: file(fixture.nested.path), name: "c"),
      harness, kind: .clone)
    assertDecisions(
      .clone(
        source: file(fixture.home.path), targetDirectory: file(fixture.outside.path), name: "c"),
      harness, kind: .clone)
    assertOutsideScope(
      .clone(
        source: file(fixture.elsewhere), targetDirectory: file(fixture.outside.path), name: "c"),
      harness)
  }

  func testCopyFileChecksSourceTargetDirectoryAndOverwrittenFile() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    assertDecisions(
      .copyFile(
        source: file(fixture.inside), existingTarget: nil,
        targetDirectory: file(fixture.outside.path), name: "copy"),
      harness, kind: .copyFile)
    assertDecisions(
      .copyFile(
        source: file(fixture.elsewhere), existingTarget: nil,
        targetDirectory: file(fixture.root.path), name: "copy"),
      harness, kind: .copyFile)
    assertDecisions(
      .copyFile(
        source: file(fixture.elsewhere), existingTarget: file(fixture.inside),
        targetDirectory: file(fixture.outside.path), name: "copy"),
      harness, kind: .copyFile)
    assertDecisions(
      .copyFile(
        source: file(fixture.base.path), existingTarget: nil,
        targetDirectory: file(fixture.outside.path), name: "copy"),
      harness, kind: .copyFile)
    assertOutsideScope(
      .copyFile(
        source: file(fixture.elsewhere), existingTarget: nil,
        targetDirectory: file(fixture.outside.path), name: "copy"),
      harness)
  }

  func testCreateChecksTheNewPathAndItsDirectory() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let newFile = FileOperationRequest.create(in: file(fixture.root.path), name: "new.txt")
    assertDecisions(newFile, harness, kind: .create)
    XCTAssertEqual(newFile.primaryPath.path, fixture.root.appendingPathComponent("new.txt").path)
    XCTAssertEqual(newFile.checkedPaths.map(\.path), [newFile.primaryPath.path, fixture.root.path])
    assertDecisions(.create(existing: file(fixture.inside)), harness, kind: .create)
    assertDecisions(.create(in: file(fixture.home.path), name: "Protected"), harness, kind: .create)
    // A new sibling of the protected folder is outside it.
    assertOutsideScope(.create(in: file(fixture.home.path), name: "notes.txt"), harness)
    assertOutsideScope(.create(in: file(fixture.outside.path), name: "new.txt"), harness)
  }

  func testTruncateChecksOnlyTheFile() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    assertDecisions(.truncate(target: file(fixture.inside)), harness, kind: .truncate)
    assertOutsideScope(.truncate(target: file(fixture.elsewhere)), harness)
    assertOutsideScope(.truncate(target: file(fixture.home.path)), harness)
  }

  func testExchangeDataChecksBothFiles() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    assertDecisions(
      .exchangeData(file(fixture.inside), file(fixture.elsewhere)), harness, kind: .exchangeData)
    assertDecisions(
      .exchangeData(file(fixture.elsewhere), file(fixture.inside)), harness, kind: .exchangeData)
    assertDecisions(
      .exchangeData(file(fixture.elsewhere), file(fixture.root.path)), harness, kind: .exchangeData)
    assertOutsideScope(
      .exchangeData(
        file(fixture.elsewhere), file(fixture.outside.appendingPathComponent("b").path)),
      harness)
  }

  /// A metadata change is checked on the object it changes: a file or folder inside the
  /// protected folder, or the protected folder itself. Changing the metadata of a folder that
  /// contains the protected folder, or of a folder beside it, is not checked.
  func testMetadataChangesAreCheckedOnTheFolderAndItsContents() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    for kind in FileOperationKind.allCases where kind.changesMetadata {
      for target in [fixture.inside, fixture.nested.path, fixture.root.path] {
        let request = FileOperationRequest.metadataChange(kind, target: file(target))
        XCTAssertEqual(request.checkedPaths.map(\.path), [target])
        XCTAssertFalse(request.primaryPath.affectsEnclosedFolders)
        XCTAssertNil(request.destinationPath)
        XCTAssertNil(request.newObjectPath)
        XCTAssertNil(request.requestedOpenFlags)
        assertDecisions(request, harness, kind: kind, message: "\(kind.rawValue) \(target)")
      }
      for target in [
        fixture.home.path, fixture.base.path, "/", fixture.outside.path, fixture.elsewhere,
        fixture.root.path + "-other",
      ] {
        assertOutsideScope(.metadataChange(kind, target: file(target)), harness)
      }
    }
  }

  func testAuditPolicyRecordsMetadataChangesWithoutDenying() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture, mode: .audit)
    for kind in FileOperationKind.allCases where kind.changesMetadata {
      let result = harness.coordinator.evaluate(
        .metadataChange(kind, target: file(fixture.inside)), process: harness.unlisted)
      XCTAssertTrue(result.isInScope, kind.rawValue)
      XCTAssertFalse(result.isDenied, kind.rawValue)
      XCTAssertEqual(result.policyDecision, "audit-only", kind.rawValue)
      XCTAssertEqual(result.policyEvaluations.map(\.decision), [.wouldDeny], kind.rawValue)
    }
  }

  /// A truncated path or an undecodable process is handled as for every other request: denied
  /// under the fail-closed setting, allowed under fail-open.
  func testMetadataChangesFailClosedLikeOtherRequests() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let scope = try ProtectedPathScope(root: fixture.root.path, homeDirectory: fixture.home.path)
    let failOpen = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [configuration(id: 1, name: "Policy", mode: .protection, scope: scope, rules: [])],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failOpen)
    for kind in FileOperationKind.allCases where kind.changesMetadata {
      let truncated = FileOperationRequest.metadataChange(
        kind, target: snapshot(fixture.root.path + "/Nest", truncated: true))
      XCTAssertTrue(truncated.pathWasTruncated)
      let denied = harness.coordinator.evaluate(truncated, process: harness.allowed)
      XCTAssertTrue(denied.isDenied, kind.rawValue)
      XCTAssertEqual(denied.policyEvaluations.map(\.match), [.truncatedPath], kind.rawValue)
      XCTAssertFalse(failOpen.evaluate(truncated, process: harness.allowed).isDenied)

      let request = FileOperationRequest.metadataChange(kind, target: file(fixture.inside))
      let undecoded = harness.coordinator.evaluate(
        request, process: nil, decodeErrorDescription: "unavailable")
      XCTAssertTrue(undecoded.isDenied, kind.rawValue)
      XCTAssertEqual(undecoded.policyEvaluations.map(\.match), [.decodeError], kind.rawValue)
      XCTAssertFalse(
        failOpen.evaluate(request, process: nil, decodeErrorDescription: "unavailable").isDenied)
    }
  }

  func testOpenStillChecksOnlyTheOpenedPath() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    assertDecisions(.open(path: fixture.inside), harness, kind: .open)
    assertDecisions(.open(path: fixture.root.path), harness, kind: .open)
    // Listing the parent folder does not touch the protected folder.
    assertOutsideScope(.open(path: fixture.home.path), harness)
    let open = FileOperationRequest.open(path: fixture.inside, flags: UInt32(FREAD))
    XCTAssertEqual(open.requestedOpenFlags, UInt32(FREAD))
    XCTAssertNil(FileOperationRequest.unlink(target: file(fixture.inside)).requestedOpenFlags)
  }

  func testAuditPolicyRecordsOtherOperationsWithoutDenying() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture, mode: .audit)
    for request in [
      FileOperationRequest.rename(
        source: file(fixture.root.path), destination: CheckedPath(path: fixture.elsewhere)),
      .unlink(target: file(fixture.inside)),
      .clone(source: file(fixture.inside), targetDirectory: file(fixture.outside.path), name: "c"),
    ] {
      let result = harness.coordinator.evaluate(request, process: harness.unlisted)
      XCTAssertTrue(result.isInScope, request.kind.rawValue)
      XCTAssertFalse(result.isDenied, request.kind.rawValue)
      XCTAssertEqual(result.policyDecision, "audit-only", request.kind.rawValue)
      XCTAssertEqual(result.policyEvaluations.map(\.decision), [.wouldDeny], request.kind.rawValue)
    }
  }

  /// A mount hides the folder at its mount point and everything below it, whoever asked for it.
  /// The mount point alone decides: the protected folder itself, a folder inside it and a folder
  /// that contains it are denied for every program; a folder beside it is outside scope.
  func testMountAtOrAroundTheProtectedFolderIsDeniedForEveryProgram() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let covering = [fixture.root.path, fixture.nested.path, fixture.home.path, fixture.base.path]
    for mountPoint in covering {
      let request = FileOperationRequest.mount(
        mountPoint: mountPoint, volumeSource: "/dev/disk9s1")
      XCTAssertEqual(request.kind, .mount, mountPoint)
      XCTAssertEqual(request.checkedPaths.map(\.path), [mountPoint], mountPoint)
      XCTAssertEqual(request.destinationPath?.path, "/dev/disk9s1", mountPoint)
      XCTAssertNil(request.requestedOpenFlags)
      for process in [harness.unlisted, harness.allowed] {
        let result = harness.coordinator.evaluate(request, process: process)
        XCTAssertTrue(result.isInScope, mountPoint)
        XCTAssertTrue(result.isDenied, mountPoint)
        XCTAssertEqual(result.policyDecision, "denied", mountPoint)
        XCTAssertEqual(result.policyEvaluations.map(\.match), [.mountPoint], mountPoint)
        XCTAssertEqual(result.policyEvaluations.map(\.decision), [.deny], mountPoint)
        XCTAssertNil(result.policyEvaluations.first?.executionOrigin, mountPoint)
        XCTAssertEqual(
          result.policyEvaluations.first?.detail,
          "A volume mounted here would hide this policy’s folder.", mountPoint)
      }
      // The decision does not need the mounting process at all.
      let withoutProcess = harness.coordinator.evaluate(request, process: nil)
      XCTAssertTrue(withoutProcess.isDenied, mountPoint)
      XCTAssertEqual(withoutProcess.policyEvaluations.map(\.match), [.mountPoint], mountPoint)
    }
    assertOutsideScope(
      .mount(mountPoint: fixture.outside.path, volumeSource: "/dev/disk9s1"), harness)
    assertOutsideScope(.mount(mountPoint: fixture.root.path + "-other", volumeSource: nil), harness)
    assertOutsideScope(.mount(mountPoint: "/Volumes/Image", volumeSource: "/dev/disk9s1"), harness)
    // A network share's source is never compared with policy folders.
    let share = FileOperationRequest.mount(
      mountPoint: "/Volumes/share", volumeSource: "//user@server/" + fixture.root.path)
    assertOutsideScope(share, harness)
  }

  func testMountIsDeniedEvenWhenTheProcessCannotBeDecodedUnderFailOpen() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let scope = try ProtectedPathScope(root: fixture.root.path, homeDirectory: fixture.home.path)
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [configuration(id: 1, name: "Policy", mode: .protection, scope: scope, rules: [])],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failOpen)
    let result = coordinator.evaluate(
      .mount(mountPoint: fixture.root.path, volumeSource: nil), process: nil,
      decodeErrorDescription: "unavailable")
    XCTAssertTrue(result.isDenied)
    XCTAssertEqual(result.policyEvaluations.map(\.match), [.mountPoint])
    // An open with the same missing process is still allowed by the fail-open setting.
    let open = coordinator.evaluate(
      .open(path: fixture.inside), process: nil, decodeErrorDescription: "unavailable")
    XCTAssertFalse(open.isDenied)
  }

  func testAuditPolicyRecordsAMountWithoutDenying() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture, mode: .audit)
    for mountPoint in [fixture.root.path, fixture.nested.path, fixture.home.path] {
      let result = harness.coordinator.evaluate(
        .mount(mountPoint: mountPoint, volumeSource: "/dev/disk9s1"), process: harness.unlisted)
      XCTAssertTrue(result.isInScope, mountPoint)
      XCTAssertFalse(result.isDenied, mountPoint)
      XCTAssertEqual(result.policyDecision, "audit-only", mountPoint)
      XCTAssertEqual(result.policyEvaluations.map(\.match), [.mountPoint], mountPoint)
      XCTAssertEqual(result.policyEvaluations.map(\.decision), [.wouldDeny], mountPoint)
    }
  }

  func testMountOverlappingPoliciesAreAllDeniedAndNamed() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let rootScope = try ProtectedPathScope(
      root: fixture.root.path, homeDirectory: fixture.home.path)
    let nestedScope = try ProtectedPathScope(
      root: fixture.nested.path, homeDirectory: fixture.home.path)
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        configuration(id: 1, name: "Root", mode: .protection, scope: rootScope, rules: []),
        configuration(id: 2, name: "Nested", mode: .audit, scope: nestedScope, rules: []),
      ],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed)
    let onParent = coordinator.evaluate(
      .mount(mountPoint: fixture.home.path, volumeSource: nil), process: nil)
    XCTAssertTrue(onParent.isDenied)
    XCTAssertEqual(onParent.policyEvaluations.map(\.policyName).sorted(), ["Nested", "Root"])
    XCTAssertEqual(
      onParent.policyEvaluations.map(\.decision).sorted(by: { $0.rawValue < $1.rawValue }),
      [.deny, .wouldDeny])
    // Mounting inside the nested folder involves both; the audit one only records.
    let insideNested = coordinator.evaluate(
      .mount(mountPoint: fixture.nested.appendingPathComponent("Deep").path, volumeSource: nil),
      process: nil)
    XCTAssertTrue(insideNested.isDenied)
    XCTAssertEqual(insideNested.policyEvaluations.count, 2)
  }

  func testUnmountOfAVolumeHoldingAPolicyFolderIsReported() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let scope = try ProtectedPathScope(root: fixture.root.path, homeDirectory: fixture.home.path)
    let reports = OSAllocatedUnfairLock<[(MountedVolume, [String])]>(initialState: [])
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        configuration(id: 1, name: "Policy", mode: .protection, scope: scope, rules: []),
        configuration(id: 2, name: "Watch", mode: .audit, scope: scope, rules: []),
      ],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed,
      protectedVolumeUnmounted: { volume, names in
        reports.withLock { $0.append((volume, names)) }
      })
    coordinator.noteUnmount(MountedVolume(mountPoint: fixture.outside.path, source: "/dev/disk9s1"))
    coordinator.noteUnmount(MountedVolume(mountPoint: "/Volumes/Other", source: nil))
    XCTAssertTrue(reports.withLock { $0.isEmpty })
    for mountPoint in [fixture.root.path, fixture.nested.path, fixture.home.path] {
      coordinator.noteUnmount(MountedVolume(mountPoint: mountPoint, source: "/dev/disk9s1"))
    }
    let reported = reports.withLock { $0 }
    XCTAssertEqual(
      reported.map(\.0.mountPoint), [fixture.root.path, fixture.nested.path, fixture.home.path])
    XCTAssertEqual(reported.map(\.1), Array(repeating: ["Policy", "Watch"], count: 3))
    XCTAssertEqual(reported.first?.0.source, "/dev/disk9s1")
  }

  func testTruncatedPathAnywhereInTheRequestFailsClosed() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let harness = try makeHarness(fixture)
    let request = FileOperationRequest.rename(
      source: file(fixture.elsewhere),
      destination: CheckedPath(path: fixture.inside, wasTruncated: true))
    XCTAssertTrue(request.pathWasTruncated)
    let result = harness.coordinator.evaluate(request, process: harness.allowed)
    XCTAssertTrue(result.isInScope)
    XCTAssertTrue(result.isDenied)
    XCTAssertEqual(result.policyEvaluations.map(\.match), [.truncatedPath])
  }

  func testOverlappingPoliciesEachTakePartForTheirOwnPaths() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let rootScope = try ProtectedPathScope(
      root: fixture.root.path, homeDirectory: fixture.home.path)
    let nestedScope = try ProtectedPathScope(
      root: fixture.nested.path, homeDirectory: fixture.home.path)
    let editorRule = AllowRule(
      id: "rule.editor",
      program: SignedProgramIdentity(
        teamIdentifier: "TEAM123456", signingIdentifier: "com.example.Editor"),
      allowsDescendants: false)
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        configuration(
          id: 1, name: "Root", mode: .protection, scope: rootScope, rules: [editorRule]),
        configuration(id: 2, name: "Nested", mode: .protection, scope: nestedScope, rules: []),
      ],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed)
    let editor = try processFacts(seed: 10, team: "TEAM123456", signing: "com.example.Editor")
    try observeLaunch(editor, in: coordinator)
    // Moving a file within the root policy only involves that policy.
    let withinRoot = coordinator.evaluate(
      .rename(
        source: file(fixture.inside),
        destination: CheckedPath(path: fixture.root.appendingPathComponent("renamed").path)),
      process: editor)
    XCTAssertFalse(withinRoot.isDenied)
    XCTAssertEqual(withinRoot.policyEvaluations.map(\.policyName), ["Root"])
    // Moving it into the nested folder also involves the nested policy, which allows nobody.
    let intoNested = coordinator.evaluate(
      .rename(
        source: file(fixture.inside),
        destination: CheckedPath(path: fixture.nested.appendingPathComponent("renamed").path)),
      process: editor)
    XCTAssertTrue(intoNested.isDenied)
    XCTAssertEqual(
      intoNested.policyEvaluations.map(\.policyName).sorted(), ["Nested", "Root"])
    // Renaming the root folder itself involves both policies, because the nested one lies
    // inside. For the nested policy it renames a folder that contains its folder, which every
    // program may do; the root policy decides by its list.
    let wholeRoot = coordinator.evaluate(
      .rename(
        source: file(fixture.root.path),
        destination: CheckedPath(path: fixture.outside.appendingPathComponent("moved").path)),
      process: editor)
    XCTAssertFalse(wholeRoot.isDenied)
    XCTAssertEqual(
      wholeRoot.policyEvaluations.map(\.policyName).sorted(), ["Nested", "Root"])
    XCTAssertEqual(
      wholeRoot.policyEvaluations.first { $0.policyName == "Nested" }?.match, .enclosingFolder)
    XCTAssertEqual(
      wholeRoot.policyEvaluations.first { $0.policyName == "Root" }?.match, .direct)
    let other = try processFacts(seed: 30, team: "OTHERTEAM1", signing: "com.example.Other")
    try observeLaunch(other, in: coordinator)
    let byOther = coordinator.evaluate(
      .rename(
        source: file(fixture.root.path),
        destination: CheckedPath(path: fixture.outside.appendingPathComponent("again").path)),
      process: other)
    XCTAssertTrue(byOther.isDenied)
  }

  func testDecoderReadsTheDocumentedFieldsOfEachEvent() throws {
    let arena = FileArena()
    defer { arena.release() }
    let source = arena.file("/Users/example/Protected/a.txt")
    let existing = arena.file("/Users/example/Protected/b.txt", truncated: true)
    let directory = arena.file("/Users/example/Other")
    let storage = UnsafeMutablePointer<es_events_t>.allocate(capacity: 1)
    defer { storage.deallocate() }

    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.open.fflag = Int32(FREAD | FWRITE)
    storage.pointee.open.file = source
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.open, event: storage.pointee),
      .open(path: "/Users/example/Protected/a.txt", flags: UInt32(FREAD | FWRITE)))

    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.rename.source = source
    storage.pointee.rename.destination_type = ES_DESTINATION_TYPE_NEW_PATH
    storage.pointee.rename.destination.new_path.dir = directory
    storage.pointee.rename.destination.new_path.filename = arena.token("moved.txt")
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.rename, event: storage.pointee),
      .rename(
        source: snapshot("/Users/example/Protected/a.txt"),
        destination: CheckedPath(path: "/Users/example/Other/moved.txt")))
    storage.pointee.rename.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE
    storage.pointee.rename.destination.existing_file = existing
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.rename, event: storage.pointee),
      .rename(
        source: snapshot("/Users/example/Protected/a.txt"),
        destination: CheckedPath(path: "/Users/example/Protected/b.txt", wasTruncated: true),
        destinationIsExistingFile: true))

    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.create.destination_type = ES_DESTINATION_TYPE_NEW_PATH
    storage.pointee.create.destination.new_path.dir = directory
    storage.pointee.create.destination.new_path.filename = arena.token("new.txt")
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.create, event: storage.pointee),
      .create(in: snapshot("/Users/example/Other"), name: "new.txt"))
    storage.pointee.create.destination_type = ES_DESTINATION_TYPE_EXISTING_FILE
    storage.pointee.create.destination.existing_file = existing
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.create, event: storage.pointee),
      .create(existing: snapshot("/Users/example/Protected/b.txt", truncated: true)))

    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.unlink.target = source
    storage.pointee.unlink.parent_dir = directory
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.unlink, event: storage.pointee),
      .unlink(target: snapshot("/Users/example/Protected/a.txt")))

    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.link.source = source
    storage.pointee.link.target_dir = directory
    storage.pointee.link.target_filename = arena.token("alias")
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.link, event: storage.pointee),
      .link(
        source: snapshot("/Users/example/Protected/a.txt"),
        targetDirectory: snapshot("/Users/example/Other"), name: "alias"))

    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.clone.source = source
    storage.pointee.clone.target_dir = directory
    storage.pointee.clone.target_name = arena.token("clone")
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.clone, event: storage.pointee),
      .clone(
        source: snapshot("/Users/example/Protected/a.txt"),
        targetDirectory: snapshot("/Users/example/Other"), name: "clone"))

    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.copyfile.source = source
    storage.pointee.copyfile.target_file = nil
    storage.pointee.copyfile.target_dir = directory
    storage.pointee.copyfile.target_name = arena.token("copy")
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.copyFile, event: storage.pointee),
      .copyFile(
        source: snapshot("/Users/example/Protected/a.txt"), existingTarget: nil,
        targetDirectory: snapshot("/Users/example/Other"), name: "copy"))
    storage.pointee.copyfile.target_file = existing
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.copyFile, event: storage.pointee)
        .checkedPaths
        .map(\.path),
      [
        "/Users/example/Protected/a.txt", "/Users/example/Other/copy", "/Users/example/Other",
        "/Users/example/Protected/b.txt",
      ])

    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.truncate.target = source
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.truncate, event: storage.pointee),
      .truncate(target: snapshot("/Users/example/Protected/a.txt")))

    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.exchangedata.file1 = source
    storage.pointee.exchangedata.file2 = existing
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.exchangeData, event: storage.pointee),
      .exchangeData(
        snapshot("/Users/example/Protected/a.txt"),
        snapshot("/Users/example/Protected/b.txt", truncated: true)))

    let stats = arena.statfs(mountPoint: "/Users/example/Protected", source: "/dev/disk9s1")
    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.mount.statfs = stats
    XCTAssertEqual(
      EndpointDecoder.fileOperation(.mount, event: storage.pointee),
      .mount(mountPoint: "/Users/example/Protected", volumeSource: "/dev/disk9s1"))
    memset(storage, 0, MemoryLayout<es_events_t>.size)
    storage.pointee.unmount.statfs = stats
    XCTAssertEqual(
      EndpointDecoder.unmountedVolume(storage.pointee),
      MountedVolume(mountPoint: "/Users/example/Protected", source: "/dev/disk9s1"))
    let unnamed = arena.statfs(mountPoint: "/Volumes/Image", source: "")
    XCTAssertEqual(
      EndpointDecoder.mountedVolume(unnamed),
      MountedVolume(mountPoint: "/Volumes/Image", source: nil))
  }

  /// Each metadata change names its object in `target`; the other fields describe the change.
  func testDecoderReadsTheTargetOfEachMetadataChange() {
    let arena = FileArena()
    defer { arena.release() }
    let storage = UnsafeMutablePointer<es_events_t>.allocate(capacity: 1)
    defer { storage.deallocate() }
    let setters: [(FileOperationKind, (UnsafeMutablePointer<es_file_t>) -> Void)] = [
      (
        .setMode,
        {
          storage.pointee.setmode.mode = 0o644
          storage.pointee.setmode.target = $0
        }
      ),
      (
        .setOwner,
        {
          storage.pointee.setowner.uid = 501
          storage.pointee.setowner.gid = 20
          storage.pointee.setowner.target = $0
        }
      ),
      (
        .setFlags,
        {
          storage.pointee.setflags.flags = UInt32(UF_IMMUTABLE)
          storage.pointee.setflags.target = $0
        }
      ),
      (
        .setACL,
        {
          storage.pointee.setacl.set_or_clear = ES_CLEAR
          storage.pointee.setacl.target = $0
        }
      ),
      (
        .setExtendedAttribute,
        {
          storage.pointee.setextattr.extattr = arena.token("com.example.attribute")
          storage.pointee.setextattr.target = $0
        }
      ),
      (
        .deleteExtendedAttribute,
        {
          storage.pointee.deleteextattr.extattr = arena.token("com.example.attribute")
          storage.pointee.deleteextattr.target = $0
        }
      ),
      (.setAttributeList, { storage.pointee.setattrlist.target = $0 }),
      (
        .setTimes,
        {
          storage.pointee.utimes.mtime = timespec(tv_sec: 1, tv_nsec: 0)
          storage.pointee.utimes.target = $0
        }
      ),
    ]
    XCTAssertEqual(
      setters.map(\.0), FileOperationKind.allCases.filter(\.changesMetadata))
    for (kind, set) in setters {
      for (path, truncated) in [
        ("/Users/example/Protected/a.txt", false), ("/Users/example/Prot", true),
      ] {
        memset(storage, 0, MemoryLayout<es_events_t>.size)
        set(arena.file(path, truncated: truncated))
        XCTAssertEqual(
          EndpointDecoder.fileOperation(kind, event: storage.pointee),
          .metadataChange(kind, target: snapshot(path, truncated: truncated)), kind.rawValue)
      }
    }
  }

  // MARK: - Helpers

  /// A Protection policy must deny an unlisted program and allow a listed one for `request`.
  private func assertDecisions(
    _ request: FileOperationRequest, _ harness: Harness, kind: FileOperationKind,
    message: String = "", file: StaticString = #filePath, line: UInt = #line
  ) {
    XCTAssertEqual(request.kind, kind, message, file: file, line: line)
    let denied = harness.coordinator.evaluate(request, process: harness.unlisted)
    XCTAssertTrue(denied.isInScope, "in scope \(message)", file: file, line: line)
    XCTAssertTrue(denied.isDenied, "denied \(message)", file: file, line: line)
    XCTAssertEqual(denied.policyDecision, "denied", message, file: file, line: line)
    XCTAssertEqual(
      denied.policyEvaluations.first?.executionOrigin?.reason, .originNotAllowed, message,
      file: file, line: line)
    let allowed = harness.coordinator.evaluate(request, process: harness.allowed)
    XCTAssertTrue(allowed.isInScope, "in scope \(message)", file: file, line: line)
    XCTAssertFalse(allowed.isDenied, "allowed \(message)", file: file, line: line)
    XCTAssertEqual(allowed.policyDecision, "allowed", message, file: file, line: line)
  }

  private func assertOutsideScope(
    _ request: FileOperationRequest, _ harness: Harness,
    file: StaticString = #filePath, line: UInt = #line
  ) {
    let result = harness.coordinator.evaluate(request, process: harness.unlisted)
    XCTAssertFalse(
      result.isInScope, request.checkedPaths.map(\.path).joined(separator: " "),
      file: file, line: line)
    XCTAssertFalse(result.isDenied, file: file, line: line)
    XCTAssertEqual(result.policyDecision, "outside-scope", file: file, line: line)
    XCTAssertTrue(result.policyEvaluations.isEmpty, file: file, line: line)
  }

  private func file(_ path: String) -> EndpointFileSnapshot {
    EndpointFileSnapshot(path: path, pathWasTruncated: false)
  }

  private func snapshot(_ path: String, truncated: Bool = false) -> EndpointFileSnapshot {
    EndpointFileSnapshot(path: path, pathWasTruncated: truncated)
  }

  private func makeHarness(_ fixture: Fixture, mode: PolicyMode = .protection) throws -> Harness {
    let scope = try ProtectedPathScope(root: fixture.root.path, homeDirectory: fixture.home.path)
    let editorRule = AllowRule(
      id: "rule.editor",
      program: SignedProgramIdentity(
        teamIdentifier: "TEAM123456", signingIdentifier: "com.example.Editor"),
      allowsDescendants: false)
    let coordinator = EndpointEventCoordinator(
      policySetIdentifier: uuid(100),
      policies: [
        configuration(id: 1, name: "Policy", mode: mode, scope: scope, rules: [editorRule])
      ],
      policyRevision: 1, sink: NoopSink(), decodeFailurePolicy: .failClosed)
    let allowed = try processFacts(seed: 10, team: "TEAM123456", signing: "com.example.Editor")
    let unlisted = try processFacts(seed: 20, team: "OTHERTEAM1", signing: "com.example.Other")
    try observeLaunch(allowed, in: coordinator)
    try observeLaunch(unlisted, in: coordinator)
    return Harness(coordinator: coordinator, allowed: allowed, unlisted: unlisted)
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

  private func configuration(
    id: Int, name: String, mode: PolicyMode, scope: ProtectedPathScope, rules: [AllowRule]
  ) -> EndpointPolicyConfiguration {
    EndpointPolicyConfiguration(
      id: uuid(id), name: name, mode: mode, policyType: .whitelist, scope: scope,
      rules: PolicySnapshot(rules: rules))
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

  private func makeFixture() throws -> Fixture {
    let base = PhysicalPath.resolve(
      FileManager.default.temporaryDirectory
        .appendingPathComponent("PasuFSFileOperationTests-\(UUID().uuidString)"))
    let home = base.appendingPathComponent("home")
    let root = home.appendingPathComponent("Protected")
    let nested = root.appendingPathComponent("Nested")
    let outside = home.appendingPathComponent("Outside")
    try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    return Fixture(base: base, home: home, root: root, nested: nested, outside: outside)
  }

  private func uuid(_ value: Int) -> UUID {
    UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", value))!
  }
}

/// Owns the C strings and `es_file_t` values a decoded event points at.
private final class FileArena {
  private var strings: [UnsafeMutablePointer<CChar>] = []
  private var files: [UnsafeMutablePointer<es_file_t>] = []
  private var volumes: [UnsafeMutablePointer<statfs>] = []

  func token(_ text: String) -> es_string_token_t {
    let copy = strdup(text)!
    strings.append(copy)
    return es_string_token_t(length: strlen(copy), data: copy)
  }

  func statfs(mountPoint: String, source: String) -> UnsafeMutablePointer<statfs> {
    let pointer = UnsafeMutablePointer<statfs>.allocate(capacity: 1)
    pointer.initialize(to: Darwin.statfs())
    withUnsafeMutablePointer(to: &pointer.pointee.f_mntonname) {
      $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
        _ = strlcpy($0, mountPoint, Int(MAXPATHLEN))
      }
    }
    withUnsafeMutablePointer(to: &pointer.pointee.f_mntfromname) {
      $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) {
        _ = strlcpy($0, source, Int(MAXPATHLEN))
      }
    }
    volumes.append(pointer)
    return pointer
  }

  func file(_ path: String, truncated: Bool = false) -> UnsafeMutablePointer<es_file_t> {
    let pointer = UnsafeMutablePointer<es_file_t>.allocate(capacity: 1)
    pointer.initialize(to: es_file_t())
    pointer.pointee.path = token(path)
    pointer.pointee.path_truncated = truncated
    files.append(pointer)
    return pointer
  }

  func release() {
    for pointer in files { pointer.deallocate() }
    for pointer in volumes { pointer.deallocate() }
    for string in strings { free(string) }
    files.removeAll()
    volumes.removeAll()
    strings.removeAll()
  }
}

private struct NoopSink: EndpointEventSink {
  func record(_: EndpointEventRecord) {}
}
