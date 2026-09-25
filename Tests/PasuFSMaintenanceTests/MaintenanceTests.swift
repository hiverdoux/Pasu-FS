import Darwin
import Foundation
import PasuFSConfiguration
import PasuFSMaintenanceCore
import XCTest

@testable import PasuFSMaintenance

final class MaintenanceTests: XCTestCase {
  func testRemoteErrorKeepsDescriptionAfterSecureArchiving() throws {
    let error = MaintenanceContract.remoteError(MaintenanceError(.authorizationCanceled))
    let data = try NSKeyedArchiver.archivedData(withRootObject: error, requiringSecureCoding: true)
    let decoded = try XCTUnwrap(
      NSKeyedUnarchiver.unarchivedObject(ofClass: NSError.self, from: data))
    XCTAssertEqual(
      decoded.localizedDescription,
      "Administrator authentication was canceled. No files were removed.")
  }
  func testBuildVersionsPermitRepairAndUpgradeButRejectDowngradeAndUnknownVersions() throws {
    try ProductBuildVersion.validateUpgrade(incoming: "11", installed: nil)
    try ProductBuildVersion.validateUpgrade(incoming: "11", installed: "11.0")
    try ProductBuildVersion.validateUpgrade(incoming: "1.10", installed: "1.2")
    XCTAssertThrowsError(try ProductBuildVersion.validateUpgrade(incoming: "10", installed: "11"))
    for invalid in ["", "1..2", "-1", "12-beta", "1.2.3.4", "18446744073709551616", "１２"] {
      XCTAssertThrowsError(
        try ProductBuildVersion.validateUpgrade(incoming: invalid, installed: nil))
      XCTAssertThrowsError(
        try ProductBuildVersion.validateUpgrade(incoming: "12", installed: invalid))
    }
  }

  func testTicketIsConnectionBoundAndExpires() throws {
    let connection = UUID()
    let now = Date()
    let session = UninstallSession(
      connection: connection, processID: 123, removeData: false, now: now)
    try session.validate(ticket: session.ticket, connection: connection, now: now)
    XCTAssertThrowsError(try session.validate(ticket: UUID(), connection: connection, now: now))
    XCTAssertThrowsError(try session.validate(ticket: session.ticket, connection: UUID(), now: now))
    XCTAssertThrowsError(
      try session.validate(
        ticket: session.ticket, connection: connection, now: now.addingTimeInterval(600)))
  }

  func testMissingAndFabricatedAuthorizationCannotGrantRemoval() {
    XCTAssertThrowsError(try UninstallAuthorization.validate(Data()))
    XCTAssertThrowsError(try UninstallAuthorization.validate(Data(repeating: 0, count: 32)))
    XCTAssertThrowsError(try UninstallAuthorization.validate(Data(repeating: 0xff, count: 4096)))
  }

  func testOversizedAndMalformedRequestsAreRejected() {
    XCTAssertThrowsError(
      try MaintenanceContract.decode(
        UninstallPreparation.self, from: Data(repeating: 65, count: 17000)))
    XCTAssertThrowsError(
      try MaintenanceContract.decode(UninstallCommit.self, from: Data("{}".utf8)))
    XCTAssertThrowsError(
      try MaintenanceContract.decode(
        UninstallCommit.self, from: Data("{\"ticket\":\"invalid\",\"action\":\"shell\"}".utf8)))
  }

  func testRemovalUnlinksChildSymlinkWithoutTouchingItsDestination() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let product = root.appendingPathComponent("product")
    let outside = root.appendingPathComponent("protected")
    try FileManager.default.createDirectory(at: product, withIntermediateDirectories: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    let document = outside.appendingPathComponent("document.txt")
    try Data("keep me".utf8).write(to: document)
    try FileManager.default.createSymbolicLink(
      at: product.appendingPathComponent("link"), withDestinationURL: outside)
    try Data("product".utf8).write(to: product.appendingPathComponent("settings.json"))
    try SafeRemoval.remove(product, requiredOwner: getuid())
    XCTAssertFalse(FileManager.default.fileExists(atPath: product.path))
    XCTAssertEqual(try Data(contentsOf: document), Data("keep me".utf8))
    try SafeRemoval.remove(product, requiredOwner: getuid())  // Idempotent retry.
  }

  func testRemovalRejectsSymlinkInAnAncestor() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let outside = root.appendingPathComponent("protected")
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: true)
    let document = outside.appendingPathComponent("keep")
    try Data("keep".utf8).write(to: document)
    let link = root.appendingPathComponent("link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)
    XCTAssertThrowsError(
      try SafeRemoval.remove(link.appendingPathComponent("keep"), requiredOwner: getuid()))
    XCTAssertTrue(FileManager.default.fileExists(atPath: document.path))
  }

  func testRemovalRejectsUnexpectedOwnerBeforeDeletingFiles() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let document = root.appendingPathComponent("keep")
    try Data("keep".utf8).write(to: document)
    XCTAssertThrowsError(try SafeRemoval.remove(document, requiredOwner: getuid() + 1))
    XCTAssertTrue(FileManager.default.fileExists(atPath: document.path))
  }

  func testStateSurvivesReopeningWithoutSavingAuthority() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let store = try UninstallStateStore(root: root, owner: getuid())
    XCTAssertNil(try store.read())
    let pending = UninstallState(phase: .awaitingRestart, removeData: true)
    try store.write(pending)
    XCTAssertEqual(try UninstallStateStore(root: root, owner: getuid()).read(), pending)
    let bytes = try Data(contentsOf: root.appendingPathComponent(MaintenanceContract.stateFilename))
    let text = String(decoding: bytes, as: UTF8.self)
    XCTAssertFalse(text.contains("authorization"))
    XCTAssertFalse(text.contains("ticket"))
    XCTAssertNotNil(pending.bootSession)
    try store.clear()
    XCTAssertNil(try store.read())
  }

  func testStateStoreWorksUnderASymbolicLinkAlias() throws {
    // Any symbolic link among the parents of the storage root must work like a real path.
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let real = root.appendingPathComponent("real", isDirectory: true)
    try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
    let alias = root.appendingPathComponent("alias", isDirectory: true)
    try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: real)
    let store = try UninstallStateStore(
      root: alias.appendingPathComponent("state", isDirectory: true), owner: getuid())
    let pending = UninstallState(phase: .awaitingRestart, removeData: false)
    try store.write(pending)
    XCTAssertEqual(try store.read(), pending)
    try store.clear()
    XCTAssertNil(try store.read())
    XCTAssertFalse(
      FileManager.default.fileExists(
        atPath: real.appendingPathComponent("state/\(MaintenanceContract.stateFilename)").path))
  }

  func testStateStoreWorksUnderTheSystemTemporaryAlias() throws {
    // macOS reaches /tmp through a symbolic link, and Foundation's standardized paths hide the
    // real /private/tmp location. The store must write and remove through that alias.
    let name = "pasu-maintenance-tests-\(UUID().uuidString)"
    let physical = URL(fileURLWithPath: "/private/tmp/\(name)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: physical) }
    let store = try UninstallStateStore(
      root: URL(fileURLWithPath: "/tmp/\(name)/state", isDirectory: true), owner: getuid())
    let pending = UninstallState(phase: .awaitingRestart, removeData: false)
    try store.write(pending)
    let stateFile = physical.appendingPathComponent("state/\(MaintenanceContract.stateFilename)")
    XCTAssertTrue(FileManager.default.fileExists(atPath: stateFile.path))
    XCTAssertEqual(try store.read(), pending)
    try store.clear()
    XCTAssertFalse(FileManager.default.fileExists(atPath: stateFile.path))
  }

  func testStorageRootThatIsASymbolicLinkIsRefused() throws {
    let root = try temporaryDirectory()
    defer { try? FileManager.default.removeItem(at: root) }
    let real = root.appendingPathComponent("real", isDirectory: true)
    try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
    let alias = root.appendingPathComponent("alias", isDirectory: true)
    try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: real)
    let store = try UninstallStateStore(root: alias, owner: getuid())
    XCTAssertThrowsError(try store.write(UninstallState(phase: .prepared, removeData: false)))
    XCTAssertThrowsError(try SafeRemoval.validateRoot(alias, requiredOwner: getuid()))
    XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: real.path), [])
  }

  func testErrorCodeRawValuesArePersistedFormats() {
    // Renaming a case would silently change the state file and XPC formats.
    let expected: Set<String> = [
      "messageTooLarge", "unknownStateFormat", "invalidPackageBuildVersion",
      "installedBuildVersionUnknown", "downgradeNotSupported", "approvalExpired",
      "unsafeRemovalPath", "removalTargetUntrusted", "unexpectedOwner", "mountCrossingRefused",
      "removalTargetChanged", "systemCallFailed", "authorizationMalformed",
      "authorizationInvalid", "authorizationRuleUnexpected", "authorizationCanceled",
      "authorizationDenied", "invalidHandshake", "requestInProgress", "noCurrentApproval",
      "notRunningAsRoot", "unsupportedOperation", "commandFailed", "runningApplicationsUnknown",
      "applicationRunning", "installationPathUnreadable", "installationPathNotDirectory",
      "installationPathOccupied", "installedVersionUnreadable", "componentPermissionsUnsafe",
      "helperSignatureMismatch", "helperMismatch", "applicationDidNotExit",
      "receiptUnverifiable", "dataDirectoryNotRemoved", "authorizationRightsNotRegistered",
      "authorizationRightsNotRemoved", "handshakeMismatch", "connectionLost",
      "requestNotAccepted", "serviceUnavailable", "serviceNoReply", "invalidReply",
      "internalFailure",
    ]
    XCTAssertEqual(Set(MaintenanceErrorCode.allCases.map(\.rawValue)), expected)
  }

  func testFailedStateCarriesTheErrorCodeAndDetail() throws {
    let failure = MaintenanceError(.systemCallFailed, detail: "remove entry failed: Busy")
    let state = UninstallState(phase: .failed, removeData: true, failure: failure)
    let decoded = try MaintenanceContract.decode(
      UninstallState.self, from: MaintenanceContract.encode(state))
    XCTAssertEqual(decoded.failure, "remove entry failed: Busy.")
    XCTAssertEqual(decoded.failureCode, .systemCallFailed)
    XCTAssertEqual(decoded.failureDetail, "remove entry failed: Busy")
    // A state file written before the code fields existed still decodes.
    let older = Data(
      """
      {"formatVersion":1,"phase":"failed","removeData":false,"failure":"Older text."}
      """.utf8)
    let decodedOlder = try MaintenanceContract.decode(UninstallState.self, from: older)
    XCTAssertEqual(decodedOlder.failure, "Older text.")
    XCTAssertNil(decodedOlder.failureCode)
    // A newer maintenance service may record a code this version does not know.
    let newer = Data(
      """
      {"formatVersion":1,"phase":"failed","removeData":false,"failure":"Newer text.","failureCode":"somethingNewer","failureDetail":"x"}
      """.utf8)
    let decodedNewer = try MaintenanceContract.decode(UninstallState.self, from: newer)
    XCTAssertEqual(decodedNewer.failure, "Newer text.")
    XCTAssertNil(decodedNewer.failureCode)
    XCTAssertEqual(decodedNewer.failureDetail, "x")
  }

  func testRemoteErrorCarriesTheCodeAcrossSecureArchiving() throws {
    let error = MaintenanceContract.remoteError(
      MaintenanceError(.authorizationDenied, detail: "-60005"))
    let data = try NSKeyedArchiver.archivedData(withRootObject: error, requiringSecureCoding: true)
    let decoded = try XCTUnwrap(
      NSKeyedUnarchiver.unarchivedObject(ofClass: NSError.self, from: data))
    XCTAssertEqual(decoded.domain, MaintenanceContract.errorDomain)
    XCTAssertEqual(
      decoded.userInfo[MaintenanceContract.errorCodeKey] as? String,
      MaintenanceErrorCode.authorizationDenied.rawValue)
    XCTAssertEqual(decoded.userInfo[MaintenanceContract.errorDetailKey] as? String, "-60005")
    XCTAssertEqual(
      decoded.localizedDescription,
      "Administrator approval for uninstalling was not granted (OSStatus -60005).")
  }

  /// A unique directory under the system temporary directory, as a physical path. Removal
  /// refuses symbolic-link components, and macOS reaches its temporary directory through one.
  private func temporaryDirectory() throws -> URL {
    let root = PhysicalPath.resolve(FileManager.default.temporaryDirectory)
      .appendingPathComponent("pasu-maintenance-tests-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return root
  }
}
