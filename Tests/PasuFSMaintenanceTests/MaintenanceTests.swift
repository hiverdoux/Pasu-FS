import Darwin
import Foundation
import PasuFSMaintenanceCore
import XCTest

@testable import PasuFSMaintenance

final class MaintenanceTests: XCTestCase {
  func testRemoteErrorKeepsDescriptionAfterSecureArchiving() throws {
    let error = MaintenanceContract.remoteError(MaintenanceError("An explicit failure reason."))
    let data = try NSKeyedArchiver.archivedData(withRootObject: error, requiringSecureCoding: true)
    let decoded = try XCTUnwrap(
      NSKeyedUnarchiver.unarchivedObject(ofClass: NSError.self, from: data))
    XCTAssertEqual(decoded.localizedDescription, "An explicit failure reason.")
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

  private func temporaryDirectory() throws -> URL {
    // Use the repo's artifact directory; macOS's /var temporary-directory alias is a symlink.
    let root = URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
      .appendingPathComponent("dist")
      .appendingPathComponent("pasu-maintenance-tests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
    return root
  }
}
