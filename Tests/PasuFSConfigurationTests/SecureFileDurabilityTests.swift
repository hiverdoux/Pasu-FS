import Darwin
import Foundation
import XCTest

@testable import PasuFSConfiguration

/// How the secure store synchronizes a write, and that a policy save reaches the storage device
/// before it returns while other writes, such as the status file, don't wait for it.
final class SecureFileDurabilityTests: XCTestCase {
  func testStorageDeviceWriteFlushesTheFileThenTheDirectory() throws {
    let fixture = try Fixture()
    defer { fixture.remove() }
    try fixture.store.write(
      Data("first".utf8), to: "policy.json", mode: 0o600, durability: .storageDevice)
    XCTAssertEqual(
      fixture.calls.list,
      [
        "fsync file", "F_FULLFSYNC file", "fsync directory", "F_FULLFSYNC directory",
      ])
    XCTAssertEqual(try fixture.store.read("policy.json", maximumSize: 64), Data("first".utf8))
    XCTAssertTrue(fixture.unavailable.list.isEmpty)
  }

  func testDefaultWriteUsesFsyncOnly() throws {
    let fixture = try Fixture()
    defer { fixture.remove() }
    try fixture.store.write(Data("status".utf8), to: "status.json", mode: 0o644)
    XCTAssertEqual(fixture.calls.list, ["fsync file", "fsync directory"])
    try fixture.store.remove("status.json")
    XCTAssertEqual(fixture.calls.list, ["fsync file", "fsync directory", "fsync directory"])
  }

  func testUnsupportedFullSynchronizationKeepsTheFsyncResult() throws {
    for code in [ENOTSUP, EINVAL] {
      let fixture = try Fixture(fullFsyncError: { _ in code })
      defer { fixture.remove() }
      try fixture.store.write(
        Data("saved".utf8), to: "policy.json", mode: 0o600, durability: .storageDevice)
      XCTAssertEqual(try fixture.store.read("policy.json", maximumSize: 64), Data("saved".utf8))
      XCTAssertEqual(
        fixture.unavailable.list,
        [
          "F_FULLFSYNC temporary file \(code)", "F_FULLFSYNC secure-store directory \(code)",
        ])
    }
  }

  func testFailedFullSynchronizationOfTheFileKeepsThePreviousContents() throws {
    let fixture = try Fixture(fullFsyncError: { $0 == "file" ? EIO : nil })
    defer { fixture.remove() }
    try fixture.store.write(Data("old".utf8), to: "policy.json", mode: 0o600)
    XCTAssertThrowsError(
      try fixture.store.write(
        Data("new".utf8), to: "policy.json", mode: 0o600, durability: .storageDevice)
    ) { error in
      XCTAssertEqual(
        error as? SecureFileStoreError,
        .systemCall(operation: "F_FULLFSYNC temporary file", code: EIO))
    }
    XCTAssertEqual(try fixture.store.read("policy.json", maximumSize: 64), Data("old".utf8))
    XCTAssertEqual(
      try FileManager.default.contentsOfDirectory(atPath: fixture.directory.path), ["policy.json"],
      "the temporary file is removed")
    XCTAssertTrue(fixture.unavailable.list.isEmpty)
  }

  func testFailedFullSynchronizationOfTheDirectoryIsAnError() throws {
    let fixture = try Fixture(fullFsyncError: { $0 == "directory" ? EIO : nil })
    defer { fixture.remove() }
    XCTAssertThrowsError(
      try fixture.store.write(
        Data("new".utf8), to: "policy.json", mode: 0o600, durability: .storageDevice)
    ) { error in
      XCTAssertEqual(
        error as? SecureFileStoreError,
        .systemCall(operation: "F_FULLFSYNC secure-store directory", code: EIO))
    }
  }

  func testFailedFsyncStopsBeforeFullSynchronization() throws {
    let fixture = try Fixture(fsyncError: EIO)
    defer { fixture.remove() }
    XCTAssertThrowsError(
      try fixture.store.write(
        Data("new".utf8), to: "policy.json", mode: 0o600, durability: .storageDevice)
    ) { error in
      XCTAssertEqual(
        error as? SecureFileStoreError,
        .systemCall(operation: "fsync temporary file", code: EIO))
    }
    XCTAssertEqual(fixture.calls.list, ["fsync file"])
  }

  func testPolicySaveFlushesBothCopiesAndTheCommitToTheDevice() throws {
    let fixture = try Fixture()
    defer { fixture.remove() }
    let repository = PolicyRepository(store: fixture.store)
    let document = PolicySetDocument(
      setIdentifier: UUID(), revision: 1,
      policies: [
        DirectoryPolicy(
          name: "Example", mode: .protection, protectedRootPath: "/Users/example/Protected")
      ])
    let scopes = [
      PersistedPolicyScope(
        policyIdentifier: document.policies[0].id, canonicalRoot: "/Users/example/Protected",
        caseSensitive: false)
    ]
    try repository.save(document, scopes: scopes)
    // Primary copy, backup copy and commit record, each followed by its directory; then the
    // removal of the retired single-policy file, which isn't there and syncs nothing.
    let oneFile = ["fsync file", "F_FULLFSYNC file", "fsync directory", "F_FULLFSYNC directory"]
    XCTAssertEqual(fixture.calls.list, oneFile + oneFile + oneFile)
    XCTAssertEqual(try repository.load().document, document)

    fixture.calls.clear()
    try repository.updateScopes(scopes)
    XCTAssertEqual(fixture.calls.list, oneFile)
  }
}

/// Records calls made from the store's synchronization closures.
private final class CallLog: @unchecked Sendable {
  private let lock = NSLock()
  private var entries: [String] = []

  var list: [String] { lock.withLock { entries } }
  func append(_ entry: String) { lock.withLock { entries.append(entry) } }
  func clear() { lock.withLock { entries.removeAll() } }
}

private struct Fixture {
  let directory: URL
  let store: SecureAtomicFileStore
  let calls: CallLog
  let unavailable: CallLog

  /// `fullFsyncError` returns the `errno` to fail `F_FULLFSYNC` with for "file" or "directory",
  /// or nil to let it succeed; `fsyncError` fails every `fsync`.
  init(
    fullFsyncError: @escaping @Sendable (String) -> Int32? = { _ in nil },
    fsyncError: Int32? = nil
  ) throws {
    directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let calls = CallLog()
    let unavailable = CallLog()
    self.calls = calls
    self.unavailable = unavailable
    let synchronization = SecureFileSynchronization(
      fsync: { descriptor in
        calls.append("fsync \(Self.kind(descriptor))")
        if let fsyncError {
          errno = fsyncError
          return -1
        }
        return Darwin.fsync(descriptor)
      },
      fullFsync: { descriptor in
        let kind = Self.kind(descriptor)
        calls.append("F_FULLFSYNC \(kind)")
        if let code = fullFsyncError(kind) {
          errno = code
          return -1
        }
        return 0
      })
    store = SecureAtomicFileStore(
      rootDirectory: directory, requiredOwnerUserID: getuid(), synchronization: synchronization,
      fullSynchronizationUnavailable: { operation, code in
        unavailable.append("\(operation) \(code)")
      })
    try store.prepareDirectory(mode: 0o700)
  }

  func remove() { try? FileManager.default.removeItem(at: directory) }

  private static func kind(_ descriptor: Int32) -> String {
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0 else { return "unknown" }
    return metadata.st_mode & S_IFMT == S_IFDIR ? "directory" : "file"
  }
}
