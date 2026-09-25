import Darwin
import Foundation
import PasuFSConfiguration
import XCTest

final class PhysicalPathTests: XCTestCase {
  private func makeBase() throws -> URL {
    let base = PhysicalPath.resolve(FileManager.default.temporaryDirectory)
      .appendingPathComponent("pasu-fs-physical-path-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: base, withIntermediateDirectories: true)
    return base
  }

  private func makeAlias(in base: URL) throws -> (real: URL, alias: URL) {
    let real = base.appendingPathComponent("real", isDirectory: true)
    try FileManager.default.createDirectory(at: real, withIntermediateDirectories: true)
    let alias = base.appendingPathComponent("alias", isDirectory: true)
    try FileManager.default.createSymbolicLink(at: alias, withDestinationURL: real)
    return (real, alias)
  }

  func testResolvesSymbolicLinksInTheParentDirectories() throws {
    let base = try makeBase()
    defer { try? FileManager.default.removeItem(at: base) }
    let (real, alias) = try makeAlias(in: base)

    let resolved = PhysicalPath.resolve(alias.appendingPathComponent("missing/file.json"))
    XCTAssertEqual(resolved.path, real.appendingPathComponent("missing/file.json").path)
    XCTAssertFalse(resolved.hasDirectoryPath)
  }

  func testKeepsTheLastComponentEvenWhenItIsASymbolicLink() throws {
    // A storage root that is itself a link must stay visible as a link, so the checks that
    // open the root without following links can refuse it.
    let base = try makeBase()
    defer { try? FileManager.default.removeItem(at: base) }
    let (_, alias) = try makeAlias(in: base)

    let resolved = PhysicalPath.resolve(alias)
    XCTAssertEqual(resolved.path, alias.path)
    XCTAssertTrue(resolved.hasDirectoryPath)
  }

  func testKeepsThePrivatePrefixOfSystemAliases() {
    // Foundation's standardized paths drop "/private"; the physical path keeps it because the
    // shorter name is a symbolic link, which descriptor-relative removal refuses.
    let name = "pasu-fs-\(UUID().uuidString)"
    XCTAssertEqual(
      PhysicalPath.resolve(URL(fileURLWithPath: "/tmp/\(name)")).path, "/private/tmp/\(name)")
    XCTAssertEqual(
      PhysicalPath.resolve(URL(fileURLWithPath: "/private/tmp/../tmp/./\(name)")).path,
      "/private/tmp/\(name)")
  }

  func testRemovesDotComponentsBeforeResolving() {
    XCTAssertEqual(PhysicalPath.resolve(URL(fileURLWithPath: "/../..")).path, "/")
    XCTAssertEqual(
      PhysicalPath.resolve(URL(fileURLWithPath: "/Library/./Application Support/../Logs")).path,
      "/Library/Logs")
  }

  func testResolvesTheAccessiblePrefixWhenADirectoryCannotBeSearched() throws {
    let base = try makeBase()
    defer { try? FileManager.default.removeItem(at: base) }
    let (real, alias) = try makeAlias(in: base)
    let locked = real.appendingPathComponent("locked", isDirectory: true)
    try FileManager.default.createDirectory(at: locked, withIntermediateDirectories: true)
    guard chmod(locked.path, 0) == 0 else { throw XCTSkip("Cannot lock the directory.") }
    defer { _ = chmod(locked.path, 0o755) }

    let resolved = PhysicalPath.resolve(alias.appendingPathComponent("locked/inner/file"))
    XCTAssertEqual(resolved.path, real.appendingPathComponent("locked/inner/file").path)
  }
}
