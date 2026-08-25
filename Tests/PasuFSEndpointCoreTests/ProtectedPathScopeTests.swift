import Foundation
import XCTest

@testable import PasuFSEndpointCore

final class ProtectedPathScopeTests: XCTestCase {
  func testContainsRootAndDescendantsButNotSiblingPrefix() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }

    let scope = try ProtectedPathScope(
      root: fixture.protected.path,
      homeDirectory: fixture.home.path
    )

    XCTAssertTrue(scope.contains(fixture.protected.path))
    XCTAssertTrue(scope.contains(fixture.protected.appendingPathComponent("nested/file.txt").path))
    XCTAssertFalse(
      scope.contains(fixture.base.appendingPathComponent("PasuFSTest-copy/file.txt").path)
    )
    XCTAssertFalse(scope.contains(fixture.base.appendingPathComponent("outside.txt").path))
  }

  func testMatchesDifferentPathCaseForDefaultMacOSAPFS() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }

    let scope = try ProtectedPathScope(
      root: fixture.protected.path.lowercased(),
      homeDirectory: fixture.home.path
    )

    XCTAssertTrue(scope.contains(fixture.protected.appendingPathComponent("Sample.txt").path))
  }

  func testRejectsRelativePath() throws {
    XCTAssertThrowsError(try ProtectedPathScope(root: "relative/path")) { error in
      XCTAssertEqual(error as? ProtectedPathScopeError, .pathMustBeAbsolute)
    }
  }

  func testRejectsHomeDirectoryAsProtectedRoot() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }

    XCTAssertThrowsError(
      try ProtectedPathScope(root: fixture.home.path, homeDirectory: fixture.home.path)
    ) { error in
      XCTAssertEqual(
        error as? ProtectedPathScopeError,
        .unsafeRoot(fixture.home.standardizedFileURL.path)
      )
    }
  }

  func testRejectsMissingDirectory() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let missing = fixture.base.appendingPathComponent("missing").path

    XCTAssertThrowsError(
      try ProtectedPathScope(root: missing, homeDirectory: fixture.home.path)
    ) { error in
      XCTAssertEqual(error as? ProtectedPathScopeError, .pathDoesNotExist(missing))
    }
  }

  private func makeFixture() throws -> (base: URL, home: URL, protected: URL) {
    let base = FileManager.default.temporaryDirectory
      .appendingPathComponent("PasuFSEndpointCoreTests-\(UUID().uuidString)")
    let home = base.appendingPathComponent("home")
    let protected = home.appendingPathComponent("PasuFSTest")
    try FileManager.default.createDirectory(at: protected, withIntermediateDirectories: true)
    return (base, home, protected)
  }
}
