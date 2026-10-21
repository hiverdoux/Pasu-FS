import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSEndpointCore

final class ProtectedPathScopeTests: XCTestCase {
  func testPreservesPhysicalPrivatePrefixReportedByEndpointSecurity() throws {
    let root = "/private/tmp/PasuFSPhysicalScope-\(UUID().uuidString)"
    try FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(atPath: root) }
    let throughAlias = String(root.dropFirst("/private".count))
    for selected in [root, throughAlias] {
      let scope = try ProtectedPathScope(root: selected)
      XCTAssertEqual(scope.root, root)
      XCTAssertTrue(scope.contains(root + "/sample.txt"))
    }
  }
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

  func testUsesTheSelectedVolumesCaseRules() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }

    let scope = try ProtectedPathScope(
      root: fixture.protected.path,
      homeDirectory: fixture.home.path
    )

    XCTAssertTrue(scope.contains(fixture.protected.appendingPathComponent("Sample.txt").path))
    let sensitive = try XCTUnwrap(
      fixture.protected.resourceValues(
        forKeys: [.volumeSupportsCaseSensitiveNamesKey]).volumeSupportsCaseSensitiveNames)
    XCTAssertEqual(scope.contains(fixture.protected.path.uppercased()), !sensitive)
  }

  func testCaseSensitivePathsRemainDistinct() {
    let sensitive = ProtectedPathScope(canonicalRoot: "/sample/Folder", caseSensitive: true)
    XCTAssertTrue(sensitive.contains("/sample/Folder/item"))
    XCTAssertFalse(sensitive.contains("/sample/folder/item"))
    let insensitive = ProtectedPathScope(canonicalRoot: "/sample/Folder", caseSensitive: false)
    XCTAssertTrue(insensitive.contains("/sample/folder/item"))
  }

  func testEventComparisonIsLexicalAndDoesNotRequireTheFileToExist() throws {
    let fixture = try makeFixture()
    let scope = try ProtectedPathScope(
      root: fixture.protected.path, homeDirectory: fixture.home.path)
    try FileManager.default.removeItem(at: fixture.base)
    XCTAssertTrue(scope.contains(scope.root + "/missing/../file"))
    XCTAssertFalse(scope.contains(scope.root + "/../outside"))
    XCTAssertFalse(scope.contains("relative/file"))
  }

  func testResolvesSelectedSymlinkBeforeMatchingEventPaths() throws {
    let fixture = try makeFixture()
    defer { try? FileManager.default.removeItem(at: fixture.base) }
    let link = fixture.base.appendingPathComponent("selected-link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: fixture.protected)
    let scope = try ProtectedPathScope(root: link.path, homeDirectory: fixture.home.path)
    XCTAssertEqual(scope.root, fixture.protected.path)
    XCTAssertTrue(scope.contains(scope.root + "/file"))
    XCTAssertFalse(scope.contains(link.path + "/file"))
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
        .unsafeRoot(fixture.home.path)
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
    let base = PhysicalPath.resolve(
      FileManager.default.temporaryDirectory
        .appendingPathComponent("PasuFSEndpointCoreTests-\(UUID().uuidString)"))
    let home = base.appendingPathComponent("home")
    let protected = home.appendingPathComponent("PasuFSTest")
    try FileManager.default.createDirectory(at: protected, withIntermediateDirectories: true)
    return (base, home, protected)
  }
}
