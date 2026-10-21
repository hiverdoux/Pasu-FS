import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSHostCore

final class ProgramRuleReaderTests: XCTestCase {
  func testPlatformBinaryIsReadBySigningIdentifier() throws {
    let rule = try ProgramRuleReader.read(
      at: URL(fileURLWithPath: "/bin/ls"), ruleIdentifier: "example-rule")
    XCTAssertEqual(
      rule,
      .platformBinary(
        id: "example-rule", signingIdentifier: "com.apple.ls", allowsDescendants: false))
  }

  func testFileWithoutSignatureIsUnsupportedRatherThanInvalid() throws {
    let folder = FileManager.default.temporaryDirectory
      .appendingPathComponent("ProgramRuleReaderTests-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: folder) }
    let tool = folder.appendingPathComponent("example-tool")
    try Data("#!/bin/sh\n".utf8).write(to: tool)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: tool.path)

    XCTAssertThrowsError(try ProgramRuleReader.read(at: tool)) { error in
      XCTAssertEqual(error as? ProgramRuleReaderError, .unsupportedIdentity)
    }
  }
}
