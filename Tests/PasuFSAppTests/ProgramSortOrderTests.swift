import PasuFSConfiguration
import XCTest

@testable import PasuFSApp

final class ProgramSortOrderTests: XCTestCase {
  private let rules = [
    PolicyRule.teamSigned(
      id: "r1", teamIdentifier: "ZZZZZ99999", signingIdentifier: "com.example.zeta",
      allowsDescendants: false),
    PolicyRule.platformBinary(
      id: "r2", signingIdentifier: "com.apple.ls", allowsDescendants: false),
    PolicyRule.teamSigned(
      id: "r3", teamIdentifier: "AAAAA11111", signingIdentifier: "com.example.tool10",
      allowsDescendants: false),
    PolicyRule.teamSigned(
      id: "r4", teamIdentifier: "AAAAA11111", signingIdentifier: "com.example.tool9",
      allowsDescendants: false),
    PolicyRule.platformBinary(
      id: "r5", signingIdentifier: "com.apple.cat", allowsDescendants: false),
  ]
  private let names = ["r1": "zeta", "r2": "ls", "r3": "Tool 10", "r4": "tool 9", "r5": "cat"]

  private func ids(_ order: ProgramSortOrder) -> [String] {
    order.sorted(rules) { names[$0.id] ?? "" }.map(\.id)
  }

  func testNameOrderIgnoresCaseAndComparesNumbersByValue() {
    // cat, ls, tool 9, Tool 10, zeta
    XCTAssertEqual(ids(.name), ["r5", "r2", "r4", "r3", "r1"])
  }

  func testSigningIdentifierOrder() {
    // com.apple.cat, com.apple.ls, com.example.tool9, com.example.tool10, com.example.zeta
    XCTAssertEqual(ids(.signingIdentifier), ["r5", "r2", "r4", "r3", "r1"])
  }

  func testSignatureOrderGroupsDeveloperSignedProgramsByTeamBeforePlatformBinaries() {
    // Team AAAAA11111: tool 9, Tool 10; team ZZZZZ99999: zeta; platform binaries: cat, ls
    XCTAssertEqual(ids(.signature), ["r4", "r3", "r1", "r5", "r2"])
  }

  func testOrderAddedKeepsTheList() {
    XCTAssertEqual(ids(.orderAdded), ["r1", "r2", "r3", "r4", "r5"])
  }

  func testRulesThatCompareTheSameKeepTheirOrder() {
    let same = [
      PolicyRule.platformBinary(
        id: "a", signingIdentifier: "com.apple.same", allowsDescendants: false),
      PolicyRule.platformBinary(
        id: "b", signingIdentifier: "com.apple.same", allowsDescendants: false),
    ]
    XCTAssertEqual(ProgramSortOrder.name.sorted(same) { _ in "Same" }.map(\.id), ["a", "b"])
    XCTAssertEqual(
      ProgramSortOrder.signature.sorted(same.reversed()) { _ in "Same" }.map(\.id), ["b", "a"])
    XCTAssertEqual(ProgramSortOrder.name.sorted([]) { _ in "" }, [])
  }

  func testTheDefaultIsNameOrderAndEveryOrderIsNamed() {
    XCTAssertEqual(ProgramSortOrder.default, .name)
    XCTAssertEqual(
      Set(ProgramSortOrder.allCases.map(\.displayName)).count, ProgramSortOrder.allCases.count)
    XCTAssertEqual(ProgramSortOrder(rawValue: "name"), .name)
    XCTAssertNil(ProgramSortOrder(rawValue: "unknown"))
  }
}
