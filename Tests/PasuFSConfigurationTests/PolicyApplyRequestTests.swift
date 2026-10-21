import Foundation
import XCTest

@testable import PasuFSConfiguration

final class PolicyApplyRequestTests: XCTestCase {
  func testRequestRoundTripsWithAndWithoutAuthorization() throws {
    let policySet = try PolicySetDocumentCodec.encode(makeSet())
    for authorization in [nil, Data(repeating: 7, count: 32)] {
      let request = PolicyApplyRequest(policySetData: policySet, authorization: authorization)
      let decoded = try PolicyApplyRequest.decode(JSONEncoder().encode(request))
      XCTAssertEqual(decoded, request)
      XCTAssertEqual(
        decoded.configurationProtocolVersion,
        XPCHandshakeRequest.currentConfigurationProtocolVersion)
      XCTAssertEqual(try PolicySetDocumentCodec.decode(decoded.policySetData), makeSet())
    }
  }

  func testBarePolicySetFromAnOlderAppIsNamedAsAProtocolMismatch() throws {
    let bare = try PolicySetDocumentCodec.encode(makeSet())
    XCTAssertThrowsError(try PolicyApplyRequest.decode(bare)) { error in
      XCTAssertEqual(
        error as? PolicyApplyRequestError,
        .unversionedRequest(expected: PolicyApplyRequest.currentConfigurationProtocolVersion))
      XCTAssertTrue(String(describing: error).contains("Update the Pasu FS app"))
    }
  }

  func testOtherProtocolVersionsAreRejected() throws {
    let request = PolicyApplyRequest(
      policySetData: try PolicySetDocumentCodec.encode(makeSet()),
      configurationProtocolVersion: PolicyApplyRequest.currentConfigurationProtocolVersion + 1)
    XCTAssertThrowsError(try PolicyApplyRequest.decode(JSONEncoder().encode(request))) { error in
      XCTAssertEqual(
        error as? PolicyApplyRequestError,
        .protocolMismatch(
          expected: PolicyApplyRequest.currentConfigurationProtocolVersion,
          received: PolicyApplyRequest.currentConfigurationProtocolVersion + 1))
    }
  }

  func testOversizedAndMalformedRequestsAreRejected() {
    let oversized = Data(repeating: 65, count: PolicyApplyRequest.maximumEncodedSize + 1)
    XCTAssertThrowsError(try PolicyApplyRequest.decode(oversized)) { error in
      XCTAssertEqual(
        error as? PolicyApplyRequestError,
        .requestTooLarge(PolicyApplyRequest.maximumEncodedSize + 1))
    }
    XCTAssertThrowsError(try PolicyApplyRequest.decode(Data("[1]".utf8))) { error in
      guard case .malformedRequest? = error as? PolicyApplyRequestError else {
        return XCTFail("\(error)")
      }
    }
    XCTAssertThrowsError(try PolicyApplyRequest.decode(Data("not json".utf8)))
    let missingPolicySet = Data(
      "{\"configurationProtocolVersion\":\(PolicyApplyRequest.currentConfigurationProtocolVersion)}"
        .utf8)
    XCTAssertThrowsError(try PolicyApplyRequest.decode(missingPolicySet)) { error in
      guard case .malformedRequest? = error as? PolicyApplyRequestError else {
        return XCTFail("\(error)")
      }
    }
  }

  private func makeSet() -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(uuidString: "00000000-0000-0000-0000-000000000099")!, revision: 1,
      policies: [
        DirectoryPolicy(
          id: UUID(uuidString: "00000000-0000-0000-0000-000000000001")!, name: "Secrets",
          mode: .protection, protectedRootPath: "/Users/example/Secrets")
      ])
  }
}
