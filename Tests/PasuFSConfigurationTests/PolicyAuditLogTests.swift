import Foundation
import XCTest

@testable import PasuFSConfiguration

final class PolicyAuditLogTests: XCTestCase {
  func testOnlyCanonicalOwnedPolicyFilenamesAreRecognized() {
    let key = PolicyAuditLogKey(setIdentifier: UUID(), policyIdentifier: UUID())
    XCTAssertEqual(PolicyAuditLogKey(filename: key.filename), key)
    XCTAssertEqual(PolicyAuditLogKey(filename: key.filename + ".1"), key)
    XCTAssertNil(PolicyAuditLogKey(filename: "../" + key.filename))
    XCTAssertNil(PolicyAuditLogKey(filename: key.filename + ".2"))
    XCTAssertNil(PolicyAuditLogKey(filename: "policy-example.jsonl"))
    XCTAssertNil(PolicyAuditLogKey(filename: "endpoint-events.jsonl"))
  }

  func testHandshakeCapabilityDefaultsToUnsupportedForOldReplies() throws {
    let response = XPCHandshakeResponse(
      nonce: Data([1]), runtimeInstanceIdentifier: UUID(), supportsPolicyAuditLog: true)
    let encoded = try JSONEncoder().encode(response)
    XCTAssertTrue(
      try JSONDecoder().decode(XPCHandshakeResponse.self, from: encoded).supportsPolicyAuditLog)
    var object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    object.removeValue(forKey: "supportsPolicyAuditLog")
    let legacy = try JSONSerialization.data(withJSONObject: object)
    let decoded = try JSONDecoder().decode(XPCHandshakeResponse.self, from: legacy)
    XCTAssertFalse(decoded.supportsPolicyAuditLog)
    XCTAssertEqual(decoded.configurationProtocolVersion, response.configurationProtocolVersion)
  }

  func testOldAuditBatchesRemainDecodableAndRequestsRoundTrip() throws {
    let legacy = Data(
      "{\"records\":[],\"skippedLineCount\":0,\"droppedEventCount\":0,\"isTruncated\":false}".utf8)
    XCTAssertNil(try JSONDecoder().decode(AuditLogBatch.self, from: legacy).warning)
    let request = PolicyAuditLogRequest(
      key: PolicyAuditLogKey(setIdentifier: UUID(), policyIdentifier: UUID()), maximumLineCount: 500
    )
    XCTAssertEqual(
      try JSONDecoder().decode(
        PolicyAuditLogRequest.self,
        from: JSONEncoder().encode(request)), request)
  }
}
