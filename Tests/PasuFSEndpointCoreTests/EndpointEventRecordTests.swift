import Foundation
import PasuFSConfiguration
import XCTest

@testable import PasuFSEndpointCore

final class EndpointEventRecordTests: XCTestCase {
  func testPlatformBinaryFieldIsEncoded() throws {
    let record = EndpointEventRecord(
      timestamp: Date(timeIntervalSince1970: 0),
      eventType: "AUTH_OPEN",
      signingIdentifier: "com.apple.finder",
      isPlatformBinary: true,
      policyDecision: "allowed-direct:allow.harness.platform.1",
      kernelResponse: "allow"
    )

    let data = try JSONEncoder().encode(record)
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: data) as? [String: Any]
    )

    XCTAssertEqual(object["isPlatformBinary"] as? Bool, true)
  }

  func testRecordWithoutPlatformBinaryFieldStillDecodes() throws {
    let record = EndpointEventRecord(
      timestamp: Date(timeIntervalSince1970: 0),
      eventType: "AUTH_OPEN",
      signingIdentifier: "com.apple.finder",
      isPlatformBinary: true,
      policyDecision: "allowed-direct:allow.harness.platform.1",
      kernelResponse: "allow"
    )
    let encoded = try JSONEncoder().encode(record)
    var object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: encoded) as? [String: Any]
    )
    object.removeValue(forKey: "isPlatformBinary")
    let legacyData = try JSONSerialization.data(withJSONObject: object)

    let decoded = try JSONDecoder().decode(EndpointEventRecord.self, from: legacyData)

    XCTAssertNil(decoded.isPlatformBinary)
    XCTAssertNil(decoded.policyEvaluations)
  }

  func testOneEventEncodesMultiplePolicyEvaluations() throws {
    let setIdentifier = UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!
    let record = EndpointEventRecord(
      timestamp: Date(timeIntervalSince1970: 0),
      policySetIdentifier: setIdentifier,
      policyRevision: 4,
      eventSequence: 9,
      eventType: "AUTH_OPEN",
      signingIdentifier: "com.example.Editor",
      policyDecision: "denied",
      kernelResponse: "deny",
      policyEvaluations: [
        PolicyEvaluationRecord(
          policyIdentifier: UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!,
          policyName: "Parent",
          mode: .protection,
          policyType: .whitelist,
          match: .direct,
          ruleIdentifier: "rule.editor",
          decision: .allow
        ),
        PolicyEvaluationRecord(
          policyIdentifier: UUID(uuidString: "CCCCCCCC-CCCC-CCCC-CCCC-CCCCCCCCCCCC")!,
          policyName: "Nested",
          mode: .protection,
          policyType: .blacklist,
          match: .direct,
          ruleIdentifier: "rule.editor",
          decision: .deny
        ),
      ]
    )

    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let data = try encoder.encode(record)
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    let decoded = try decoder.decode(EndpointEventRecord.self, from: data)

    XCTAssertEqual(decoded.policySetIdentifier, setIdentifier)
    XCTAssertEqual(decoded.policyEvaluations?.count, 2)
    XCTAssertEqual(decoded.policyEvaluations?.map(\.decision), [.allow, .deny])
  }
}
