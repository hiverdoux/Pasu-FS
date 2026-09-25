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
      codeSigningFlags: 0x0000_0001,
      operatingSystemBuild: "23A000",
      policyDecision: "allowed-direct:allow.example.platform.1",
      kernelResponse: "allow"
    )

    let data = try JSONEncoder().encode(record)
    let object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: data) as? [String: Any]
    )

    XCTAssertEqual(object["isPlatformBinary"] as? Bool, true)
    XCTAssertEqual((object["codeSigningFlags"] as? NSNumber)?.uint32Value, 0x0000_0001)
    XCTAssertEqual(object["operatingSystemBuild"] as? String, "23A000")
  }

  func testRecordWithoutPlatformBinaryFieldStillDecodes() throws {
    let record = EndpointEventRecord(
      timestamp: Date(timeIntervalSince1970: 0),
      eventType: "AUTH_OPEN",
      signingIdentifier: "com.apple.finder",
      isPlatformBinary: true,
      operatingSystemBuild: "23A000",
      policyDecision: "allowed-direct:allow.example.platform.1",
      kernelResponse: "allow"
    )
    let encoded = try JSONEncoder().encode(record)
    var object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: encoded) as? [String: Any]
    )
    object.removeValue(forKey: "isPlatformBinary")
    object.removeValue(forKey: "operatingSystemBuild")
    let legacyData = try JSONSerialization.data(withJSONObject: object)

    let decoded = try JSONDecoder().decode(EndpointEventRecord.self, from: legacyData)

    XCTAssertNil(decoded.isPlatformBinary)
    XCTAssertNil(decoded.operatingSystemBuild)
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

  func testSystemCompatibilityDecisionSourceRoundTrips() throws {
    let evaluation = PolicyEvaluationRecord(
      policyIdentifier: UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!,
      policyName: "Protected Files",
      mode: .protection,
      policyType: .whitelist,
      match: .systemCompatibilityProfile,
      systemCompatibilityProfileIdentifier: "system.example.read",
      systemCompatibilityAuthorizationDigest: String(repeating: "a", count: 64),
      decision: .allow
    )
    let data = try JSONEncoder().encode(evaluation)
    let decoded = try JSONDecoder().decode(PolicyEvaluationRecord.self, from: data)

    XCTAssertEqual(decoded, evaluation)
    XCTAssertEqual(decoded.match, .systemCompatibilityProfile)
    XCTAssertNil(decoded.ruleIdentifier)
  }
}
