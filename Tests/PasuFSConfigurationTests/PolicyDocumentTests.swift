import Darwin
import Foundation
import PasuFSPolicy
import XCTest

@testable import PasuFSConfiguration

final class PolicyDocumentTests: XCTestCase {
  func testCodecRoundTripAndEnabledRuleMapping() throws {
    var policy = makeWhitelistPolicy()
    policy.rules[1].isEnabled = false
    let document = makeDocument(policies: [policy])

    let data = try PolicySetDocumentCodec.encode(document)
    let decoded = try PolicySetDocumentCodec.decode(data)

    XCTAssertEqual(decoded, document)
    XCTAssertEqual(try decoded.policies[0].policySnapshot().rules.count, 1)
    XCTAssertEqual(try PolicySetDocumentCodec.digest(of: decoded).count, 64)
  }

  func testStrictCodecRejectsUnknownKeysAtEveryLevel() throws {
    let data = try PolicySetDocumentCodec.encode(makeDocument())
    var top = try XCTUnwrap(JSONSerialization.jsonObject(with: data) as? [String: Any])
    top["unexpected"] = true
    XCTAssertThrowsError(
      try PolicySetDocumentCodec.decode(JSONSerialization.data(withJSONObject: top))
    ) { error in
      XCTAssertEqual(
        error as? PolicySetDocumentCodecError,
        .unknownTopLevelKeys(["unexpected"])
      )
    }

    top.removeValue(forKey: "unexpected")
    var policies = try XCTUnwrap(top["policies"] as? [[String: Any]])
    policies[0]["unexpected"] = true
    top["policies"] = policies
    XCTAssertThrowsError(
      try PolicySetDocumentCodec.decode(JSONSerialization.data(withJSONObject: top))
    ) { error in
      XCTAssertEqual(
        error as? PolicySetDocumentCodecError,
        .unknownPolicyKeys(index: 0, keys: ["unexpected"])
      )
    }

    policies[0].removeValue(forKey: "unexpected")
    var rules = try XCTUnwrap(policies[0]["rules"] as? [[String: Any]])
    rules[0]["unexpected"] = true
    policies[0]["rules"] = rules
    top["policies"] = policies
    XCTAssertThrowsError(
      try PolicySetDocumentCodec.decode(JSONSerialization.data(withJSONObject: top))
    ) { error in
      XCTAssertEqual(
        error as? PolicySetDocumentCodecError,
        .unknownRuleKeys(policy: 0, rule: 0, keys: ["unexpected"])
      )
    }
  }

  func testValidationRejectsDuplicateRuleIDAndIdentityIncludingDisabledRules() throws {
    let first = PolicyRule.teamSigned(
      id: "rule.editor",
      teamIdentifier: "TEAM123456",
      signingIdentifier: "com.example.Editor",
      allowsDescendants: false
    )
    let duplicateID = PolicyRule.platformBinary(
      id: first.id,
      signingIdentifier: "com.apple.TextEdit",
      allowsDescendants: false
    )
    var policy = makeWhitelistPolicy(rules: [first, duplicateID])
    var document = makeDocument(policies: [policy])

    XCTAssertThrowsError(try document.validate()) { error in
      XCTAssertEqual(
        error as? PolicyValidationError,
        .duplicateRuleID(policy: policy.name, ruleID: first.id)
      )
    }

    var duplicateIdentity = first
    duplicateIdentity.id = "rule.editor.copy"
    duplicateIdentity.teamIdentifier = "team123456"
    duplicateIdentity.isEnabled = false
    policy.rules = [first, duplicateIdentity]
    document.policies = [policy]
    XCTAssertThrowsError(try document.validate()) { error in
      XCTAssertEqual(
        error as? PolicyValidationError,
        .duplicateIdentity(
          policy: policy.name,
          identity: "team:TEAM123456:com.example.Editor"
        )
      )
    }
  }

  func testModeAndDirectoryUniquenessAllowsRequiredCombinationsAndNestedScopes() throws {
    let protection = makeWhitelistPolicy(
      id: uuid(1),
      name: "Protection",
      path: "/Users/example/Protected"
    )
    let auditSamePath = DirectoryPolicy(
      id: uuid(2),
      name: "Audit",
      mode: .audit,
      policyType: .blacklist,
      protectedRootPath: protection.protectedRootPath,
      rules: []
    )
    let nestedProtection = makeWhitelistPolicy(
      id: uuid(3),
      name: "Nested",
      path: "/Users/example/Protected/Nested"
    )
    XCTAssertNoThrow(
      try makeDocument(policies: [protection, auditSamePath, nestedProtection]).validate()
    )

    var duplicate = makeWhitelistPolicy(
      id: uuid(4),
      name: "Duplicate",
      path: "/Users/example/Protected/../Protected"
    )
    duplicate.policyType = .blacklist
    duplicate.rules = []
    XCTAssertThrowsError(
      try makeDocument(policies: [protection, duplicate]).validate()
    ) { error in
      XCTAssertEqual(
        error as? PolicyValidationError,
        .duplicateModeAndDirectory(mode: .protection, path: duplicate.protectedRootPath)
      )
    }
  }

  func testNamesAreUniqueCaseAndDiacriticInsensitively() throws {
    let first = makeWhitelistPolicy(id: uuid(1), name: "Résumé")
    let second = makeWhitelistPolicy(
      id: uuid(2),
      name: "resume",
      path: "/Users/example/Other"
    )
    XCTAssertThrowsError(try makeDocument(policies: [first, second]).validate()) { error in
      XCTAssertEqual(error as? PolicyValidationError, .duplicatePolicyName(second.name))
    }
  }

  func testOnlyProtectionWhitelistRequiresAnEnabledRule() throws {
    var whitelist = makeWhitelistPolicy()
    whitelist.rules = whitelist.rules.map {
      var rule = $0
      rule.isEnabled = false
      return rule
    }
    XCTAssertThrowsError(try makeDocument(policies: [whitelist]).validate()) { error in
      XCTAssertEqual(
        error as? PolicyValidationError,
        .protectionWhitelistRequiresEnabledRule(whitelist.name)
      )
    }

    let protectionBlacklist = DirectoryPolicy(
      id: uuid(2),
      name: "Protection Blacklist",
      mode: .protection,
      policyType: .blacklist,
      protectedRootPath: "/Users/example/Blacklist",
      rules: []
    )
    let auditWhitelist = DirectoryPolicy(
      id: uuid(3),
      name: "Audit Whitelist",
      mode: .audit,
      policyType: .whitelist,
      protectedRootPath: "/Users/example/Audit",
      rules: []
    )
    XCTAssertNoThrow(
      try makeDocument(policies: [protectionBlacklist, auditWhitelist]).validate()
    )
    XCTAssertNoThrow(try makeDocument(policies: []).validate())
  }

  func testPolicyAndRuleCountLimitsAreSetWide() throws {
    let tooManyPolicies = (0...PolicySetDocument.maximumPolicyCount).map { index in
      DirectoryPolicy(
        id: UUID(),
        name: "Policy \(index)",
        mode: .audit,
        policyType: .blacklist,
        protectedRootPath: "/Users/example/Policy-\(index)",
        rules: []
      )
    }
    XCTAssertThrowsError(try makeDocument(policies: tooManyPolicies).validate()) { error in
      XCTAssertEqual(
        error as? PolicyValidationError,
        .tooManyPolicies(tooManyPolicies.count)
      )
    }

    let rules = (0...PolicySetDocument.maximumRuleCount).map { index in
      PolicyRule.platformBinary(
        id: "rule.\(index)",
        signingIdentifier: "com.apple.tool.\(index)",
        allowsDescendants: false
      )
    }
    let tooManyRules = DirectoryPolicy(
      name: "Audit",
      mode: .audit,
      policyType: .blacklist,
      protectedRootPath: "/Users/example/Audit",
      rules: rules
    )
    XCTAssertThrowsError(try makeDocument(policies: [tooManyRules]).validate()) { error in
      XCTAssertEqual(error as? PolicyValidationError, .tooManyRules(rules.count))
    }
  }

  func testRevisionValidationChecksSetIdentityCollisionAndDowngrade() throws {
    let active = makeDocument(revision: 2)
    XCTAssertEqual(
      try PolicyUpdateValidator.validate(candidate: active, against: active),
      .unchanged
    )

    var collision = active
    collision.policies[0].name = "Changed"
    XCTAssertThrowsError(
      try PolicyUpdateValidator.validate(candidate: collision, against: active)
    ) { error in
      XCTAssertEqual(error as? PolicyUpdateError, .revisionCollision(2))
    }

    let older = makeDocument(revision: 1)
    XCTAssertThrowsError(
      try PolicyUpdateValidator.validate(candidate: older, against: active)
    ) { error in
      XCTAssertEqual(
        error as? PolicyUpdateError,
        .revisionDowngrade(candidate: 1, active: 2)
      )
    }

    let differentSet = makeDocument(setIdentifier: uuid(99), revision: 3)
    XCTAssertThrowsError(
      try PolicyUpdateValidator.validate(candidate: differentSet, against: active)
    ) { error in
      XCTAssertEqual(
        error as? PolicyUpdateError,
        .setIdentifierMismatch(candidate: uuid(99), active: active.setIdentifier)
      )
    }
  }

  func testTeamIdentifierIsCanonicalizedForMatching() throws {
    let rule = PolicyRule.teamSigned(
      id: "rule.editor",
      teamIdentifier: "team123456",
      signingIdentifier: "com.example.Editor",
      allowsDescendants: false
    )
    let mapped = try rule.matcherRule()
    guard case .teamSigned(let identity) = mapped.identity else {
      return XCTFail("Expected a team-signed identity.")
    }
    XCTAssertEqual(identity.teamIdentifier, "TEAM123456")
  }

  func testLegacyV1RecognitionIsNarrow() throws {
    let legacy = Data(
      """
      {"schemaVersion":1,"revision":4,"mode":"enforce","protectedRootPath":"/Users/example/Protected","rules":[]}
      """.utf8
    )
    XCTAssertTrue(PolicySetDocumentCodec.isLegacyV1Document(legacy))
    XCTAssertFalse(
      PolicySetDocumentCodec.isLegacyV1Document(try PolicySetDocumentCodec.encode(makeDocument()))
    )
    XCTAssertFalse(
      PolicySetDocumentCodec.isLegacyV1Document(Data("{\"schemaVersion\":1}".utf8))
    )
    XCTAssertFalse(
      PolicySetDocumentCodec.isLegacyV1Document(
        Data(
          """
          {"schemaVersion":true,"revision":4,"mode":"enforce","protectedRootPath":"/Users/example/Protected","rules":[]}
          """.utf8
        )
      )
    )
  }

  func testLegacyHandshakeDecodesAsProtocolVersionOne() throws {
    struct LegacyHandshake: Codable {
      let nonce: Data
      let runtimeInstanceIdentifier: UUID
      let timestamp: Date
    }
    let legacy = LegacyHandshake(
      nonce: Data([1, 2, 3]),
      runtimeInstanceIdentifier: uuid(7),
      timestamp: Date(timeIntervalSinceReferenceDate: 12)
    )

    let decoded = try JSONDecoder().decode(
      XPCHandshakeResponse.self,
      from: JSONEncoder().encode(legacy)
    )

    XCTAssertEqual(decoded.configurationProtocolVersion, 1)
    XCTAssertEqual(decoded.nonce, legacy.nonce)
  }

  func testHandshakeRequestCarriesCurrentProtocolVersion() throws {
    let request = XPCHandshakeRequest(nonce: Data([4, 5, 6]))
    let decoded = try JSONDecoder().decode(
      XPCHandshakeRequest.self,
      from: JSONEncoder().encode(request)
    )

    XCTAssertEqual(decoded, request)
    XCTAssertEqual(
      decoded.configurationProtocolVersion,
      XPCHandshakeRequest.currentConfigurationProtocolVersion
    )
  }

  func testSecureAtomicStoreRoundTripRemovalAndSymlinkRejection() throws {
    let base = FileManager.default.temporaryDirectory
      .appendingPathComponent("pasu-fs-store-test-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: base) }

    let store = SecureAtomicFileStore(
      rootDirectory: base,
      requiredOwnerUserID: getuid()
    )
    try store.prepareDirectory()
    let expected = Data("secure policy".utf8)
    try store.write(expected, to: "policy.json", mode: 0o600)
    XCTAssertEqual(try store.read("policy.json", maximumSize: 1_024), expected)
    try store.remove("policy.json")
    XCTAssertThrowsError(try store.read("policy.json", maximumSize: 1_024)) { error in
      guard case SecureFileStoreError.fileNotFound = error else {
        return XCTFail("Expected fileNotFound, got \(error)")
      }
    }

    try store.write(expected, to: "target.json", mode: 0o600)
    let link = base.appendingPathComponent("link.json")
    try FileManager.default.createSymbolicLink(
      at: link,
      withDestinationURL: base.appendingPathComponent("target.json")
    )
    XCTAssertThrowsError(try store.remove("link.json")) { error in
      XCTAssertEqual(error as? SecureFileStoreError, .notRegularFile("link.json"))
    }
    XCTAssertTrue(FileManager.default.fileExists(atPath: link.path))
  }

  func testLegacyRetirementPermanentlyRemovesOnlyConfirmedV1File() throws {
    let base = FileManager.default.temporaryDirectory
      .appendingPathComponent("pasu-fs-retirement-test-\(UUID().uuidString)", isDirectory: true)
    defer { try? FileManager.default.removeItem(at: base) }
    let store = SecureAtomicFileStore(
      rootDirectory: base,
      requiredOwnerUserID: getuid()
    )
    try store.prepareDirectory()
    let legacy = Data(
      """
      {"schemaVersion":1,"revision":4,"mode":"enforce","protectedRootPath":"/Users/example/Protected","rules":[]}
      """.utf8
    )
    try store.write(
      legacy,
      to: ExtensionStorageLocations.legacyPolicyFilename,
      mode: 0o600
    )

    XCTAssertEqual(try LegacyPolicyRetirement.run(store: store), .removed)
    XCTAssertEqual(try LegacyPolicyRetirement.run(store: store), .notFound)

    let unknown = Data("{\"schemaVersion\":99}".utf8)
    try store.write(
      unknown,
      to: ExtensionStorageLocations.legacyPolicyFilename,
      mode: 0o600
    )
    XCTAssertEqual(try LegacyPolicyRetirement.run(store: store), .unrecognized)
    XCTAssertEqual(
      try store.read(
        ExtensionStorageLocations.legacyPolicyFilename,
        maximumSize: 1_024
      ),
      unknown
    )
  }

  private func makeDocument(
    setIdentifier: UUID = UUID(uuidString: "AAAAAAAA-AAAA-AAAA-AAAA-AAAAAAAAAAAA")!,
    revision: UInt64 = 1,
    policies: [DirectoryPolicy]? = nil
  ) -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: setIdentifier,
      revision: revision,
      policies: policies ?? [makeWhitelistPolicy()]
    )
  }

  private func makeWhitelistPolicy(
    id: UUID = UUID(uuidString: "BBBBBBBB-BBBB-BBBB-BBBB-BBBBBBBBBBBB")!,
    name: String = "Protected Files",
    path: String = "/Users/example/Protected",
    rules: [PolicyRule]? = nil
  ) -> DirectoryPolicy {
    DirectoryPolicy(
      id: id,
      name: name,
      mode: .protection,
      policyType: .whitelist,
      protectedRootPath: path,
      rules: rules ?? [
        .teamSigned(
          id: "rule.editor",
          teamIdentifier: "TEAM123456",
          signingIdentifier: "com.example.Editor",
          allowsDescendants: true
        ),
        .platformBinary(
          id: "rule.textedit",
          signingIdentifier: "com.apple.TextEdit",
          allowsDescendants: false
        ),
      ]
    )
  }

  private func uuid(_ value: Int) -> UUID {
    UUID(uuidString: String(format: "00000000-0000-0000-0000-%012d", value))!
  }
}
