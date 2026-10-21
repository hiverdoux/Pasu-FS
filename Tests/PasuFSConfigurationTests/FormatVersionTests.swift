import Darwin
import Foundation
import XCTest

@testable import PasuFSConfiguration

/// The stored formats and the app-extension contract of this version, and how the formats of
/// the previous version are read after an update.
final class FormatVersionTests: XCTestCase {
  func testFormatVersionsOfThisRelease() {
    XCTAssertEqual(PolicySetDocument.currentSchemaVersion, 5)
    XCTAssertEqual(AuditEventRecord.currentSchemaVersion, 9)
    let record = AuditEventRecord(
      eventType: "AUTH_OPEN", policyDecision: "allowed", kernelResponse: "allow")
    XCTAssertEqual(record.schemaVersion, 9)
    XCTAssertEqual(ExtensionStatusSnapshot.currentSchemaVersion, 7)
    XCTAssertEqual(XPCHandshakeRequest.currentConfigurationProtocolVersion, 8)
    XCTAssertEqual(PolicyApplyRequest.currentConfigurationProtocolVersion, 8)
    XCTAssertEqual(XPCHandshakeResponse.currentConfigurationProtocolVersion, 8)
    XCTAssertEqual(ExecutionOriginCapabilities.currentVersion, 3)
    XCTAssertEqual(ExecutionOriginCapabilities().version, 3)
    XCTAssertEqual(ExecutionOriginCapabilities().policySchemaVersion, 5)
    XCTAssertEqual(SystemCompatibilityCatalog.currentSchemaVersion, 3)
  }

  func testSchemaFourSetIsReadUnchangedButLiveWritesNeedTheCurrentSchema() throws {
    let current = sampleSet()
    let data = try encode(current, schemaVersion: 4)
    XCTAssertThrowsError(try PolicySetDocumentCodec.decode(data)) { error in
      XCTAssertEqual(error as? PolicyValidationError, .unsupportedSchemaVersion(4))
    }
    XCTAssertEqual(try PolicySetDocumentCodec.storedSchemaVersion(of: data), 4)
    let read = try PolicySetDocumentCodec.migrateStoredDocument(data)
    XCTAssertEqual(read, current)
    // Unlike schemas 2 and 3, schema 4 enforced descendant options, so they stay on.
    XCTAssertTrue(read.policies[0].allowRules[0].allowsDescendants)
    XCTAssertEqual(read.policies[0].systemCompatibilityProfiles, profiles())
  }

  func testNewerSchemaIsRejectedInsteadOfReadWithUnknownRules() throws {
    let data = try encode(sampleSet(), schemaVersion: PolicySetDocument.currentSchemaVersion + 1)
    XCTAssertThrowsError(try PolicySetDocumentCodec.migrateStoredDocument(data)) { error in
      XCTAssertEqual(
        error as? PolicyValidationError,
        .unsupportedSchemaVersion(PolicySetDocument.currentSchemaVersion + 1))
    }
  }

  func testCommittedSchemaFourSetLoadsAsReadyAndIsRewrittenInTheCurrentSchema() throws {
    for damagedCopies in 0...2 {
      let fixture = try repository()
      defer { try? FileManager.default.removeItem(at: fixture.directory) }
      let current = sampleSet()
      let scopes = sampleScopes(current)
      try storeInSchemaFour(current, scopes: scopes, fixture: fixture, damagedCopies: damagedCopies)

      let loaded = try fixture.repository.load()
      XCTAssertEqual(loaded.scopes, scopes, "folder identities and retired paths are kept")
      if damagedCopies == 2 {
        // Both copies lost: the known Protection folders still deny every request.
        XCTAssertEqual(loaded.state, .denyAllRecovery)
        XCTAssertEqual(loaded.emergencyScopes, scopes)
        XCTAssertEqual(loaded.document?.policies.map(\.id), current.policies.map(\.id))
        XCTAssertEqual(loaded.document?.policies[0].allowRules, [])
        XCTAssertFalse(loaded.storedInEarlierSchema)
        continue
      }
      XCTAssertEqual(loaded.state, damagedCopies == 1 ? .recovered : .ready)
      XCTAssertTrue(loaded.storedInEarlierSchema)
      XCTAssertEqual(loaded.document, current)

      // The extension stores the unchanged set again, which writes the current schema.
      let document = try XCTUnwrap(loaded.document)
      try fixture.repository.save(document, scopes: loaded.scopes)
      let rewritten = try fixture.repository.load()
      XCTAssertEqual(rewritten.state, .ready)
      XCTAssertFalse(rewritten.storedInEarlierSchema)
      XCTAssertEqual(rewritten.document, current)
      XCTAssertEqual(rewritten.scopes, scopes)
      let commit = try readCommit(fixture)
      XCTAssertEqual(commit.emergencyDocument.schemaVersion, PolicySetDocument.currentSchemaVersion)
      for backup in [false, true] {
        let stored = try fixture.store.read(
          PolicyRepository.filename(commit.slot, backup: backup), maximumSize: 1_048_576)
        XCTAssertEqual(
          try PolicySetDocumentCodec.storedSchemaVersion(of: stored),
          PolicySetDocument.currentSchemaVersion)
        XCTAssertEqual(try PolicySetDocumentCodec.decode(stored), current)
      }
    }
  }

  func testCompatibilityProfileApprovalsOfThePreviousVersionsStayValid() throws {
    // Approvals stored in policies by versions 0.8.0 to 0.10.0 carry these digests; 0.9.0 added
    // Finder Copy. A change to them would turn every approved profile off after an update.
    // XProtect Malware Scanning is the exception: adding the XProtect analysis service changed
    // what it allows, so an earlier approval of it needs review until it is turned on again.
    let catalog = BuiltInSystemCompatibilityCatalog.catalog
    XCTAssertEqual(
      try catalog.authorizationDigest(
        profileIdentifier: BuiltInSystemCompatibilityCatalog.containerManagementIdentifier),
      "b91d4cb4ceb550c51d6fac3fa8ce88049c521aa79dc04b0080a890aa3770d185")
    XCTAssertEqual(
      try catalog.authorizationDigest(
        profileIdentifier: BuiltInSystemCompatibilityCatalog.finderCopyIdentifier),
      "80e070fa9fbd0df22a7e7498e9c5477b253ab274f214077b62ef99b24658e7b2")
    let earlierXProtect = PolicySystemCompatibilityProfile(
      profileIdentifier: BuiltInSystemCompatibilityCatalog.xprotectRemediationIdentifier,
      authorizationDigest: "dacae4974af160fbc88f9bb513c9dfaed5c83025dbaddfdd4068a80c39c45341")
    let (resolution, resolved) = try SystemCompatibilityResolver.resolve(
      earlierXProtect, policyIdentifier: UUID(), catalog: catalog,
      operatingSystemVersion: OperatingSystemVersion(
        majorVersion: 27, minorVersion: 2, patchVersion: 0))
    XCTAssertEqual(resolution.state, .needsReview)
    XCTAssertNil(resolved)
    var earlier = catalog
    earlier.schemaVersion = 2
    XCTAssertThrowsError(try earlier.validate()) { error in
      XCTAssertEqual(
        error as? SystemCompatibilityValidationError, .unsupportedCatalogSchemaVersion(2))
    }
  }

  func testStatusOfThePreviousExtensionRemainsReadable() throws {
    var snapshot = ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: UUID(), phase: .enforcing, protectionPolicyCount: 1,
      retiredFolderPaths: [
        PolicyRetiredFolderPaths(policyIdentifier: UUID(), paths: ["/Users/example/Protected"])
      ])
    snapshot.targetPathMuting = TargetPathMutingStatus(
      isInverted: true, deliversAllRequests: false, prefixCount: 4, literalCount: 6)
    snapshot.uncheckedRequests = UncheckedRequestMetrics()
    snapshot.deadlineMissMode = DeadlineMissModeStatus(
      setting: .failClosed, maximumDeadlineMilliseconds: 3_000)
    snapshot.extensionVersion = "1.2.3"
    snapshot.extensionBuildVersion = "45"
    let subscribedAt = Date(timeIntervalSince1970: 1_800_000_014)
    snapshot.endpointConnection = EndpointConnectionStatus(
      requestsEarlyBoot: true, clientCreatedAt: subscribedAt,
      clientCreatedSecondsAfterStartup: 13.9, firstSubscriptionAt: subscribedAt,
      firstSubscriptionSecondsAfterStartup: 14, firstSubscriptionEventCount: 24,
      firstSubscriptionIncludesPolicyEvents: true)
    // The app reads the status the same way: JSON with ISO 8601 dates.
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    var current = try XCTUnwrap(
      JSONSerialization.jsonObject(with: encoder.encode(snapshot)) as? [String: Any])
    XCTAssertEqual(current["schemaVersion"] as? Int, 7)
    let historyStatus: [String: Any] = [
      "bootIdentifier": "example-boot", "observedProcessCount": 3, "estimatedDataBytes": 900,
      "maximumEstimatedDataBytes": 16_777_216, "maximumProcessCount": 16_384,
      "coverageEpoch": 1, "invalidationCount": 0, "discardedProcessCount": 0,
    ]
    var currentHistory = historyStatus
    currentHistory["observationStartedAt"] = "2027-01-15T08:00:13Z"
    currentHistory["kernelLaunchdStartHistoryCount"] = 12
    current["executionOriginStatus"] = currentHistory
    let read = try decoder.decode(
      ExtensionStatusSnapshot.self, from: JSONSerialization.data(withJSONObject: current))
    XCTAssertEqual(read.extensionVersion, "1.2.3")
    XCTAssertEqual(read.extensionBuildVersion, "45")
    XCTAssertEqual(read.endpointConnection, snapshot.endpointConnection)
    XCTAssertEqual(read.executionOriginStatus?.kernelLaunchdStartHistoryCount, 12)
    XCTAssertNotNil(read.executionOriginStatus?.observationStartedAt)

    // Version 0.12.4 wrote schema 6, without the connection times and without the start of
    // tracking and the histories begun with a launchd start.
    var schemaSix = current
    schemaSix["schemaVersion"] = 6
    schemaSix.removeValue(forKey: "endpointConnection")
    schemaSix["executionOriginStatus"] = historyStatus
    let beforeConnection = try decoder.decode(
      ExtensionStatusSnapshot.self, from: JSONSerialization.data(withJSONObject: schemaSix))
    XCTAssertEqual(beforeConnection.schemaVersion, 6)
    XCTAssertNil(beforeConnection.endpointConnection)
    XCTAssertEqual(beforeConnection.executionOriginStatus?.observedProcessCount, 3)
    XCTAssertNil(beforeConnection.executionOriginStatus?.observationStartedAt)
    XCTAssertNil(beforeConnection.executionOriginStatus?.kernelLaunchdStartHistoryCount)
    XCTAssertEqual(beforeConnection.extensionVersion, "1.2.3")

    // Version 0.10.3 wrote schema 5, without the extension's own version.
    var object = schemaSix
    object["schemaVersion"] = 5
    object.removeValue(forKey: "extensionVersion")
    object.removeValue(forKey: "extensionBuildVersion")
    let unversioned = try decoder.decode(
      ExtensionStatusSnapshot.self, from: JSONSerialization.data(withJSONObject: object))
    XCTAssertEqual(unversioned.schemaVersion, 5)
    XCTAssertNil(unversioned.extensionVersion)
    XCTAssertNil(unversioned.extensionBuildVersion)
    XCTAssertEqual(unversioned.deadlineMissMode, snapshot.deadlineMissMode)

    // Version 0.9.0 wrote schema 4: the missed-deadline setting without the maximum deadline.
    object["schemaVersion"] = 4
    object["deadlineMissMode"] = ["setting": "failClosed"]
    let previous = try decoder.decode(
      ExtensionStatusSnapshot.self, from: JSONSerialization.data(withJSONObject: object))
    XCTAssertEqual(previous.schemaVersion, 4)
    XCTAssertEqual(previous.deadlineMissMode, DeadlineMissModeStatus(setting: .failClosed))
    XCTAssertNil(previous.deadlineMissMode?.maximumDeadlineMilliseconds)
    XCTAssertTrue(previous.deadlineMissMode?.deniesUnansweredRequests == true)
    XCTAssertEqual(previous.retiredFolderPaths, snapshot.retiredFolderPaths)
    XCTAssertEqual(previous.targetPathMuting, snapshot.targetPathMuting)
    XCTAssertEqual(previous.uncheckedRequests, snapshot.uncheckedRequests)

    // Version 0.8.0 wrote schema 3, without any of these fields.
    object["schemaVersion"] = 3
    for key in ["retiredFolderPaths", "targetPathMuting", "deadlineMissMode", "uncheckedRequests"] {
      object.removeValue(forKey: key)
    }
    let earlier = try decoder.decode(
      ExtensionStatusSnapshot.self, from: JSONSerialization.data(withJSONObject: object))
    XCTAssertEqual(earlier.schemaVersion, 3)
    XCTAssertEqual(earlier.protectionPolicyCount, 1)
    XCTAssertNil(earlier.retiredFolderPaths)
    XCTAssertNil(earlier.targetPathMuting)
    XCTAssertNil(earlier.deadlineMissMode)
  }

  func testPolicyRequestOfThePreviousProtocolIsRejectedWithAReason() throws {
    let previous = PolicyApplyRequest.currentConfigurationProtocolVersion - 1
    let request = PolicyApplyRequest(
      policySetData: try PolicySetDocumentCodec.encode(sampleSet()),
      configurationProtocolVersion: previous)
    XCTAssertThrowsError(try PolicyApplyRequest.decode(JSONEncoder().encode(request))) { error in
      XCTAssertEqual(
        error as? PolicyApplyRequestError,
        .protocolMismatch(
          expected: PolicyApplyRequest.currentConfigurationProtocolVersion, received: previous))
      XCTAssertTrue(String(describing: error).contains("Update the Pasu FS app"))
    }
  }

  // MARK: - Helpers

  private func profiles() -> [PolicySystemCompatibilityProfile] {
    [
      PolicySystemCompatibilityProfile(
        profileIdentifier: BuiltInSystemCompatibilityCatalog.containerManagementIdentifier,
        authorizationDigest: "b91d4cb4ceb550c51d6fac3fa8ce88049c521aa79dc04b0080a890aa3770d185")
    ]
  }

  /// Three policies as version 0.8.0 stored them: one with a descendant option and a
  /// compatibility profile, one followed to a new folder, and an Audit policy.
  private func sampleSet() -> PolicySetDocument {
    PolicySetDocument(
      setIdentifier: UUID(), revision: 7,
      policies: [
        DirectoryPolicy(
          name: "Containers", mode: .protection,
          protectedRootPath: "/Users/example/Library/Containers/com.example.editor",
          allowRules: [
            .platformBinary(
              id: "editor", signingIdentifier: "com.apple.TextEdit", allowsDescendants: true)
          ],
          systemCompatibilityProfiles: profiles()),
        DirectoryPolicy(
          name: "Followed", mode: .protection, protectedRootPath: "/Users/example/Moved/Protected",
          allowRules: [
            .platformBinary(
              id: "cat", signingIdentifier: "com.apple.cat", allowsDescendants: false)
          ]),
        DirectoryPolicy(
          name: "Observed", mode: .audit, protectedRootPath: "/Users/example/Observed"),
      ])
  }

  private func sampleScopes(_ document: PolicySetDocument) -> [PersistedPolicyScope] {
    document.policies.enumerated().map { index, policy in
      PersistedPolicyScope(
        policyIdentifier: policy.id, canonicalRoot: policy.protectedRootPath,
        caseSensitive: false,
        folderIdentity: FolderIdentity(
          fileSystemID: 0x1_0000_0010, volumeUUID: "00000000-0000-0000-0000-000000000001",
          objectID: UInt64(100 + index)),
        retiredFolderPaths: index == 1
          ? [RetiredFolderPath(path: "/Users/example/Protected", caseSensitive: false)] : [])
    }
  }

  private func encode(_ document: PolicySetDocument, schemaVersion: Int) throws -> Data {
    var object = try XCTUnwrap(
      JSONSerialization.jsonObject(with: PolicySetDocumentCodec.encode(document)) as? [String: Any])
    object["schemaVersion"] = schemaVersion
    return try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
  }

  /// Rewrites a committed store as version 0.8.0 left it: both copies and the commit's emergency
  /// document in schema 4, with the digests that version computed.
  private func storeInSchemaFour(
    _ document: PolicySetDocument, scopes: [PersistedPolicyScope],
    fixture: (directory: URL, store: SecureAtomicFileStore, repository: PolicyRepository),
    damagedCopies: Int
  ) throws {
    try fixture.repository.save(document, scopes: scopes)
    let oldData = try encode(document, schemaVersion: 4)
    var commit = try readCommit(fixture)
    commit.emergencyDocument.schemaVersion = 4
    commit.digest = PolicySetDocumentCodec.digest(of: oldData)
    commit.metadataDigest = nil
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    commit.metadataDigest = PolicySetDocumentCodec.digest(of: try encoder.encode(commit))
    try fixture.store.write(
      encoder.encode(commit), to: PolicyRepository.commitFilename, mode: 0o600)
    for (index, backup) in [false, true].enumerated() {
      try fixture.store.write(
        index < damagedCopies ? Data("broken".utf8) : oldData,
        to: PolicyRepository.filename(commit.slot, backup: backup), mode: 0o600)
    }
  }

  private func readCommit(
    _ fixture: (directory: URL, store: SecureAtomicFileStore, repository: PolicyRepository)
  ) throws -> PolicyRepository.Commit {
    try JSONDecoder().decode(
      PolicyRepository.Commit.self,
      from: fixture.store.read(PolicyRepository.commitFilename, maximumSize: 1_048_576))
  }

  private func repository() throws -> (
    directory: URL, store: SecureAtomicFileStore, repository: PolicyRepository
  ) {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let store = SecureAtomicFileStore(rootDirectory: directory, requiredOwnerUserID: getuid())
    try store.prepareDirectory(mode: 0o700)
    return (directory, store, PolicyRepository(store: store))
  }
}
