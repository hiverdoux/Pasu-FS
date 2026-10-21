import Darwin
import Dispatch
import EndpointSecurity
import Foundation
import PasuFSConfiguration
import PasuFSEndpointCore
import PasuFSIPC
import PasuFSPolicy
import os

enum ExtensionRuntimeError: Error, CustomStringConvertible {
  case rootPrivilegesRequired
  case expectedHostPathMissing
  case endpointClientCreation(String)
  case endpointSubscriptionFailed
  case endpointUnsubscriptionFailed
  case targetPathRegistrationFailed
  case auditLogUnavailable

  var description: String {
    switch self {
    case .rootPrivilegesRequired:
      "The Endpoint Security system extension must run as root."
    case .expectedHostPathMissing:
      "The signed extension metadata does not contain the expected host application path."
    case .endpointClientCreation(let result):
      "es_new_client failed: \(result)."
    case .endpointSubscriptionFailed:
      "es_subscribe failed."
    case .endpointUnsubscriptionFailed:
      "es_unsubscribe_all failed."
    case .targetPathRegistrationFailed:
      "The policy folders could not be registered with Endpoint Security."
    case .auditLogUnavailable:
      "The audit log is unavailable."
    }
  }
}

/// Registers target paths with an Endpoint Security client, keeping each path's exact bytes.
private struct EndpointTargetPathMuting: TargetPathMuting, @unchecked Sendable {
  let client: OpaquePointer

  func add(_ path: TargetPathString, match: TargetPathMatch, events: [UInt32]) -> Bool {
    withArguments(path, events) { path, events, count in
      es_mute_path_events(client, path, Self.type(match), events, count) == ES_RETURN_SUCCESS
    }
  }

  func remove(_ path: TargetPathString, match: TargetPathMatch, events: [UInt32]) -> Bool {
    withArguments(path, events) { path, events, count in
      es_unmute_path_events(client, path, Self.type(match), events, count) == ES_RETURN_SUCCESS
    }
  }

  static func type(_ match: TargetPathMatch) -> es_mute_path_type_t {
    match == .prefix ? ES_MUTE_PATH_TYPE_TARGET_PREFIX : ES_MUTE_PATH_TYPE_TARGET_LITERAL
  }

  private func withArguments(
    _ path: TargetPathString, _ events: [UInt32],
    _ body: (UnsafePointer<CChar>, UnsafePointer<es_event_type_t>, Int) -> Bool
  ) -> Bool {
    let bytes = path.bytes.map { CChar(bitPattern: $0) } + [0]
    let types = events.map { es_event_type_t(rawValue: $0) }
    return bytes.withUnsafeBufferPointer { path in
      types.withUnsafeBufferPointer { events in
        body(path.baseAddress!, events.baseAddress!, events.count)
      }
    }
  }
}

private enum EndpointClientFactory {
  nonisolated static func create(
    client: inout OpaquePointer?,
    runtime: ExtensionRuntime
  ) -> es_new_client_result_t {
    es_new_client(&client) { client, message in
      runtime.handleEndpointEvent(client: client, message: message)
    }
  }
}

final class ExtensionRuntime: @unchecked Sendable {
  private static let systemCompatibilityLog = Logger(
    subsystem: "com.example.pasu.fs.endpointsecurity",
    category: "system-compatibility"
  )
  private static let folderLog = Logger(
    subsystem: "com.example.pasu.fs.endpointsecurity",
    category: "policy-folders"
  )
  private static let endpointLog = Logger(
    subsystem: "com.example.pasu.fs.endpointsecurity",
    category: "endpoint-client"
  )
  private static let storageLog = Logger(
    subsystem: "com.example.pasu.fs.endpointsecurity",
    category: "policy-storage"
  )

  private struct PreparedPolicySet {
    var policies: [EndpointPolicyConfiguration]
    var compatibilityResolution: SystemCompatibilityResolution
  }

  private let runtimeIdentifier = UUID()
  private let queue = DispatchQueue(label: "com.example.pasu.fs.extension-runtime")
  /// One administrator password dialog at a time, off the runtime queue.
  private let authorizationQueue = DispatchQueue(
    label: "com.example.pasu.fs.extension-runtime.authorization")
  private let coordinator = OSAllocatedUnfairLock<EndpointEventCoordinator?>(initialState: nil)
  private let locations: ExtensionStorageLocations
  private let rootStore: SecureAtomicFileStore
  private let policyRepository: PolicyRepository
  private let auditStore: SecureAtomicFileStore
  private let logger: PolicyAuditLogStore
  private let auditWorkBudget = AuditWorkBudget.partitioned()
  private let lineageTracker = OSAllocatedUnfairLock<ProcessLineageTracker?>(initialState: nil)
  private let systemCompatibilityCatalog: SystemCompatibilityCatalog
  private let systemCompatibilityCatalogDigest: String

  private var client: OpaquePointer?
  private var isSubscribed = false
  /// The target paths registered with `client`; nil while there is no client.
  private var targetPaths: TargetPathRegistry?
  /// What Endpoint Security does with the requests `client` doesn't answer; nil while there is no
  /// client.
  private var deadlineMissMode: DeadlineMissModeStatus?
  private let targetPathResolver = SystemTargetPathResolver()
  /// The folders and retired paths of the policies in effect, from which the registered set is
  /// computed again after each folder check.
  private var activeTargetLocations: [ProtectedPathScope] = []
  private var storedPolicySet: PolicySetDocument?
  private var policyStorageState: PolicyStorageState = .notConfigured
  private var emergencyScopes: [UUID: PersistedPolicyScope] = [:]
  /// The scopes committed with `storedPolicySet`, including each folder's identity.
  private var storedScopes: [UUID: PersistedPolicyScope] = [:]
  private let folderLocator = SystemFolderLocator()
  /// Policies whose folder could not be found or followed, from the latest folder check.
  private var folderWarning: String?
  private let folderCheckScheduled = OSAllocatedUnfairLock(initialState: false)
  private var activePolicySet: PolicySetDocument?
  private var activePolicySetDigest: String?
  private var activeSystemCompatibilityResolution = SystemCompatibilityResolution()
  /// Compatibility profiles that are turned on but inactive, from the latest prepared set.
  private var systemCompatibilityWarning: String?
  private var phase: ExtensionRuntimePhase = .starting
  private var detail: String?
  private var policyWarning: String?
  private var heartbeatTimer: DispatchSourceTimer?
  private var endpointRetryTimer: DispatchSourceTimer?
  private var signalSources: [DispatchSourceSignal] = []
  private var xpcService: ExtensionXPCService?
  /// When the client was created and first subscribed, and the latest failure to connect.
  private var endpointConnection = EndpointConnectionStatus(
    requestsEarlyBoot: Bundle.main.object(forInfoDictionaryKey: "NSEndpointSecurityEarlyBoot")
      as? Bool ?? false)
  /// The moment observation of process events began for the current client: taken before the
  /// first subscription, so that a process forked while it takes effect counts as unobserved.
  private var observationStart: Date?

  init() throws {
    guard geteuid() == 0 else {
      throw ExtensionRuntimeError.rootPrivilegesRequired
    }
    self.locations = try ExtensionStorageLocations.localSystemDefault()
    self.rootStore = SecureAtomicFileStore(
      rootDirectory: locations.rootDirectory,
      requiredOwnerUserID: 0,
      fullSynchronizationUnavailable: { operation, code in
        Self.storageLog.error(
          "\(operation, privacy: .public) is not supported (errno \(code, privacy: .public)); the policy save relies on fsync alone."
        )
      }
    )
    self.policyRepository = PolicyRepository(store: rootStore)
    self.auditStore = SecureAtomicFileStore(
      rootDirectory: locations.auditDirectory,
      requiredOwnerUserID: 0
    )
    try rootStore.prepareDirectory(mode: 0o755)
    try auditStore.prepareDirectory(mode: 0o700)
    let catalog = BuiltInSystemCompatibilityCatalog.catalog
    try catalog.validate()
    self.systemCompatibilityCatalog = catalog
    self.systemCompatibilityCatalogDigest = try catalog.catalogDigest()
    self.logger = try PolicyAuditLogStore(
      directoryURL: locations.auditDirectory,
      requiredOwnerUserID: 0,
      maximumPendingRecords: 1_024,
      maximumFileSize: 10 * 1_024 * 1_024,
      budget: auditWorkBudget
    )
  }

  func start() {
    queue.sync {
      installSignalHandlers()
      retireLegacyPolicy()
      removeRetiredSystemCompatibilitySettings()
      loadStoredPolicySet()
      // A folder moved while the extension was not running is followed before it is protected.
      reconcilePolicyFolders()
      startAuthenticatedXPC()
      startHeartbeat()
      connectEndpointSecurity()
      writeStatusSnapshot()
    }
  }

  func handshake(
    _ requestData: Data,
    reply: @escaping (Data?, NSError?) -> Void
  ) {
    let reply = XPCReplyBox(reply)
    queue.async { [self] in
      do {
        let request = try XPCJSONCodec.decode(XPCHandshakeRequest.self, from: requestData)
        let expectedProtocol = XPCHandshakeRequest.currentConfigurationProtocolVersion
        guard request.configurationProtocolVersion == expectedProtocol else {
          throw PasuFSXPCError.make(
            .invalidRequest,
            description:
              "Configuration protocol mismatch: expected \(expectedProtocol), received \(request.configurationProtocolVersion)."
          )
        }
        let response = XPCHandshakeResponse(
          nonce: request.nonce,
          runtimeInstanceIdentifier: runtimeIdentifier,
          systemCompatibilityCatalogDigest: systemCompatibilityCatalogDigest,
          supportsPolicyAuditLog: true
        )
        reply.call(try XPCJSONCodec.encode(response), nil)
      } catch {
        reply.call(nil, PasuFSXPCError.wrap(error, code: .internalFailure))
      }
    }
  }

  func applyPolicy(
    _ policyData: Data,
    reply: @escaping (Data?, NSError?) -> Void
  ) {
    let reply = XPCReplyBox(reply)
    queue.async { [self] in
      applyPolicy(policyData, authorizationVerified: false, reply: reply)
    }
  }

  /// Runs on `queue`. A change that reduces protection is verified on `authorizationQueue`,
  /// where the administrator password dialog can stay open without holding up status
  /// queries, and then comes back here; the content checks run again because the stored
  /// set may have changed meanwhile.
  private func applyPolicy(_ policyData: Data, authorizationVerified: Bool, reply: XPCReplyBox) {
    do {
      let request = try PolicyApplyRequest.decode(policyData)
      let candidate = try PolicySetDocumentCodec.decode(request.policySetData)
      let disposition = try PolicyUpdateValidator.validate(
        candidate: candidate,
        against: storedPolicySet
      )
      // Saving a policy from the app releases its retired folder paths; the other policies
      // keep theirs. A set that is not stored changes nothing.
      let retiredFolderPaths = storedRetiredFolderPaths(
        for: candidate,
        releasing: disposition == .accepted ? request.savedPolicyIdentifier : nil)
      let prepared = try preparePolicySet(candidate, retiredFolderPaths: retiredFolderPaths)
      try SystemCompatibilityResolver.validateNewlyTurnedOn(
        candidate: candidate, comparedTo: storedPolicySet,
        resolution: prepared.compatibilityResolution)
      let digest = try PolicySetDocumentCodec.digest(of: candidate)
      // Only a set that passed every content check asks the administrator for a password.
      if disposition == .accepted, !authorizationVerified,
        PolicyWeakeningAnalyzer.weakens(candidate: candidate, comparedTo: storedPolicySet)
      {
        guard let authorization = request.authorization else {
          throw PasuFSXPCError.make(
            .authorizationRequired,
            description:
              "The change reduces protection and was sent without an administrator authorization."
          )
        }
        authorizationQueue.async { [self] in
          do {
            try Self.verifyWeakeningAuthorization(authorization)
          } catch {
            reply.call(nil, PasuFSXPCError.wrap(error, code: .authorizationRequired))
            return
          }
          queue.async { [self] in
            applyPolicy(policyData, authorizationVerified: true, reply: reply)
          }
        }
        return
      }

      if disposition == .accepted {
        let scopes = persistedScopes(
          for: prepared.policies, retiredFolderPaths: retiredFolderPaths)
        try policyRepository.save(candidate, scopes: scopes)
        policyStorageState = .ready
        emergencyScopes = [:]
        storedScopes = Dictionary(
          scopes.map { ($0.policyIdentifier, $0) }, uniquingKeysWith: { a, _ in a })
        storedPolicySet = candidate
        logger.updatePolicySet(candidate)
        if client != nil {
          do {
            try activatePolicySet(
              candidate,
              prepared: prepared.policies,
              digest: digest,
              compatibilityResolution: prepared.compatibilityResolution
            )
          } catch {
            phase = .degraded
            detail =
              "Policy-set revision \(candidate.revision) was accepted but could not be activated: \(error)"
          }
        } else {
          detail =
            "Policy-set revision \(candidate.revision) is accepted but Endpoint Security is unavailable."
        }
      }

      systemCompatibilityWarning = prepared.compatibilityResolution.inactiveProfileWarning
      if disposition == .accepted { policyWarning = nil }
      writeStatusSnapshot()
      let receipt = PolicyApplyReceipt(
        result: disposition == .accepted ? .accepted : .unchanged,
        acceptedSetIdentifier: candidate.setIdentifier,
        acceptedRevision: candidate.revision,
        acceptedDigest: digest
      )
      reply.call(try XPCJSONCodec.encode(receipt), nil)
    } catch let error as NSError where Self.isAuthorizationFailure(error) {
      // The set itself was acceptable; the status keeps no warning about it.
      reply.call(nil, error)
    } catch {
      policyWarning = String(describing: error)
      writeStatusSnapshot()
      reply.call(nil, PasuFSXPCError.wrap(error, code: .policyRejected))
    }
  }

  /// Verifies the administrator authorization that a weakening change must carry. Blocks
  /// while macOS shows the password dialog, so it never runs on `queue`.
  private static func verifyWeakeningAuthorization(_ authorization: Data) throws {
    do {
      try ExternalAuthorizationVerifier.verify(authorization, grants: .policyWeaken)
    } catch ExternalAuthorizationError.canceled {
      throw PasuFSXPCError.make(
        .authorizationCanceled, description: "Administrator authentication was canceled.")
    } catch {
      throw PasuFSXPCError.make(.authorizationRequired, description: String(describing: error))
    }
  }

  private static func isAuthorizationFailure(_ error: NSError) -> Bool {
    guard error.domain == PasuFSXPCError.domain else { return false }
    switch PasuFSXPCErrorCode(rawValue: error.code) {
    case .authorizationRequired, .authorizationCanceled: return true
    default: return false
    }
  }

  func queryStatus(reply: @escaping (Data?, NSError?) -> Void) {
    let reply = XPCReplyBox(reply)
    queue.async { [self] in
      do {
        reply.call(try XPCJSONCodec.encode(makeStatusSnapshot()), nil)
      } catch {
        reply.call(nil, PasuFSXPCError.wrap(error, code: .internalFailure))
      }
    }
  }

  func queryPolicy(reply: @escaping (Data?, NSError?) -> Void) {
    let reply = XPCReplyBox(reply)
    queue.async { [self] in
      do {
        guard let storedPolicySet else {
          throw PasuFSXPCError.make(
            .invalidRequest,
            description: "No accepted policy set is stored."
          )
        }
        reply.call(try PolicySetDocumentCodec.encode(storedPolicySet), nil)
      } catch {
        reply.call(nil, PasuFSXPCError.wrap(error, code: .internalFailure))
      }
    }
  }

  func readAuditLog(
    _ requestedMaximumLineCount: Int,
    reply: @escaping (Data?, NSError?) -> Void
  ) {
    let reply = XPCReplyBox(reply)
    queue.async { [self] in
      do {
        let maximumLineCount = min(max(requestedMaximumLineCount, 1), 500)
        let batch = try logger.readAuditLog(maximumLineCount: maximumLineCount)
        reply.call(try XPCJSONCodec.encode(batch), nil)
      } catch {
        reply.call(nil, PasuFSXPCError.wrap(error, code: .internalFailure))
      }
    }
  }

  func readPolicyAuditLog(
    _ requestData: Data,
    reply: @escaping (Data?, NSError?) -> Void
  ) {
    let reply = XPCReplyBox(reply)
    queue.async { [self] in
      do {
        let request = try XPCJSONCodec.decode(PolicyAuditLogRequest.self, from: requestData)
        guard let storedPolicySet,
          storedPolicySet.setIdentifier == request.key.setIdentifier,
          storedPolicySet.policies.contains(where: { $0.id == request.key.policyIdentifier })
        else {
          throw PasuFSXPCError.make(
            .invalidRequest, description: "The requested policy is not stored.")
        }
        let batch = try logger.readPolicyAuditLog(request)
        reply.call(try XPCJSONCodec.encode(batch), nil)
      } catch {
        reply.call(nil, PasuFSXPCError.wrap(error, code: .internalFailure))
      }
    }
  }

  func handleEndpointEvent(
    client: OpaquePointer,
    message: UnsafePointer<es_message_t>
  ) {
    coordinator.withLock { $0 }?.handle(client: client, message: message)
  }

  private func startAuthenticatedXPC() {
    do {
      guard
        let expectedPath = Bundle.main.object(
          forInfoDictionaryKey: PasuFSXPC.expectedHostApplicationPathInfoKey
        ) as? String
      else {
        throw ExtensionRuntimeError.expectedHostPathMissing
      }
      let expectedRequirement = try CodeSigningRequirementResolver.designatedRequirement(
        forCodeAt: URL(fileURLWithPath: expectedPath, isDirectory: true),
        requireRootOwnedBundle: true
      )
      let helperURL = URL(fileURLWithPath: expectedPath, isDirectory: true)
        .appendingPathComponent("Contents/MacOS/pasu-fs-host", isDirectory: false)
      let helperRequirement = try CodeSigningRequirementResolver.designatedRequirement(
        forCodeAt: helperURL,
        requireRootOwnedBundle: true
      )
      let service = ExtensionXPCService(
        runtime: self,
        expectedHostRequirement: "(\(expectedRequirement)) or (\(helperRequirement))"
      )
      service.activate()
      xpcService = service
    } catch {
      policyWarning = "Authenticated XPC unavailable: \(error)"
    }
  }

  private func retireLegacyPolicy() {
    do {
      switch try LegacyPolicyRetirement.run(store: rootStore) {
      case .notFound:
        return
      case .unrecognized:
        policyWarning = "An unrecognized legacy policy file was not removed or activated."
      case .removed:
        policyWarning = "The schema v1 policy was permanently removed. Create new policies."
      }
    } catch {
      policyWarning = "The legacy policy could not be retired and was not activated: \(error)"
    }
  }

  private func loadStoredPolicySet() {
    do {
      let loaded = try policyRepository.load()
      var scopes = loaded.scopes
      if loaded.state == .migrated, let document = loaded.document {
        let committed = Dictionary(
          loaded.scopes.map { ($0.policyIdentifier, $0) }, uniquingKeysWith: { a, _ in a })
        scopes = try document.policies.map { policy in
          let scope = try ProtectedPathScope(root: policy.protectedRootPath)
          return PersistedPolicyScope(
            policyIdentifier: policy.id, canonicalRoot: scope.root,
            caseSensitive: scope.caseSensitive,
            folderIdentity: folderLocator.identity(ofFolderAt: scope.root)
              ?? committed[policy.id].flatMap {
                $0.canonicalRoot == scope.root ? $0.folderIdentity : nil
              },
            retiredFolderPaths: committed[policy.id]?.retiredPaths ?? [])
        }
        try policyRepository.save(document, scopes: scopes)
      } else if loaded.storedInEarlierSchema, let document = loaded.document {
        // Storing the unchanged set writes the current schema. If that fails, the set read
        // from the earlier schema stays in effect and the next start tries again.
        do {
          try policyRepository.save(document, scopes: scopes)
        } catch {
          Self.folderLog.error(
            "The policies could not be stored in the current schema: \(String(describing: error), privacy: .public)"
          )
        }
      }
      storedPolicySet = loaded.document
      storedScopes = Dictionary(
        scopes.map { ($0.policyIdentifier, $0) }, uniquingKeysWith: { a, _ in a })
      policyStorageState = loaded.state
      emergencyScopes = Dictionary(
        uniqueKeysWithValues: loaded.emergencyScopes.map {
          ($0.policyIdentifier, $0)
        })
      if let document = loaded.document { logger.updatePolicySet(document) }
      switch loaded.state {
      case .migrated:
        policyWarning =
          "Policy storage migrated. Review and enable descendant access for each allowed program."
      case .recovered:
        policyWarning =
          loaded.recoveryWarning
          ?? "The latest committed policy was recovered from its verified copy."
      case .denyAllRecovery:
        policyWarning =
          "Both current policy copies are unavailable. Known Protection scopes deny all access until a newer valid policy is saved."
      default:
        break
      }
    } catch {
      storedPolicySet = nil
      storedScopes = [:]
      policyStorageState = .unavailable
      policyWarning =
        "Stored policy set rejected; protected scopes could not be recovered: \(error)"
    }
  }

  /// Earlier versions kept compatibility approvals in a file of their own. Its catalog was
  /// empty, so the file could never turn a profile on; profiles are now part of each policy.
  private func removeRetiredSystemCompatibilitySettings() {
    do {
      try rootStore.remove(
        ExtensionStorageLocations.retiredSystemCompatibilitySettingsFilename, ifExists: true)
    } catch {
      Self.systemCompatibilityLog.error(
        "Retired system-compatibility settings could not be removed: \(String(describing: error), privacy: .private)"
      )
    }
  }

  private func connectEndpointSecurity() {
    guard client == nil else { return }
    phase = .starting
    detail = "Creating the Endpoint Security client."

    var newClient: OpaquePointer?
    let result = EndpointClientFactory.create(client: &newClient, runtime: self)
    guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let newClient else {
      let resultDescription = name(of: result)
      let retries =
        result == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED
        || result == ES_NEW_CLIENT_RESULT_ERR_INTERNAL
        || result == ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS
      if result == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED {
        phase = .waitingForFullDiskAccess
        detail = "Full Disk Access is required."
      } else {
        phase = .degraded
        detail = ExtensionRuntimeError.endpointClientCreation(resultDescription).description
      }
      noteConnectionFailure(
        ExtensionRuntimeError.endpointClientCreation(resultDescription).description,
        retries: retries)
      if retries { scheduleEndpointRetry() }
      writeStatusSnapshot()
      return
    }

    client = newClient
    let created = Date()
    endpointConnection.clientCreatedAt = created
    endpointConnection.clientCreatedSecondsAfterStartup = Self.secondsAfterStartup(at: created)
    Self.endpointLog.notice(
      "Endpoint Security client created \(Self.describeSecondsAfterStartup(at: created), privacy: .public)."
    )
    let deadlineMissMode = DeadlineMaximumConfiguration.apply(
      to: DeadlineMissModeConfiguration.configure(client: newClient, functions: .system()),
      client: newClient, events: FileOperationKind.subscribedEventTypes, functions: .system())
    if let error = deadlineMissMode.error {
      Self.endpointLog.error("Deadline miss mode: \(error, privacy: .public)")
    }
    if let error = deadlineMissMode.maximumDeadlineError {
      Self.endpointLog.error("Maximum deadline: \(error, privacy: .public)")
    }
    self.deadlineMissMode = deadlineMissMode
    let targetPaths = Self.prepareTargetPathSelection(client: newClient)
    self.targetPaths = targetPaths
    let tracker = ProcessLineageTracker(
      bootIdentifier: ProcessLineageTracker.currentBootIdentifier(), sink: logger,
      budget: auditWorkBudget)
    lineageTracker.withLock { $0 = tracker }

    // The stored policies, their target paths and the coordinator that decides with them are
    // ready before the first subscription, which names the process events and the policies'
    // events together. With NSEndpointSecurityEarlyBoot that subscription ends macOS's hold on
    // mounts and on programs other than Apple platform binaries, so their first requests can
    // arrive at once, and none of them meets an empty coordinator or an event not yet
    // subscribed.
    var activation: (prepared: PreparedPolicySet, digest: String)?
    var activationError: (any Error)?
    if let storedPolicySet {
      do {
        let prepared = try preparePolicySet(
          storedPolicySet, retiredFolderPaths: storedRetiredFolderPaths(for: storedPolicySet))
        let digest = try PolicySetDocumentCodec.digest(of: storedPolicySet)
        let locations = prepared.policies.flatMap { [$0.scope] + $0.retiredScopes }
        guard
          targetPaths.extend(TargetPathPlan.entries(for: locations, resolver: targetPathResolver))
        else { throw ExtensionRuntimeError.targetPathRegistrationFailed }
        activation = (prepared, digest)
      } catch {
        activationError = error
      }
    }
    let policies = activation?.prepared.policies ?? []
    let observationStart = Date()
    self.observationStart = observationStart
    coordinator.withLock {
      $0 = EndpointEventCoordinator(
        policySetIdentifier: storedPolicySet?.setIdentifier ?? runtimeIdentifier,
        policies: policies, policyRevision: storedPolicySet?.revision ?? 0, sink: logger,
        recordLifecycleEvents: true, lineageTracker: tracker, decodeFailurePolicy: .failClosed,
        observationStart: observationStart,
        protectedVolumeUnmounted: { [weak self] volume, policyNames in
          self?.noteProtectedVolumeUnmounted(volume, policyNames: policyNames)
        },
        folderMoveReported: { [weak self] in
          self?.schedulePolicyFolderCheck()
        },
        targetPaths: targetPaths)
    }
    let lifecycle = EndpointEventCoordinator.processEventTypes
    let events = EndpointEventCoordinator.firstSubscriptionEventTypes(
      withPolicies: !policies.isEmpty)
    let subscribed = events.withUnsafeBufferPointer {
      es_subscribe(newClient, $0.baseAddress!, UInt32($0.count))
    }
    guard subscribed == ES_RETURN_SUCCESS else {
      _ = es_delete_client(newClient)
      client = nil
      self.targetPaths = nil
      self.deadlineMissMode = nil
      self.observationStart = nil
      tracker.close()
      coordinator.withLock { $0 = nil }
      phase = .degraded
      detail = "Process history event subscription failed."
      noteConnectionFailure(
        "es_subscribe failed for \(events.count) event types; the client was deleted.",
        retries: true)
      scheduleEndpointRetry()
      writeStatusSnapshot()
      return
    }
    isSubscribed = !policies.isEmpty
    noteSubscription(eventCount: events.count, includesPolicyEvents: !policies.isEmpty)
    inspectLifecycleExclusions(client: newClient, tracker: tracker, lifecycle: lifecycle)
    cancelEndpointRetry()
    guard let storedPolicySet else {
      phase = .degraded
      detail = "No accepted policy set is stored."
      writeStatusSnapshot()
      return
    }

    do {
      if let activationError { throw activationError }
      if let activation {
        // Already in effect; this records the set as active and keeps the registered paths.
        try activatePolicySet(
          storedPolicySet,
          prepared: activation.prepared.policies,
          digest: activation.digest,
          compatibilityResolution: activation.prepared.compatibilityResolution
        )
      }
    } catch {
      phase = .degraded
      detail = "Stored policy set could not be activated: \(error)"
    }
    writeStatusSnapshot()
  }

  /// Records the first successful subscription of this run. Until it, an early-boot hold lasts.
  private func noteSubscription(eventCount: Int, includesPolicyEvents: Bool) {
    guard endpointConnection.firstSubscriptionAt == nil else { return }
    let subscribedAt = Date()
    endpointConnection.firstSubscriptionAt = subscribedAt
    endpointConnection.firstSubscriptionSecondsAfterStartup = Self.secondsAfterStartup(
      at: subscribedAt)
    endpointConnection.firstSubscriptionEventCount = eventCount
    endpointConnection.firstSubscriptionIncludesPolicyEvents = includesPolicyEvents
    let scope = includesPolicyEvents ? "process and policy events" : "process events only"
    let hold =
      endpointConnection.requestsEarlyBoot
      ? " At startup, macOS holds mounts and programs other than Apple platform binaries until this first subscription."
      : ""
    Self.endpointLog.notice(
      "First subscription: \(eventCount, privacy: .public) event types (\(scope, privacy: .public)) \(Self.describeSecondsAfterStartup(at: subscribedAt), privacy: .public).\(hold, privacy: .public)"
    )
  }

  /// Logs a failure to create a client or to subscribe, and keeps it for the status.
  private func noteConnectionFailure(_ failure: String, retries: Bool) {
    endpointConnection.lastFailure = failure
    endpointConnection.lastFailureAt = Date()
    let next =
      retries ? "Trying again every 10 seconds." : "Not trying again until the extension restarts."
    // Before the first subscription, an early-boot hold lasts until macOS's own timeout.
    let hold =
      endpointConnection.requestsEarlyBoot && endpointConnection.firstSubscriptionAt == nil
      ? " No subscription has succeeded yet: at startup, macOS keeps holding mounts and programs other than Apple platform binaries until its early-boot timeout ends the hold."
      : ""
    Self.endpointLog.error(
      "\(failure, privacy: .public) \(next, privacy: .public)\(hold, privacy: .public)")
  }

  /// Seconds from the start of the Mac to `date`, from `kern.boottime`, which macOS moves along
  /// when it sets the clock; nil when it can't be read.
  private static func secondsAfterStartup(at date: Date) -> Double? {
    var boot = timeval()
    var size = MemoryLayout<timeval>.size
    guard sysctlbyname("kern.boottime", &boot, &size, nil, 0) == 0, boot.tv_sec > 0 else {
      return nil
    }
    let started = Double(boot.tv_sec) + Double(boot.tv_usec) / 1_000_000
    return date.timeIntervalSince1970 - started
  }

  private static func describeSecondsAfterStartup(at date: Date) -> String {
    guard let seconds = secondsAfterStartup(at: date) else { return "at an unknown time" }
    return String(format: "%.3f s after startup", seconds)
  }

  /// Sets up target path selection on a new client before anything is subscribed, in the order
  /// Endpoint Security requires: the target paths muted by default are removed, target path
  /// muting is inverted, and process starts are registered for every path. The process mutes
  /// macOS sets by default stay in place. If a step fails, muting is left or put back as it was
  /// and every request is delivered.
  private static func prepareTargetPathSelection(client: OpaquePointer) -> TargetPathRegistry {
    guard es_unmute_all_target_paths(client) == ES_RETURN_SUCCESS else {
      return TargetPathRegistry(notInvertedBecause: "es_unmute_all_target_paths failed.")
    }
    let inverted = es_invert_muting(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH)
    switch es_muting_inverted(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH) {
    case ES_MUTE_INVERTED:
      break
    case ES_MUTE_NOT_INVERTED:
      return TargetPathRegistry(notInvertedBecause: "es_invert_muting failed.")
    default:
      guard inverted == ES_RETURN_SUCCESS else {
        return TargetPathRegistry(notInvertedBecause: "es_invert_muting failed.")
      }
    }
    let registry = TargetPathRegistry(muting: EndpointTargetPathMuting(client: client))
    guard registry.deliversProcessStarts else {
      // Nothing is subscribed yet, so inverting again restores ordinary muting safely.
      _ = es_invert_muting(client, ES_MUTE_INVERSION_TYPE_TARGET_PATH)
      _ = es_unmute_all_target_paths(client)
      return TargetPathRegistry(
        notInvertedBecause: "Process starts could not be registered with Endpoint Security.")
    }
    return registry
  }

  /// The target path entries the client reports, or nil when they can't be read.
  private func kernelTargetPathEntries() -> Set<TargetPathEntry>? {
    guard let client else { return nil }
    let output = UnsafeMutablePointer<UnsafeMutablePointer<es_muted_paths_t>>.allocate(capacity: 1)
    defer { output.deallocate() }
    guard es_muted_paths_events(client, output) == ES_RETURN_SUCCESS else { return nil }
    let muted = output.pointee
    defer { es_release_muted_paths(muted) }
    var entries = Set<TargetPathEntry>()
    for path in UnsafeBufferPointer(start: muted.pointee.paths, count: muted.pointee.count) {
      let match: TargetPathMatch
      switch path.type {
      case ES_MUTE_PATH_TYPE_TARGET_PREFIX: match = .prefix
      case ES_MUTE_PATH_TYPE_TARGET_LITERAL: match = .literal
      default: continue
      }
      let bytes =
        path.path.data.map {
          Array(UnsafeRawBufferPointer(start: $0, count: path.path.length))
        } ?? []
      for event in UnsafeBufferPointer(start: path.events, count: path.event_count) {
        entries.insert(
          TargetPathEntry(
            path: TargetPathString(bytes: bytes), match: match, eventType: event.rawValue))
      }
    }
    return entries
  }

  /// Registers the spellings that the policy folders, retired paths and the folders on the way
  /// to them have now, and compares the registered set with the client's. Runs after every
  /// folder check, before pending moves are withdrawn.
  private func refreshTargetPaths() {
    guard let targetPaths, targetPaths.isInverted else { return }
    targetPaths.settle(
      TargetPathPlan.entries(for: activeTargetLocations, resolver: targetPathResolver))
    let registered = targetPaths.registeredEntries
    if let kernel = kernelTargetPathEntries() {
      targetPaths.verify(kernelEntries: kernel, registeredBefore: registered)
    }
  }

  /// - Parameter retiredFolderPaths: The retired folder paths of each policy, which the prepared
  ///   policies keep reserved.
  private func preparePolicySet(
    _ policySet: PolicySetDocument, retiredFolderPaths: [UUID: [RetiredFolderPath]]
  ) throws -> PreparedPolicySet {
    try policySet.validate()
    let compatibilityResolution = try SystemCompatibilityResolver.resolve(
      policySet: policySet,
      catalog: systemCompatibilityCatalog
    )
    let storedPaths = Dictionary(
      (storedPolicySet?.policies ?? []).map { ($0.id, $0.protectedRootPath) },
      uniquingKeysWith: { a, _ in a })
    let policies = try policySet.policies.map { policy in
      let scope: ProtectedPathScope
      if policyStorageState == .denyAllRecovery, let saved = emergencyScopes[policy.id],
        policySet == storedPolicySet
      {
        scope = ProtectedPathScope(recovering: saved)
      } else {
        do {
          scope = try ProtectedPathScope(root: policy.protectedRootPath)
        } catch let error as ProtectedPathScopeError {
          // A stored policy whose folder is gone, or is no longer a folder, keeps denying at
          // the path it was accepted for. A new or changed folder must exist.
          guard Self.isMissingFolder(error), let saved = storedScopes[policy.id],
            storedPaths[policy.id] == policy.protectedRootPath
          else { throw error }
          scope = ProtectedPathScope(recovering: saved)
        }
      }
      return EndpointPolicyConfiguration(
        id: policy.id,
        name: policy.name,
        mode: policy.mode,
        policyType: policy.policyType,
        scope: scope,
        rules: try policy.policySnapshot(),
        executionOriginPolicy: try policy.executionOriginSnapshot(),
        systemCompatibilityProfiles:
          compatibilityResolution.activeProfilesByPolicy[policy.id] ?? [],
        retiredScopes: (retiredFolderPaths[policy.id] ?? []).map(ProtectedPathScope.init(retired:))
      )
    }
    return PreparedPolicySet(
      policies: policies,
      compatibilityResolution: compatibilityResolution
    )
  }

  private func activatePolicySet(
    _ policySet: PolicySetDocument,
    prepared: [EndpointPolicyConfiguration],
    digest: String,
    compatibilityResolution: SystemCompatibilityResolution
  ) throws {
    // The new policies' paths are registered before the policies take effect, and the paths
    // only the previous policies needed are removed after.
    let locations = prepared.flatMap { [$0.scope] + $0.retiredScopes }
    let targetPathEntries = TargetPathPlan.entries(for: locations, resolver: targetPathResolver)
    if let targetPaths, !targetPaths.extend(targetPathEntries) {
      throw ExtensionRuntimeError.targetPathRegistrationFailed
    }
    if prepared.isEmpty {
      try stopCoordinatingEmptyPolicySet(
        setIdentifier: policySet.setIdentifier,
        revision: policySet.revision
      )
    } else if let existingCoordinator = coordinator.withLock({ $0 }) {
      existingCoordinator.replacePolicySet(
        setIdentifier: policySet.setIdentifier,
        policies: prepared,
        revision: policySet.revision
      )
    } else {
      let newCoordinator = EndpointEventCoordinator(
        policySetIdentifier: policySet.setIdentifier,
        policies: prepared,
        policyRevision: policySet.revision,
        sink: logger,
        recordLifecycleEvents: true,
        lineageTracker: lineageTracker.withLock { $0 },
        decodeFailurePolicy: .failClosed,
        observationStart: observationStart,
        protectedVolumeUnmounted: { [weak self] volume, policyNames in
          self?.noteProtectedVolumeUnmounted(volume, policyNames: policyNames)
        },
        folderMoveReported: { [weak self] in
          self?.schedulePolicyFolderCheck()
        },
        targetPaths: targetPaths
      )
      coordinator.withLock { $0 = newCoordinator }
      do {
        try subscribeIfNeeded()
      } catch {
        coordinator.withLock { $0 = nil }
        throw error
      }
    }

    if !prepared.isEmpty { try subscribeIfNeeded() }
    activeTargetLocations = locations
    targetPaths?.settle(targetPathEntries)

    activePolicySet = policySet
    activePolicySetDigest = digest
    activeSystemCompatibilityResolution = compatibilityResolution
    systemCompatibilityWarning = compatibilityResolution.inactiveProfileWarning
    if policyStorageState == .denyAllRecovery {
      phase = .degraded
      detail =
        "Recovery protection denies access in known Protection scopes until a newer valid policy is saved."
    } else if policySet.policies.isEmpty {
      phase = .idle
      detail = "No file policies configured. Process history tracking is active."
    } else if policySet.policies.contains(where: { $0.mode == .protection }) {
      phase = .enforcing
      detail = "Enforcing Protection policies and monitoring Audit policies for file requests."
    } else {
      phase = .monitoring
      detail = "Monitoring Audit policies for file requests; kernel requests are allowed."
    }
  }

  private func stopCoordinatingEmptyPolicySet(
    setIdentifier: UUID,
    revision: UInt64
  ) throws {
    coordinator.withLock { coordinator in
      coordinator?.replacePolicySet(
        setIdentifier: setIdentifier,
        policies: [],
        revision: revision
      )
    }
    guard isSubscribed else { return }
    guard let client else { throw ExtensionRuntimeError.endpointUnsubscriptionFailed }
    let events = Self.policyEventTypes
    let unsubscribed = events.withUnsafeBufferPointer {
      es_unsubscribe(client, $0.baseAddress!, UInt32($0.count))
    }
    guard unsubscribed == ES_RETURN_SUCCESS else {
      throw ExtensionRuntimeError.endpointUnsubscriptionFailed
    }
    isSubscribed = false
  }

  private func subscribeIfNeeded() throws {
    guard !isSubscribed else { return }
    guard let client else {
      throw ExtensionRuntimeError.endpointClientCreation("client unavailable")
    }
    let events = Self.policyEventTypes
    let subscribed = events.withUnsafeBufferPointer {
      es_subscribe(client, $0.baseAddress!, UInt32($0.count))
    }
    guard subscribed == ES_RETURN_SUCCESS else {
      throw ExtensionRuntimeError.endpointSubscriptionFailed
    }
    isSubscribed = true
  }

  private static var policyEventTypes: [es_event_type_t] {
    EndpointEventCoordinator.policyEventTypes
  }

  private static func isMissingFolder(_ error: ProtectedPathScopeError) -> Bool {
    switch error {
    case .pathDoesNotExist, .pathIsNotDirectory: true
    default: false
    }
  }

  /// The scopes to commit with a policy set that was just prepared, each with the identity of
  /// the folder now at its path. A folder that can't be read keeps the identity stored for the
  /// same path, so it can still be found when it returns.
  private func persistedScopes(
    for policies: [EndpointPolicyConfiguration], retiredFolderPaths: [UUID: [RetiredFolderPath]]
  ) -> [PersistedPolicyScope] {
    policies.map { policy in
      let previous = storedScopes[policy.id]
      return PersistedPolicyScope(
        policyIdentifier: policy.id, canonicalRoot: policy.scope.root,
        caseSensitive: policy.scope.caseSensitive,
        folderIdentity: folderLocator.identity(ofFolderAt: policy.scope.root)
          ?? (previous?.canonicalRoot == policy.scope.root ? previous?.folderIdentity : nil),
        retiredFolderPaths: retiredFolderPaths[policy.id] ?? [])
    }
  }

  /// The stored retired folder paths of the policies in `policySet`, except those of
  /// `releasing`, the policy the user saved.
  private func storedRetiredFolderPaths(
    for policySet: PolicySetDocument, releasing: UUID? = nil
  ) -> [UUID: [RetiredFolderPath]] {
    PersistedPolicyScope.retiredFolderPaths(
      in: Array(storedScopes.values), keptBy: policySet, releasing: releasing)
  }

  /// Runs one folder check soon, once however many renames were reported meanwhile.
  private func schedulePolicyFolderCheck() {
    let alreadyScheduled = folderCheckScheduled.withLock { scheduled -> Bool in
      defer { scheduled = true }
      return scheduled
    }
    guard !alreadyScheduled else { return }
    queue.async { [self] in
      folderCheckScheduled.withLock { $0 = false }
      reconcilePolicyFolders()
      writeStatusSnapshot()
    }
  }

  /// Compares every policy folder with its stored identity. A folder found at another path is
  /// followed: the policy set is stored as a new revision naming the new path, then the new
  /// locations protected since the rename are withdrawn. A folder that can't be found keeps
  /// its old path denied and is reported in the status. Runs on `queue`.
  private func reconcilePolicyFolders() {
    guard let storedPolicySet,
      [.ready, .recovered, .migrated].contains(policyStorageState)
    else {
      folderWarning = nil
      refreshTargetPaths()
      return
    }
    let activeCoordinator = coordinator.withLock { $0 }
    let result = PolicyFolderReconciler.reconcile(
      policySet: storedPolicySet,
      scopes: storedPolicySet.policies.compactMap { storedScopes[$0.id] },
      pendingMoves: activeCoordinator?.pendingFolderMoves ?? [],
      now: DispatchTime.now().uptimeNanoseconds,
      locator: folderLocator,
      prepareScope: { try ProtectedPathScope(root: $0) })
    do {
      if let followed = result.policySet {
        try storeFollowedFolders(followed, scopes: result.scopes)
        for folder in result.followed {
          Self.folderLog.notice(
            "Policy \(folder.policyIdentifier.uuidString, privacy: .public) followed its folder to a new path; revision \(followed.revision, privacy: .public)."
          )
        }
      } else if result.scopesChanged {
        try policyRepository.updateScopes(result.scopes)
        storedScopes = Dictionary(
          result.scopes.map { ($0.policyIdentifier, $0) }, uniquingKeysWith: { a, _ in a })
      }
      refreshTargetPaths()
      // The new locations are withdrawn only once the policies in effect name the moved folders.
      if activePolicySet == self.storedPolicySet {
        activeCoordinator?.withdrawPendingFolderMoves(result.settledMoves)
      }
      folderWarning = result.warning
    } catch {
      refreshTargetPaths()
      // Nothing is withdrawn: the new locations stay protected until a later check succeeds.
      let lines =
        result.followed.map {
          "Protected folder moved but not followed: \($0.currentPath) (\($0.policyName)): \(error)"
        } + (result.warning.map { [$0] } ?? [])
      folderWarning =
        lines.isEmpty ? "Protected folder check failed: \(error)" : lines.joined(separator: "\n")
    }
  }

  /// Stores and applies a policy set whose only change is the path of folders that moved. The
  /// protection is the same, so no administrator authorization is involved.
  private func storeFollowedFolders(
    _ followed: PolicySetDocument, scopes: [PersistedPolicyScope]
  ) throws {
    try followed.validate()
    // A followed folder exists at its new path; a policy whose folder is missing keeps its
    // path, so the stored scopes still describe it. Following is not a save from the app, so
    // every retired folder path is kept, now with the paths the folders just left.
    let prepared = try preparePolicySet(
      followed,
      retiredFolderPaths: Dictionary(
        scopes.map { ($0.policyIdentifier, $0.retiredPaths) }, uniquingKeysWith: { a, _ in a }))
    let digest = try PolicySetDocumentCodec.digest(of: followed)
    try policyRepository.save(followed, scopes: scopes)
    storedScopes = Dictionary(
      scopes.map { ($0.policyIdentifier, $0) }, uniquingKeysWith: { a, _ in a })
    storedPolicySet = followed
    logger.updatePolicySet(followed)
    if client != nil {
      do {
        try activatePolicySet(
          followed,
          prepared: prepared.policies,
          digest: digest,
          compatibilityResolution: prepared.compatibilityResolution
        )
      } catch {
        phase = .degraded
        detail =
          "Policy-set revision \(followed.revision) was accepted but could not be activated: \(error)"
        throw error
      }
    }
  }

  /// The folder of a policy went away with the volume it was on, or a volume that had been
  /// mounted over it was removed. The status keeps the notice until the next policy save.
  private func noteProtectedVolumeUnmounted(_ volume: MountedVolume, policyNames: [String]) {
    queue.async {
      self.policyWarning =
        "Protected volume unmounted: \(volume.mountPoint) (\(policyNames.joined(separator: ", ")))"
      self.writeStatusSnapshot()
    }
  }

  private func inspectLifecycleExclusions(
    client: OpaquePointer, tracker: ProcessLineageTracker, lifecycle: [es_event_type_t]
  ) {
    let output = UnsafeMutablePointer<UnsafeMutablePointer<es_muted_paths_t>>.allocate(capacity: 1)
    defer { output.deallocate() }
    guard es_muted_paths_events(client, output) == ES_RETURN_SUCCESS else {
      tracker.note("muteInspectionFailed")
      return
    }
    let muted = output.pointee
    defer { es_release_muted_paths(muted) }
    // Only process mutes exclude a process from the histories; the target paths registered for
    // process starts select them.
    for path in UnsafeBufferPointer(start: muted.pointee.paths, count: muted.pointee.count)
    where path.type == ES_MUTE_PATH_TYPE_PREFIX || path.type == ES_MUTE_PATH_TYPE_LITERAL {
      if UnsafeBufferPointer(start: path.events, count: path.event_count).contains(where: {
        lifecycle.contains($0)
      }) {
        tracker.note("mutedLifecycle")
        return
      }
    }
  }

  private func startHeartbeat() {
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + 5, repeating: 5)
    timer.setEventHandler { [weak self] in
      self?.reconcilePolicyFolders()
      self?.writeStatusSnapshot()
    }
    timer.activate()
    heartbeatTimer = timer
  }

  private func scheduleEndpointRetry() {
    guard endpointRetryTimer == nil else { return }
    let timer = DispatchSource.makeTimerSource(queue: queue)
    timer.schedule(deadline: .now() + 10, repeating: 10)
    timer.setEventHandler { [weak self] in
      self?.connectEndpointSecurity()
    }
    timer.activate()
    endpointRetryTimer = timer
  }

  private func cancelEndpointRetry() {
    endpointRetryTimer?.cancel()
    endpointRetryTimer = nil
  }

  private func makeStatusSnapshot() -> ExtensionStatusSnapshot {
    let protectionPolicyCount =
      activePolicySet?.policies.lazy.filter { $0.mode == .protection }.count ?? 0
    let auditPolicyCount =
      activePolicySet?.policies.lazy.filter { $0.mode == .audit }.count ?? 0
    let activeCoordinator = coordinator.withLock { $0 }
    // A stretch of dropped messages counts once its window has ended.
    activeCoordinator?.finishDeliveryGaps()
    return ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: runtimeIdentifier,
      phase: phase,
      activePolicySetIdentifier: activePolicySet?.setIdentifier,
      activePolicyRevision: activePolicySet?.revision,
      activePolicyDigest: activePolicySetDigest,
      systemCompatibilityCatalogDigest: systemCompatibilityCatalogDigest,
      activeSystemCompatibilityProfileCount: activeSystemCompatibilityResolution.activeProfileCount,
      systemCompatibilityWarning: systemCompatibilityWarning,
      protectionPolicyCount: protectionPolicyCount,
      auditPolicyCount: auditPolicyCount,
      policyWarning: Self.combinedWarning(
        [policyWarning ?? logger.lastErrorDescription, folderWarning]),
      detail: detail,
      coveredAuthorizationEvents: isSubscribed ? AuthorizationEventCatalog.supportedEventNames : [],
      processLineageStatus: lineageTracker.withLock { $0?.status },
      droppedAuditEventCount: logger.droppedEventCount,
      auditDelivery: logger.deliveryMetrics,
      authorization: activeCoordinator?.authorizationMetrics,
      uncheckedRequests: activeCoordinator?.uncheckedRequestMetrics,
      executionOriginStatus: activeCoordinator?.executionOriginStatus,
      policyStorageState: policyStorageState,
      executionOriginCapabilities: ExecutionOriginCapabilities(),
      retiredFolderPaths: (storedPolicySet?.policies ?? []).compactMap { policy in
        guard let paths = storedScopes[policy.id]?.retiredPaths, !paths.isEmpty else { return nil }
        return PolicyRetiredFolderPaths(policyIdentifier: policy.id, paths: paths.map(\.path))
      },
      targetPathMuting: targetPaths?.status(kernelEntries: kernelTargetPathEntries()),
      deadlineMissMode: deadlineMissMode,
      extensionVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString")
        as? String,
      extensionBuildVersion: Bundle.main.object(forInfoDictionaryKey: "CFBundleVersion") as? String,
      endpointConnection: endpointConnection
    )
  }

  /// Separate warnings on their own lines; the app translates each line.
  private static func combinedWarning(_ warnings: [String?]) -> String? {
    let lines = warnings.compactMap { $0 }.filter { !$0.isEmpty }
    return lines.isEmpty ? nil : lines.joined(separator: "\n")
  }

  private func writeStatusSnapshot() {
    do {
      try rootStore.write(
        XPCJSONCodec.encode(makeStatusSnapshot()),
        to: "status.json",
        mode: 0o644
      )
    } catch {
      policyWarning = "Status persistence failed: \(error)"
    }
  }

  private func installSignalHandlers() {
    for signalNumber in [SIGINT, SIGTERM] {
      signal(signalNumber, SIG_IGN)
      let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: queue)
      source.setEventHandler { [weak self] in
        self?.stop(exitCode: EXIT_SUCCESS)
      }
      source.activate()
      signalSources.append(source)
    }
  }

  private func stop(exitCode: Int32) -> Never {
    heartbeatTimer?.cancel()
    cancelEndpointRetry()
    if let client {
      _ = es_unsubscribe_all(client)
      _ = es_delete_client(client)
      self.client = nil
    }
    targetPaths = nil
    deadlineMissMode = nil
    observationStart = nil
    isSubscribed = false
    coordinator.withLock { $0 }?.finishDeliveryGaps(force: true)
    coordinator.withLock { $0 = nil }
    lineageTracker.withLock { $0 }?.close()
    phase = .stopped
    detail = "Endpoint Security client stopped."
    writeStatusSnapshot()
    xpcService?.invalidate()
    logger.flushAndClose()
    exit(exitCode)
  }

  private func name(of result: es_new_client_result_t) -> String {
    switch result {
    case ES_NEW_CLIENT_RESULT_SUCCESS: "SUCCESS"
    case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: "ERR_INVALID_ARGUMENT"
    case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: "ERR_INTERNAL"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: "ERR_NOT_ENTITLED"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: "ERR_NOT_PERMITTED"
    case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: "ERR_NOT_PRIVILEGED"
    case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: "ERR_TOO_MANY_CLIENTS"
    default: "UNKNOWN(\(result.rawValue))"
    }
  }
}

private final class XPCReplyBox: @unchecked Sendable {
  private let reply: (Data?, NSError?) -> Void

  init(_ reply: @escaping (Data?, NSError?) -> Void) {
    self.reply = reply
  }

  func call(_ data: Data?, _ error: NSError?) {
    reply(data, error)
  }
}
