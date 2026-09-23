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
    case .auditLogUnavailable:
      "The audit log is unavailable."
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

  private struct PreparedPolicySet {
    var policies: [EndpointPolicyConfiguration]
    var compatibilityResolution: SystemCompatibilityResolution
  }

  private let runtimeIdentifier = UUID()
  private let queue = DispatchQueue(label: "com.example.pasu.fs.extension-runtime")
  private let coordinator = OSAllocatedUnfairLock<EndpointEventCoordinator?>(initialState: nil)
  private let locations: ExtensionStorageLocations
  private let rootStore: SecureAtomicFileStore
  private let auditStore: SecureAtomicFileStore
  private let logger: PolicyAuditLogStore
  private let auditWorkBudget = AuditWorkBudget.partitioned()
  private let lineageTracker = OSAllocatedUnfairLock<ProcessLineageTracker?>(initialState: nil)
  private let systemCompatibilityCatalog: SystemCompatibilityCatalog
  private let systemCompatibilityCatalogDigest: String

  private var client: OpaquePointer?
  private var isSubscribed = false
  private var storedPolicySet: PolicySetDocument?
  private var storedSystemCompatibilitySettings: SystemCompatibilitySettingsDocument?
  private var storedSystemCompatibilitySettingsDigest: String?
  private var activePolicySet: PolicySetDocument?
  private var activePolicySetDigest: String?
  private var activeSystemCompatibilityResolution = SystemCompatibilityResolution()
  private var systemCompatibilityWarnings = SystemCompatibilityWarningState()
  private var phase: ExtensionRuntimePhase = .starting
  private var detail: String?
  private var policyWarning: String?
  private var heartbeatTimer: DispatchSourceTimer?
  private var endpointRetryTimer: DispatchSourceTimer?
  private var signalSources: [DispatchSourceSignal] = []
  private var xpcService: ExtensionXPCService?

  init() throws {
    guard geteuid() == 0 else {
      throw ExtensionRuntimeError.rootPrivilegesRequired
    }
    self.locations = try ExtensionStorageLocations.localSystemDefault()
    self.rootStore = SecureAtomicFileStore(
      rootDirectory: locations.rootDirectory,
      requiredOwnerUserID: 0
    )
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
      loadStoredPolicySet()
      loadStoredSystemCompatibilitySettings()
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
      do {
        let candidate = try PolicySetDocumentCodec.decode(policyData)
        let disposition = try PolicyUpdateValidator.validate(
          candidate: candidate,
          against: storedPolicySet
        )
        let prepared = try preparePolicySet(
          candidate,
          compatibilitySettings: storedSystemCompatibilitySettings
        )
        let canonicalData = try PolicySetDocumentCodec.encode(candidate)
        let digest = try PolicySetDocumentCodec.digest(of: candidate)

        if disposition == .accepted {
          try rootStore.write(
            canonicalData,
            to: ExtensionStorageLocations.policySetFilename,
            mode: 0o600
          )
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

        systemCompatibilityWarnings.replaceResolutionWarning(
          warning(for: prepared.compatibilityResolution.profileResolutions)
        )
        policyWarning = nil
        writeStatusSnapshot()
        let receipt = PolicyApplyReceipt(
          result: disposition == .accepted ? .accepted : .unchanged,
          acceptedSetIdentifier: candidate.setIdentifier,
          acceptedRevision: candidate.revision,
          acceptedDigest: digest
        )
        reply.call(try XPCJSONCodec.encode(receipt), nil)
      } catch {
        policyWarning = String(describing: error)
        writeStatusSnapshot()
        reply.call(nil, PasuFSXPCError.wrap(error, code: .policyRejected))
      }
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

  func applySystemCompatibilitySettings(
    _ settingsData: Data,
    reply: @escaping (Data?, NSError?) -> Void
  ) {
    let reply = XPCReplyBox(reply)
    queue.async { [self] in
      do {
        guard let storedPolicySet else {
          throw PasuFSXPCError.make(
            .invalidRequest,
            description: "No accepted policy set is available for system-compatibility settings."
          )
        }
        guard settingsData.count <= SystemCompatibilitySettingsApplyRequest.maximumEncodedSize
        else {
          throw PasuFSXPCError.make(
            .invalidRequest,
            description: "System-compatibility settings apply request is too large."
          )
        }
        let request = try XPCJSONCodec.decode(
          SystemCompatibilitySettingsApplyRequest.self,
          from: settingsData
        )
        guard SystemCompatibilityDigest.isCanonicalSHA256(request.catalogDigest),
          request.catalogDigest == systemCompatibilityCatalogDigest
        else {
          throw PasuFSXPCError.make(
            .invalidRequest,
            description:
              "System-compatibility settings cannot be edited while the host and extension catalogs differ."
          )
        }
        let candidate = try SystemCompatibilitySettingsCodec.decode(request.settingsData)
        let comparableStoredSettings = storedSystemCompatibilitySettings.flatMap {
          $0.policySetIdentifier == storedPolicySet.setIdentifier ? $0 : nil
        }
        let disposition = try SystemCompatibilitySettingsUpdateValidator.validate(
          candidate: candidate,
          against: comparableStoredSettings
        )
        try SystemCompatibilityResolver.validateForApply(
          candidate,
          against: comparableStoredSettings,
          policySet: storedPolicySet,
          catalog: systemCompatibilityCatalog
        )
        let prepared = try preparePolicySet(
          storedPolicySet,
          compatibilitySettings: candidate
        )
        let canonicalData = try SystemCompatibilitySettingsCodec.encode(candidate)
        let digest = try SystemCompatibilitySettingsCodec.digest(of: candidate)

        if disposition == .accepted {
          try rootStore.write(
            canonicalData,
            to: ExtensionStorageLocations.systemCompatibilitySettingsFilename,
            mode: 0o600
          )
          storedSystemCompatibilitySettings = candidate
          storedSystemCompatibilitySettingsDigest = digest
          systemCompatibilityWarnings.clearStorageWarning()
          if client != nil {
            let policyDigest = try PolicySetDocumentCodec.digest(of: storedPolicySet)
            try activatePolicySet(
              storedPolicySet,
              prepared: prepared.policies,
              digest: policyDigest,
              compatibilityResolution: prepared.compatibilityResolution
            )
          }
        }

        systemCompatibilityWarnings.replaceResolutionWarning(
          warning(for: prepared.compatibilityResolution.profileResolutions)
        )
        writeStatusSnapshot()
        let receipt = SystemCompatibilitySettingsApplyReceipt(
          result: disposition == .accepted ? .accepted : .unchanged,
          acceptedSettingsIdentifier: candidate.settingsIdentifier,
          acceptedRevision: candidate.revision,
          acceptedDigest: digest
        )
        reply.call(try XPCJSONCodec.encode(receipt), nil)
      } catch {
        reply.call(
          nil,
          PasuFSXPCError.wrap(error, code: .systemCompatibilitySettingsRejected)
        )
      }
    }
  }

  func querySystemCompatibilityState(
    reply: @escaping (Data?, NSError?) -> Void
  ) {
    let reply = XPCReplyBox(reply)
    queue.async { [self] in
      do {
        let resolutions: [SystemCompatibilityProfileResolution]
        if let storedPolicySet {
          resolutions = try SystemCompatibilityResolver.resolve(
            settings: storedSystemCompatibilitySettings,
            policySet: storedPolicySet,
            catalog: systemCompatibilityCatalog
          ).profileResolutions
        } else {
          resolutions = []
        }
        let snapshot = SystemCompatibilityStateSnapshot(
          catalogDigest: systemCompatibilityCatalogDigest,
          settings: storedSystemCompatibilitySettings,
          settingsDigest: storedSystemCompatibilitySettingsDigest,
          profileResolutions: resolutions
        )
        reply.call(try XPCJSONCodec.encode(snapshot), nil)
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
      let data = try rootStore.read(
        ExtensionStorageLocations.policySetFilename,
        maximumSize: PolicySetDocumentCodec.maximumDocumentSize
      )
      let document = try PolicySetDocumentCodec.decode(data)
      storedPolicySet = document
      logger.updatePolicySet(document)
    } catch SecureFileStoreError.fileNotFound {
      storedPolicySet = nil
    } catch {
      storedPolicySet = nil
      policyWarning = "Stored policy set rejected: \(error)"
    }
  }

  private func loadStoredSystemCompatibilitySettings() {
    do {
      let data = try rootStore.read(
        ExtensionStorageLocations.systemCompatibilitySettingsFilename,
        maximumSize: SystemCompatibilitySettingsCodec.maximumDocumentSize
      )
      let settings = try SystemCompatibilitySettingsCodec.decode(data)
      storedSystemCompatibilitySettings = settings
      storedSystemCompatibilitySettingsDigest =
        try SystemCompatibilitySettingsCodec.digest(of: settings)
      systemCompatibilityWarnings.clearStorageWarning()
    } catch SecureFileStoreError.fileNotFound {
      storedSystemCompatibilitySettings = nil
      storedSystemCompatibilitySettingsDigest = nil
      systemCompatibilityWarnings.clearStorageWarning()
    } catch {
      storedSystemCompatibilitySettings = nil
      storedSystemCompatibilitySettingsDigest = nil
      Self.systemCompatibilityLog.error(
        "Stored system-compatibility settings were rejected: \(String(describing: error), privacy: .private)"
      )
      systemCompatibilityWarnings.recordStorageRejection()
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
      if result == ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED {
        phase = .waitingForFullDiskAccess
        detail = "Full Disk Access is required."
        scheduleEndpointRetry()
      } else {
        phase = .degraded
        detail = ExtensionRuntimeError.endpointClientCreation(resultDescription).description
        if result == ES_NEW_CLIENT_RESULT_ERR_INTERNAL
          || result == ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS
        {
          scheduleEndpointRetry()
        }
      }
      writeStatusSnapshot()
      return
    }

    client = newClient
    let tracker = ProcessLineageTracker(
      bootIdentifier: ProcessLineageTracker.currentBootIdentifier(), sink: logger,
      budget: auditWorkBudget)
    lineageTracker.withLock { $0 = tracker }
    coordinator.withLock {
      $0 = EndpointEventCoordinator(
        policySetIdentifier: storedPolicySet?.setIdentifier ?? runtimeIdentifier, policies: [],
        policyRevision: storedPolicySet?.revision ?? 0, sink: logger,
        recordLifecycleEvents: true, lineageTracker: tracker, decodeFailurePolicy: .failClosed)
    }
    let lifecycle: [es_event_type_t] = [
      ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
    ]
    let subscribed = lifecycle.withUnsafeBufferPointer {
      es_subscribe(newClient, $0.baseAddress!, UInt32($0.count))
    }
    guard subscribed == ES_RETURN_SUCCESS else {
      _ = es_delete_client(newClient)
      client = nil
      tracker.close()
      coordinator.withLock { $0 = nil }
      phase = .degraded
      detail = "Process history event subscription failed."
      scheduleEndpointRetry()
      writeStatusSnapshot()
      return
    }
    inspectLifecycleExclusions(client: newClient, tracker: tracker, lifecycle: lifecycle)
    cancelEndpointRetry()
    guard let storedPolicySet else {
      phase = .degraded
      detail = "No accepted policy set is stored."
      writeStatusSnapshot()
      return
    }

    do {
      let prepared = try preparePolicySet(
        storedPolicySet,
        compatibilitySettings: storedSystemCompatibilitySettings
      )
      let digest = try PolicySetDocumentCodec.digest(of: storedPolicySet)
      try activatePolicySet(
        storedPolicySet,
        prepared: prepared.policies,
        digest: digest,
        compatibilityResolution: prepared.compatibilityResolution
      )
    } catch {
      phase = .degraded
      detail = "Stored policy set could not be activated: \(error)"
    }
    writeStatusSnapshot()
  }

  private func preparePolicySet(
    _ policySet: PolicySetDocument,
    compatibilitySettings: SystemCompatibilitySettingsDocument?
  ) throws -> PreparedPolicySet {
    try policySet.validate()
    let compatibilityResolution = try SystemCompatibilityResolver.resolve(
      settings: compatibilitySettings,
      policySet: policySet,
      catalog: systemCompatibilityCatalog
    )
    let policies = try policySet.policies.map { policy in
      let scope = try ProtectedPathScope(
        root: policy.protectedRootPath
      )
      return EndpointPolicyConfiguration(
        id: policy.id,
        name: policy.name,
        mode: policy.mode,
        policyType: policy.policyType,
        scope: scope,
        rules: try policy.policySnapshot(),
        systemCompatibilityProfiles:
          compatibilityResolution.activeProfilesByPolicy[policy.id] ?? []
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
        decodeFailurePolicy: .failClosed
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

    activePolicySet = policySet
    activePolicySetDigest = digest
    activeSystemCompatibilityResolution = compatibilityResolution
    systemCompatibilityWarnings.replaceResolutionWarning(
      warning(for: compatibilityResolution.profileResolutions)
    )
    if policySet.policies.isEmpty {
      phase = .idle
      detail = "No file policies configured. Process history tracking is active."
    } else if policySet.policies.contains(where: { $0.mode == .protection }) {
      phase = .enforcing
      detail = "Enforcing Protection policies and monitoring Audit policies for AUTH_OPEN."
    } else {
      phase = .monitoring
      detail = "Monitoring Audit policies for AUTH_OPEN; kernel requests are allowed."
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
    var event = ES_EVENT_TYPE_AUTH_OPEN
    guard es_unsubscribe(client, &event, 1) == ES_RETURN_SUCCESS else {
      throw ExtensionRuntimeError.endpointUnsubscriptionFailed
    }
    isSubscribed = false
  }

  private func subscribeIfNeeded() throws {
    guard !isSubscribed else { return }
    guard let client else {
      throw ExtensionRuntimeError.endpointClientCreation("client unavailable")
    }
    var event = ES_EVENT_TYPE_AUTH_OPEN
    guard es_subscribe(client, &event, 1) == ES_RETURN_SUCCESS else {
      throw ExtensionRuntimeError.endpointSubscriptionFailed
    }
    isSubscribed = true
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
    for path in UnsafeBufferPointer(start: muted.pointee.paths, count: muted.pointee.count) {
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
    return ExtensionStatusSnapshot(
      runtimeInstanceIdentifier: runtimeIdentifier,
      phase: phase,
      activePolicySetIdentifier: activePolicySet?.setIdentifier,
      activePolicyRevision: activePolicySet?.revision,
      activePolicyDigest: activePolicySetDigest,
      systemCompatibilityCatalogDigest: systemCompatibilityCatalogDigest,
      activeSystemCompatibilitySettingsIdentifier:
        storedSystemCompatibilitySettings?.settingsIdentifier,
      activeSystemCompatibilitySettingsRevision:
        storedSystemCompatibilitySettings?.revision,
      activeSystemCompatibilitySettingsDigest: storedSystemCompatibilitySettingsDigest,
      activeSystemCompatibilityProfileCount:
        activeSystemCompatibilityResolution.profileResolutions.lazy.filter {
          $0.state == .active
        }.count,
      systemCompatibilityWarning: systemCompatibilityWarnings.combinedWarning,
      protectionPolicyCount: protectionPolicyCount,
      auditPolicyCount: auditPolicyCount,
      policyWarning: policyWarning ?? logger.lastErrorDescription,
      detail: detail,
      coveredAuthorizationEvents: ["AUTH_OPEN"],
      processLineageStatus: lineageTracker.withLock { $0?.status },
      droppedAuditEventCount: logger.droppedEventCount,
      auditDelivery: logger.deliveryMetrics,
      authorization: coordinator.withLock { $0?.authorizationMetrics }
    )
  }

  private func warning(
    for resolutions: [SystemCompatibilityProfileResolution]
  ) -> String? {
    let unresolved = resolutions.filter { $0.isEnabled && $0.state != .active }
    guard let first = unresolved.first else { return nil }
    if unresolved.count == 1 {
      return
        "System-compatibility profile \(first.profileIdentifier) is inactive: \(first.state.rawValue)."
    }
    return "\(unresolved.count) enabled system-compatibility profiles are inactive."
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
    isSubscribed = false
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
