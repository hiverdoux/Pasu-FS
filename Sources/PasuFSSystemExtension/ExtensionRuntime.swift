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
  private let runtimeIdentifier = UUID()
  private let queue = DispatchQueue(label: "com.dennis.pasu.fs.extension-runtime")
  private let coordinator = OSAllocatedUnfairLock<EndpointEventCoordinator?>(initialState: nil)
  private let locations: ExtensionStorageLocations
  private let rootStore: SecureAtomicFileStore
  private let auditStore: SecureAtomicFileStore
  private let logger: JSONLineEventLogger

  private var client: OpaquePointer?
  private var isSubscribed = false
  private var storedPolicySet: PolicySetDocument?
  private var activePolicySet: PolicySetDocument?
  private var activePolicySetDigest: String?
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
    self.logger = try JSONLineEventLogger(
      directoryURL: locations.auditDirectory,
      requiredOwnerUserID: 0,
      maximumPendingRecords: 1_024,
      maximumFileSize: 10 * 1_024 * 1_024,
      fileMode: 0o600
    )
  }

  func start() {
    queue.sync {
      installSignalHandlers()
      retireLegacyPolicy()
      loadStoredPolicySet()
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
          runtimeInstanceIdentifier: runtimeIdentifier
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
        let prepared = try preparePolicySet(candidate)
        let canonicalData = try PolicySetDocumentCodec.encode(candidate)
        let digest = try PolicySetDocumentCodec.digest(of: candidate)

        if disposition == .accepted {
          try rootStore.write(
            canonicalData,
            to: ExtensionStorageLocations.policySetFilename,
            mode: 0o600
          )
          storedPolicySet = candidate
          if client != nil {
            do {
              try activatePolicySet(candidate, prepared: prepared, digest: digest)
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

  func readAuditLog(
    _ requestedMaximumLineCount: Int,
    reply: @escaping (Data?, NSError?) -> Void
  ) {
    let reply = XPCReplyBox(reply)
    queue.async { [self] in
      do {
        let maximumLineCount = min(max(requestedMaximumLineCount, 1), 500)
        let batch = try loadAuditLog(maximumLineCount: maximumLineCount)
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
      storedPolicySet = try PolicySetDocumentCodec.decode(data)
    } catch SecureFileStoreError.fileNotFound {
      storedPolicySet = nil
    } catch {
      storedPolicySet = nil
      policyWarning = "Stored policy set rejected: \(error)"
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
    cancelEndpointRetry()
    guard let storedPolicySet else {
      phase = .degraded
      detail = "No accepted policy set is stored."
      writeStatusSnapshot()
      return
    }

    do {
      let prepared = try preparePolicySet(storedPolicySet)
      let digest = try PolicySetDocumentCodec.digest(of: storedPolicySet)
      try activatePolicySet(storedPolicySet, prepared: prepared, digest: digest)
    } catch {
      phase = .degraded
      detail = "Stored policy set could not be activated: \(error)"
    }
    writeStatusSnapshot()
  }

  private func preparePolicySet(
    _ policySet: PolicySetDocument
  ) throws -> [EndpointPolicyConfiguration] {
    try policySet.validate()
    return try policySet.policies.map { policy in
      let scope = try ProtectedPathScope(
        root: policy.protectedRootPath,
        homeDirectory: inferredHomeDirectory(for: policy.protectedRootPath)
      )
      return EndpointPolicyConfiguration(
        id: policy.id,
        name: policy.name,
        mode: policy.mode,
        policyType: policy.policyType,
        scope: scope,
        rules: try policy.policySnapshot()
      )
    }
  }

  private func activatePolicySet(
    _ policySet: PolicySetDocument,
    prepared: [EndpointPolicyConfiguration],
    digest: String
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

    activePolicySet = policySet
    activePolicySetDigest = digest
    if policySet.policies.isEmpty {
      phase = .idle
      detail = "No policies configured."
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
    guard isSubscribed else {
      coordinator.withLock { $0 = nil }
      return
    }
    guard let client, es_unsubscribe_all(client) == ES_RETURN_SUCCESS else {
      throw ExtensionRuntimeError.endpointUnsubscriptionFailed
    }
    isSubscribed = false
    coordinator.withLock { $0 = nil }
  }

  private func subscribeIfNeeded() throws {
    guard !isSubscribed else { return }
    guard let client else {
      throw ExtensionRuntimeError.endpointClientCreation("client unavailable")
    }
    let events: [es_event_type_t] = [
      ES_EVENT_TYPE_NOTIFY_EXEC,
      ES_EVENT_TYPE_NOTIFY_FORK,
      ES_EVENT_TYPE_NOTIFY_EXIT,
      ES_EVENT_TYPE_AUTH_OPEN,
    ]
    let result = events.withUnsafeBufferPointer { buffer in
      es_subscribe(client, buffer.baseAddress!, UInt32(buffer.count))
    }
    guard result == ES_RETURN_SUCCESS else {
      throw ExtensionRuntimeError.endpointSubscriptionFailed
    }
    isSubscribed = true
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
      protectionPolicyCount: protectionPolicyCount,
      auditPolicyCount: auditPolicyCount,
      policyWarning: policyWarning ?? logger.lastErrorDescription,
      detail: detail,
      coveredAuthorizationEvents: ["AUTH_OPEN"],
      droppedAuditEventCount: logger.droppedEventCount
    )
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

  private func loadAuditLog(maximumLineCount: Int) throws -> AuditLogBatch {
    let data: Data
    do {
      data = try auditStore.read(
        "endpoint-events.jsonl",
        maximumSize: 10 * 1_024 * 1_024
      )
    } catch SecureFileStoreError.fileNotFound {
      return AuditLogBatch(records: [], droppedEventCount: logger.droppedEventCount)
    }

    let allLines = data.split(separator: 0x0A, omittingEmptySubsequences: true)
    let selectedLines = allLines.suffix(maximumLineCount)
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    var records: [AuditEventRecord] = []
    var skippedLineCount = 0
    for line in selectedLines {
      do {
        records.append(try decoder.decode(AuditEventRecord.self, from: Data(line)))
      } catch {
        skippedLineCount += 1
      }
    }
    return AuditLogBatch(
      records: records,
      skippedLineCount: skippedLineCount,
      droppedEventCount: logger.droppedEventCount,
      isTruncated: allLines.count > maximumLineCount
    )
  }

  private func inferredHomeDirectory(for protectedRoot: String) -> String {
    let components = URL(fileURLWithPath: protectedRoot).standardizedFileURL.pathComponents
    if components.count >= 3, components[1] == "Users" {
      return "/Users/\(components[2])"
    }
    return "/var/empty"
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
