import EndpointSecurity
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import os

public enum DecodeFailurePolicy: String, Codable, Sendable {
  case failOpen
  case failClosed
}

public typealias EndpointEventRecord = AuditEventRecord

public protocol EndpointEventSink: Sendable {
  func record(_ event: EndpointEventRecord)
}

public struct EndpointPolicyConfiguration: Sendable {
  public let id: UUID
  public let name: String
  public let mode: PolicyMode
  public let policyType: PolicyType
  public let scope: ProtectedPathScope
  public let rules: PolicySnapshot
  public let executionOriginPolicy: ExecutionOriginPolicySnapshot
  public let systemCompatibilityProfiles: [ResolvedSystemCompatibilityProfile]
  /// Former paths of the folder that stay reserved for the programs the policy allows.
  public let retiredScopes: [ProtectedPathScope]

  public init(
    id: UUID,
    name: String,
    mode: PolicyMode,
    policyType: PolicyType,
    scope: ProtectedPathScope,
    rules: PolicySnapshot,
    executionOriginPolicy: ExecutionOriginPolicySnapshot? = nil,
    systemCompatibilityProfiles: [ResolvedSystemCompatibilityProfile] = [],
    retiredScopes: [ProtectedPathScope] = []
  ) {
    self.id = id
    self.name = name
    self.mode = mode
    self.policyType = policyType
    self.scope = scope
    self.rules = rules
    self.executionOriginPolicy =
      executionOriginPolicy
      ?? ExecutionOriginPolicySnapshot(
        isBlacklistEnabled: policyType == .blacklist,
        allowRules: policyType == .whitelist ? rules.rules : [],
        denyRules: policyType == .blacklist ? rules.rules : [])
    self.systemCompatibilityProfiles = systemCompatibilityProfiles
    self.retiredScopes = retiredScopes
  }
}

public final class EndpointEventCoordinator: @unchecked Sendable {
  /// Notifications subscribed together with the authorization events: an unmount tells whether
  /// a volume that held a policy folder went away, and a rename tells when a move of a policy
  /// folder or of a folder that contains it has finished, successfully or not.
  public static let policyNotificationEventTypes: [es_event_type_t] = [
    ES_EVENT_TYPE_NOTIFY_UNMOUNT, ES_EVENT_TYPE_NOTIFY_RENAME,
  ]

  /// The process starts, forks and exits that the execution histories are built from. They are
  /// subscribed for as long as the client exists.
  public static let processEventTypes: [es_event_type_t] = [
    ES_EVENT_TYPE_NOTIFY_EXEC, ES_EVENT_TYPE_NOTIFY_FORK, ES_EVENT_TYPE_NOTIFY_EXIT,
  ]

  /// The events subscribed while at least one policy is active: every authorization event the
  /// extension answers, plus the unmount notification for the volume warning and the rename
  /// notification that starts a check of the policy folders.
  public static var policyEventTypes: [es_event_type_t] {
    FileOperationKind.subscribedEventTypes + policyNotificationEventTypes
  }

  /// The events of a new client's first subscription. With policies to apply, it names their
  /// events together with the process events, so that the first subscription, which ends an
  /// early-boot hold, leaves no request of theirs unsubscribed.
  public static func firstSubscriptionEventTypes(withPolicies: Bool) -> [es_event_type_t] {
    processEventTypes + (withPolicies ? policyEventTypes : [])
  }

  /// At most this many allowed moves of one policy folder wait for confirmation at a time.
  /// A rename that would need another is denied until the extension has checked the folder.
  public static let maximumPendingMovesPerPolicy = 32

  /// Called with the unmounted volume and the names of the policies whose folder was the mount
  /// point, lay below it or contained it. Runs on the Endpoint Security delivery thread.
  public typealias ProtectedVolumeUnmountedHandler = @Sendable (MountedVolume, [String]) -> Void

  /// Called when macOS reports a finished rename that may have moved a policy folder, so its
  /// location should be checked. Runs on the Endpoint Security delivery thread.
  public typealias FolderMoveReportedHandler = @Sendable () -> Void

  /// How a request relates to a policy folder.
  enum ScopeRelation: Equatable {
    /// A path of the request is the policy folder or lies inside it.
    case inside
    /// The request acts on a folder that contains the policy folder, and on no path inside it.
    case enclosing
  }

  /// A policy that takes part in a request: through its folder, a retired path, or both.
  struct PolicyMatch {
    let index: Int
    /// Nil when the request touches only a retired path of the policy.
    let relation: ScopeRelation?
    let retiredPath: String?
  }

  private struct ActivePolicyState: Sendable {
    var id: UUID
    var name: String
    var mode: PolicyMode
    var policyType: PolicyType
    var scope: ProtectedPathScope
    var executionOriginPolicy: ExecutionOriginPolicySnapshot
    var systemCompatibilityProfiles: [ResolvedSystemCompatibilityProfile]
    var retiredScopes: [ProtectedPathScope]
    /// Allowed moves of the folder that the extension has not confirmed yet. Each one's new
    /// location is protected like the folder itself.
    var pendingMoves: [PendingFolderMove] = []

    init(configuration: EndpointPolicyConfiguration) {
      id = configuration.id
      name = configuration.name
      mode = configuration.mode
      policyType = configuration.policyType
      scope = configuration.scope
      executionOriginPolicy = configuration.executionOriginPolicy
      systemCompatibilityProfiles = configuration.systemCompatibilityProfiles
      retiredScopes = configuration.retiredScopes
    }

    /// The folder and the new locations of its unconfirmed moves.
    var scopes: [ProtectedPathScope] { [scope] + pendingMoves.map(\.scope) }

    /// The retired paths and, for unconfirmed moves, the locations they move to.
    var allRetiredScopes: [ProtectedPathScope] {
      retiredScopes + pendingMoves.flatMap(\.retiredScopes)
    }

    /// The first retired path of the policy that the request touches, or nil. A request touches
    /// a retired path when one of its paths is that path or lies below it, when it acts as a
    /// whole on a folder that contains it (rename or move, delete, clone, copy, data exchange
    /// or mount), or when it places an object at that path or at a folder leading to it, which
    /// could recreate the path or send it elsewhere through a symbolic link.
    ///
    /// Three cases don't count. A retired path inside the folder or one of its pending locations
    /// is protected as part of the folder. A rename of a folder that also contains the policy
    /// folder moves the retired paths inside it along with the policy folder, which keeps them
    /// retired at their new location. And a rename that brings the policy folder itself onto a
    /// retired path places the folder's own protection there.
    func retiredPathTouched(by request: FileOperationRequest) -> String? {
      let retiredScopes = allRetiredScopes
      guard !retiredScopes.isEmpty else { return nil }
      let currentScopes = scopes
      var relocated: [ProtectedPathScope] = []
      let source = request.primaryPath.path
      let destination = request.kind == .rename ? request.destinationPath?.path : nil
      if let destination {
        relocated = currentScopes.compactMap { $0.relocated(from: source, to: destination) }
      }
      let placed = request.newObjectPath
      for retired in retiredScopes
      where !currentScopes.contains(where: { $0.contains(retired.root) }) {
        let arrivesWithFolder = relocated.contains { $0.contains(retired.root) }
        let movesWithFolder =
          !relocated.isEmpty
          && destination.flatMap { retired.relocated(from: source, to: $0) } != nil
        for path in request.checkedPaths {
          if arrivesWithFolder, path == request.destinationPath { continue }
          if movesWithFolder, path == request.primaryPath { continue }
          if path.affects(retired) { return retired.root }
        }
        if let placed, !arrivesWithFolder, retired.rootIsInside(placed.path) {
          return retired.root
        }
      }
      return nil
    }

    func relation(to request: FileOperationRequest) -> ScopeRelation? {
      var encloses = false
      for path in request.checkedPaths {
        for scope in scopes {
          if scope.contains(path.path) { return .inside }
          if path.affectsEnclosedFolders, scope.rootIsInside(path.path) { encloses = true }
        }
      }
      return encloses ? .enclosing : nil
    }

    /// Whether `path`, with `affectsEnclosedFolders` set, reaches the folder or a new location.
    func isAffected(by path: CheckedPath) -> Bool {
      scopes.contains { path.affects($0) }
    }
  }

  private struct MutableState: Sendable {
    var policySetIdentifier: UUID?
    var policies: [ActivePolicyState]
    var policyRevision: UInt64?
    var originTracker: ExecutionOriginTracker
    var deliveryGaps = DeliveryGapAccounting()
  }

  struct AccessEvaluation: Equatable, Sendable {
    let isInScope: Bool
    let policySetIdentifier: UUID?
    let policyRevision: UInt64?
    let policyDecision: String
    let policyEvaluations: [PolicyEvaluationRecord]
    /// `UInt32.max` allows and 0 denies; an open answers with these flags directly.
    let authorizedFlags: UInt32
    let detail: String?

    var isDenied: Bool { authorizedFlags == 0 }
  }

  private let state: OSAllocatedUnfairLock<MutableState>
  private let responseMetrics = OSAllocatedUnfairLock(initialState: AuthorizationMetrics())
  public var authorizationMetrics: AuthorizationMetrics { responseMetrics.withLock { $0 } }
  private let sink: any EndpointEventSink
  private let lineageTracker: ProcessLineageTracker?
  private let recordLifecycleEvents: Bool
  private let decodeFailurePolicy: DecodeFailurePolicy
  private let operatingSystemBuild: String
  private let protectedVolumeUnmounted: ProtectedVolumeUnmountedHandler?
  private let folderMoveReported: FolderMoveReportedHandler?
  /// Registers the new locations of allowed renames with Endpoint Security; nil when every
  /// request is delivered regardless.
  private let targetPaths: TargetPathRegistry?
  private let uptime: @Sendable () -> UInt64

  public init(
    policySetIdentifier: UUID,
    policies: [EndpointPolicyConfiguration],
    policyRevision: UInt64,
    sink: any EndpointEventSink,
    recordLifecycleEvents: Bool = false,
    lineageTracker: ProcessLineageTracker? = nil,
    decodeFailurePolicy: DecodeFailurePolicy = .failOpen,
    operatingSystemBuild: String = SystemCompatibilityOSBuild.current(),
    bootIdentifier: String = ProcessLineageTracker.currentBootIdentifier(),
    observationStart: Date? = nil,
    protectedVolumeUnmounted: ProtectedVolumeUnmountedHandler? = nil,
    folderMoveReported: FolderMoveReportedHandler? = nil,
    targetPaths: TargetPathRegistry? = nil,
    uptime: @escaping @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
  ) {
    var originTracker = ExecutionOriginTracker(
      bootIdentifier: bootIdentifier, observationStart: observationStart)
    originTracker.configure(policies: policies.map(\.executionOriginPolicy))
    state = OSAllocatedUnfairLock(
      initialState: MutableState(
        policySetIdentifier: policySetIdentifier,
        policies: policies.map(ActivePolicyState.init),
        policyRevision: policyRevision,
        originTracker: originTracker
      )
    )
    self.sink = sink
    self.lineageTracker = lineageTracker
    self.recordLifecycleEvents = recordLifecycleEvents
    self.decodeFailurePolicy = decodeFailurePolicy
    self.operatingSystemBuild = operatingSystemBuild
    self.protectedVolumeUnmounted = protectedVolumeUnmounted
    self.folderMoveReported = folderMoveReported
    self.targetPaths = targetPaths
    self.uptime = uptime
  }

  public func replacePolicySet(
    setIdentifier: UUID,
    policies: [EndpointPolicyConfiguration],
    revision: UInt64
  ) {
    state.withLock { state in
      let existing = Dictionary(uniqueKeysWithValues: state.policies.map { ($0.id, $0) })
      state.policies = policies.map { configuration in
        guard var retained = existing[configuration.id] else {
          return ActivePolicyState(configuration: configuration)
        }
        retained.name = configuration.name
        retained.mode = configuration.mode
        retained.policyType = configuration.policyType
        retained.scope = configuration.scope
        retained.executionOriginPolicy = configuration.executionOriginPolicy
        retained.systemCompatibilityProfiles = configuration.systemCompatibilityProfiles
        retained.retiredScopes = configuration.retiredScopes
        return retained
      }
      state.originTracker.configure(policies: policies.map(\.executionOriginPolicy))
      state.policySetIdentifier = setIdentifier
      state.policyRevision = revision
      // The pending moves of removed policies end with them.
      targetPaths?.retainPins(Set(state.policies.flatMap(\.pendingMoves).map(\.identifier)))
    }
  }

  public var currentPolicyRevision: UInt64? {
    state.withLock { $0.policyRevision }
  }

  /// The allowed moves of policy folders that wait for confirmation.
  public var pendingFolderMoves: [PendingFolderMove] {
    state.withLock { $0.policies.flatMap(\.pendingMoves) }
  }

  /// Stops protecting the new locations of these moves. Called after the policy folders were
  /// checked and any moved folder is named by its policy.
  public func withdrawPendingFolderMoves(_ identifiers: Set<UUID>) {
    guard !identifiers.isEmpty else { return }
    state.withLock { state in
      for index in state.policies.indices {
        state.policies[index].pendingMoves.removeAll { identifiers.contains($0.identifier) }
      }
    }
    targetPaths?.unpin(identifiers)
  }

  public func handle(
    client: OpaquePointer,
    message: UnsafePointer<es_message_t>
  ) {
    let finishedGaps = observeDelivery(
      eventType: message.pointee.event_type,
      sequence: message.pointee.version >= 2 ? message.pointee.seq_num : nil,
      globalSequence: message.pointee.version >= 4 ? message.pointee.global_seq_num : nil,
      at: Date(
        timeIntervalSince1970: Double(message.pointee.time.tv_sec)
          + Double(message.pointee.time.tv_nsec) / 1_000_000_000))
    var record: EndpointEventRecord?
    switch message.pointee.event_type {
    case ES_EVENT_TYPE_NOTIFY_EXEC:
      handleExec(message) { record = $0 }
    case ES_EVENT_TYPE_NOTIFY_FORK:
      handleFork(message) { record = $0 }
    case ES_EVENT_TYPE_NOTIFY_EXIT:
      handleExit(message) { record = $0 }
    case ES_EVENT_TYPE_NOTIFY_UNMOUNT:
      noteUnmount(EndpointDecoder.unmountedVolume(message.pointee.event))
    case ES_EVENT_TYPE_NOTIFY_RENAME:
      let rename = EndpointDecoder.fileOperation(.rename, event: message.pointee.event)
      noteRename(
        source: rename.primaryPath.path, destination: rename.destinationPath?.path ?? "")
    default:
      if let kind = FileOperationKind(eventType: message.pointee.event_type) {
        handleFileOperation(kind, client: client, message: message) { record = $0 }
      }
    }
    // The kernel response above is complete before history decoding or queuing.
    if let lineageTracker {
      lineageTracker.submit(EndpointDecoder.lineageObservation(message), record: record)
    } else if let record {
      sink.record(record)
    }
    if let finishedGaps { recordDeliveryGaps(finishedGaps) }
  }

  /// Reports an unmount whose mount point was a policy folder, lay inside one or contained one.
  /// A mount there is denied while the policy is in Protection mode, so this is reached after a
  /// mount that predates the policy, an Audit policy's folder or a volume that the folder lives on.
  func noteUnmount(_ volume: MountedVolume) {
    let path = CheckedPath(path: volume.mountPoint, affectsEnclosedFolders: true)
    let names = state.withLock { state in
      state.policies.filter { $0.isAffected(by: path) }.map(\.name)
    }
    guard !names.isEmpty else { return }
    protectedVolumeUnmounted?(volume, names)
  }

  /// Marks the pending moves this finished rename belongs to, and asks for the policy folders
  /// to be checked when the rename may have moved one, or may have changed the spelling of a
  /// retired path or of a folder on the way to one, which the registered target paths follow.
  /// macOS also reports renames that it denied or that failed, so this never changes a policy
  /// by itself.
  func noteRename(source: String, destination: String) {
    let affectsPolicyFolder = state.withLock { state -> Bool in
      var affects = false
      for index in state.policies.indices {
        for move in state.policies[index].pendingMoves.indices
        where state.policies[index].pendingMoves[move].source == source
          && state.policies[index].pendingMoves[move].destination == destination
        {
          state.policies[index].pendingMoves[move].wasNotified = true
          affects = true
        }
        if !affects, state.policies[index].scopes.contains(where: { $0.rootIsInside(source) }) {
          affects = true
        }
        if !affects,
          state.policies[index].allRetiredScopes.contains(where: {
            $0.rootIsInside(source) || $0.rootIsInside(destination)
          })
        {
          affects = true
        }
      }
      return affects
    }
    if affectsPolicyFolder { folderMoveReported?() }
  }

  private var shouldRecordLifecycle: Bool {
    recordLifecycleEvents && state.withLock { !$0.policies.isEmpty }
  }

  private func handleExec(
    _ message: UnsafePointer<es_message_t>, emit: (EndpointEventRecord) -> Void
  ) {
    do {
      let version = message.pointee.version
      let source = try EndpointDecoder.process(message.pointee.process, messageVersion: version)
      let process = try EndpointDecoder.process(
        message.pointee.event.exec.target, messageVersion: version)
      let evaluation = state.withLock { state -> ([PolicyEvaluationRecord], UUID?, UInt64?) in
        state.originTracker.observeExec(from: source.executionProgram, to: process.executionProgram)
        return ([], state.policySetIdentifier, state.policyRevision)
      }
      guard shouldRecordLifecycle else { return }

      emit(
        EndpointEventRecord(
          policySetIdentifier: evaluation.1,
          policyRevision: evaluation.2,
          eventSequence: message.pointee.version >= 2 ? message.pointee.seq_num : nil,
          eventType: "NOTIFY_EXEC",
          processID: process.processID,
          executablePath: process.executablePath,
          teamIdentifier: process.facts.teamIdentifier,
          signingIdentifier: process.facts.signingIdentifier,
          isPlatformBinary: process.facts.isPlatformBinary,
          codeSigningFlags: process.facts.codeSigningFlags,
          operatingSystemBuild: operatingSystemBuild,
          policyDecision: evaluation.0.isEmpty ? "no-rule-match" : "matched-rules",
          kernelResponse: "notify-only",
          policyEvaluations: evaluation.0,
          detail: "sourceAuditToken=\(auditTokenDescription(source.facts.auditToken)) "
            + "targetAuditToken=\(auditTokenDescription(process.facts.auditToken))"
        )
      )
    } catch {
      recordLifecycleDecodeError(
        eventType: "NOTIFY_EXEC",
        sequence: message.pointee.version >= 2 ? message.pointee.seq_num : nil,
        error: error,
        emit: emit
      )
    }
  }

  private func handleFork(
    _ message: UnsafePointer<es_message_t>, emit: (EndpointEventRecord) -> Void
  ) {
    do {
      let version = message.pointee.version
      let parent = try EndpointDecoder.process(message.pointee.process, messageVersion: version)
      let child = try EndpointDecoder.process(
        message.pointee.event.fork.child, messageVersion: version)
      let evaluation = state.withLock { state -> ([PolicyEvaluationRecord], UUID?, UInt64?) in
        state.originTracker.observeFork(
          parent: parent.executionProgram, child: child.executionProgram)
        return ([], state.policySetIdentifier, state.policyRevision)
      }
      guard shouldRecordLifecycle else { return }

      let forkDetail = [
        "parentProcessID=\(parent.processID)",
        "parentPath=\(parent.executablePath)",
        "parentAuditToken=\(auditTokenDescription(parent.facts.auditToken))",
        "childAuditToken=\(auditTokenDescription(child.facts.auditToken))",
      ].joined(separator: " ")

      emit(
        EndpointEventRecord(
          policySetIdentifier: evaluation.1,
          policyRevision: evaluation.2,
          eventSequence: message.pointee.version >= 2 ? message.pointee.seq_num : nil,
          eventType: "NOTIFY_FORK",
          processID: child.processID,
          executablePath: child.executablePath,
          teamIdentifier: child.facts.teamIdentifier,
          signingIdentifier: child.facts.signingIdentifier,
          isPlatformBinary: child.facts.isPlatformBinary,
          codeSigningFlags: child.facts.codeSigningFlags,
          operatingSystemBuild: operatingSystemBuild,
          policyDecision: evaluation.0.isEmpty ? "no-rule-match" : "matched-rules",
          kernelResponse: "notify-only",
          policyEvaluations: evaluation.0,
          detail: forkDetail
        )
      )
    } catch {
      recordLifecycleDecodeError(
        eventType: "NOTIFY_FORK",
        sequence: message.pointee.version >= 2 ? message.pointee.seq_num : nil,
        error: error,
        emit: emit
      )
    }
  }

  private func handleExit(
    _ message: UnsafePointer<es_message_t>, emit: (EndpointEventRecord) -> Void
  ) {
    do {
      let process = try EndpointDecoder.process(message.pointee.process)
      let evaluation = state.withLock { state -> ([PolicyEvaluationRecord], UUID?, UInt64?) in
        state.originTracker.observeExit(process.facts.processInstance)
        return ([], state.policySetIdentifier, state.policyRevision)
      }
      guard shouldRecordLifecycle else { return }

      emit(
        EndpointEventRecord(
          policySetIdentifier: evaluation.1,
          policyRevision: evaluation.2,
          eventSequence: message.pointee.version >= 2 ? message.pointee.seq_num : nil,
          eventType: "NOTIFY_EXIT",
          processID: process.processID,
          executablePath: process.executablePath,
          teamIdentifier: process.facts.teamIdentifier,
          signingIdentifier: process.facts.signingIdentifier,
          isPlatformBinary: process.facts.isPlatformBinary,
          codeSigningFlags: process.facts.codeSigningFlags,
          operatingSystemBuild: operatingSystemBuild,
          policyDecision: evaluation.0.isEmpty ? "no-rule-match" : "matched-rules",
          kernelResponse: "notify-only",
          policyEvaluations: evaluation.0,
          detail: "auditToken=\(auditTokenDescription(process.facts.auditToken))"
        )
      )
    } catch {
      recordLifecycleDecodeError(
        eventType: "NOTIFY_EXIT",
        sequence: message.pointee.version >= 2 ? message.pointee.seq_num : nil,
        error: error,
        emit: emit
      )
    }
  }

  private func handleFileOperation(
    _ kind: FileOperationKind,
    client: OpaquePointer,
    message: UnsafePointer<es_message_t>,
    emit: (EndpointEventRecord) -> Void
  ) {
    let request = EndpointDecoder.fileOperation(kind, event: message.pointee.event)
    let processResult = Result {
      try EndpointDecoder.process(message.pointee.process, messageVersion: message.pointee.version)
    }

    let process = try? processResult.get()
    let decodeErrorDescription: String?
    switch processResult {
    case .success:
      decodeErrorDescription = nil
    case .failure(let error):
      decodeErrorDescription = String(describing: error)
    }
    let evaluation = evaluate(
      request,
      process: process?.facts,
      executionProgram: process?.executionProgram,
      decodeErrorDescription: decodeErrorDescription
    )

    guard evaluation.isInScope else {
      _ = respondMeasured(client: client, message: message, kind: request.kind, allowed: true)
      return
    }

    respond(
      client: client,
      message: message,
      kind: request.kind,
      allowed: !evaluation.isDenied,
      record: EndpointEventRecord(
        policySetIdentifier: evaluation.policySetIdentifier,
        policyRevision: evaluation.policyRevision,
        eventSequence: message.pointee.version >= 2 ? message.pointee.seq_num : nil,
        eventType: request.kind.rawValue,
        processID: process?.processID,
        executablePath: process?.executablePath,
        teamIdentifier: process?.facts.teamIdentifier,
        signingIdentifier: process?.facts.signingIdentifier,
        isPlatformBinary: process?.facts.isPlatformBinary,
        codeSigningFlags: process?.facts.codeSigningFlags,
        operatingSystemBuild: operatingSystemBuild,
        targetPath: request.primaryPath.path,
        destinationPath: request.destinationPath?.path,
        pathWasTruncated: request.pathWasTruncated,
        requestedFlags: request.requestedOpenFlags.map(Int32.init(bitPattern:)),
        policyDecision: evaluation.policyDecision,
        kernelResponse: evaluation.isDenied ? "deny" : "allow",
        policyEvaluations: evaluation.policyEvaluations,
        detail: evaluation.detail
      ),
      emit: emit
    )
  }

  func evaluateOpen(
    path: String,
    pathWasTruncated: Bool,
    process: ProcessFacts?,
    executionProgram: ExecutionProgram? = nil,
    requestedOpenFlags: UInt32 = 0,
    decodeErrorDescription: String? = nil
  ) -> AccessEvaluation {
    evaluate(
      .open(path: path, wasTruncated: pathWasTruncated, flags: requestedOpenFlags),
      process: process, executionProgram: executionProgram,
      decodeErrorDescription: decodeErrorDescription)
  }

  /// Decides one request. A policy takes part when any checked path of the request is inside
  /// its folder, or when the request acts on a folder that encloses the policy folder. Every
  /// kind of request uses the same program lists and execution history as a file open, and a
  /// compatibility profile turned on for the policy can allow a request those would deny.
  func evaluate(
    _ request: FileOperationRequest,
    process: ProcessFacts?,
    executionProgram: ExecutionProgram? = nil,
    decodeErrorDescription: String? = nil
  ) -> AccessEvaluation {
    let started = mach_absolute_time()
    defer {
      let elapsed = mach_absolute_time() - started
      responseMetrics.withLock {
        $0.evaluatedOpenCount = ($0.evaluatedOpenCount ?? 0) &+ 1
        $0.totalEvaluationTicks = ($0.totalEvaluationTicks ?? 0) &+ elapsed
        $0.maximumEvaluationTicks = max($0.maximumEvaluationTicks ?? 0, elapsed)
      }
    }
    return state.withLock { state -> AccessEvaluation in
      let matches: [PolicyMatch] = state.policies.indices.compactMap { index in
        let policy = state.policies[index]
        let relation = policy.relation(to: request)
        let retiredPath = policy.retiredPathTouched(by: request)
        guard relation != nil || retiredPath != nil else { return nil }
        return PolicyMatch(index: index, relation: relation, retiredPath: retiredPath)
      }
      guard !matches.isEmpty else {
        return AccessEvaluation(
          isInScope: false,
          policySetIdentifier: state.policySetIdentifier,
          policyRevision: state.policyRevision,
          policyDecision: "outside-scope",
          policyEvaluations: [],
          authorizedFlags: UInt32.max,
          detail: nil
        )
      }

      var records: [PolicyEvaluationRecord]
      let detail: String?
      if request.pathWasTruncated {
        records = matches.map {
          Self.makeFailureEvaluation(
            for: state.policies[$0.index],
            match: .truncatedPath,
            detail: "The reported truncated prefix is inside this policy scope."
          )
        }
        detail = "The reported truncated prefix is inside at least one policy scope."
      } else if request.kind.isDecidedByPathAlone {
        // The mount point hides the policy folder, or a retired path, whoever asked for it.
        records = matches.map {
          Self.makeFailureEvaluation(
            for: state.policies[$0.index],
            match: .mountPoint,
            detail: $0.relation == nil
              ? "A volume mounted here would cover a retired path of this policy."
              : "A volume mounted here would hide this policy’s folder."
          )
        }
        detail = nil
      } else {
        let program = process.map {
          executionProgram ?? ExecutionProgram(facts: $0, executablePath: "")
        }
        let summary = program.map { state.originTracker.summary(for: $0) }
        let errorDescription = decodeErrorDescription ?? "Process facts are unavailable."
        records = matches.map { match in
          let policy = state.policies[match.index]
          if request.kind == .rename, match.relation == .enclosing, match.retiredPath == nil {
            // Renaming a folder that contains the policy folder leaves the files where they
            // are and the policy follows them, so no program needs to be listed for it. A
            // retired path does not follow, so a rename that touches one is decided below.
            return Self.makeEnclosingRenameEvaluation(for: policy)
          }
          guard let summary, let process else {
            return Self.makeFailureEvaluation(
              for: policy, match: .decodeError, detail: errorDescription)
          }
          let origin = state.originTracker.evaluate(summary, policy: policy.executionOriginPolicy)
          // A blocked program in the history denies whatever profile the process matches. A
          // process the program lists already allow keeps that evidence.
          if !origin.isAllowed, origin.reason != .deniedInHistory,
            let profile = Self.admittingProfile(
              of: policy, process: process, request: request, origin: origin,
              parent: process.parentProcessInstance.flatMap {
                state.originTracker.program(for: $0)
              })
          {
            return Self.makeProfileEvaluation(
              for: policy, profile: profile, origin: origin,
              enclosing: match.relation == .enclosing)
          }
          return Self.makeOriginEvaluation(
            for: policy, origin: origin, enclosing: match.relation == .enclosing)
        }
        detail = records.contains { $0.match == .decodeError } ? errorDescription : nil
      }
      for (offset, match) in matches.enumerated() {
        records[offset].retiredFolderPath = match.retiredPath
      }

      // A rename that moves a policy folder protects the folder's new location as well, from
      // before the answer until the extension has confirmed where the folder is.
      var moves: [(index: Int, scope: ProtectedPathScope)] = []
      if request.kind == .rename, !request.pathWasTruncated,
        let destination = request.destinationPath?.path
      {
        let source = request.primaryPath.path
        for match in matches where match.relation != nil {
          for scope in state.policies[match.index].scopes {
            if let moved = scope.relocated(from: source, to: destination) {
              moves.append((match.index, moved))
            }
          }
        }
        let crowded = Set(
          moves.map(\.index).filter {
            state.policies[$0].pendingMoves.count >= Self.maximumPendingMovesPerPolicy
          })
        for (offset, match) in matches.enumerated() where crowded.contains(match.index) {
          records[offset] = Self.makeFailureEvaluation(
            for: state.policies[match.index], match: records[offset].match,
            detail: "Too many moves of this policy’s folder are waiting to be confirmed.")
        }
      }

      let hasProtectionPolicy = records.contains { $0.mode == .protection }
      let denials = records.filter { $0.mode == .protection && $0.decision == .deny }
      var authorizedFlags: UInt32
      if !denials.isEmpty, decodeFailurePolicy == .failOpen,
        denials.allSatisfy({ $0.match == .decodeError || $0.match == .truncatedPath })
      {
        authorizedFlags = UInt32.max
      } else {
        authorizedFlags = denials.isEmpty ? UInt32.max : 0
      }
      var finalDenied = authorizedFlags == 0
      if !finalDenied, !moves.isEmpty {
        let now = uptime()
        let source = request.primaryPath.path
        let destination = request.destinationPath?.path ?? ""
        var added: [(index: Int, move: PendingFolderMove)] = []
        for move in moves {
          // Retired paths inside the renamed folder move with it and stay retired there.
          let retired = state.policies[move.index].allRetiredScopes.compactMap {
            $0.relocated(from: source, to: destination)
          }
          if let pending = Self.pendingMove(
            for: state.policies[move.index], scope: move.scope, retiredScopes: retired,
            source: source, destination: destination,
            destinationIsExistingFile: request.destinationIsExistingFile, at: now)
          {
            added.append((move.index, pending))
          }
        }
        // The new locations are registered before the answer, so that the kernel delivers the
        // requests that reach the folder there as soon as the rename is done.
        var pinned: Set<UUID> = []
        let registered = added.allSatisfy { entry in
          guard let targetPaths else { return true }
          guard targetPaths.pin(entry.move.identifier, TargetPathPlan.entries(for: entry.move))
          else { return false }
          pinned.insert(entry.move.identifier)
          return true
        }
        if registered {
          for entry in added {
            let replaced = state.policies[entry.index].pendingMoves.filter {
              $0.scope.namesSameLocation(as: entry.move.scope)
            }
            state.policies[entry.index].pendingMoves.removeAll {
              $0.scope.namesSameLocation(as: entry.move.scope)
            }
            state.policies[entry.index].pendingMoves.append(entry.move)
            targetPaths?.unpin(Set(replaced.map(\.identifier)))
          }
        } else {
          targetPaths?.unpin(pinned)
          let affected = Set(added.map(\.index))
          for (offset, match) in matches.enumerated() where affected.contains(match.index) {
            records[offset] = Self.makeFailureEvaluation(
              for: state.policies[match.index], match: records[offset].match,
              detail: "The folder's new location could not be registered with Endpoint Security.")
            records[offset].retiredFolderPath = match.retiredPath
          }
          finalDenied = records.contains { $0.mode == .protection && $0.decision == .deny }
          if finalDenied { authorizedFlags = 0 }
        }
      }
      return AccessEvaluation(
        isInScope: true,
        policySetIdentifier: state.policySetIdentifier,
        policyRevision: state.policyRevision,
        policyDecision: hasProtectionPolicy
          ? (finalDenied ? "denied" : "allowed")
          : "audit-only",
        policyEvaluations: records,
        authorizedFlags: authorizedFlags,
        detail: detail
      )
    }
  }

  /// The pending move to record for an allowed move, or nil. A location the policy already
  /// protects needs no new entry, unless the destination was an existing file: the folder may
  /// then take a spelling that the request doesn't show. A repeated move to a pending location
  /// replaces that entry and restarts its confirmation.
  private static func pendingMove(
    for policy: ActivePolicyState, scope: ProtectedPathScope,
    retiredScopes: [ProtectedPathScope], source: String, destination: String,
    destinationIsExistingFile: Bool, at now: UInt64
  ) -> PendingFolderMove? {
    guard destinationIsExistingFile || !policy.scope.namesSameLocation(as: scope) else {
      return nil
    }
    let others = policy.pendingMoves.filter { !$0.scope.namesSameLocation(as: scope) }
    guard others.count < maximumPendingMovesPerPolicy else { return nil }
    return PendingFolderMove(
      policyIdentifier: policy.id, scope: scope, retiredScopes: retiredScopes, source: source,
      destination: destination, allowedAt: now,
      destinationIsExistingFile: destinationIsExistingFile)
  }

  public var executionOriginStatus: ExecutionOriginStatus {
    state.withLock { $0.originTracker.status }
  }

  /// The event type of a log record for messages macOS dropped.
  public static let deliveryGapEventType = "DELIVERY_GAP"

  /// The notifications the execution histories are built from, by raw value.
  static let processEventRawValues = Set(processEventTypes.map(\.rawValue))

  /// Checks the numbering of one delivered message before it is handled. A gap in the numbering
  /// of process starts, forks or exits makes every execution history incomplete; any other
  /// dropped message only counts toward unchecked requests. Returns a finished stretch of gaps
  /// for `recordDeliveryGaps(_:)`, which the caller logs after answering the message.
  func observeDelivery(
    eventType: es_event_type_t, sequence: UInt64?, globalSequence: UInt64?, at time: Date
  ) -> DeliveryGapAccounting.Stretch? {
    let now = uptime()
    return state.withLock { state in
      let observation = state.deliveryGaps.observe(
        eventType: eventType.rawValue,
        isProcessEvent: Self.processEventRawValues.contains(eventType.rawValue),
        sequence: sequence, globalSequence: globalSequence, at: time, uptime: now)
      if observation.lacksNumbering {
        state.originTracker.invalidate(.unavailableEventVersion)
      } else if observation.lostProcessEvents {
        state.originTracker.invalidate(.eventLoss)
      }
      return observation.finished
    }
  }

  /// Logs the stretch of dropped messages whose one-second window has ended, or the open one when
  /// `force` is set. Call before reporting status and before closing the log.
  public func finishDeliveryGaps(force: Bool = false) {
    let now = uptime()
    if let finished = state.withLock({ $0.deliveryGaps.finish(uptime: now, force: force) }) {
      recordDeliveryGaps(finished)
    }
  }

  public var uncheckedRequestMetrics: UncheckedRequestMetrics {
    state.withLock { $0.deliveryGaps.metrics }
  }

  /// Saves one record for a stretch of dropped messages. It names no process and no policy, so
  /// only the global log receives it.
  func recordDeliveryGaps(_ stretch: DeliveryGapAccounting.Stretch) {
    let metadata = state.withLock { ($0.policySetIdentifier, $0.policyRevision) }
    sink.record(
      EndpointEventRecord(
        timestamp: stretch.firstGapAt,
        policySetIdentifier: metadata.0,
        policyRevision: metadata.1,
        eventSequence: stretch.firstSequence,
        eventType: Self.deliveryGapEventType,
        operatingSystemBuild: operatingSystemBuild,
        policyDecision: "unchecked",
        kernelResponse: "not-delivered",
        detail: "missedMessages=\(stretch.missedMessages) "
          + "missedProcessEvents=\(stretch.missedProcessEvents) "
          + "estimatedUncheckedRequests=\(stretch.estimatedUncheckedRequests) "
          + "gaps=\(stretch.gapCount)",
        lastTimestamp: stretch.gapCount > 1 ? stretch.lastGapAt : nil
      )
    )
  }

  /// These entry points accept the same kernel-derived facts as the Endpoint Security message
  /// handlers in this type (`handleExec`, `handleFork` and `handleExit`). Missing history is
  /// never reconstructed from a responsible token, nor from a current parent other than launchd:
  /// the one exception, an Apple platform binary that launchd forked before observation began,
  /// is described at `ExecutionHistoryEvidence.kernelLaunchdStart` and decided in
  /// `ExecutionOriginTracker.summary(for:)`.
  public func observeExec(from source: ExecutionProgram, to target: ExecutionProgram) {
    state.withLock { $0.originTracker.observeExec(from: source, to: target) }
  }

  public func observeFork(parent: ExecutionProgram, child: ExecutionProgram) {
    state.withLock { $0.originTracker.observeFork(parent: parent, child: child) }
  }

  public func observeExit(_ instance: ProcessInstanceKey) {
    state.withLock { $0.originTracker.observeExit(instance) }
  }

  public func invalidateExecutionOrigin(_ reason: ExecutionOriginUncertainty) {
    state.withLock { $0.originTracker.invalidate(reason) }
  }

  private func respondMeasured(
    client: OpaquePointer, message: UnsafePointer<es_message_t>, kind: FileOperationKind,
    allowed: Bool
  ) -> es_respond_result_t {
    let deadline = message.pointee.deadline
    let result: es_respond_result_t
    if kind.answersWithFlags {
      result = es_respond_flags_result(client, message, allowed ? UInt32.max : 0, false)
    } else {
      result = es_respond_auth_result(
        client, message, allowed ? ES_AUTH_RESULT_ALLOW : ES_AUTH_RESULT_DENY, false)
    }
    let finished = mach_absolute_time()
    responseMetrics.withLock {
      $0.responses &+= 1
      if result != ES_RESPOND_RESULT_SUCCESS { $0.failures &+= 1 }
      if finished >= deadline { $0.deadlineExceeded &+= 1 }
      let remaining = finished >= deadline ? 0 : deadline - finished
      $0.minimumRemainingTicks = min($0.minimumRemainingTicks ?? remaining, remaining)
    }
    return result
  }

  private func respond(
    client: OpaquePointer,
    message: UnsafePointer<es_message_t>,
    kind: FileOperationKind,
    allowed: Bool,
    record: EndpointEventRecord,
    emit: (EndpointEventRecord) -> Void
  ) {
    let result = respondMeasured(client: client, message: message, kind: kind, allowed: allowed)
    if result == ES_RESPOND_RESULT_SUCCESS {
      emit(record)
    } else {
      var failedRecord = record
      failedRecord.kernelResponse = "response-error"
      failedRecord.detail =
        kind.answersWithFlags
        ? "es_respond_flags_result failed." : "es_respond_auth_result failed."
      emit(failedRecord)
    }
  }

  private func recordLifecycleDecodeError(
    eventType: String,
    sequence: UInt64?,
    error: any Error,
    emit: (EndpointEventRecord) -> Void
  ) {
    invalidateExecutionOrigin(.decodeFailure)
    guard shouldRecordLifecycle else { return }
    let metadata = state.withLock { ($0.policySetIdentifier, $0.policyRevision) }
    emit(
      EndpointEventRecord(
        policySetIdentifier: metadata.0,
        policyRevision: metadata.1,
        eventSequence: sequence,
        eventType: eventType,
        operatingSystemBuild: operatingSystemBuild,
        policyDecision: "decode-error",
        kernelResponse: "notify-only",
        detail: String(describing: error)
      )
    )
  }

  private static func makeOriginEvaluation(
    for policy: ActivePolicyState, origin: ExecutionOriginDecision, enclosing: Bool = false
  ) -> PolicyEvaluationRecord {
    PolicyEvaluationRecord(
      policyIdentifier: policy.id, policyName: policy.name, mode: policy.mode,
      policyType: policy.policyType,
      match: enclosing
        ? .enclosingFolder
        : origin.actorRuleIdentifier != nil || origin.denyRuleIdentifier != nil
          ? .direct : (origin.inheritedRuleIdentifier != nil ? .inherited : .none),
      ruleIdentifier: origin.denyRuleIdentifier ?? origin.actorRuleIdentifier
        ?? origin.inheritedRuleIdentifier,
      decision: decision(mode: policy.mode, allows: origin.isAllowed),
      executionOrigin: origin)
  }

  /// The first compatibility profile of the policy under which the process may make this request.
  private static func admittingProfile(
    of policy: ActivePolicyState, process: ProcessFacts, request: FileOperationRequest,
    origin: ExecutionOriginDecision, parent: ExecutionProgram?
  ) -> ResolvedSystemCompatibilityProfile? {
    guard !policy.systemCompatibilityProfiles.isEmpty,
      let kind = SystemCompatibilityRequestKind(rawValue: request.kind.rawValue)
    else { return nil }
    let scope = policy.scope
    return policy.systemCompatibilityProfiles.first { profile in
      request.checkedPaths.allSatisfy {
        profile.pathForm.admits(
          $0.path, ownerHome: scope.ownerHome, caseSensitive: scope.caseSensitive)
      }
        && profile.admits(
          process: process, request: kind, openFlags: request.requestedOpenFlags, origin: origin,
          parent: parent, folderOwnerUserID: scope.ownerUserID)
    }
  }

  /// An allowing decision made by a compatibility profile. The execution-origin evidence
  /// records why the program lists alone would not have allowed the request.
  private static func makeProfileEvaluation(
    for policy: ActivePolicyState, profile: ResolvedSystemCompatibilityProfile,
    origin: ExecutionOriginDecision, enclosing: Bool
  ) -> PolicyEvaluationRecord {
    PolicyEvaluationRecord(
      policyIdentifier: policy.id, policyName: policy.name, mode: policy.mode,
      policyType: policy.policyType, match: .systemCompatibilityProfile,
      systemCompatibilityProfileIdentifier: profile.profileIdentifier,
      systemCompatibilityAuthorizationDigest: profile.authorizationDigest,
      decision: decision(mode: policy.mode, allows: true),
      detail: enclosing
        ? "The request acts on a folder that contains this policy’s folder." : nil,
      executionOrigin: origin)
  }

  private static func makeEnclosingRenameEvaluation(for policy: ActivePolicyState)
    -> PolicyEvaluationRecord
  {
    PolicyEvaluationRecord(
      policyIdentifier: policy.id, policyName: policy.name, mode: policy.mode,
      policyType: policy.policyType, match: .enclosingFolder,
      decision: decision(mode: policy.mode, allows: true))
  }

  private static func makeFailureEvaluation(
    for policy: ActivePolicyState,
    match: PolicyRuleMatchKind,
    detail: String
  ) -> PolicyEvaluationRecord {
    PolicyEvaluationRecord(
      policyIdentifier: policy.id,
      policyName: policy.name,
      mode: policy.mode,
      policyType: policy.policyType,
      match: match,
      decision: decision(mode: policy.mode, allows: false),
      detail: detail
    )
  }

  private static func decision(
    mode: PolicyMode,
    allows: Bool
  ) -> PolicyEvaluationDecision {
    switch (mode, allows) {
    case (.protection, true): .allow
    case (.protection, false): .deny
    case (.audit, true): .wouldAllow
    case (.audit, false): .wouldDeny
    }
  }

  static func evaluationDecision(
    mode: PolicyMode,
    policyType: PolicyType,
    match: RuleMatch
  ) -> PolicyEvaluationDecision {
    let didMatch = match != .none
    let allows = policyType == .whitelist ? didMatch : !didMatch
    return decision(mode: mode, allows: allows)
  }

  private func auditTokenDescription(_ token: AuditTokenKey) -> String {
    token.words.map(String.init).joined(separator: ",")
  }
}
