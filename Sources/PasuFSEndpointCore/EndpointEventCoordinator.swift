import EndpointSecurity
import Foundation
import PasuFSConfiguration
import PasuFSPolicy
import os

public enum EndpointHarnessMode: String, Codable, Sendable {
  case audit
  case enforce
}

public enum DecodeFailurePolicy: String, Codable, Sendable {
  case failOpen
  case failClosed
}

public typealias EndpointEventRecord = AuditEventRecord

public protocol EndpointEventSink: Sendable {
  func record(_ event: EndpointEventRecord)
}

public struct OpenFailureDecision: Equatable, Sendable {
  public let authorizedFlags: UInt32
  public let kernelResponse: String

  public init(authorizedFlags: UInt32, kernelResponse: String) {
    self.authorizedFlags = authorizedFlags
    self.kernelResponse = kernelResponse
  }
}

public struct EndpointPolicyConfiguration: Sendable {
  public let id: UUID
  public let name: String
  public let mode: PolicyMode
  public let policyType: PolicyType
  public let scope: ProtectedPathScope
  public let rules: PolicySnapshot

  public init(
    id: UUID,
    name: String,
    mode: PolicyMode,
    policyType: PolicyType,
    scope: ProtectedPathScope,
    rules: PolicySnapshot
  ) {
    self.id = id
    self.name = name
    self.mode = mode
    self.policyType = policyType
    self.scope = scope
    self.rules = rules
  }
}

public final class EndpointEventCoordinator: @unchecked Sendable {
  private struct ActivePolicyState: Sendable {
    var id: UUID
    var name: String
    var mode: PolicyMode
    var policyType: PolicyType
    var scope: ProtectedPathScope
    var evaluator: PolicyEvaluator

    init(configuration: EndpointPolicyConfiguration) {
      id = configuration.id
      name = configuration.name
      mode = configuration.mode
      policyType = configuration.policyType
      scope = configuration.scope
      evaluator = PolicyEvaluator(policy: configuration.rules)
    }
  }

  private struct MutableState: Sendable {
    var policySetIdentifier: UUID?
    var policies: [ActivePolicyState]
    var policyRevision: UInt64?
  }

  struct OpenEvaluation: Equatable, Sendable {
    let isInScope: Bool
    let policySetIdentifier: UUID?
    let policyRevision: UInt64?
    let policyDecision: String
    let policyEvaluations: [PolicyEvaluationRecord]
    let authorizedFlags: UInt32
    let detail: String?
  }

  private static let legacyPolicyIdentifier = UUID(
    uuidString: "00000000-0000-0000-0000-000000000001"
  )!

  private let state: OSAllocatedUnfairLock<MutableState>
  private let sink: any EndpointEventSink
  private let recordLifecycleEvents: Bool
  private let decodeFailurePolicy: DecodeFailurePolicy

  public init(
    policySetIdentifier: UUID,
    policies: [EndpointPolicyConfiguration],
    policyRevision: UInt64,
    sink: any EndpointEventSink,
    recordLifecycleEvents: Bool = false,
    decodeFailurePolicy: DecodeFailurePolicy = .failOpen
  ) {
    state = OSAllocatedUnfairLock(
      initialState: MutableState(
        policySetIdentifier: policySetIdentifier,
        policies: policies.map(ActivePolicyState.init),
        policyRevision: policyRevision
      )
    )
    self.sink = sink
    self.recordLifecycleEvents = recordLifecycleEvents
    self.decodeFailurePolicy = decodeFailurePolicy
  }

  /// Compatibility initializer for the single-whitelist development harness.
  public init(
    mode: EndpointHarnessMode,
    scope: ProtectedPathScope,
    policy: PolicySnapshot,
    policyRevision: UInt64? = nil,
    sink: any EndpointEventSink,
    recordLifecycleEvents: Bool = false,
    decodeFailurePolicy: DecodeFailurePolicy = .failOpen
  ) {
    state = OSAllocatedUnfairLock(
      initialState: MutableState(
        policySetIdentifier: nil,
        policies: [
          ActivePolicyState(
            configuration: EndpointPolicyConfiguration(
              id: Self.legacyPolicyIdentifier,
              name: "Development Harness",
              mode: mode == .audit ? .audit : .protection,
              policyType: .whitelist,
              scope: scope,
              rules: policy
            )
          )
        ],
        policyRevision: policyRevision
      )
    )
    self.sink = sink
    self.recordLifecycleEvents = recordLifecycleEvents
    self.decodeFailurePolicy = decodeFailurePolicy
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
        retained.evaluator.replacePolicy(with: configuration.rules)
        return retained
      }
      state.policySetIdentifier = setIdentifier
      state.policyRevision = revision
    }
  }

  /// Compatibility replacement for the single-whitelist development harness.
  public func replacePolicy(
    mode: EndpointHarnessMode,
    scope: ProtectedPathScope,
    policy: PolicySnapshot,
    revision: UInt64
  ) {
    replacePolicySet(
      setIdentifier: state.withLock { $0.policySetIdentifier } ?? UUID(),
      policies: [
        EndpointPolicyConfiguration(
          id: Self.legacyPolicyIdentifier,
          name: "Development Harness",
          mode: mode == .audit ? .audit : .protection,
          policyType: .whitelist,
          scope: scope,
          rules: policy
        )
      ],
      revision: revision
    )
  }

  public var currentPolicyRevision: UInt64? {
    state.withLock { $0.policyRevision }
  }

  public func handle(
    client: OpaquePointer,
    message: UnsafePointer<es_message_t>
  ) {
    switch message.pointee.event_type {
    case ES_EVENT_TYPE_NOTIFY_EXEC:
      handleExec(message)
    case ES_EVENT_TYPE_NOTIFY_FORK:
      handleFork(message)
    case ES_EVENT_TYPE_NOTIFY_EXIT:
      handleExit(message)
    case ES_EVENT_TYPE_AUTH_OPEN:
      handleOpen(client: client, message: message)
    default:
      break
    }
  }

  public static func failureDecision(
    mode: EndpointHarnessMode,
    policy: DecodeFailurePolicy
  ) -> OpenFailureDecision {
    let shouldDeny = mode == .enforce && policy == .failClosed
    return OpenFailureDecision(
      authorizedFlags: shouldDeny ? 0 : UInt32.max,
      kernelResponse: shouldDeny ? "deny" : "allow"
    )
  }

  private func handleExec(_ message: UnsafePointer<es_message_t>) {
    do {
      let source = try EndpointDecoder.process(message.pointee.process)
      let process = try EndpointDecoder.process(message.pointee.event.exec.target)
      let evaluation = state.withLock { state -> ([PolicyEvaluationRecord], UUID?, UInt64?) in
        var records: [PolicyEvaluationRecord] = []
        for index in state.policies.indices {
          state.policies[index].evaluator.observeExec(
            from: source.facts.processInstance,
            to: process.facts
          )
          let match = state.policies[index].evaluator.match(for: process.facts)
          if match != .none {
            records.append(Self.makeEvaluation(for: state.policies[index], match: match))
          }
        }
        return (records, state.policySetIdentifier, state.policyRevision)
      }
      guard recordLifecycleEvents else { return }

      sink.record(
        EndpointEventRecord(
          policySetIdentifier: evaluation.1,
          policyRevision: evaluation.2,
          eventSequence: message.pointee.seq_num,
          eventType: "NOTIFY_EXEC",
          processID: process.processID,
          executablePath: process.executablePath,
          teamIdentifier: process.facts.teamIdentifier,
          signingIdentifier: process.facts.signingIdentifier,
          isPlatformBinary: process.facts.isPlatformBinary,
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
        sequence: message.pointee.seq_num,
        error: error
      )
    }
  }

  private func handleFork(_ message: UnsafePointer<es_message_t>) {
    do {
      let parent = try EndpointDecoder.process(message.pointee.process)
      let child = try EndpointDecoder.process(message.pointee.event.fork.child)
      let evaluation = state.withLock { state -> ([PolicyEvaluationRecord], UUID?, UInt64?) in
        var records: [PolicyEvaluationRecord] = []
        for index in state.policies.indices {
          state.policies[index].evaluator.observeFork(
            parent: parent.facts.processInstance,
            child: child.facts.processInstance
          )
          let match = state.policies[index].evaluator.match(for: child.facts)
          if match != .none {
            records.append(Self.makeEvaluation(for: state.policies[index], match: match))
          }
        }
        return (records, state.policySetIdentifier, state.policyRevision)
      }
      guard recordLifecycleEvents else { return }

      let forkDetail = [
        "parentProcessID=\(parent.processID)",
        "parentPath=\(parent.executablePath)",
        "parentAuditToken=\(auditTokenDescription(parent.facts.auditToken))",
        "childAuditToken=\(auditTokenDescription(child.facts.auditToken))",
      ].joined(separator: " ")

      sink.record(
        EndpointEventRecord(
          policySetIdentifier: evaluation.1,
          policyRevision: evaluation.2,
          eventSequence: message.pointee.seq_num,
          eventType: "NOTIFY_FORK",
          processID: child.processID,
          executablePath: child.executablePath,
          teamIdentifier: child.facts.teamIdentifier,
          signingIdentifier: child.facts.signingIdentifier,
          isPlatformBinary: child.facts.isPlatformBinary,
          policyDecision: evaluation.0.isEmpty ? "no-rule-match" : "matched-rules",
          kernelResponse: "notify-only",
          policyEvaluations: evaluation.0,
          detail: forkDetail
        )
      )
    } catch {
      recordLifecycleDecodeError(
        eventType: "NOTIFY_FORK",
        sequence: message.pointee.seq_num,
        error: error
      )
    }
  }

  private func handleExit(_ message: UnsafePointer<es_message_t>) {
    do {
      let process = try EndpointDecoder.process(message.pointee.process)
      let evaluation = state.withLock { state -> ([PolicyEvaluationRecord], UUID?, UInt64?) in
        var records: [PolicyEvaluationRecord] = []
        for index in state.policies.indices {
          let match = state.policies[index].evaluator.match(for: process.facts)
          if match != .none {
            records.append(Self.makeEvaluation(for: state.policies[index], match: match))
          }
          state.policies[index].evaluator.observeExit(process.facts.processInstance)
        }
        return (records, state.policySetIdentifier, state.policyRevision)
      }
      guard recordLifecycleEvents else { return }

      sink.record(
        EndpointEventRecord(
          policySetIdentifier: evaluation.1,
          policyRevision: evaluation.2,
          eventSequence: message.pointee.seq_num,
          eventType: "NOTIFY_EXIT",
          processID: process.processID,
          executablePath: process.executablePath,
          teamIdentifier: process.facts.teamIdentifier,
          signingIdentifier: process.facts.signingIdentifier,
          isPlatformBinary: process.facts.isPlatformBinary,
          policyDecision: evaluation.0.isEmpty ? "no-rule-match" : "matched-rules",
          kernelResponse: "notify-only",
          policyEvaluations: evaluation.0,
          detail: "auditToken=\(auditTokenDescription(process.facts.auditToken))"
        )
      )
    } catch {
      recordLifecycleDecodeError(
        eventType: "NOTIFY_EXIT",
        sequence: message.pointee.seq_num,
        error: error
      )
    }
  }

  private func handleOpen(
    client: OpaquePointer,
    message: UnsafePointer<es_message_t>
  ) {
    let openEvent = message.pointee.event.open
    let file = EndpointDecoder.file(openEvent.file)
    let processResult = Result {
      try EndpointDecoder.process(message.pointee.process)
    }

    let process = try? processResult.get()
    let decodeErrorDescription: String?
    switch processResult {
    case .success:
      decodeErrorDescription = nil
    case .failure(let error):
      decodeErrorDescription = String(describing: error)
    }
    let evaluation = evaluateOpen(
      path: file.path,
      pathWasTruncated: file.pathWasTruncated,
      process: process?.facts,
      decodeErrorDescription: decodeErrorDescription
    )

    guard evaluation.isInScope else {
      _ = es_respond_flags_result(client, message, UInt32.max, false)
      return
    }

    respond(
      client: client,
      message: message,
      authorizedFlags: evaluation.authorizedFlags,
      record: EndpointEventRecord(
        policySetIdentifier: evaluation.policySetIdentifier,
        policyRevision: evaluation.policyRevision,
        eventSequence: message.pointee.seq_num,
        eventType: "AUTH_OPEN",
        processID: process?.processID,
        executablePath: process?.executablePath,
        teamIdentifier: process?.facts.teamIdentifier,
        signingIdentifier: process?.facts.signingIdentifier,
        isPlatformBinary: process?.facts.isPlatformBinary,
        targetPath: file.path,
        pathWasTruncated: file.pathWasTruncated,
        requestedFlags: openEvent.fflag,
        policyDecision: evaluation.policyDecision,
        kernelResponse: evaluation.authorizedFlags == 0 ? "deny" : "allow",
        policyEvaluations: evaluation.policyEvaluations,
        detail: evaluation.detail
      )
    )
  }

  func evaluateOpen(
    path: String,
    pathWasTruncated: Bool,
    process: ProcessFacts?,
    decodeErrorDescription: String? = nil
  ) -> OpenEvaluation {
    state.withLock { state -> OpenEvaluation in
      let matchingIndices = state.policies.indices.filter {
        state.policies[$0].scope.contains(path)
      }
      guard !matchingIndices.isEmpty else {
        return OpenEvaluation(
          isInScope: false,
          policySetIdentifier: state.policySetIdentifier,
          policyRevision: state.policyRevision,
          policyDecision: "outside-scope",
          policyEvaluations: [],
          authorizedFlags: UInt32.max,
          detail: nil
        )
      }

      let records: [PolicyEvaluationRecord]
      let detail: String?
      if pathWasTruncated {
        records = matchingIndices.map {
          Self.makeFailureEvaluation(
            for: state.policies[$0],
            match: .truncatedPath,
            detail: "The reported truncated prefix is inside this policy scope."
          )
        }
        detail = "The reported truncated prefix is inside at least one policy scope."
      } else {
        if let process {
          records = matchingIndices.map {
            let policy = state.policies[$0]
            return Self.makeEvaluation(
              for: policy,
              match: policy.evaluator.match(for: process)
            )
          }
          detail = nil
        } else {
          let errorDescription = decodeErrorDescription ?? "Process facts are unavailable."
          records = matchingIndices.map {
            Self.makeFailureEvaluation(
              for: state.policies[$0],
              match: .decodeError,
              detail: errorDescription
            )
          }
          detail = errorDescription
        }
      }

      let hasProtectionPolicy = records.contains { $0.mode == .protection }
      let shouldDeny = records.contains {
        $0.mode == .protection && $0.decision == .deny
      }
      let authorizedFlags: UInt32
      if shouldDeny, decodeFailurePolicy == .failOpen,
        records.allSatisfy({ $0.match == .decodeError || $0.match == .truncatedPath })
      {
        authorizedFlags = UInt32.max
      } else {
        authorizedFlags = shouldDeny ? 0 : UInt32.max
      }
      let finalDenied = authorizedFlags == 0
      return OpenEvaluation(
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

  /// Pure-facts lifecycle entry points used by integration adapters and tests
  /// that do not construct raw Endpoint Security messages.
  func observeExec(_ process: ProcessFacts) {
    state.withLock { state in
      for index in state.policies.indices {
        state.policies[index].evaluator.observeExec(process)
      }
    }
  }

  func observeFork(
    parent: ProcessInstanceKey,
    child: ProcessInstanceKey
  ) {
    state.withLock { state in
      for index in state.policies.indices {
        state.policies[index].evaluator.observeFork(parent: parent, child: child)
      }
    }
  }

  private func respond(
    client: OpaquePointer,
    message: UnsafePointer<es_message_t>,
    authorizedFlags: UInt32,
    record: EndpointEventRecord
  ) {
    let result = es_respond_flags_result(client, message, authorizedFlags, false)
    if result == ES_RESPOND_RESULT_SUCCESS {
      sink.record(record)
    } else {
      var failedRecord = record
      failedRecord.kernelResponse = "response-error"
      failedRecord.detail = "es_respond_flags_result failed."
      sink.record(failedRecord)
    }
  }

  private func recordLifecycleDecodeError(
    eventType: String,
    sequence: UInt64,
    error: any Error
  ) {
    guard recordLifecycleEvents else { return }
    let metadata = state.withLock { ($0.policySetIdentifier, $0.policyRevision) }
    sink.record(
      EndpointEventRecord(
        policySetIdentifier: metadata.0,
        policyRevision: metadata.1,
        eventSequence: sequence,
        eventType: eventType,
        policyDecision: "decode-error",
        kernelResponse: "notify-only",
        detail: String(describing: error)
      )
    )
  }

  private static func makeEvaluation(
    for policy: ActivePolicyState,
    match: RuleMatch
  ) -> PolicyEvaluationRecord {
    let matchKind: PolicyRuleMatchKind
    let ruleIdentifier: String?
    switch match {
    case .direct(let ruleID):
      matchKind = .direct
      ruleIdentifier = ruleID
    case .inherited(let ruleID):
      matchKind = .inherited
      ruleIdentifier = ruleID
    case .none:
      matchKind = .none
      ruleIdentifier = nil
    }

    return PolicyEvaluationRecord(
      policyIdentifier: policy.id,
      policyName: policy.name,
      mode: policy.mode,
      policyType: policy.policyType,
      match: matchKind,
      ruleIdentifier: ruleIdentifier,
      decision: evaluationDecision(
        mode: policy.mode,
        policyType: policy.policyType,
        match: match
      )
    )
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
