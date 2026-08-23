import EndpointSecurity
import Foundation
import PasuFSPolicy

public enum EndpointHarnessMode: String, Codable, Sendable {
  case audit
  case enforce
}

public struct EndpointEventRecord: Codable, Equatable, Sendable {
  public let timestamp: Date
  public let eventType: String
  public let processID: Int32?
  public let executablePath: String?
  public let teamIdentifier: String?
  public let signingIdentifier: String?
  public let targetPath: String?
  public let requestedFlags: Int32?
  public let policyDecision: String
  public let kernelResponse: String
  public let detail: String?

  public init(
    timestamp: Date = Date(),
    eventType: String,
    processID: Int32? = nil,
    executablePath: String? = nil,
    teamIdentifier: String? = nil,
    signingIdentifier: String? = nil,
    targetPath: String? = nil,
    requestedFlags: Int32? = nil,
    policyDecision: String,
    kernelResponse: String,
    detail: String? = nil
  ) {
    self.timestamp = timestamp
    self.eventType = eventType
    self.processID = processID
    self.executablePath = executablePath
    self.teamIdentifier = teamIdentifier
    self.signingIdentifier = signingIdentifier
    self.targetPath = targetPath
    self.requestedFlags = requestedFlags
    self.policyDecision = policyDecision
    self.kernelResponse = kernelResponse
    self.detail = detail
  }
}

public protocol EndpointEventSink: Sendable {
  func record(_ event: EndpointEventRecord)
}

public final class EndpointEventCoordinator: @unchecked Sendable {
  private let mode: EndpointHarnessMode
  private let scope: ProtectedPathScope
  private let sink: any EndpointEventSink
  private let recordLifecycleEvents: Bool
  private var evaluator: PolicyEvaluator

  public init(
    mode: EndpointHarnessMode,
    scope: ProtectedPathScope,
    policy: PolicySnapshot,
    sink: any EndpointEventSink,
    recordLifecycleEvents: Bool = false
  ) {
    self.mode = mode
    self.scope = scope
    self.sink = sink
    self.recordLifecycleEvents = recordLifecycleEvents
    self.evaluator = PolicyEvaluator(policy: policy)
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

  private func handleExec(_ message: UnsafePointer<es_message_t>) {
    do {
      let source = try EndpointDecoder.process(message.pointee.process)
      let process = try EndpointDecoder.process(message.pointee.event.exec.target)
      evaluator.observeExec(from: source.facts.processInstance, to: process.facts)
      guard recordLifecycleEvents else { return }

      sink.record(
        EndpointEventRecord(
          eventType: "NOTIFY_EXEC",
          processID: process.processID,
          executablePath: process.executablePath,
          teamIdentifier: process.facts.teamIdentifier,
          signingIdentifier: process.facts.signingIdentifier,
          policyDecision: policyDescription(evaluator.decision(for: process.facts)),
          kernelResponse: "notify-only",
          detail: "sourceAuditToken=\(auditTokenDescription(source.facts.auditToken)) "
            + "targetAuditToken=\(auditTokenDescription(process.facts.auditToken))"
        )
      )
    } catch {
      sink.record(
        EndpointEventRecord(
          eventType: "NOTIFY_EXEC",
          policyDecision: "decode-error",
          kernelResponse: "notify-only",
          detail: String(describing: error)
        )
      )
    }
  }

  private func handleFork(_ message: UnsafePointer<es_message_t>) {
    do {
      let parent = try EndpointDecoder.process(message.pointee.process)
      let child = try EndpointDecoder.process(message.pointee.event.fork.child)
      let parentDecision = evaluator.decision(for: parent.facts)
      evaluator.observeFork(
        parent: parent.facts.processInstance,
        child: child.facts.processInstance
      )
      guard recordLifecycleEvents else { return }
      let forkDetail = [
        "parentProcessID=\(parent.processID)",
        "parentDecision=\(policyDescription(parentDecision))",
        "parentPath=\(parent.executablePath)",
        "parentAuditToken=\(auditTokenDescription(parent.facts.auditToken))",
        "childAuditToken=\(auditTokenDescription(child.facts.auditToken))",
      ].joined(separator: " ")

      sink.record(
        EndpointEventRecord(
          eventType: "NOTIFY_FORK",
          processID: child.processID,
          executablePath: child.executablePath,
          teamIdentifier: child.facts.teamIdentifier,
          signingIdentifier: child.facts.signingIdentifier,
          policyDecision: policyDescription(evaluator.decision(for: child.facts)),
          kernelResponse: "notify-only",
          detail: forkDetail
        )
      )
    } catch {
      sink.record(
        EndpointEventRecord(
          eventType: "NOTIFY_FORK",
          policyDecision: "decode-error",
          kernelResponse: "notify-only",
          detail: String(describing: error)
        )
      )
    }
  }

  private func handleExit(_ message: UnsafePointer<es_message_t>) {
    do {
      let process = try EndpointDecoder.process(message.pointee.process)
      let decision = evaluator.decision(for: process.facts)
      evaluator.observeExit(process.facts.processInstance)
      guard recordLifecycleEvents else { return }

      sink.record(
        EndpointEventRecord(
          eventType: "NOTIFY_EXIT",
          processID: process.processID,
          executablePath: process.executablePath,
          teamIdentifier: process.facts.teamIdentifier,
          signingIdentifier: process.facts.signingIdentifier,
          policyDecision: policyDescription(decision),
          kernelResponse: "notify-only",
          detail: "auditToken=\(auditTokenDescription(process.facts.auditToken))"
        )
      )
    } catch {
      sink.record(
        EndpointEventRecord(
          eventType: "NOTIFY_EXIT",
          policyDecision: "decode-error",
          kernelResponse: "notify-only",
          detail: String(describing: error)
        )
      )
    }
  }

  private func handleOpen(
    client: OpaquePointer,
    message: UnsafePointer<es_message_t>
  ) {
    let openEvent = message.pointee.event.open
    let file = EndpointDecoder.file(openEvent.file)

    guard !file.pathWasTruncated else {
      respond(
        client: client,
        message: message,
        authorizedFlags: UInt32.max,
        record: EndpointEventRecord(
          eventType: "AUTH_OPEN",
          targetPath: file.path,
          requestedFlags: openEvent.fflag,
          policyDecision: "unscoped-truncated-path",
          kernelResponse: "allow",
          detail: "A truncated path is never denied by this integration harness."
        )
      )
      return
    }

    guard scope.contains(file.path) else {
      _ = es_respond_flags_result(client, message, UInt32.max, false)
      return
    }

    do {
      let process = try EndpointDecoder.process(message.pointee.process)
      let decision = evaluator.decision(for: process.facts)
      let shouldAllow = decision != .denied
      let authorizedFlags: UInt32 = mode == .audit || shouldAllow ? UInt32.max : 0
      let kernelResponse = authorizedFlags == 0 ? "deny" : "allow"

      respond(
        client: client,
        message: message,
        authorizedFlags: authorizedFlags,
        record: EndpointEventRecord(
          eventType: "AUTH_OPEN",
          processID: process.processID,
          executablePath: process.executablePath,
          teamIdentifier: process.facts.teamIdentifier,
          signingIdentifier: process.facts.signingIdentifier,
          targetPath: file.path,
          requestedFlags: openEvent.fflag,
          policyDecision: policyDescription(decision),
          kernelResponse: kernelResponse,
          detail: mode == .audit && !shouldAllow ? "Audit mode would deny in enforce mode." : nil
        )
      )
    } catch {
      respond(
        client: client,
        message: message,
        authorizedFlags: UInt32.max,
        record: EndpointEventRecord(
          eventType: "AUTH_OPEN",
          targetPath: file.path,
          requestedFlags: openEvent.fflag,
          policyDecision: "decode-error",
          kernelResponse: "allow",
          detail: String(describing: error)
        )
      )
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
      sink.record(
        EndpointEventRecord(
          eventType: record.eventType,
          processID: record.processID,
          executablePath: record.executablePath,
          teamIdentifier: record.teamIdentifier,
          signingIdentifier: record.signingIdentifier,
          targetPath: record.targetPath,
          requestedFlags: record.requestedFlags,
          policyDecision: record.policyDecision,
          kernelResponse: "response-error",
          detail: "es_respond_flags_result failed."
        )
      )
    }
  }

  private func policyDescription(_ decision: AuthorizationDecision) -> String {
    switch decision {
    case .allowedDirect(let ruleID):
      "allowed-direct:\(ruleID)"
    case .allowedInherited(let ruleID):
      "allowed-inherited:\(ruleID)"
    case .denied:
      "denied"
    }
  }

  private func auditTokenDescription(_ token: AuditTokenKey) -> String {
    token.words.map(String.init).joined(separator: ",")
  }
}
