import Darwin
import EndpointSecurity
import Foundation
import PasuFSConfiguration
import PasuFSPolicy

public struct EndpointProcessSnapshot: Equatable, Sendable {
  public let facts: ProcessFacts
  public let processID: Int32
  public let executablePath: String
  public let executablePathWasTruncated: Bool
  public let isPlatformBinary: Bool
  public let isEndpointSecurityClient: Bool

  public init(
    facts: ProcessFacts,
    processID: Int32,
    executablePath: String,
    executablePathWasTruncated: Bool,
    isPlatformBinary: Bool,
    isEndpointSecurityClient: Bool
  ) {
    self.facts = facts
    self.processID = processID
    self.executablePath = executablePath
    self.executablePathWasTruncated = executablePathWasTruncated
    self.isPlatformBinary = isPlatformBinary
    self.isEndpointSecurityClient = isEndpointSecurityClient
  }
}

public struct EndpointFileSnapshot: Equatable, Sendable {
  public let path: String
  public let pathWasTruncated: Bool

  public init(path: String, pathWasTruncated: Bool) {
    self.path = path
    self.pathWasTruncated = pathWasTruncated
  }
}

public enum EndpointDecoder {
  public static func lineageObservation(_ pointer: UnsafePointer<es_message_t>)
    -> LineageObservation
  {
    let message = pointer.pointee
    let timestamp = Date(
      timeIntervalSince1970: Double(message.time.tv_sec) + Double(message.time.tv_nsec)
        / 1_000_000_000)
    let type: String
    switch message.event_type {
    case ES_EVENT_TYPE_NOTIFY_FORK: type = "NOTIFY_FORK"
    case ES_EVENT_TYPE_NOTIFY_EXEC: type = "NOTIFY_EXEC"
    case ES_EVENT_TYPE_NOTIFY_EXIT: type = "NOTIFY_EXIT"
    case ES_EVENT_TYPE_AUTH_OPEN: type = "AUTH_OPEN"
    default: type = "OTHER"
    }
    var result = LineageObservation(
      eventType: type, timestamp: timestamp,
      sequence: message.version >= 2 ? message.seq_num : nil,
      globalSequence: message.version >= 4 ? message.global_seq_num : nil
    )
    if message.version < 4 { result.issues.append("versionUnavailable") }
    do {
      result.source = try lineageProcess(message.process, version: message.version, at: timestamp)
      if message.event_type == ES_EVENT_TYPE_NOTIFY_FORK {
        result.target = try lineageProcess(
          message.event.fork.child, version: message.version, at: timestamp)
      } else if message.event_type == ES_EVENT_TYPE_NOTIFY_EXEC {
        result.target = try lineageProcess(
          message.event.exec.target, version: message.version, at: timestamp)
      }
    } catch {
      result.issues.append("decodeError")
    }
    return result
  }

  static func lineageProcess(
    _ pointer: UnsafePointer<es_process_t>, version: UInt32, at: Date
  ) throws -> LineageProcess {
    let raw = pointer.pointee
    let decoded = try process(pointer)
    func key(_ token: audit_token_t) -> LineageProcessKey? {
      let pid = audit_token_to_pid(token)
      guard pid > 0 else { return nil }
      return LineageProcessKey(pid: pid, version: Int32(audit_token_to_pidversion(token)))
    }
    let instance = decoded.facts.processInstance
    return LineageProcess(
      key: LineageProcessKey(pid: instance.processID, version: instance.processVersion),
      executablePath: decoded.executablePath, pathWasTruncated: decoded.executablePathWasTruncated,
      signingIdentifier: decoded.facts.signingIdentifier,
      teamIdentifier: decoded.facts.teamIdentifier,
      codeSigningFlags: decoded.facts.codeSigningFlags, isPlatformBinary: decoded.isPlatformBinary,
      startTime: version >= 3
        ? Date(
          timeIntervalSince1970: Double(raw.start_time.tv_sec) + Double(raw.start_time.tv_usec)
            / 1_000_000) : nil,
      parent: version >= 4 ? key(raw.parent_audit_token) : nil,
      responsible: version >= 4 ? key(raw.responsible_audit_token) : nil,
      originalParentPID: raw.original_ppid, observedAt: at
    )
  }

  public static func auditTokenKey(_ token: audit_token_t) throws -> AuditTokenKey {
    var copy = token
    let words = withUnsafeBytes(of: &copy) { rawBuffer in
      Array(rawBuffer.bindMemory(to: UInt32.self))
    }
    return try AuditTokenKey(words: words)
  }

  public static func string(_ token: es_string_token_t) -> String? {
    guard token.length > 0, let data = token.data else {
      return nil
    }

    let bytes = UnsafeRawBufferPointer(start: data, count: Int(token.length))
    return String(decoding: bytes, as: UTF8.self)
  }

  public static func file(_ pointer: UnsafePointer<es_file_t>) -> EndpointFileSnapshot {
    let file = pointer.pointee
    return EndpointFileSnapshot(
      path: string(file.path) ?? "",
      pathWasTruncated: file.path_truncated
    )
  }

  public static func process(
    _ pointer: UnsafePointer<es_process_t>
  ) throws -> EndpointProcessSnapshot {
    let process = pointer.pointee
    let executable = file(UnsafePointer(process.executable))
    let processID = audit_token_to_pid(process.audit_token)
    let facts = ProcessFacts(
      auditToken: try auditTokenKey(process.audit_token),
      processInstance: ProcessInstanceKey(
        processID: processID,
        processVersion: Int32(audit_token_to_pidversion(process.audit_token))
      ),
      teamIdentifier: string(process.team_id),
      signingIdentifier: string(process.signing_id),
      isPlatformBinary: process.is_platform_binary,
      codeSigningFlags: process.codesigning_flags
    )

    return EndpointProcessSnapshot(
      facts: facts,
      processID: processID,
      executablePath: executable.path,
      executablePathWasTruncated: executable.pathWasTruncated,
      isPlatformBinary: process.is_platform_binary,
      isEndpointSecurityClient: process.is_es_client
    )
  }
}
