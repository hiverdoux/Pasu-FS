import Darwin
import EndpointSecurity
import Foundation
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
      isPlatformBinary: process.is_platform_binary
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
