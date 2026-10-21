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

  public var executionProgram: ExecutionProgram {
    ExecutionProgram(
      facts: facts, executablePath: executablePath,
      pathWasTruncated: executablePathWasTruncated)
  }

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

/// The location of a mounted file system: where it appears and what it was mounted from.
public struct MountedVolume: Equatable, Sendable {
  public let mountPoint: String
  public let source: String?

  public init(mountPoint: String, source: String?) {
    self.mountPoint = mountPoint
    self.source = source
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
    default: type = FileOperationKind(eventType: message.event_type)?.rawValue ?? "OTHER"
    }
    var result = LineageObservation(
      eventType: type, timestamp: timestamp,
      sequence: message.version >= 2 ? message.seq_num : nil,
      globalSequence: message.version >= 4 ? message.global_seq_num : nil,
      machTime: message.mach_time
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

  /// The paths of an authorization event, read from the fields Endpoint Security documents for
  /// that event.
  public static func fileOperation(
    _ kind: FileOperationKind, event: es_events_t
  ) -> FileOperationRequest {
    switch kind {
    case .open:
      let open = event.open
      return .open(file(open.file), flags: UInt32(bitPattern: open.fflag))
    case .create:
      let create = event.create
      if create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        return .create(existing: file(create.destination.existing_file))
      }
      return .create(
        in: file(create.destination.new_path.dir),
        name: string(create.destination.new_path.filename)
      )
    case .rename:
      let rename = event.rename
      let destination: CheckedPath
      if rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE {
        destination = CheckedPath(file(rename.destination.existing_file))
      } else {
        destination = CheckedPath(
          directory: file(rename.destination.new_path.dir),
          name: string(rename.destination.new_path.filename))
      }
      return .rename(
        source: file(rename.source), destination: destination,
        destinationIsExistingFile: rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE)
    case .unlink:
      return .unlink(target: file(event.unlink.target))
    case .link:
      let link = event.link
      return .link(
        source: file(link.source), targetDirectory: file(link.target_dir),
        name: string(link.target_filename))
    case .clone:
      let clone = event.clone
      return .clone(
        source: file(clone.source), targetDirectory: file(clone.target_dir),
        name: string(clone.target_name))
    case .copyFile:
      let copy = event.copyfile
      return .copyFile(
        source: file(copy.source), existingTarget: copy.target_file.map { file($0) },
        targetDirectory: file(copy.target_dir), name: string(copy.target_name))
    case .truncate:
      return .truncate(target: file(event.truncate.target))
    case .exchangeData:
      let exchange = event.exchangedata
      return .exchangeData(file(exchange.file1), file(exchange.file2))
    case .setMode:
      return .metadataChange(kind, target: file(event.setmode.target))
    case .setOwner:
      return .metadataChange(kind, target: file(event.setowner.target))
    case .setFlags:
      return .metadataChange(kind, target: file(event.setflags.target))
    case .setACL:
      return .metadataChange(kind, target: file(event.setacl.target))
    case .setExtendedAttribute:
      return .metadataChange(kind, target: file(event.setextattr.target))
    case .deleteExtendedAttribute:
      return .metadataChange(kind, target: file(event.deleteextattr.target))
    case .setAttributeList:
      return .metadataChange(kind, target: file(event.setattrlist.target))
    case .setTimes:
      return .metadataChange(kind, target: file(event.utimes.target))
    case .mount:
      let volume = mountedVolume(event.mount.statfs)
      return .mount(mountPoint: volume.mountPoint, volumeSource: volume.source)
    }
  }

  /// The mount point and source of the file system an unmount notification names.
  public static func unmountedVolume(_ event: es_events_t) -> MountedVolume {
    mountedVolume(event.unmount.statfs)
  }

  /// `f_mntonname` and `f_mntfromname` of a `statfs` record, as the kernel spelled them.
  public static func mountedVolume(_ pointer: UnsafePointer<statfs>) -> MountedVolume {
    var record = pointer.pointee
    let mountPoint = withUnsafePointer(to: &record.f_mntonname) {
      $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
    }
    let source = withUnsafePointer(to: &record.f_mntfromname) {
      $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
    }
    return MountedVolume(mountPoint: mountPoint, source: source.isEmpty ? nil : source)
  }

  /// `messageVersion` decides whether the start time (version 3 and later) and the parent's
  /// audit token (version 4 and later) are reported.
  public static func process(
    _ pointer: UnsafePointer<es_process_t>, messageVersion: UInt32 = 0
  ) throws -> EndpointProcessSnapshot {
    let process = pointer.pointee
    let executable = file(UnsafePointer(process.executable))
    let processID = audit_token_to_pid(process.audit_token)
    let parentID = messageVersion >= 4 ? audit_token_to_pid(process.parent_audit_token) : 0
    let startTime =
      messageVersion >= 3 && process.start_time.tv_sec > 0
      ? Date(
        timeIntervalSince1970: Double(process.start_time.tv_sec)
          + Double(process.start_time.tv_usec) / 1_000_000) : nil
    let facts = ProcessFacts(
      auditToken: try auditTokenKey(process.audit_token),
      processInstance: ProcessInstanceKey(
        processID: processID,
        processVersion: Int32(audit_token_to_pidversion(process.audit_token))
      ),
      teamIdentifier: string(process.team_id),
      signingIdentifier: string(process.signing_id),
      isPlatformBinary: process.is_platform_binary,
      codeSigningFlags: process.codesigning_flags,
      effectiveUserID: audit_token_to_euid(process.audit_token),
      originalParentProcessID: process.original_ppid,
      parentProcessInstance: parentID > 0
        ? ProcessInstanceKey(
          processID: parentID,
          processVersion: Int32(audit_token_to_pidversion(process.parent_audit_token))) : nil,
      parentEffectiveUserID: parentID > 0 ? audit_token_to_euid(process.parent_audit_token) : nil,
      startTime: startTime
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
