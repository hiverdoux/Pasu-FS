import Darwin
import Dispatch
import Foundation
import os

public enum JSONLineEventLoggerError: Error, CustomStringConvertible, Sendable {
  case invalidDirectory(String)
  case ownerMismatch(path: String, expected: UInt32, actual: UInt32)
  case unsafePermissions(String)
  case systemCall(operation: String, code: Int32)

  public var description: String {
    switch self {
    case .invalidDirectory(let path):
      "Audit-log directory is not a real directory: \(path)."
    case .ownerMismatch(let path, let expected, let actual):
      "Audit-log owner mismatch for \(path): expected \(expected), found \(actual)."
    case .unsafePermissions(let path):
      "Audit-log location is writable by a group or other users: \(path)."
    case .systemCall(let operation, let code):
      "\(operation) failed with errno \(code): \(String(cString: strerror(code)))."
    }
  }
}

public final class JSONLineEventLogger: EndpointEventSink, @unchecked Sendable {
  private struct State {
    var droppedEventCount: UInt64 = 0
    var lastErrorDescription: String?
    var isClosed = false
  }

  public let fileURL: URL

  private let directoryURL: URL
  private let filename: String
  private let requiredOwnerUserID: UInt32?
  private let maximumFileSize: Int64
  private let pendingSlots: DispatchSemaphore
  private let queue: DispatchQueue
  private let state = OSAllocatedUnfairLock(initialState: State())
  private var fileDescriptor: Int32

  public init(
    directoryURL: URL,
    filename: String = "endpoint-events.jsonl",
    requiredOwnerUserID: UInt32? = nil,
    maximumPendingRecords: Int = 1_024,
    maximumFileSize: Int64 = 10 * 1_024 * 1_024,
    fileMode: mode_t = 0o600
  ) throws {
    precondition(maximumPendingRecords > 0)
    precondition(maximumFileSize > 0)
    self.directoryURL = directoryURL.standardizedFileURL
    self.filename = filename
    self.requiredOwnerUserID = requiredOwnerUserID
    self.maximumFileSize = maximumFileSize
    self.pendingSlots = DispatchSemaphore(value: maximumPendingRecords)
    self.queue = DispatchQueue(label: "com.dennis.pasu.fs.endpoint-audit-log")
    self.fileURL = self.directoryURL.appendingPathComponent(filename, isDirectory: false)
    self.fileDescriptor = -1

    try FileManager.default.createDirectory(
      at: self.directoryURL,
      withIntermediateDirectories: true
    )
    try Self.validateDirectory(
      self.directoryURL,
      requiredOwnerUserID: requiredOwnerUserID
    )
    self.fileDescriptor = try Self.openLogFile(
      self.fileURL,
      requiredOwnerUserID: requiredOwnerUserID,
      mode: fileMode
    )
  }

  deinit {
    flushAndClose()
  }

  public var droppedEventCount: UInt64 {
    state.withLock { $0.droppedEventCount }
  }

  public var lastErrorDescription: String? {
    state.withLock { $0.lastErrorDescription }
  }

  public func record(_ event: EndpointEventRecord) {
    let isClosed = state.withLock { $0.isClosed }
    guard !isClosed else { return }
    guard pendingSlots.wait(timeout: .now()) == .success else {
      state.withLock { $0.droppedEventCount &+= 1 }
      return
    }

    queue.async { [weak self] in
      defer { self?.pendingSlots.signal() }
      self?.write(event)
    }
  }

  public func flushAndClose() {
    let shouldClose = state.withLock { state in
      guard !state.isClosed else { return false }
      state.isClosed = true
      return true
    }
    guard shouldClose else { return }

    queue.sync {
      guard fileDescriptor >= 0 else { return }
      _ = fsync(fileDescriptor)
      close(fileDescriptor)
      fileDescriptor = -1
    }
  }

  private func write(_ event: EndpointEventRecord) {
    do {
      let encoder = JSONEncoder()
      encoder.dateEncodingStrategy = .iso8601
      encoder.outputFormatting = [.sortedKeys]
      var data = try encoder.encode(event)
      data.append(0x0A)
      try rotateIfNeeded(addingByteCount: data.count)
      try writeAll(data)
    } catch {
      state.withLock { state in
        state.droppedEventCount &+= 1
        state.lastErrorDescription = String(describing: error)
      }
    }
  }

  private func rotateIfNeeded(addingByteCount: Int) throws {
    var metadata = stat()
    guard fstat(fileDescriptor, &metadata) == 0 else {
      throw systemCall("fstat audit log")
    }
    guard metadata.st_size + Int64(addingByteCount) > maximumFileSize else { return }

    _ = fsync(fileDescriptor)
    close(fileDescriptor)
    fileDescriptor = -1

    let rotatedURL = directoryURL.appendingPathComponent("\(filename).1", isDirectory: false)
    _ = unlink(rotatedURL.path)
    guard rename(fileURL.path, rotatedURL.path) == 0 || errno == ENOENT else {
      throw systemCall("rotate audit log")
    }
    fileDescriptor = try Self.openLogFile(
      fileURL,
      requiredOwnerUserID: requiredOwnerUserID,
      mode: 0o600
    )
  }

  private func writeAll(_ data: Data) throws {
    guard fileDescriptor >= 0 else {
      throw JSONLineEventLoggerError.systemCall(operation: "write closed audit log", code: EBADF)
    }
    try data.withUnsafeBytes { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      var offset = 0
      while offset < buffer.count {
        let count = Darwin.write(
          fileDescriptor,
          baseAddress.advanced(by: offset),
          buffer.count - offset
        )
        guard count >= 0 else {
          if errno == EINTR { continue }
          throw systemCall("write audit log")
        }
        offset += count
      }
    }
  }

  private static func validateDirectory(
    _ url: URL,
    requiredOwnerUserID: UInt32?
  ) throws {
    var metadata = stat()
    guard lstat(url.path, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFDIR else {
      throw JSONLineEventLoggerError.invalidDirectory(url.path)
    }
    if let requiredOwnerUserID, metadata.st_uid != requiredOwnerUserID {
      throw JSONLineEventLoggerError.ownerMismatch(
        path: url.path,
        expected: requiredOwnerUserID,
        actual: metadata.st_uid
      )
    }
    if requiredOwnerUserID != nil,
      metadata.st_mode & (S_IWGRP | S_IWOTH) != 0
    {
      throw JSONLineEventLoggerError.unsafePermissions(url.path)
    }
  }

  private static func openLogFile(
    _ url: URL,
    requiredOwnerUserID: UInt32?,
    mode: mode_t
  ) throws -> Int32 {
    let descriptor = open(
      url.path,
      O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW | O_CLOEXEC,
      mode
    )
    guard descriptor >= 0 else {
      throw JSONLineEventLoggerError.systemCall(
        operation: "open audit log",
        code: errno
      )
    }

    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0, metadata.st_mode & S_IFMT == S_IFREG else {
      let savedError = errno == 0 ? EINVAL : errno
      close(descriptor)
      throw JSONLineEventLoggerError.systemCall(
        operation: "validate audit log",
        code: savedError
      )
    }
    if let requiredOwnerUserID, metadata.st_uid != requiredOwnerUserID {
      close(descriptor)
      throw JSONLineEventLoggerError.ownerMismatch(
        path: url.path,
        expected: requiredOwnerUserID,
        actual: metadata.st_uid
      )
    }
    if requiredOwnerUserID != nil,
      metadata.st_mode & (S_IWGRP | S_IWOTH) != 0
    {
      close(descriptor)
      throw JSONLineEventLoggerError.unsafePermissions(url.path)
    }
    guard fchmod(descriptor, mode) == 0 else {
      let savedError = errno
      close(descriptor)
      throw JSONLineEventLoggerError.systemCall(
        operation: "fchmod audit log",
        code: savedError
      )
    }
    return descriptor
  }

  private func systemCall(_ operation: String) -> JSONLineEventLoggerError {
    JSONLineEventLoggerError.systemCall(operation: operation, code: errno)
  }
}
