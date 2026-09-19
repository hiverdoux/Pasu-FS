import Dispatch
import Foundation
import PasuFSConfiguration
import os

public enum PolicyAuditLogStoreError: Error, CustomStringConvertible {
  case unknownPolicy

  public var description: String { "The requested policy is not in the stored policy set." }
}

/// A bounded, nonblocking event sink. All file operations and policy retirement
/// are serialized on its worker queue; the kernel response never waits for disk.
public final class PolicyAuditLogStore: EndpointEventSink, @unchecked Sendable {
  private struct State {
    var isClosed = false
    var allowedKeys: Set<PolicyAuditLogKey> = []
    var droppedEventCount: UInt64 = 0
    var policyDrops: [PolicyAuditLogKey: UInt64] = [:]
  }

  private let state = OSAllocatedUnfairLock(initialState: State())
  private let queue = DispatchQueue(label: "com.example.pasu.fs.audit-router")
  private let queueKey = DispatchSpecificKey<UInt8>()
  private let budget: AuditWorkBudget
  private let store: SecureAtomicFileStore
  private let global: JSONLineEventLogger
  private let maximumFileSize: Int64
  private var allowedKeys: Set<PolicyAuditLogKey> = []
  private var writers: [PolicyAuditLogKey: JSONLineEventLogger] = [:]
  private var creationDrops: [PolicyAuditLogKey: UInt64] = [:]
  private var creationErrors: [PolicyAuditLogKey: String] = [:]
  private var cleanupWarning: String?

  public init(
    directoryURL: URL,
    requiredOwnerUserID: UInt32? = nil,
    maximumPendingRecords: Int = 1_024,
    maximumFileSize: Int64 = 10 * 1_024 * 1_024,
    budget: AuditWorkBudget? = nil
  ) throws {
    precondition(maximumPendingRecords > 0 && maximumFileSize > 0)
    self.budget = budget ?? AuditWorkBudget(maximumEntries: maximumPendingRecords)
    self.maximumFileSize = maximumFileSize
    self.store = SecureAtomicFileStore(
      rootDirectory: directoryURL, requiredOwnerUserID: requiredOwnerUserID)
    self.global = try JSONLineEventLogger(
      directoryURL: directoryURL,
      requiredOwnerUserID: requiredOwnerUserID,
      maximumFileSize: maximumFileSize
    )
    queue.setSpecific(key: queueKey, value: 1)
  }

  deinit { flushAndClose() }

  public var droppedEventCount: UInt64 {
    state.withLock { $0.droppedEventCount } &+ global.droppedEventCount
  }

  public var lastErrorDescription: String? {
    queue.sync { combinedWarning }
  }

  /// Call only after successfully loading or persisting a validated policy set.
  /// Never call with an inferred empty set following a policy-store read failure.
  public func updatePolicySet(_ document: PolicySetDocument) {
    queue.sync {
      allowedKeys = Set(
        document.policies.map {
          PolicyAuditLogKey(setIdentifier: document.setIdentifier, policyIdentifier: $0.id)
        })
      state.withLock {
        $0.allowedKeys = allowedKeys
        $0.policyDrops = $0.policyDrops.filter { allowedKeys.contains($0.key) }
      }
      for key in Array(writers.keys) where !allowedKeys.contains(key) {
        writers.removeValue(forKey: key)?.flushAndClose()
      }
      creationDrops = creationDrops.filter { allowedKeys.contains($0.key) }
      creationErrors = creationErrors.filter { allowedKeys.contains($0.key) }
      var failures: [String] = []
      do {
        let names = try FileManager.default.contentsOfDirectory(atPath: store.rootDirectory.path)
        for name in names {
          guard let key = PolicyAuditLogKey(filename: name), !allowedKeys.contains(key) else {
            continue
          }
          do { try store.remove(name, ifExists: true) } catch {
            failures.append("Could not remove retired policy log \(name): \(error)")
          }
        }
      } catch {
        failures.append("Could not inspect retired policy logs: \(error)")
      }
      cleanupWarning = failures.isEmpty ? nil : failures.sorted().joined(separator: "\n")
    }
  }

  public func record(_ original: EndpointEventRecord) {
    let event: EndpointEventRecord
    do {
      event =
        original.estimatedByteCount > maximumFileSize
        ? try JSONLineEventLogger.recordWithinLimit(original, maximumBytes: maximumFileSize)
        : original
    } catch {
      state.withLock { state in
        state.droppedEventCount &+= 1
        for key in Self.keys(for: original) where state.allowedKeys.contains(key) {
          state.policyDrops[key, default: 0] &+= 1
        }
      }
      return
    }
    let bytes = event.estimatedByteCount
    state.withLock { state in
      guard !state.isClosed else { return }
      guard budget.acquire(bytes: bytes) else {
        state.droppedEventCount &+= 1
        for key in Self.keys(for: event) where state.allowedKeys.contains(key) {
          state.policyDrops[key, default: 0] &+= 1
        }
        return
      }
      // Enqueue under the same lock as close, so close drains every accepted event.
      queue.async { [self] in
        defer { budget.release(bytes: bytes) }
        global.recordSynchronously(event)
        for key in Self.keys(for: event) where allowedKeys.contains(key) {
          guard
            let evaluation = event.policyEvaluations?.first(where: {
              $0.policyIdentifier == key.policyIdentifier
            })
          else { continue }
          var scoped = event
          scoped.policyEvaluations = [evaluation]
          do {
            let writer: JSONLineEventLogger
            if let existing = writers[key] {
              writer = existing
            } else {
              writer = try JSONLineEventLogger(
                directoryURL: store.rootDirectory,
                filename: key.filename,
                requiredOwnerUserID: store.requiredOwnerUserID,
                maximumFileSize: maximumFileSize
              )
              writers[key] = writer
              creationErrors.removeValue(forKey: key)
            }
            writer.recordSynchronously(scoped)
          } catch {
            creationDrops[key, default: 0] &+= 1
            creationErrors[key] = "Policy log \(key.filename): \(error)"
          }
        }
      }
    }
  }

  public func readAuditLog(maximumLineCount: Int) throws -> AuditLogBatch {
    try queue.sync {
      try read(
        filenames: ["endpoint-events.jsonl"], maximumLineCount: maximumLineCount,
        key: nil, dropped: droppedEventCount, warning: combinedWarning)
    }
  }

  public func readPolicyAuditLog(_ request: PolicyAuditLogRequest) throws -> AuditLogBatch {
    try queue.sync {
      guard allowedKeys.contains(request.key) else { throw PolicyAuditLogStoreError.unknownPolicy }
      let key = request.key
      let dropped =
        state.withLock { $0.policyDrops[key, default: 0] }
        &+ creationDrops[key, default: 0] &+ (writers[key]?.droppedEventCount ?? 0)
      return try read(
        filenames: [key.filename + ".1", key.filename],
        maximumLineCount: request.maximumLineCount, key: key, dropped: dropped,
        warning: creationErrors[key] ?? writers[key]?.lastErrorDescription)
    }
  }

  public func flushAndClose() {
    let shouldClose = state.withLock {
      guard !$0.isClosed else { return false }
      $0.isClosed = true
      return true
    }
    guard shouldClose else { return }
    let closeFiles = { [self] in
      global.flushAndClose()
      for writer in writers.values { writer.flushAndClose() }
    }
    if DispatchQueue.getSpecific(key: queueKey) != nil {
      closeFiles()
    } else {
      queue.sync(execute: closeFiles)
    }
  }

  private var combinedWarning: String? {
    let warnings =
      [cleanupWarning, global.lastErrorDescription]
      + creationErrors.values.map(Optional.some)
      + writers.values.map(\.lastErrorDescription)
    let values = Set(warnings.compactMap { $0 }).sorted()
    return values.isEmpty ? nil : values.joined(separator: "\n")
  }

  private static func keys(for event: EndpointEventRecord) -> Set<PolicyAuditLogKey> {
    guard event.eventType == "AUTH_OPEN", let set = event.policySetIdentifier,
      let target = event.targetPath, !target.isEmpty
    else { return [] }
    return Set(
      (event.policyEvaluations ?? []).map {
        PolicyAuditLogKey(setIdentifier: set, policyIdentifier: $0.policyIdentifier)
      })
  }

  private func read(
    filenames: [String], maximumLineCount: Int, key: PolicyAuditLogKey?,
    dropped: UInt64, warning: String?
  ) throws -> AuditLogBatch {
    var lines: [Data] = []
    for filename in filenames {
      do {
        let data = try store.read(filename, maximumSize: Int(maximumFileSize))
        lines.append(contentsOf: data.split(separator: 0x0A).map { Data($0) })
      } catch SecureFileStoreError.fileNotFound {
        continue
      }
    }
    let maximum = min(max(maximumLineCount, 1), 500)
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601
    var records: [AuditEventRecord] = []
    var skipped = 0
    for line in lines.suffix(maximum) {
      do {
        let record = try decoder.decode(AuditEventRecord.self, from: line)
        if let key {
          guard Self.keys(for: record) == [key], record.policyEvaluations?.count == 1 else {
            skipped += 1
            continue
          }
        }
        records.append(record)
      } catch { skipped += 1 }
    }
    return AuditLogBatch(
      records: records, skippedLineCount: skipped, droppedEventCount: dropped,
      isTruncated: lines.count > maximum, warning: warning)
  }
}
