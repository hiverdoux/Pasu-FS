import Foundation

/// One execution, not just a reusable process number. Keys are scoped to the
/// bootIdentifier in the enclosing snapshot.
public struct LineageProcessKey: Codable, Hashable, Sendable, Identifiable {
  public var pid: Int32
  public var version: Int32
  public var id: String { "\(pid):\(version)" }

  public init(pid: Int32, version: Int32) {
    self.pid = pid
    self.version = version
  }
}

public struct LineageProcess: Codable, Equatable, Sendable, Identifiable {
  public var key: LineageProcessKey
  public var executablePath: String?
  public var pathWasTruncated: Bool
  public var signingIdentifier: String?
  public var teamIdentifier: String?
  public var codeSigningFlags: UInt32?
  public var isPlatformBinary: Bool?
  public var startTime: Date?
  public var parent: LineageProcessKey?
  public var responsible: LineageProcessKey?
  public var originalParentPID: Int32?
  public var observedAt: Date?
  public var exitedAt: Date?
  public var id: String { key.id }

  public init(
    key: LineageProcessKey, executablePath: String? = nil,
    pathWasTruncated: Bool = false, signingIdentifier: String? = nil,
    teamIdentifier: String? = nil, codeSigningFlags: UInt32? = nil,
    isPlatformBinary: Bool? = nil, startTime: Date? = nil,
    parent: LineageProcessKey? = nil, responsible: LineageProcessKey? = nil,
    originalParentPID: Int32? = nil, observedAt: Date? = nil, exitedAt: Date? = nil
  ) {
    self.key = key
    self.executablePath = executablePath
    self.pathWasTruncated = pathWasTruncated
    self.signingIdentifier = signingIdentifier
    self.teamIdentifier = teamIdentifier
    self.codeSigningFlags = codeSigningFlags
    self.isPlatformBinary = isPlatformBinary
    self.startTime = startTime
    self.parent = parent
    self.responsible = responsible
    self.originalParentPID = originalParentPID
    self.observedAt = observedAt
    self.exitedAt = exitedAt
  }

  public var displayName: String {
    if let executablePath, !executablePath.isEmpty {
      return (executablePath as NSString).lastPathComponent
    }
    if let signingIdentifier, !signingIdentifier.isEmpty { return signingIdentifier }
    return "PID \(key.pid)"
  }

  public var estimatedByteCount: Int {
    512 + (executablePath?.utf8.count ?? 0) + (signingIdentifier?.utf8.count ?? 0)
      + (teamIdentifier?.utf8.count ?? 0)
  }
}

public enum LineageRelationKind: String, Codable, Sendable {
  case fork
  case exec
  case parent
  case responsible

  public var displayName: String {
    switch self {
    case .fork: "Child creation observed"
    case .exec: "Executable replaced in the same process"
    case .parent: "Parent reported by macOS"
    case .responsible: "Responsibility reported by macOS"
    }
  }
}

public struct LineageRelation: Codable, Equatable, Sendable, Identifiable {
  public var source: LineageProcessKey
  public var target: LineageProcessKey
  public var kind: LineageRelationKind
  public var observedAt: Date
  public var observation: UInt64
  public var id: String { "\(observation):\(kind.rawValue):\(source.id):\(target.id)" }

  public init(
    source: LineageProcessKey, target: LineageProcessKey, kind: LineageRelationKind,
    observedAt: Date, observation: UInt64
  ) {
    self.source = source
    self.target = target
    self.kind = kind
    self.observedAt = observedAt
    self.observation = observation
  }
}

public struct LineageIssue: Codable, Equatable, Sendable, Identifiable {
  public static func lossAccountingWarning(version: Int?, issues: [Self]) -> String? {
    guard version == nil,
      issues.contains(where: { $0.reason == "kernelEventLoss" }),
      issues.contains(where: { $0.reason == "queueOverflow" })
    else { return nil }
    return
      "This older collector could count local queue losses again as macOS delivery gaps. These two counts may overlap."
  }
  public var reason: String
  public var process: LineageProcessKey?
  public var count: UInt64
  public var firstObservedAt: Date
  public var lastObservedAt: Date
  public var id: String { "\(reason):\(process?.id ?? "collector")" }

  public init(reason: String, process: LineageProcessKey? = nil, count: UInt64 = 1, at: Date) {
    self.reason = reason
    self.process = process
    self.count = count
    self.firstObservedAt = at
    self.lastObservedAt = at
  }

  public var explanation: String {
    switch reason {
    case "unobserved": "Identity reported, but this execution was not observed."
    case "parentUnavailable":
      "The parent execution identity was not available; the chain cannot be continued here."
    case "kernelEventLoss":
      "macOS event delivery contained gaps. Unobserved transitions cannot be reconstructed."
    case "queueOverflow": "The process-history queue could not accept some observations."
    case "resourceLimit":
      "The process-history data budget was exhausted; some observations could not be retained."
    case "decodeError": "Some process event fields could not be decoded."
    case "cycle":
      "Conflicting cyclic relationships were observed; they were not treated as a linear ancestry."
    case "oversizedRecord":
      "The complete process history exceeded the log file limit and could not be stored."
    case "mutedLifecycle": "macOS excludes some process lifecycle events from this client."
    case "muteInspectionFailed": "The macOS event exclusion list could not be inspected."
    case "versionUnavailable":
      "This event version did not provide parent and responsibility identities."
    case "executionMismatch":
      "The execution transition did not identify the same process; it was not linked."
    default: reason
    }
  }
}

public struct ProcessLineageSnapshot: Codable, Equatable, Sendable {
  /// Missing in early schema-5 records whose kernel/queue loss counts could overlap.
  public var deliveryAccountingVersion: Int?
  public var bootIdentifier: String
  public var collectionIdentifier: UUID
  public var collectionStartedAt: Date
  public var capturedAt: Date
  public var actor: LineageProcessKey?
  public var responsible: LineageProcessKey?
  /// Dependency-first order, including all observed execution replacements.
  public var processes: [LineageProcess]
  public var relations: [LineageRelation]
  public var issues: [LineageIssue]

  public init(
    bootIdentifier: String, collectionIdentifier: UUID, collectionStartedAt: Date,
    capturedAt: Date, actor: LineageProcessKey?, responsible: LineageProcessKey?,
    processes: [LineageProcess] = [], relations: [LineageRelation] = [],
    issues: [LineageIssue] = [], deliveryAccountingVersion: Int? = 1
  ) {
    self.bootIdentifier = bootIdentifier
    self.collectionIdentifier = collectionIdentifier
    self.collectionStartedAt = collectionStartedAt
    self.capturedAt = capturedAt
    self.actor = actor
    self.responsible = responsible
    self.processes = processes
    self.relations = relations
    self.issues = issues
    self.deliveryAccountingVersion = deliveryAccountingVersion
  }

  public var estimatedByteCount: Int {
    512 + processes.reduce(0) { $0 + $1.estimatedByteCount }
      + relations.count * 160 + issues.count * 256
  }

  public var actorAncestryKeys: Set<LineageProcessKey> {
    let incoming = Dictionary(grouping: relations.filter { $0.kind != .responsible }, by: \.target)
    var result = Set<LineageProcessKey>()
    var pending = [actor].compactMap { $0 }
    while let key = pending.popLast() {
      guard result.insert(key).inserted else { continue }
      pending.append(contentsOf: (incoming[key] ?? []).map(\.source))
    }
    return result
  }
}

public struct ProcessLineageStatus: Codable, Equatable, Sendable {
  public var deliveryAccountingVersion: Int?
  public var isTracking: Bool
  public var collectionStartedAt: Date
  public var observedEventCount: UInt64
  public var retainedProcessCount: Int
  public var retainedDataBytes: Int
  public var issues: [LineageIssue]

  public init(
    isTracking: Bool = false, collectionStartedAt: Date = Date(),
    observedEventCount: UInt64 = 0, retainedProcessCount: Int = 0,
    retainedDataBytes: Int = 0, issues: [LineageIssue] = [], deliveryAccountingVersion: Int? = 1
  ) {
    self.isTracking = isTracking
    self.collectionStartedAt = collectionStartedAt
    self.observedEventCount = observedEventCount
    self.retainedProcessCount = retainedProcessCount
    self.retainedDataBytes = retainedDataBytes
    self.issues = issues
    self.deliveryAccountingVersion = deliveryAccountingVersion
  }
}

extension AuditEventRecord {
  public var directProcessName: String {
    return
      executablePath.flatMap { $0.isEmpty ? nil : ($0 as NSString).lastPathComponent }
      ?? signingIdentifier ?? processID.map { "PID \($0)" } ?? "Unknown"
  }

  public var responsibleProcessName: String {
    processLineage?.responsible.map { key in
      processLineage?.processes.first { $0.key == key }?.displayName ?? "PID \(key.pid)"
    } ?? "Unknown"
  }

  public var processPreview: String {
    "\(responsibleProcessName) > \(directProcessName)"
  }

  public var lineageSearchValues: [String] {
    [processPreview]
      + (processLineage?.processes ?? []).flatMap {
        [
          $0.displayName, $0.executablePath ?? "", $0.signingIdentifier ?? "",
          $0.teamIdentifier ?? "", $0.key.id,
        ]
      }
  }

  public var estimatedByteCount: Int {
    1_024 + (executablePath?.utf8.count ?? 0) + (targetPath?.utf8.count ?? 0)
      + (detail?.utf8.count ?? 0) + (policyEvaluations?.count ?? 0) * 1_024
      + (processLineage?.estimatedByteCount ?? 0)
  }
}
