import Foundation
import PasuFSConfiguration

/// One program seen in a policy's loaded log records, grouped by its signing identity.
struct PolicyProgramSummary: Identifiable, Equatable {
  enum Identity: Equatable {
    case teamSigned(teamIdentifier: String, signingIdentifier: String)
    case platformBinary(signingIdentifier: String)
    case unsigned(executablePath: String?)
  }

  let id: String
  let identity: Identity
  let displayName: String
  let executablePath: String?
  let processPreview: String
  let observationCount: Int
  let deniedCount: Int
  let allowedCount: Int
  let latestDecision: PolicyEvaluationDecision?
  /// The policy revision the latest decision was made under.
  let latestDecisionRevision: UInt64?
  /// The revision of the policies in use when the summary was made.
  let currentRevision: UInt64?
  let lastSeen: Date
  let targetSamples: [String]

  /// Whether the latest decision was made under an earlier revision than the policies in use.
  /// Every save creates a revision, including one that changes only another policy or follows a
  /// moved folder, so the current rules may decide the program's next request differently, not
  /// necessarily that they will.
  var latestDecisionPrecedesCurrentRevision: Bool {
    guard latestDecision != nil, let latestDecisionRevision, let currentRevision else {
      return false
    }
    return latestDecisionRevision < currentRevision
  }

  var ruleCandidate: AuditRuleCandidate? {
    switch identity {
    case .teamSigned(let team, let signing):
      AuditRuleCandidate(
        id: id, kind: .teamSigned, teamIdentifier: team, signingIdentifier: signing,
        displayName: displayName, executablePath: executablePath, lastSeen: lastSeen,
        observationCount: observationCount)
    case .platformBinary(let signing):
      AuditRuleCandidate(
        id: id, kind: .platformBinary, teamIdentifier: nil, signingIdentifier: signing,
        displayName: displayName, executablePath: executablePath, lastSeen: lastSeen,
        observationCount: observationCount)
    case .unsigned:
      nil
    }
  }

  var kindDescription: String {
    switch identity {
    case .teamSigned: PolicyRuleKind.teamSigned.displayName
    case .platformBinary: PolicyRuleKind.platformBinary.displayName
    case .unsigned: String(localized: "No signing information")
    }
  }
}

enum PolicyProgramSummarizer {
  static func summaries(
    records: [AuditEventRecord],
    policyID: UUID,
    currentRevision: UInt64? = nil,
    displayName: (String, String?) -> String
  ) -> [PolicyProgramSummary] {
    struct Accumulator {
      var identity: PolicyProgramSummary.Identity
      var executablePath: String?
      var processPreview: String
      var observationCount = 0
      var deniedCount = 0
      var allowedCount = 0
      var latestDecision: PolicyEvaluationDecision?
      var latestDecisionRevision: UInt64?
      var lastSeen: Date
      var targets: [String] = []
    }

    var grouped: [String: Accumulator] = [:]
    var order: [String] = []
    for record in records {
      let evaluation = record.evaluation(for: policyID)
      let identity = identity(of: record)
      let key = identityKey(identity)
      // One record can stand for several requests of one process.
      let requests = Int(clamping: record.representedRequestCount)
      let seen = record.lastRequestTimestamp
      var entry =
        grouped[key]
        ?? Accumulator(
          identity: identity, executablePath: record.executablePath,
          processPreview: ProcessText.preview(record), lastSeen: seen)
      if grouped[key] == nil { order.append(key) }
      entry.observationCount += requests
      if let decision = evaluation?.decision {
        if decision.isDenial {
          entry.deniedCount += requests
        } else {
          entry.allowedCount += requests
        }
      }
      if seen >= entry.lastSeen || entry.latestDecision == nil {
        entry.lastSeen = max(entry.lastSeen, seen)
        if let decision = evaluation?.decision {
          entry.latestDecision = decision
          entry.latestDecisionRevision = record.policyRevision
        }
        entry.executablePath = record.executablePath ?? entry.executablePath
        entry.processPreview = ProcessText.preview(record)
      }
      if let target = record.targetPath, entry.targets.count < 5, !entry.targets.contains(target) {
        entry.targets.append(target)
      }
      grouped[key] = entry
    }

    return order.compactMap { key in
      guard let entry = grouped[key] else { return nil }
      let signing: String?
      switch entry.identity {
      case .teamSigned(_, let value), .platformBinary(let value): signing = value
      case .unsigned: signing = nil
      }
      let name =
        signing.map { displayName($0, entry.executablePath) }
        ?? entry.executablePath.map { ($0 as NSString).lastPathComponent }
        ?? String(localized: "Unknown program")
      return PolicyProgramSummary(
        id: key, identity: entry.identity, displayName: name,
        executablePath: entry.executablePath, processPreview: entry.processPreview,
        observationCount: entry.observationCount, deniedCount: entry.deniedCount,
        allowedCount: entry.allowedCount, latestDecision: entry.latestDecision,
        latestDecisionRevision: entry.latestDecisionRevision, currentRevision: currentRevision,
        lastSeen: entry.lastSeen, targetSamples: entry.targets)
    }
    .sorted { $0.lastSeen > $1.lastSeen }
  }

  static func identity(of record: AuditEventRecord) -> PolicyProgramSummary.Identity {
    if let signing = record.signingIdentifier, !signing.isEmpty {
      if record.isPlatformBinary == true {
        return .platformBinary(signingIdentifier: signing)
      }
      if record.isPlatformBinary == false, let team = record.teamIdentifier, !team.isEmpty {
        return .teamSigned(teamIdentifier: team.uppercased(), signingIdentifier: signing)
      }
    }
    return .unsigned(executablePath: record.executablePath)
  }

  static func identityKey(_ identity: PolicyProgramSummary.Identity) -> String {
    switch identity {
    case .teamSigned(let team, let signing): "team:\(team.uppercased()):\(signing)"
    case .platformBinary(let signing): "platform:\(signing)"
    case .unsigned(let path): "unsigned:\(path ?? "")"
    }
  }

  static func ruleKey(_ rule: PolicyRule) -> String {
    switch rule.kind {
    case .teamSigned: "team:\((rule.teamIdentifier ?? "").uppercased()):\(rule.signingIdentifier)"
    case .platformBinary: "platform:\(rule.signingIdentifier)"
    }
  }
}

extension AuditEventRecord {
  /// The recorded decision of one policy, or the first decision of a record that names none.
  func evaluation(for policyID: UUID) -> PolicyEvaluationRecord? {
    policyEvaluations?.first { $0.policyIdentifier == policyID } ?? policyEvaluations?.first
  }
}

enum ProcessText {
  /// "Responsible › direct" when macOS reported a different responsible process.
  static func preview(_ record: AuditEventRecord) -> String {
    let direct = record.directProcessName
    guard let lineage = record.processLineage, let responsibleKey = lineage.responsible else {
      return direct
    }
    let responsible =
      lineage.processes.first { $0.key == responsibleKey }?.displayName
      ?? "PID \(responsibleKey.pid)"
    if responsibleKey == lineage.actor || responsible == direct {
      return direct
    }
    return "\(responsible) › \(direct)"
  }
}
