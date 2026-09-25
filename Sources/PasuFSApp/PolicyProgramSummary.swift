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
  let lastSeen: Date
  let targetSamples: [String]

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
      var lastSeen: Date
      var targets: [String] = []
    }

    var grouped: [String: Accumulator] = [:]
    var order: [String] = []
    for record in records {
      let evaluation =
        record.policyEvaluations?.first { $0.policyIdentifier == policyID }
        ?? record.policyEvaluations?.first
      let identity = identity(of: record)
      let key = identityKey(identity)
      var entry =
        grouped[key]
        ?? Accumulator(
          identity: identity, executablePath: record.executablePath,
          processPreview: ProcessText.preview(record), lastSeen: record.timestamp)
      if grouped[key] == nil { order.append(key) }
      entry.observationCount += 1
      if let decision = evaluation?.decision {
        if decision.isDenial {
          entry.deniedCount += 1
        } else {
          entry.allowedCount += 1
        }
      }
      if record.timestamp >= entry.lastSeen || entry.latestDecision == nil {
        entry.lastSeen = max(entry.lastSeen, record.timestamp)
        entry.latestDecision = evaluation?.decision ?? entry.latestDecision
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

  /// Programs whose opens would be denied if the policy enforced its current draft rules.
  /// This is an estimate from the loaded records: it cannot see programs that have not opened
  /// files yet, and it does not re-evaluate descendant inheritance or compatibility profiles.
  static func projectedDenials(
    summaries: [PolicyProgramSummary],
    policyType: PolicyType,
    rules: [PolicyRule]
  ) -> [PolicyProgramSummary] {
    let enabledKeys = Set(rules.filter(\.isEnabled).map(ruleKey))
    return summaries.filter { summary in
      let matchesRule = enabledKeys.contains(summary.id)
      switch policyType {
      case .whitelist:
        return !matchesRule && summary.latestDecision?.isDenial == true
      case .blacklist:
        return matchesRule
      }
    }
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
