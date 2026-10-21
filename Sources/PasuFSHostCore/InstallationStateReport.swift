import Foundation

/// The answer to one request for the extension's installation states, as the short-lived process
/// that sent it writes it to its standard output (`--pasu-fs-host --installation-states --json`).
///
/// The output is one JSON object followed by a newline, and the exit status names the outcome:
///
/// ```json
/// {"formatVersion":1,"installations":[{"bundleIdentifier":"…","bundleShortVersion":"1.2.3",
///  "bundleVersion":"123","isAwaitingUserApproval":false,"isEnabled":true,
///  "isUninstalling":false}],"outcome":"reported"}
/// {"failure":{"code":1,"description":"…","domain":"OSSystemExtensionErrorDomain",
///  "kind":"requestFailed"},"formatVersion":1,"outcome":"failed"}
/// {"failure":{"kind":"endedWithoutAnswer"},"formatVersion":1,"outcome":"failed"}
/// {"formatVersion":1,"outcome":"timedOut","timeoutSeconds":30}
/// ```
public enum InstallationStateReport: Equatable, Sendable {
  /// macOS reported the installations, none when the extension isn't installed.
  case reported([ExtensionInstallationProperties])
  /// macOS answered the request with an error.
  case requestFailed(domain: String, code: Int, description: String)
  /// macOS ended the request without installations or an error.
  case endedWithoutAnswer
  /// macOS didn't answer within the given number of seconds.
  case timedOut(seconds: Int)

  public static let formatVersion = 1
  /// The largest output the app reads from the process.
  public static let maximumEncodedSize = 1 << 20

  public static let reportedExitStatus: Int32 = 0
  public static let failedExitStatus: Int32 = 2
  public static let timedOutExitStatus: Int32 = 3

  public var exitStatus: Int32 {
    switch self {
    case .reported: Self.reportedExitStatus
    case .requestFailed, .endedWithoutAnswer: Self.failedExitStatus
    case .timedOut: Self.timedOutExitStatus
    }
  }

  /// The JSON object and a newline.
  public func encoded() -> Data {
    let wire: Wire =
      switch self {
      case .reported(let installations):
        Wire(outcome: Wire.reported, installations: installations)
      case .requestFailed(let domain, let code, let description):
        Wire(
          outcome: Wire.failed,
          failure: Wire.Failure(
            kind: Wire.requestFailed, domain: domain, code: code, description: description))
      case .endedWithoutAnswer:
        Wire(outcome: Wire.failed, failure: Wire.Failure(kind: Wire.endedWithoutAnswer))
      case .timedOut(let seconds):
        Wire(outcome: Wire.timedOut, timeoutSeconds: seconds)
      }
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    // Every field is a string, a number, a Boolean or an array of them, so encoding doesn't fail;
    // an empty output would read as unreadable.
    var data = (try? encoder.encode(wire)) ?? Data()
    data.append(0x0A)
    return data
  }

  /// Reads the output of a process that exited with `exitStatus`. Returns nil unless the output is
  /// one object in this format whose outcome matches the exit status.
  public init?(decoding data: Data, exitStatus: Int32) {
    guard data.count <= Self.maximumEncodedSize,
      let wire = try? JSONDecoder().decode(Wire.self, from: data),
      wire.formatVersion == Self.formatVersion
    else { return nil }
    let report: Self
    switch (wire.outcome, wire.installations, wire.failure, wire.timeoutSeconds) {
    case (Wire.reported, let installations?, nil, nil):
      report = .reported(installations)
    case (Wire.failed, nil, let failure?, nil):
      switch (failure.kind, failure.domain, failure.code, failure.description) {
      case (Wire.requestFailed, let domain?, let code?, let description?):
        report = .requestFailed(domain: domain, code: code, description: description)
      case (Wire.endedWithoutAnswer, nil, nil, nil):
        report = .endedWithoutAnswer
      default:
        return nil
      }
    case (Wire.timedOut, nil, nil, let seconds?) where seconds >= 0:
      report = .timedOut(seconds: seconds)
    default:
      return nil
    }
    guard report.exitStatus == exitStatus else { return nil }
    self = report
  }

  private struct Wire: Codable {
    static let reported = "reported"
    static let failed = "failed"
    static let timedOut = "timedOut"
    static let requestFailed = "requestFailed"
    static let endedWithoutAnswer = "endedWithoutAnswer"

    struct Failure: Codable {
      var kind: String
      var domain: String?
      var code: Int?
      var description: String?
    }

    var formatVersion = InstallationStateReport.formatVersion
    var outcome: String
    var installations: [ExtensionInstallationProperties]?
    var failure: Failure?
    var timeoutSeconds: Int?
  }
}

/// Sends one request for the installation states in this process and waits for its answer.
///
/// Only a process that exits soon afterward should call it: on macOS 27.2 an answered request keeps
/// its connection to `sysextd` until the process exits (see `InstallationStateQueryManager`).
public enum InstallationStateProbe {
  public static func query(
    _ lifecycle: any ExtensionLifecycleControlling, timeout: TimeInterval
  ) async -> InstallationStateReport {
    let events = lifecycle.propertiesEvents()
    return await withTaskGroup(of: InstallationStateReport?.self) { group in
      group.addTask {
        for await event in events {
          switch event {
          case .properties(let installations):
            return .reported(installations)
          case .failed(let domain, let code, let description):
            return .requestFailed(domain: domain, code: code, description: description)
          default:
            continue
          }
        }
        return Task.isCancelled ? nil : .endedWithoutAnswer
      }
      group.addTask {
        do {
          try await Task.sleep(for: .seconds(timeout))
        } catch {
          return nil
        }
        return .timedOut(seconds: Int(timeout.rounded(.up)))
      }
      let first = await group.next() ?? nil
      group.cancelAll()
      return first ?? .endedWithoutAnswer
    }
  }
}
