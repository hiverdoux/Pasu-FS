import Darwin
import EndpointSecurity
import Foundation
import PasuFSEndpointCore
import PasuFSPolicy

private enum HarnessArgumentError: Error, CustomStringConvertible {
  case missingValue(String)
  case missingRequired(String)
  case invalidMode(String)
  case unexpected(String)
  case identityRequiredForEnforcement
  case logDirectoryInsideProtectedRoot

  var description: String {
    switch self {
    case .missingValue(let option):
      "Missing value for \(option)."
    case .missingRequired(let option):
      "Missing required option \(option)."
    case .invalidMode(let mode):
      "Invalid mode \(mode); expected audit or enforce."
    case .unexpected(let argument):
      "Unexpected argument \(argument)."
    case .identityRequiredForEnforcement:
      "Enforce mode requires --allow-team-id and --allow-signing-id."
    case .logDirectoryInsideProtectedRoot:
      "The log directory must be outside the protected root."
    }
  }
}

private struct HarnessOptions {
  let mode: EndpointHarnessMode
  let protectedRoot: String
  let logDirectory: String
  let teamIdentifier: String?
  let signingIdentifier: String?
  let allowDescendants: Bool
  let logLifecycleEvents: Bool

  static func parse(_ arguments: [String]) throws -> HarnessOptions {
    var mode: EndpointHarnessMode?
    var protectedRoot: String?
    var logDirectory: String?
    var teamIdentifier: String?
    var signingIdentifier: String?
    var allowDescendants = false
    var logLifecycleEvents = false

    var index = 0
    while index < arguments.count {
      let argument = arguments[index]
      switch argument {
      case "--mode":
        let value = try nextValue(for: argument, arguments: arguments, index: &index)
        guard let parsedMode = EndpointHarnessMode(rawValue: value) else {
          throw HarnessArgumentError.invalidMode(value)
        }
        mode = parsedMode
      case "--protected-root":
        protectedRoot = try nextValue(for: argument, arguments: arguments, index: &index)
      case "--log-dir":
        logDirectory = try nextValue(for: argument, arguments: arguments, index: &index)
      case "--allow-team-id":
        teamIdentifier = try nextValue(for: argument, arguments: arguments, index: &index)
      case "--allow-signing-id":
        signingIdentifier = try nextValue(for: argument, arguments: arguments, index: &index)
      case "--allow-descendants":
        allowDescendants = true
      case "--log-lifecycle-events":
        logLifecycleEvents = true
      case "--help", "-h":
        printUsageAndExit()
      default:
        throw HarnessArgumentError.unexpected(argument)
      }
      index += 1
    }

    guard let mode else { throw HarnessArgumentError.missingRequired("--mode") }
    guard let protectedRoot else {
      throw HarnessArgumentError.missingRequired("--protected-root")
    }
    guard let logDirectory else {
      throw HarnessArgumentError.missingRequired("--log-dir")
    }

    if mode == .enforce && (teamIdentifier == nil || signingIdentifier == nil) {
      throw HarnessArgumentError.identityRequiredForEnforcement
    }

    return HarnessOptions(
      mode: mode,
      protectedRoot: protectedRoot,
      logDirectory: logDirectory,
      teamIdentifier: teamIdentifier,
      signingIdentifier: signingIdentifier,
      allowDescendants: allowDescendants,
      logLifecycleEvents: logLifecycleEvents
    )
  }

  private static func nextValue(
    for option: String,
    arguments: [String],
    index: inout Int
  ) throws -> String {
    index += 1
    guard index < arguments.count else {
      throw HarnessArgumentError.missingValue(option)
    }
    return arguments[index]
  }

  private static func printUsageAndExit() -> Never {
    print(
      """
      Usage:
        es-integration-harness --mode audit --protected-root PATH --log-dir PATH \\
          [--log-lifecycle-events]
        es-integration-harness --mode enforce --protected-root PATH --log-dir PATH \\
          --allow-team-id TEAM --allow-signing-id SIGNING [--allow-descendants] \\
          [--log-lifecycle-events]

      Requirements:
        - An Apple-approved Endpoint Security entitlement and matching provisioning.
        - Root execution after Full Disk Access is granted to the client.
        - A dedicated, non-system test directory as the protected root.

      Coverage:
        - AUTH_OPEN plus NOTIFY_EXEC, NOTIFY_FORK, and NOTIFY_EXIT.
        - Truncated paths and process-decode errors fail open in this integration target.
      """
    )
    exit(EXIT_SUCCESS)
  }
}

private final class JSONLineLogger: EndpointEventSink, @unchecked Sendable {
  let fileURL: URL

  private let queue = DispatchQueue(label: "com.dennis.pasu.fs.integration-harness.log")
  private let handle: FileHandle

  init(directory: String) throws {
    let directoryURL = URL(fileURLWithPath: directory).standardizedFileURL
    try FileManager.default.createDirectory(
      at: directoryURL,
      withIntermediateDirectories: true
    )
    fileURL = directoryURL.appendingPathComponent("endpoint-events.jsonl")
    if !FileManager.default.fileExists(atPath: fileURL.path) {
      FileManager.default.createFile(atPath: fileURL.path, contents: nil)
    }
    handle = try FileHandle(forWritingTo: fileURL)
    try handle.seekToEnd()
  }

  func record(_ event: EndpointEventRecord) {
    queue.async { [handle] in
      let encoder = JSONEncoder()
      encoder.dateEncodingStrategy = .iso8601
      guard var data = try? encoder.encode(event) else { return }
      data.append(0x0A)
      try? handle.write(contentsOf: data)
      try? FileHandle.standardOutput.write(contentsOf: data)
    }
  }

  func flushAndClose() {
    queue.sync {
      try? handle.synchronize()
      try? handle.close()
    }
  }
}

private final class HarnessRuntime: @unchecked Sendable {
  private let logger: JSONLineLogger
  private var client: OpaquePointer?
  private var signalSources: [DispatchSourceSignal] = []

  init(logger: JSONLineLogger) {
    self.logger = logger
  }

  func setClient(_ client: OpaquePointer) {
    self.client = client
  }

  func installSignalHandlers() {
    for signalNumber in [SIGINT, SIGTERM] {
      signal(signalNumber, SIG_IGN)
      let source = DispatchSource.makeSignalSource(signal: signalNumber, queue: .main)
      source.setEventHandler { [weak self] in
        self?.stop(exitCode: EXIT_SUCCESS)
      }
      source.resume()
      signalSources.append(source)
    }
  }

  func stop(exitCode: Int32) -> Never {
    if let client {
      _ = es_unsubscribe_all(client)
      _ = es_delete_client(client)
      self.client = nil
    }
    logger.flushAndClose()
    exit(exitCode)
  }
}

private enum EndpointClientFactory {
  nonisolated static func create(
    client: inout OpaquePointer?,
    coordinator: EndpointEventCoordinator
  ) -> es_new_client_result_t {
    es_new_client(&client) { client, message in
      coordinator.handle(client: client, message: message)
    }
  }
}

private func name(of result: es_new_client_result_t) -> String {
  switch result {
  case ES_NEW_CLIENT_RESULT_SUCCESS: "SUCCESS"
  case ES_NEW_CLIENT_RESULT_ERR_INVALID_ARGUMENT: "ERR_INVALID_ARGUMENT"
  case ES_NEW_CLIENT_RESULT_ERR_INTERNAL: "ERR_INTERNAL"
  case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: "ERR_NOT_ENTITLED"
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: "ERR_NOT_PERMITTED"
  case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: "ERR_NOT_PRIVILEGED"
  case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: "ERR_TOO_MANY_CLIENTS"
  default: "UNKNOWN(\(result.rawValue))"
  }
}

do {
  let options = try HarnessOptions.parse(Array(CommandLine.arguments.dropFirst()))
  let scope = try ProtectedPathScope(root: options.protectedRoot)
  let standardizedLogDirectory = URL(fileURLWithPath: options.logDirectory).standardizedFileURL.path
  guard !scope.contains(standardizedLogDirectory) else {
    throw HarnessArgumentError.logDirectoryInsideProtectedRoot
  }

  let rules: [AllowRule]
  if let teamIdentifier = options.teamIdentifier,
    let signingIdentifier = options.signingIdentifier
  {
    rules = [
      AllowRule(
        id: "allow.integration.selected-program",
        program: SignedProgramIdentity(
          teamIdentifier: teamIdentifier,
          signingIdentifier: signingIdentifier
        ),
        allowsDescendants: options.allowDescendants
      )
    ]
  } else {
    rules = []
  }

  let logger = try JSONLineLogger(directory: standardizedLogDirectory)
  let coordinator = EndpointEventCoordinator(
    mode: options.mode,
    scope: scope,
    policy: PolicySnapshot(rules: rules),
    sink: logger,
    recordLifecycleEvents: options.logLifecycleEvents
  )
  let runtime = HarnessRuntime(logger: logger)

  var client: OpaquePointer?
  let result = EndpointClientFactory.create(client: &client, coordinator: coordinator)
  guard result == ES_NEW_CLIENT_RESULT_SUCCESS, let client else {
    fputs("es_new_client failed: \(name(of: result))\n", stderr)
    logger.flushAndClose()
    exit(EXIT_FAILURE)
  }

  runtime.setClient(client)
  let events: [es_event_type_t] = [
    ES_EVENT_TYPE_NOTIFY_EXEC,
    ES_EVENT_TYPE_NOTIFY_FORK,
    ES_EVENT_TYPE_NOTIFY_EXIT,
    ES_EVENT_TYPE_AUTH_OPEN,
  ]
  let subscribeResult = events.withUnsafeBufferPointer { buffer in
    es_subscribe(client, buffer.baseAddress!, UInt32(buffer.count))
  }
  guard subscribeResult == ES_RETURN_SUCCESS else {
    fputs("es_subscribe failed.\n", stderr)
    runtime.stop(exitCode: EXIT_FAILURE)
  }

  runtime.installSignalHandlers()
  print("Pasu FS Endpoint Security integration harness")
  print("Mode: \(options.mode.rawValue)")
  print("Protected root: \(scope.root)")
  print("Log: \(logger.fileURL.path)")
  print("Lifecycle event logging: \(options.logLifecycleEvents ? "enabled" : "disabled")")
  print("Effective UID: \(geteuid())")
  dispatchMain()
} catch {
  fputs("Error: \(error)\n", stderr)
  fputs("Run with --help for usage.\n", stderr)
  exit(EXIT_FAILURE)
}
