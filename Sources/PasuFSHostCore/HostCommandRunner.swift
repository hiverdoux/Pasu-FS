import Darwin
import Foundation
import PasuFSConfiguration

private enum HostCommand: String {
  case activate
  case deactivate
  case status
}

public enum HostCommandRunner {
  public static func run(arguments: [String], hostBundleURL: URL) async {
    // The app runs this command in a child process to read the installation states; see
    // `InstallationStateQueryManager`.
    if arguments == InstallationStateChildProcessLauncher.commandArguments {
      await printInstallationStates()
    }
    guard arguments.count == 1 else {
      printUsageAndExit(EXIT_FAILURE)
    }
    if arguments[0] == "--help" || arguments[0] == "-h" {
      printUsageAndExit(EXIT_SUCCESS)
    }
    guard arguments[0].hasPrefix("--"),
      let command = HostCommand(rawValue: String(arguments[0].dropFirst(2)))
    else {
      printUsageAndExit(EXIT_FAILURE)
    }

    let controller = ActivationController()
    switch command {
    case .activate:
      do {
        let events = try OneShotAdministrativeAuthorizer().perform(
          .extensionActivate,
          submitting: controller.activationEvents
        )
        await run(events)
      } catch {
        authorizationFailed(error)
      }
    case .deactivate:
      do {
        let events = try OneShotAdministrativeAuthorizer().perform(
          .extensionDeactivate,
          submitting: controller.deactivationEvents
        )
        await run(events)
      } catch {
        authorizationFailed(error)
      }
    case .status:
      await printStatus(controller: controller, hostBundleURL: hostBundleURL)
    }
  }

  private static func authorizationFailed(_ error: any Error) -> Never {
    fputs("Administrator authorization failed: \(error)\n", stderr)
    exit(EXIT_FAILURE)
  }

  private static func run(_ events: AsyncStream<ActivationEvent>) async {
    var failed = false
    for await event in events {
      print(description(of: event))
      if case .failed = event { failed = true }
    }
    exit(failed ? EXIT_FAILURE : EXIT_SUCCESS)
  }

  /// Writes the answer to one request for the installation states as JSON and exits with the
  /// status that names its outcome (see `InstallationStateReport`).
  private static func printInstallationStates() async -> Never {
    // Nobody reads the answer once the app that started this process has quit.
    let parent = getppid()
    let parentExit = DispatchSource.makeProcessSource(
      identifier: parent, eventMask: .exit, queue: .global())
    parentExit.setEventHandler { exit(EXIT_FAILURE) }
    parentExit.resume()
    if getppid() != parent { exit(EXIT_FAILURE) }

    let report = await InstallationStateProbe.query(
      ActivationController(), timeout: InstallationStateQueries.processTimeout)
    withExtendedLifetime(parentExit) {
      FileHandle.standardOutput.write(report.encoded())
    }
    exit(report.exitStatus)
  }

  private static func printStatus(
    controller: ActivationController, hostBundleURL: URL
  ) async {
    // The command exits right after this one request, so its connection to sysextd closes then.
    let report = await InstallationStateProbe.query(
      controller, timeout: InstallationStateQueries.answerTimeout)
    print(description(of: report))
    var properties: [ExtensionInstallationProperties]?
    if case .reported(let found) = report {
      properties = found
    }

    let client = ExtensionControlClient(hostBundleURL: hostBundleURL)
    let runtimeEvidence: RuntimeStatusEvidence?
    do {
      let snapshot = try await client.queryStatus()
      if let count = snapshot.activeSystemCompatibilityProfileCount {
        print("Active compatibility profiles: \(count)")
      }
      if let warning = snapshot.systemCompatibilityWarning {
        print("System compatibility warning: \(warning)")
      }
      print(
        "Running extension: version=\(snapshot.extensionVersion ?? "unreported") build=\(snapshot.extensionBuildVersion ?? "unreported")"
      )
      if let connection = snapshot.endpointConnection {
        print(description(of: connection))
      }
      runtimeEvidence = RuntimeStatusEvidence(
        snapshot: snapshot,
        source: .authenticatedXPC
      )
    } catch {
      fputs("Authenticated runtime status unavailable: \(error)\n", stderr)
      runtimeEvidence = nil
    }
    let health = HealthStateReducer.reduce(
      installationProperties: properties,
      runtimeEvidence: runtimeEvidence
    )
    print("Health: \(description(of: health.protection))")
    switch health.changeAtRestart {
    case .update: print("Pending at restart: extension update")
    case .removal: print("Pending at restart: extension removal")
    case nil: break
    }
    if let warning = health.policyWarning {
      print("Policy warning: \(warning)")
    }
  }

  private static func description(of event: ActivationEvent) -> String {
    switch event {
    case .submitted(let action):
      "System extension request submitted: \(action)"
    case .waitingForUserApproval:
      "System extension status: waiting-for-user-approval"
    case .replacing(let existing, let new):
      "System extension status: replacing \(existing) with \(new)"
    case .completed(let rebootRequired):
      rebootRequired
        ? "System extension status: will-complete-after-reboot"
        : "System extension status: completed"
    case .properties(let properties):
      description(of: properties)
    case .failed(let domain, let code, let description):
      "System extension status: failed domain=\(domain) code=\(code) description=\(description)"
    }
  }

  private static func description(of report: InstallationStateReport) -> String {
    switch report {
    case .reported(let properties):
      description(of: properties)
    case .requestFailed(let domain, let code, let description):
      "System extension properties: failed domain=\(domain) code=\(code) description=\(description)"
    case .endedWithoutAnswer:
      "System extension properties: ended-without-answer"
    case .timedOut(let seconds):
      "System extension properties: unanswered within \(seconds) seconds"
    }
  }

  /// When the running extension connected to Endpoint Security, in seconds after the Mac
  /// started, and its latest failure to connect.
  private static func description(of connection: EndpointConnectionStatus) -> String {
    func seconds(_ value: Double?) -> String {
      value.map { String(format: "%.3fs", $0) } ?? "unreported"
    }
    let eventTypes = connection.firstSubscriptionEventCount.map(String.init) ?? "unreported"
    let policyEvents = connection.firstSubscriptionIncludesPolicyEvents.map(
      String.init(describing:))
    var line =
      "Endpoint Security: earlyBoot=\(connection.requestsEarlyBoot) clientCreatedAfterStartup=\(seconds(connection.clientCreatedSecondsAfterStartup)) firstSubscriptionAfterStartup=\(seconds(connection.firstSubscriptionSecondsAfterStartup)) eventTypes=\(eventTypes) policyEvents=\(policyEvents ?? "unreported")"
    if let failure = connection.lastFailure {
      line += "\nEndpoint Security last connection failure: \(failure)"
    }
    return line
  }

  private static func description(of properties: [ExtensionInstallationProperties]) -> String {
    properties.isEmpty
      ? "System extension properties: not-installed"
      : properties.map {
        "System extension properties: version=\($0.bundleShortVersion) build=\($0.bundleVersion) enabled=\($0.isEnabled) awaitingApproval=\($0.isAwaitingUserApproval) uninstalling=\($0.isUninstalling)"
      }.joined(separator: "\n")
  }

  private static func description(of state: ProtectionState) -> String {
    switch state {
    case .notInstalled: "not-installed"
    case .waitingForApproval: "waiting-for-approval"
    case .uninstalling: "uninstalling"
    case .stopped: "stopped"
    case .starting: "starting"
    case .waitingForFullDiskAccess: "waiting-for-full-disk-access"
    case .idle(let revision): "idle revision=\(revision)"
    case .enforcingOpenEvents(let revision): "enforcing-auth-open revision=\(revision)"
    case .monitoringOpenEvents(let revision): "monitoring-auth-open revision=\(revision)"
    case .degraded(let reason): "degraded reason=\(reason)"
    }
  }

  private static func printUsageAndExit(_ exitCode: Int32) -> Never {
    let stream = exitCode == EXIT_SUCCESS ? stdout : stderr
    fputs(
      "Usage: pasu-fs-host --activate | --deactivate | --status\n",
      stream
    )
    exit(exitCode)
  }
}
