import Darwin
import Foundation

private enum HostCommand: String {
  case activate
  case deactivate
  case status
}

public enum HostCommandRunner {
  public static func run(arguments: [String], hostBundleURL: URL) async {
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

  private static func printStatus(
    controller: ActivationController, hostBundleURL: URL
  ) async {
    var properties: [ExtensionInstallationProperties] = []
    for await event in controller.propertiesEvents() {
      print(description(of: event))
      if case .properties(let found) = event {
        properties = found
      }
    }

    let client = ExtensionControlClient(hostBundleURL: hostBundleURL)
    let runtimeEvidence: RuntimeStatusEvidence?
    do {
      let snapshot = try await client.queryStatus()
      if let warning = snapshot.systemCompatibilityWarning {
        print("System compatibility warning: \(warning)")
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
      properties.isEmpty
        ? "System extension properties: not-installed"
        : properties.map {
          "System extension properties: version=\($0.bundleShortVersion) enabled=\($0.isEnabled) awaitingApproval=\($0.isAwaitingUserApproval) uninstalling=\($0.isUninstalling)"
        }.joined(separator: "\n")
    case .failed(let domain, let code, let description):
      "System extension status: failed domain=\(domain) code=\(code) description=\(description)"
    }
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
