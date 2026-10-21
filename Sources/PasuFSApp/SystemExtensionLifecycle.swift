import Foundation
import PasuFSHostCore
import PasuFSMaintenanceCore

enum ExtensionUpdatePlanner {
  static func shouldRequestActivation(
    extensionIdentifier: String = ActivationController.extensionIdentifier,
    embeddedBuildVersion: String?,
    installations: [ExtensionInstallationProperties]
  ) -> Bool {
    guard let embeddedBuildVersion,
      let embeddedVersion = BundleBuildVersion(embeddedBuildVersion)
    else {
      return false
    }

    let matchingInstallations = installations.filter {
      $0.bundleIdentifier == extensionIdentifier
    }
    guard
      !matchingInstallations.contains(where: {
        $0.isAwaitingUserApproval
      })
    else {
      return false
    }

    let activeInstallations = matchingInstallations.filter {
      $0.isEnabled
    }
    guard !activeInstallations.isEmpty else { return false }

    let installedVersions = matchingInstallations.compactMap {
      BundleBuildVersion($0.bundleVersion)
    }
    guard installedVersions.count == matchingInstallations.count,
      let newestInstalledVersion = installedVersions.max(),
      let oldestActiveVersion = activeInstallations.compactMap({
        BundleBuildVersion($0.bundleVersion)
      }).min()
    else {
      return false
    }

    // A replaced, disabled older version can remain until reboot. It must not
    // block updating the active version, but current/newer removal still does.
    for installation in matchingInstallations where installation.isUninstalling {
      guard !installation.isEnabled,
        let removingVersion = BundleBuildVersion(installation.bundleVersion),
        removingVersion < oldestActiveVersion
      else { return false }
    }
    return newestInstalledVersion < embeddedVersion
  }
}

struct AutomaticExtensionUpdateCheck {
  private(set) var hasEvaluated = false

  mutating func shouldRequestActivation(
    embeddedBuildVersion: String?,
    installations: [ExtensionInstallationProperties]
  ) -> Bool {
    guard !hasEvaluated else { return false }
    hasEvaluated = true
    return ExtensionUpdatePlanner.shouldRequestActivation(
      embeddedBuildVersion: embeddedBuildVersion,
      installations: installations
    )
  }
}

/// Remembers the boot session in which a running extension was replaced. The new extension has
/// not observed the programs started before it, so policies deny them until they start again.
/// A restart ends the boot session and with it the recommendation. Only a running extension
/// without `NSEndpointSecurityRebootRequired`, from 0.10.3 or earlier, is replaced at once; macOS
/// defers replacing one with the key to the next restart.
struct ExtensionReplacementRecord {
  static let defaultsKey = "ExtensionReplacedBootSession"

  var defaults: UserDefaults = .standard
  var currentBootSession: () -> String? = BootSession.identifier

  var recommendsRestart: Bool {
    guard let current = currentBootSession() else { return false }
    return defaults.string(forKey: Self.defaultsKey) == current
  }

  func recordReplacement() {
    guard let current = currentBootSession() else { return }
    defaults.set(current, forKey: Self.defaultsKey)
  }
}

protocol EmbeddedSystemExtensionVersionProviding: Sendable {
  func buildVersion(in hostBundleURL: URL) -> String?
}

struct BundleEmbeddedSystemExtensionVersionProvider: EmbeddedSystemExtensionVersionProviding {
  func buildVersion(in hostBundleURL: URL) -> String? {
    let extensionBundleURL =
      hostBundleURL
      .appendingPathComponent("Contents/Library/SystemExtensions", isDirectory: true)
      .appendingPathComponent(
        "\(ActivationController.extensionIdentifier).systemextension",
        isDirectory: true
      )
    return Bundle(url: extensionBundleURL)?
      .object(forInfoDictionaryKey: "CFBundleVersion") as? String
  }
}

enum LifecycleRequestOutcome: Equatable {
  case completed
  case requiresRestart
  case failed(String)
}

enum StopProtectionQuitOutcome: Equatable {
  case stopped
  case requiresRestart
  case failed(String)
}

enum StopProtectionQuitPolicy {
  /// - Parameter extensionStopsAtRestart: Whether the extension still answers while macOS
  ///   removes every version it reports at the next restart.
  static func outcome(
    for requestOutcome: LifecycleRequestOutcome,
    extensionWasVerifiedStopped: Bool,
    extensionStopsAtRestart: Bool = false
  ) -> StopProtectionQuitOutcome {
    switch requestOutcome {
    case .completed where extensionWasVerifiedStopped:
      .stopped
    // While an update waits for a restart, macOS completes the request by removing the waiting
    // version at once, and the earlier version keeps running until the restart.
    case .completed where extensionStopsAtRestart:
      .requiresRestart
    case .completed:
      .failed(
        String(
          localized:
            "macOS accepted the deactivation request, but Pasu FS could not confirm that the extension stopped. The app stays open."
        )
      )
    case .requiresRestart:
      .requiresRestart
    case .failed(let description):
      .failed(description)
    }
  }
}

enum ProtectionStopVerification {
  static func isStopped(
    installations: [ExtensionInstallationProperties],
    authenticatedRuntimeIsAvailable: Bool
  ) -> Bool {
    let hasEnabledInstallation = installations.contains {
      $0.bundleIdentifier == ActivationController.extensionIdentifier && $0.isEnabled
    }
    return !hasEnabledInstallation && !authenticatedRuntimeIsAvailable
  }
}
