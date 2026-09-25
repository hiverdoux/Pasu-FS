import Foundation
import PasuFSHostCore

struct BundleBuildVersion: Comparable, Equatable {
  private let components: [UInt64]

  init?(_ rawValue: String) {
    let rawComponents = rawValue.split(separator: ".", omittingEmptySubsequences: false)
    guard (1...3).contains(rawComponents.count) else { return nil }

    var parsedComponents: [UInt64] = []
    for rawComponent in rawComponents {
      guard !rawComponent.isEmpty,
        rawComponent.allSatisfy({ $0.isASCII && $0.isNumber }),
        let component = UInt64(rawComponent)
      else {
        return nil
      }
      parsedComponents.append(component)
    }
    components = parsedComponents + Array(repeating: 0, count: 3 - parsedComponents.count)
  }

  static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.components.lexicographicallyPrecedes(rhs.components)
  }
}

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
  static func outcome(
    for requestOutcome: LifecycleRequestOutcome,
    extensionWasVerifiedStopped: Bool
  ) -> StopProtectionQuitOutcome {
    switch requestOutcome {
    case .completed where extensionWasVerifiedStopped:
      .stopped
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
