import Foundation
import PasuFSHostCore

struct ProductVersion: Equatable {
  let version: String?
  let build: String?

  init(bundleURL: URL) {
    let bundle = Bundle(url: bundleURL)
    version = bundle?.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String
    build = bundle?.object(forInfoDictionaryKey: "CFBundleVersion") as? String
  }

  init(installation: ExtensionInstallationProperties) {
    version = installation.bundleShortVersion
    build = installation.bundleVersion
  }

  var isKnown: Bool {
    guard let version, !version.isEmpty, let build else { return false }
    return BundleBuildVersion(build) != nil
  }

  var description: String {
    "\(version.flatMap { $0.isEmpty ? nil : $0 } ?? "Unknown") · Build \(build ?? "Unknown")"
  }

  func matches(_ other: Self) -> Bool {
    guard isKnown, other.isKnown, let build, let otherBuild = other.build else { return false }
    return version == other.version && BundleBuildVersion(build) == BundleBuildVersion(otherBuild)
  }
}

struct ExtensionVersionOverview {
  enum Tone: Equatable {
    case neutral, matching, attention
  }

  struct Notice: Identifiable {
    let id: String
    let text: String
  }

  struct Entry: Identifiable {
    let id: Int
    let version: String
    let state: String
  }

  let app: ProductVersion
  let included: ProductVersion
  var active = "Checking…"
  var comparison = "Checking versions"
  var tone: Tone = .neutral
  var notices: [Notice] = []
  var entries: [Entry] = []

  init(
    app: ProductVersion,
    included: ProductVersion,
    installations: [ExtensionInstallationProperties],
    observedAt: Date?,
    queryError: String?,
    isRequestingActivation: Bool,
    activationProgress: String?,
    activationOutcome: LifecycleRequestOutcome?,
    now: Date
  ) {
    self.app = app
    self.included = included

    guard let observedAt, queryError == nil,
      (0...HealthStateReducer.runtimeFreshnessInterval).contains(now.timeIntervalSince(observedAt))
    else {
      if observedAt != nil || queryError != nil {
        active = "Unable to confirm"
        comparison = "Version check unavailable"
        tone = .attention
        notices.append(
          Notice(
            id: "unavailable",
            text: queryError.map { "Could not refresh extension versions: \($0)" }
              ?? "Extension version information is out of date. Refresh to check again."
          ))
      }
      if isRequestingActivation {
        comparison = activationProgress ?? "Updating extension…"
        tone = .neutral
      }
      return
    }

    let matching = installations.filter {
      $0.bundleIdentifier == ActivationController.extensionIdentifier
    }.sorted {
      let left = BundleBuildVersion($0.bundleVersion)
      let right = BundleBuildVersion($1.bundleVersion)
      if let left, let right, left != right { return left > right }
      return ($0.bundleVersion, $0.bundleShortVersion) > ($1.bundleVersion, $1.bundleShortVersion)
    }
    entries = matching.enumerated().map { index, item in
      var states: [String] = []
      if item.isEnabled { states.append("Enabled") }
      if item.isAwaitingUserApproval { states.append("Approval pending") }
      if item.isUninstalling {
        states.append(item.isEnabled ? "Removal pending" : "Restart cleanup pending")
      }
      if states.isEmpty { states.append("Not active") }
      return Entry(
        id: index, version: ProductVersion(installation: item).description,
        state: states.joined(separator: " · ")
      )
    }
    let activeItems = matching.filter {
      $0.isEnabled && !$0.isUninstalling && !$0.isAwaitingUserApproval
    }
    let activeVersions = activeItems.map { ProductVersion(installation: $0) }
    active =
      activeVersions.isEmpty
      ? "None reported by macOS" : activeVersions.map(\.description).joined(separator: ", ")

    if activeVersions.count > 1 {
      comparison = "Multiple active versions"
      tone = .attention
    } else if let running = activeVersions.first {
      if !app.isKnown || !running.isKnown || !included.isKnown {
        comparison = "Version information incomplete"
        tone = .attention
      } else if !app.matches(included) {
        comparison = "App bundle versions differ"
        tone = .attention
      } else if app.matches(running) {
        comparison = "Versions match"
        tone = .matching
      } else {
        comparison = "App and extension differ"
        tone = .attention
        notices.append(
          Notice(
            id: "mismatch", text: "The active protection extension does not match this app."
          ))
      }
    } else {
      comparison = "No active extension"
      tone = .attention
    }

    if app.isKnown, included.isKnown, !app.matches(included) {
      notices.append(
        Notice(
          id: "bundleMismatch",
          text:
            "The app and its included extension have different versions. Reinstall a matching package."
        ))
    }

    for (index, item) in matching.enumerated() {
      let version = ProductVersion(installation: item).description
      if !ProductVersion(installation: item).isKnown {
        notices.append(
          Notice(id: "unknown-\(index)", text: "Incomplete version information: \(version)."))
      }
      if item.isUninstalling {
        notices.append(
          Notice(
            id: "removal-\(index)",
            text: item.isEnabled
              ? "\(version): removal pending; macOS still reports it enabled."
              : "\(version): not active; removal is waiting for a restart."
          ))
      }
      if item.isAwaitingUserApproval {
        notices.append(
          Notice(
            id: "approval-\(index)", text: "\(version): approval is pending in System Settings."
          ))
      }
      if !item.isEnabled, !item.isUninstalling, !item.isAwaitingUserApproval {
        notices.append(
          Notice(
            id: "inactive-\(index)", text: "\(version): installed but not active."
          ))
      }
    }

    if isRequestingActivation {
      comparison = activationProgress ?? "Updating extension…"
      tone = .neutral
    } else if tone != .matching {
      switch activationOutcome {
      case .requiresRestart:
        comparison = "Restart to apply extension update"
        notices.append(
          Notice(
            id: "updateRestart",
            text: "macOS requires a restart to finish activating the new extension."
          ))
      case .failed(let description):
        notices.append(
          Notice(id: "updateFailed", text: "Extension activation failed: \(description)"))
      case .completed, nil:
        break
      }
    }
  }
}
