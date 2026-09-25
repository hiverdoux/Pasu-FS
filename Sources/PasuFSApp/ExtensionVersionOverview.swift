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
    let versionText = version.flatMap { $0.isEmpty ? nil : $0 } ?? String(localized: "Unknown")
    let buildText = build ?? String(localized: "Unknown")
    return String(localized: "\(versionText) (build \(buildText))")
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
  var active = String(localized: "Checking…")
  var comparison = String(localized: "Checking versions")
  var tone: Tone = .neutral
  var notices: [Notice] = []
  var entries: [Entry] = []
  /// True only when macOS reported the installations within the freshness interval.
  var isConfirmed = false

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
        active = String(localized: "Can’t confirm")
        comparison = String(localized: "Version check unavailable")
        tone = .attention
        notices.append(
          Notice(
            id: "unavailable",
            text: queryError.map {
              String(localized: "Could not refresh extension versions: \($0)")
            }
              ?? String(
                localized: "Extension version information is out of date. Refresh to check again.")
          ))
      }
      if isRequestingActivation {
        comparison = activationProgress ?? String(localized: "Updating the extension…")
        tone = .neutral
      }
      return
    }
    isConfirmed = true

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
      if item.isEnabled { states.append(String(localized: "In use")) }
      if item.isAwaitingUserApproval { states.append(String(localized: "Waiting for approval")) }
      if item.isUninstalling {
        states.append(
          item.isEnabled
            ? String(localized: "Removal pending")
            : String(localized: "Cleanup after restart"))
      }
      if states.isEmpty { states.append(String(localized: "Not active")) }
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
      ? String(localized: "None reported by macOS")
      : activeVersions.map(\.description).joined(separator: ", ")

    if activeVersions.count > 1 {
      comparison = String(localized: "Multiple active versions")
      tone = .attention
    } else if let running = activeVersions.first {
      if !app.isKnown || !running.isKnown || !included.isKnown {
        comparison = String(localized: "Version information incomplete")
        tone = .attention
      } else if !app.matches(included) {
        comparison = String(localized: "The app and its included extension differ")
        tone = .attention
      } else if app.matches(running) {
        comparison = String(localized: "Versions match")
        tone = .matching
      } else {
        comparison = String(localized: "The app and running extension differ")
        tone = .attention
        notices.append(
          Notice(
            id: "mismatch",
            text: String(localized: "The running protection extension does not match this app.")
          ))
      }
    } else {
      comparison = String(localized: "No running extension")
      tone = .attention
    }

    if app.isKnown, included.isKnown, !app.matches(included) {
      notices.append(
        Notice(
          id: "bundleMismatch",
          text: String(
            localized:
              "The app and its included extension have different versions. Reinstall a matching package."
          )
        ))
    }

    for (index, item) in matching.enumerated() {
      let version = ProductVersion(installation: item).description
      if !ProductVersion(installation: item).isKnown {
        notices.append(
          Notice(
            id: "unknown-\(index)",
            text: String(localized: "Incomplete version information: \(version)")))
      }
      if item.isUninstalling {
        notices.append(
          Notice(
            id: "removal-\(index)",
            text: item.isEnabled
              ? String(localized: "\(version): removal pending; macOS still reports it in use.")
              : String(
                localized: "\(version): not running; macOS will clean it up after a restart.")
          ))
      }
      if item.isAwaitingUserApproval {
        notices.append(
          Notice(
            id: "approval-\(index)",
            text: String(localized: "\(version): waiting for approval in System Settings.")
          ))
      }
      if !item.isEnabled, !item.isUninstalling, !item.isAwaitingUserApproval {
        notices.append(
          Notice(
            id: "inactive-\(index)",
            text: String(localized: "\(version): installed but not running.")
          ))
      }
    }

    if isRequestingActivation {
      comparison = activationProgress ?? String(localized: "Updating the extension…")
      tone = .neutral
    } else if tone != .matching {
      switch activationOutcome {
      case .requiresRestart:
        comparison = String(localized: "Restart to finish the extension update")
        notices.append(
          Notice(
            id: "updateRestart",
            text: String(localized: "macOS needs a restart to finish activating the new extension.")
          ))
      case .failed(let description):
        notices.append(
          Notice(
            id: "updateFailed",
            text: String(localized: "The extension could not be activated: \(description)")))
      case .completed, nil:
        break
      }
    }
  }
}
