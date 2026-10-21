import Foundation
import PasuFSConfiguration
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

  /// The version that the running extension reports in its status; unknown when the extension
  /// predates the report.
  init(runningExtension status: ExtensionStatusSnapshot) {
    version = status.extensionVersion
    build = status.extensionBuildVersion
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
  /// True only when macOS answered the latest request for the installations, within
  /// `InstallationStateQueries.maximumAge`.
  var isConfirmed = false
  /// True until macOS answers the first request for the installations or doesn't answer in time.
  var isWaitingForFirstReport = false

  /// - Parameters:
  ///   - observedAt: When macOS last reported the installations.
  ///   - unansweredSince: Since when macOS hasn't answered requests for the installations, or nil
  ///     while it answers.
  ///   - runningExtension: The version from a status that the running extension answered over the
  ///     authenticated connection within the freshness interval, or nil without one. Its version
  ///     is unknown when the extension predates the report.
  init(
    app: ProductVersion,
    included: ProductVersion,
    installations: [ExtensionInstallationProperties],
    observedAt: Date?,
    unansweredSince: Date? = nil,
    queryError: String?,
    runningExtension: ProductVersion? = nil,
    isRequestingActivation: Bool,
    activationProgress: String?,
    activationOutcome: LifecycleRequestOutcome?,
    now: Date
  ) {
    self.app = app
    self.included = included

    guard let observedAt, queryError == nil, unansweredSince == nil,
      (0...InstallationStateQueries.maximumAge).contains(now.timeIntervalSince(observedAt))
    else {
      isWaitingForFirstReport = observedAt == nil && queryError == nil && unansweredSince == nil
      if !isWaitingForFirstReport {
        active = String(localized: "Can’t confirm")
        comparison = String(localized: "Version check unavailable")
        tone = .attention
        let text: String =
          if let unansweredSince {
            InstallationStateText.unanswered(since: unansweredSince, now: now)
          } else if let queryError {
            String(localized: "Could not refresh extension versions: \(queryError)")
          } else {
            String(
              localized: "Extension version information is out of date. Refresh to check again.")
          }
        notices.append(Notice(id: "unavailable", text: text))
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
    let pendingUpdate = ExtensionUpdateAwaitingRestart(installations: matching)
    // The installation that still runs although macOS reports it as being removed: the version
    // the running extension reports, or, from an extension that predates the report, the version
    // that an update waiting for a restart replaces.
    let runningRemoval: ExtensionInstallationProperties? = runningExtension.flatMap { running in
      if running.isKnown {
        return matching.first {
          $0.isUninstalling && !$0.isEnabled && running.matches(ProductVersion(installation: $0))
        }
      }
      return pendingUpdate?.replaced
    }
    entries = matching.enumerated().map { index, item in
      var states: [String] = []
      if item.isEnabled { states.append(String(localized: "In use")) }
      if item.isAwaitingUserApproval { states.append(String(localized: "Waiting for approval")) }
      if item.isUninstalling {
        if item.isEnabled {
          states.append(String(localized: "Removal pending"))
        } else if item == runningRemoval {
          states.append(String(localized: "Running until restart"))
        } else {
          states.append(String(localized: "Cleanup after restart"))
        }
      }
      if states.isEmpty {
        states.append(
          item == pendingUpdate?.next
            ? String(localized: "Starts after restart") : String(localized: "Not active"))
      }
      return Entry(
        id: index, version: ProductVersion(installation: item).description,
        state: states.joined(separator: " · ")
      )
    }
    let activeItems = matching.filter {
      $0.isEnabled && !$0.isUninstalling && !$0.isAwaitingUserApproval
    }
    let activeVersions = activeItems.map { ProductVersion(installation: $0) }
    // The running extension's own report names the version that runs; macOS reports none while
    // an update waits for a restart.
    let reportedVersion: ProductVersion? =
      if let runningExtension, runningExtension.isKnown {
        runningExtension
      } else {
        runningRemoval.map(ProductVersion.init(installation:))
      }
    if let reportedVersion {
      active = reportedVersion.description
    } else {
      active =
        activeVersions.isEmpty
        ? String(localized: "None reported by macOS")
        : activeVersions.map(\.description).joined(separator: ", ")
    }

    if activeVersions.count > 1 {
      comparison = String(localized: "Multiple active versions")
      tone = .attention
    } else if let running = reportedVersion ?? activeVersions.first {
      if !app.isKnown || !running.isKnown || !included.isKnown {
        comparison = String(localized: "Version information incomplete")
        tone = .attention
      } else if !app.matches(included) {
        comparison = String(localized: "The app and its included extension differ")
        tone = .attention
      } else if app.matches(running) {
        comparison = String(localized: "Versions match")
        tone = .matching
      } else if pendingUpdate == nil {
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
    if let pendingUpdate {
      comparison = String(localized: "Restart to finish the extension update")
      tone = .attention
      let next = ProductVersion(installation: pendingUpdate.next).description
      notices.append(
        Notice(
          id: "updateRestart",
          text: runningExtension != nil
            ? String(
              localized:
                "The extension that is running keeps checking requests until this Mac restarts. macOS then starts \(next)."
            )
            : String(localized: "macOS starts \(next) when this Mac restarts.")
        ))
      // A package installed while an update waited: macOS starts the waiting version first, and
      // the app asks for its own extension only after that restart.
      if let includedBuild = included.build.flatMap(BundleBuildVersion.init),
        let nextBuild = BundleBuildVersion(pendingUpdate.next.bundleVersion),
        nextBuild < includedBuild
      {
        notices.append(
          Notice(
            id: "updateRestartAgain",
            text: String(
              localized:
                "This app includes a newer extension than \(next). After the restart, open Pasu FS to update the extension again; that update also finishes with a restart."
            )))
      }
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
        let text =
          if item.isEnabled {
            String(localized: "\(version): removal pending; macOS still reports it in use.")
          } else if item == runningRemoval {
            String(
              localized: "\(version): keeps running until a restart; macOS then removes it.")
          } else {
            String(localized: "\(version): not running; macOS will clean it up after a restart.")
          }
        notices.append(Notice(id: "removal-\(index)", text: text))
      }
      if item.isAwaitingUserApproval {
        notices.append(
          Notice(
            id: "approval-\(index)",
            text: String(localized: "\(version): waiting for approval in System Settings.")
          ))
      }
      if !item.isEnabled, !item.isUninstalling, !item.isAwaitingUserApproval,
        item != pendingUpdate?.next
      {
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
      case .requiresRestart where pendingUpdate == nil:
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
      case .completed, .requiresRestart, nil:
        break
      }
    }
  }
}
