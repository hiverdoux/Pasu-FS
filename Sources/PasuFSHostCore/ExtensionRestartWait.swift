import Foundation

/// A bundle build version (`CFBundleVersion`) of one to three numeric components, compared
/// component by component with missing components read as zero.
public struct BundleBuildVersion: Comparable, Equatable, Sendable {
  private let components: [UInt64]

  public init?(_ rawValue: String) {
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

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.components.lexicographicallyPrecedes(rhs.components)
  }
}

/// An extension update that macOS completes at the next restart.
///
/// The extension's Info.plist sets `NSEndpointSecurityRebootRequired`. When the app asks macOS to
/// replace a running extension that has the key, Endpoint Security refuses to stop it, and macOS
/// starts the new version only at the next restart. Until then the earlier version keeps running
/// and checking requests, and macOS reports neither version as enabled: the earlier one as being
/// removed, the new one as neither enabled, being removed nor waiting for approval.
///
/// macOS reports the same for an earlier version that has already stopped, so this doesn't tell
/// whether the earlier version still runs. Only the running extension's own status does.
public struct ExtensionUpdateAwaitingRestart: Equatable, Sendable {
  /// The version that macOS starts at the next restart.
  public var next: ExtensionInstallationProperties
  /// The newest earlier version that macOS removes at the next restart.
  public var replaced: ExtensionInstallationProperties

  /// The update that waits for a restart in the installations macOS reports, or nil. The result
  /// follows from the installations alone, so it is the same each time the app reads them.
  public init?(
    installations: [ExtensionInstallationProperties],
    extensionIdentifier: String = ActivationController.extensionIdentifier
  ) {
    let matching = installations.filter { $0.bundleIdentifier == extensionIdentifier }
    guard
      !matching.contains(where: { $0.isEnabled && !$0.isUninstalling }),
      let next = matching.filter({
        !$0.isEnabled && !$0.isUninstalling && !$0.isAwaitingUserApproval
      }).max(by: Self.isOlder),
      let nextVersion = BundleBuildVersion(next.bundleVersion),
      let replaced = matching.filter({
        guard $0.isUninstalling, let version = BundleBuildVersion($0.bundleVersion) else {
          return false
        }
        return version < nextVersion
      }).max(by: Self.isOlder)
    else { return nil }
    self.next = next
    self.replaced = replaced
  }

  private static func isOlder(
    _ left: ExtensionInstallationProperties, _ right: ExtensionInstallationProperties
  ) -> Bool {
    switch (BundleBuildVersion(left.bundleVersion), BundleBuildVersion(right.bundleVersion)) {
    case (let left?, let right?): left < right
    case (nil, _?): true
    default: false
    }
  }
}
