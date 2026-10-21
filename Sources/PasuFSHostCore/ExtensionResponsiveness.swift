import Foundation
import PasuFSConfiguration

/// Whether the extension has stopped answering while it still runs.
///
/// The extension writes its status file every 5 seconds from its own timer. When the app can't
/// get the status over the authenticated connection and the file also stops changing, the
/// extension is stuck rather than slow or refusing the connection. macOS doesn't restart such an
/// extension in the fail-closed deadline mode.
public enum ExtensionResponsiveness {
  /// How old the status file must be before the extension counts as not responding: six missed
  /// updates, longer than the app's request timeout plus its polling interval.
  public static let unresponsiveAfter: TimeInterval = 30

  /// The time of the extension's last status when it doesn't respond, or nil.
  ///
  /// - Parameters:
  ///   - installation: The installation macOS reports. macOS keeps an enabled extension running.
  ///     Otherwise an extension can still run: an update or a removal that waits for a restart
  ///     leaves the earlier extension running, and macOS reports it the same way whether it
  ///     still runs or has stopped.
  ///   - evidence: The latest status the app has. Only a status read from the diagnostic file,
  ///     which the app falls back to when the connection fails, counts.
  ///   - requestTimedOutSinceLastAnswer: Whether a status request has waited out its timeout
  ///     since the extension last answered. That happens only while a process holds the
  ///     extension's service without answering; without an extension the connection fails at
  ///     once. It is required unless macOS reports an enabled installation, so that a status file
  ///     left behind by an extension that has stopped doesn't count.
  public static func lastStatusOfUnresponsiveExtension(
    installation: ExtensionInstallationProperties?, evidence: RuntimeStatusEvidence?,
    requestTimedOutSinceLastAnswer: Bool, now: Date
  ) -> Date? {
    let macOSKeepsExtensionRunning =
      installation.map {
        $0.isEnabled && !$0.isUninstalling && !$0.isAwaitingUserApproval
      } ?? false
    guard macOSKeepsExtensionRunning || requestTimedOutSinceLastAnswer else { return nil }
    guard let evidence, evidence.source == .diagnosticFile,
      evidence.snapshot.phase != .stopped
    else { return nil }
    let timestamp = evidence.snapshot.timestamp
    return now.timeIntervalSince(timestamp) >= unresponsiveAfter ? timestamp : nil
  }
}
