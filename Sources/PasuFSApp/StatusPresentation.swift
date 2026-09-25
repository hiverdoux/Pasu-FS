import Foundation
import PasuFSHostCore

enum StatusTone: Equatable {
  case protecting
  case auditing
  case attention
  case neutral
}

/// How one protection state is named on the Overview, in the menu bar and in the setup assistant.
/// "Protecting" and "Auditing" appear only for fresh authenticated evidence (see `HealthStateReducer`).
struct StatusPresentation: Equatable {
  let title: String
  let detail: String
  let symbolName: String
  let menuBarSymbolName: String
  let tone: StatusTone

  init(health: HealthState) {
    switch health.protection {
    case .enforcingOpenEvents:
      title = String(localized: "Protecting")
      detail = String(
        localized:
          "Protection policies: \(health.protectionPolicyCount) · Audit policies: \(health.auditPolicyCount)"
      )
      symbolName = "checkmark.shield"
      menuBarSymbolName = "lock.shield.fill"
      tone = .protecting
    case .monitoringOpenEvents:
      title = String(localized: "Auditing")
      detail = String(localized: "Nothing is blocked.")
      symbolName = "eye"
      menuBarSymbolName = "eye.fill"
      tone = .auditing
    case .idle:
      title = String(localized: "No Active Policies")
      detail = String(localized: "No folder is being protected or audited.")
      symbolName = "shield"
      menuBarSymbolName = "lock.shield"
      tone = .neutral
    case .degraded(let reason):
      title = String(localized: "Needs Attention")
      detail = RuntimeText.localized(reason)
      symbolName = "exclamationmark.triangle"
      menuBarSymbolName = "exclamationmark.shield.fill"
      tone = .attention
    case .starting:
      title = String(localized: "Starting")
      detail = String(localized: "Protection is not confirmed yet.")
      symbolName = "hourglass"
      menuBarSymbolName = "hourglass"
      tone = .neutral
    case .waitingForApproval:
      title = String(localized: "Waiting for Approval")
      detail = String(localized: "Approve the extension in System Settings.")
      symbolName = "hourglass"
      menuBarSymbolName = "hourglass"
      tone = .neutral
    case .waitingForFullDiskAccess:
      title = String(localized: "Full Disk Access Needed")
      detail = String(
        localized: "Allow Full Disk Access for “Pasu FS Endpoint Security” in System Settings.")
      symbolName = "hourglass"
      menuBarSymbolName = "hourglass"
      tone = .neutral
    case .stopped:
      title = String(localized: "Stopped")
      detail = String(
        localized: "The extension is installed but not running. Files are not protected.")
      symbolName = "power"
      menuBarSymbolName = "lock.shield"
      tone = .neutral
    case .uninstalling:
      title = String(localized: "Uninstalling")
      detail = String(
        localized:
          "macOS is removing the extension. Protection may continue until the Mac restarts.")
      symbolName = "shield"
      menuBarSymbolName = "lock.shield"
      tone = .neutral
    case .notInstalled:
      title = String(localized: "Not Installed")
      detail = String(localized: "Activate the Endpoint Security extension to start setup.")
      symbolName = "shield"
      menuBarSymbolName = "lock.shield"
      tone = .neutral
    }
  }
}
