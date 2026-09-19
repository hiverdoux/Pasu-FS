import ServiceManagement

enum LoginItemState: Equatable {
  case notRegistered
  case enabled
  case requiresApproval
  case notFound
}

@MainActor
protocol LoginItemControlling {
  var state: LoginItemState { get }

  func register() throws
  func unregister() throws
  func openSystemSettings()
}

struct MainAppLoginItemController: LoginItemControlling {
  var state: LoginItemState {
    switch SMAppService.mainApp.status {
    case .notRegistered:
      .notRegistered
    case .enabled:
      .enabled
    case .requiresApproval:
      .requiresApproval
    case .notFound:
      .notFound
    @unknown default:
      .notFound
    }
  }

  func register() throws {
    try SMAppService.mainApp.register()
  }

  func unregister() throws {
    try SMAppService.mainApp.unregister()
  }

  func openSystemSettings() {
    SMAppService.openSystemSettingsLoginItems()
  }
}
