import Darwin
import Foundation
import PasuFSMaintenanceCore

@main
enum PasuFSMaintenanceEntry {
  static func main() {
    do {
      guard geteuid() == 0 else {
        throw MaintenanceError(.notRunningAsRoot)
      }
      let arguments = Array(CommandLine.arguments.dropFirst())
      switch arguments {
      case ["--serve"]: try MaintenanceService().run()
      case ["--verify-installed"]: try SystemOperations.validateInstallation()
      case ["--register-authorization-rights"]:
        try SystemOperations.validateInstallation()
        try SystemOperations.registerAuthorizationRights()
      default:
        guard arguments.count == 2, arguments[0] == "--preflight" else {
          throw MaintenanceError(.unsupportedOperation)
        }
        try SystemOperations.preflight(incomingVersion: arguments[1])
      }
    } catch {
      FileHandle.standardError.write(Data("Pasu FS: \(error)\n".utf8))
      exit(EXIT_FAILURE)
    }
  }
}
