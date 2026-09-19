import Darwin
import Foundation
import PasuFSMaintenanceCore

@main
enum PasuFSMaintenanceEntry {
  static func main() {
    do {
      guard geteuid() == 0 else {
        throw MaintenanceError(
          "This maintenance executable must be started by macOS Installer or launchd.")
      }
      let arguments = Array(CommandLine.arguments.dropFirst())
      switch arguments {
      case ["--serve"]: try MaintenanceService().run()
      case ["--verify-installed"]: try SystemOperations.validateInstallation()
      default:
        guard arguments.count == 2, arguments[0] == "--preflight" else {
          throw MaintenanceError("Unsupported maintenance operation.")
        }
        try SystemOperations.preflight(incomingVersion: arguments[1])
      }
    } catch {
      FileHandle.standardError.write(Data("Pasu FS: \(error)\n".utf8))
      exit(EXIT_FAILURE)
    }
  }
}
