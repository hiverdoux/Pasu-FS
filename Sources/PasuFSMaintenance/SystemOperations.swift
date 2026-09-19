import Darwin
import Foundation
import PasuFSConfiguration
import PasuFSIPC
import PasuFSMaintenanceCore

enum SystemOperations {
  struct CommandResult {
    let status: Int32
    let output: String
  }

  static func run(_ path: String, _ arguments: [String]) throws -> CommandResult {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: path)
    task.arguments = arguments
    task.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = pipe
    try task.run()
    let output = pipe.fileHandleForReading.readDataToEndOfFile()
    task.waitUntilExit()
    return CommandResult(
      status: task.terminationStatus, output: String(decoding: output, as: UTF8.self))
  }

  static func require(_ path: String, _ arguments: [String]) throws {
    let result = try run(path, arguments)
    guard result.status == 0 else {
      throw MaintenanceError(
        "\(URL(fileURLWithPath: path).lastPathComponent) failed (\(result.status)): \(result.output.prefix(2000))"
      )
    }
  }

  static func runningApplications(excluding excludedPID: Int32? = nil) throws -> [Int32] {
    let result = try run("/bin/ps", ["-ww", "-axo", "pid=,comm="])
    guard result.status == 0 else {
      throw MaintenanceError("Could not check running Pasu FS applications.")
    }
    return result.output.split(separator: "\n").compactMap { line in
      let fields = line.split(maxSplits: 1, whereSeparator: { $0.isWhitespace })
      guard fields.count == 2, let pid = Int32(fields[0]), pid != excludedPID else { return nil }
      let executable = String(fields[1]).trimmingCharacters(in: .whitespaces)
      guard executable.hasSuffix("/Pasu FS.app/Contents/MacOS/pasu-fs-app") else { return nil }
      return pid
    }
  }

  static func requireNoRunningApplications(excluding pid: Int32? = nil) throws {
    guard try runningApplications(excluding: pid).isEmpty else {
      throw MaintenanceError(
        "Quit Pasu FS normally, then run the installer or uninstaller again. Protection continues when the app quits. Another login session may also have Pasu FS open."
      )
    }
  }

  static func preflight(incomingVersion: String) throws {
    try requireNoRunningApplications()
    let app = URL(fileURLWithPath: MaintenanceContract.appPath)
    var metadata = stat()
    let present = lstat(app.path, &metadata) == 0
    if !present, errno != ENOENT { throw MaintenanceError("Cannot inspect the installation path.") }
    var currentVersion: String?
    let receipt = try run(
      "/usr/sbin/pkgutil", ["--pkg-info-plist", MaintenanceContract.packageIdentifier])
    let receiptInfo =
      receipt.status == 0
      ? (try PropertyListSerialization.propertyList(from: Data(receipt.output.utf8), format: nil)
        as? [String: Any])
      : nil
    let receiptVersion = receiptInfo?["pkg-version"] as? String
    if present {
      guard metadata.st_mode & S_IFMT == S_IFDIR else {
        throw MaintenanceError(
          "The Pasu FS installation path is not a real directory. No files were changed.")
      }
      let info = NSDictionary(contentsOf: app.appendingPathComponent("Contents/Info.plist"))
      let identifier = info?["CFBundleIdentifier"] as? String
      guard
        identifier == PasuFSXPC.hostBundleIdentifier
          || (identifier == nil && receiptVersion != nil && metadata.st_uid == 0)
      else {
        throw MaintenanceError(
          "Another application or an unrecognized directory occupies the installation path.")
      }
      currentVersion = info?["CFBundleVersion"] as? String ?? receiptVersion
      guard currentVersion != nil else {
        throw MaintenanceError(
          "The existing application has no readable build version or package receipt.")
      }
    }
    try ProductBuildVersion.validateUpgrade(incoming: incomingVersion, installed: currentVersion)
    try ProductBuildVersion.validateUpgrade(incoming: incomingVersion, installed: receiptVersion)
    for path in [MaintenanceContract.helperPath, MaintenanceContract.daemonPath] {
      try SafeRemoval.validateRoot(URL(fileURLWithPath: path))
    }
  }

  static func validateInstallation() throws {
    let app = URL(fileURLWithPath: MaintenanceContract.appPath)
    _ = try CodeSigningRequirementResolver.designatedRequirement(
      forCodeAt: app, requireRootOwnedBundle: true)
    try require("/usr/bin/codesign", ["--verify", "--deep", "--strict", app.path])
    for path in [MaintenanceContract.helperPath, MaintenanceContract.daemonPath] {
      var info = stat()
      guard lstat(path, &info) == 0, info.st_uid == 0,
        info.st_mode & S_IFMT == S_IFREG, info.st_mode & 0o022 == 0
      else {
        throw MaintenanceError(
          "The installed maintenance component has unsafe ownership or permissions.")
      }
    }
    let embedded = app.appendingPathComponent(MaintenanceContract.embeddedHelperPath)
    let requirement = try CodeSigningRequirementResolver.designatedRequirement(forCodeAt: embedded)
    let installedRequirement = try CodeSigningRequirementResolver.designatedRequirement(
      forCodeAt: URL(fileURLWithPath: MaintenanceContract.helperPath), requireRootOwnedBundle: true)
    guard installedRequirement == requirement else {
      throw MaintenanceError("The maintenance service signature does not match this application.")
    }
    // The installed executable must be precisely the one sealed into this application.
    guard
      try Data(contentsOf: embedded)
        == Data(contentsOf: URL(fileURLWithPath: MaintenanceContract.helperPath))
    else {
      throw MaintenanceError(
        "The installed helper does not match the application. Reinstall the package.")
    }
  }

  static func validateRemoval(excluding pid: Int32) throws {
    try validateInstallation()
    try requireNoRunningApplications(excluding: pid)
    try SafeRemoval.validateRoot(ExtensionStorageLocations.localSystemDefault().rootDirectory)
  }

  static func finishRemoval(session: UninstallSession, stateStore: UninstallStateStore) throws {
    // A closed XPC connection is not sufficient: wait for the initiating process to exit.
    let deadline = Date().addingTimeInterval(30)
    while kill(session.processID, 0) == 0 || errno == EPERM {
      guard Date() < deadline else {
        throw MaintenanceError("Pasu FS did not exit. Open the app and retry uninstalling.")
      }
      Thread.sleep(forTimeInterval: 0.1)
    }
    try requireNoRunningApplications()
    try validateInstallation()
    let locations = try ExtensionStorageLocations.localSystemDefault()
    if session.removeData {
      // Keep the state marker until all other product data has been removed.
      for entry in try FileManager.default.contentsOfDirectory(
        at: locations.rootDirectory, includingPropertiesForKeys: nil)
      {
        if entry.lastPathComponent != MaintenanceContract.stateFilename {
          try SafeRemoval.remove(entry)
        }
      }
    } else {
      try SafeRemoval.remove(locations.statusFile)
    }
    try SafeRemoval.remove(URL(fileURLWithPath: MaintenanceContract.appPath))
    let receipt = try run(
      "/usr/sbin/pkgutil", ["--pkg-info", MaintenanceContract.packageIdentifier])
    if receipt.status == 0 {
      try require("/usr/sbin/pkgutil", ["--forget", MaintenanceContract.packageIdentifier])
    } else if !receipt.output.contains("No receipt") {
      throw MaintenanceError(
        "Could not verify the package receipt during removal: \(receipt.output)")
    }
    // All failures above retain the helper and its registration for package repair and retry.
    try stateStore.clear()
    if session.removeData {
      guard rmdir(locations.rootDirectory.path) == 0 || errno == ENOENT else {
        throw MaintenanceError("The product data directory could not be removed.")
      }
    }
    try SafeRemoval.remove(URL(fileURLWithPath: MaintenanceContract.daemonPath))
    try SafeRemoval.remove(URL(fileURLWithPath: MaintenanceContract.helperPath))
    // This is deliberately last. launchd can terminate this process while removing its job.
    try require("/bin/launchctl", ["bootout", "system/\(MaintenanceContract.service)"])
  }
}
