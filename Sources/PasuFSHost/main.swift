import Darwin
import Foundation
import SystemExtensions

private let extensionIdentifier = "com.dennis.pasu.fs.endpointsecurity"

private enum HostCommand: String {
  case activate
  case deactivate
}

private final class ExtensionRequestDelegate: NSObject, OSSystemExtensionRequestDelegate {
  func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    print("System extension status: waiting-for-user-approval")
  }

  func request(
    _ request: OSSystemExtensionRequest,
    actionForReplacingExtension existing: OSSystemExtensionProperties,
    withExtension ext: OSSystemExtensionProperties
  ) -> OSSystemExtensionRequest.ReplacementAction {
    print(
      "System extension status: replacing \(existing.bundleShortVersion) "
        + "with \(ext.bundleShortVersion)"
    )
    return .replace
  }

  func request(
    _ request: OSSystemExtensionRequest,
    didFinishWithResult result: OSSystemExtensionRequest.Result
  ) {
    let resultName: String
    switch result {
    case .completed:
      resultName = "completed"
    case .willCompleteAfterReboot:
      resultName = "will-complete-after-reboot"
    @unknown default:
      resultName = "unknown-\(result.rawValue)"
    }
    print("System extension status: \(resultName)")
    exit(EXIT_SUCCESS)
  }

  func request(
    _ request: OSSystemExtensionRequest,
    didFailWithError error: any Error
  ) {
    let nsError = error as NSError
    fputs(
      "System extension status: failed domain=\(nsError.domain) "
        + "code=\(nsError.code) description=\(nsError.localizedDescription)\n",
      stderr
    )
    exit(EXIT_FAILURE)
  }
}

private func printUsageAndExit(_ exitCode: Int32) -> Never {
  let stream = exitCode == EXIT_SUCCESS ? stdout : stderr
  fputs(
    "Usage: pasu-fs-host --activate | --deactivate\n"
      + "Requests lifecycle changes for \(extensionIdentifier).\n",
    stream
  )
  exit(exitCode)
}

let arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.count == 1 else {
  printUsageAndExit(EXIT_FAILURE)
}

if arguments[0] == "--help" || arguments[0] == "-h" {
  printUsageAndExit(EXIT_SUCCESS)
}

guard let command = HostCommand(rawValue: String(arguments[0].dropFirst(2))) else {
  printUsageAndExit(EXIT_FAILURE)
}

let request: OSSystemExtensionRequest
switch command {
case .activate:
  request = .activationRequest(
    forExtensionWithIdentifier: extensionIdentifier,
    queue: .main
  )
case .deactivate:
  request = .deactivationRequest(
    forExtensionWithIdentifier: extensionIdentifier,
    queue: .main
  )
}

private let requestDelegate = ExtensionRequestDelegate()
request.delegate = requestDelegate
print("System extension request: \(command.rawValue) \(extensionIdentifier)")
OSSystemExtensionManager.shared.submitRequest(request)
dispatchMain()
