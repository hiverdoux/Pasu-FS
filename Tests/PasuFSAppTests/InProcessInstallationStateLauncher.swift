import Darwin
import Foundation
import PasuFSHostCore

/// Answers the app's installation state queries from a test lifecycle, in this process, the way
/// the child process does: the answer is encoded, then read back with its exit status. Ending the
/// query cancels it and reports it as ended by SIGKILL.
struct InProcessInstallationStateLauncher: InstallationStateChildLaunching {
  let lifecycle: any ExtensionLifecycleControlling

  func launch() throws -> any InstallationStateChild {
    InProcessInstallationStateChild(lifecycle: lifecycle)
  }
}

private final class InProcessInstallationStateChild: InstallationStateChild, @unchecked Sendable {
  private let lock = NSLock()
  private var hasEnded = false
  private var wasKilled = false
  private var task: Task<InstallationStateChildTermination, Never>?

  init(lifecycle: any ExtensionLifecycleControlling) {
    task = Task { [self] in
      let report = await InstallationStateProbe.query(lifecycle, timeout: 3_600)
      let killed = lock.withLock {
        hasEnded = true
        return wasKilled
      }
      return killed
        ? InstallationStateChildTermination(reason: .signaled(SIGKILL), standardOutput: Data())
        : InstallationStateChildTermination(
          reason: .exited(report.exitStatus), standardOutput: report.encoded())
    }
  }

  func waitForTermination() async -> InstallationStateChildTermination {
    let task = lock.withLock { self.task }
    return await task!.value
  }

  func kill() {
    let task = lock.withLock { () -> Task<InstallationStateChildTermination, Never>? in
      guard !hasEnded else { return nil }
      wasKilled = true
      return self.task
    }
    task?.cancel()
  }
}

extension ExtensionLifecycleControlling {
  /// The launcher that test lifecycles return.
  func inProcessInstallationStateLauncher() -> any InstallationStateChildLaunching {
    InProcessInstallationStateLauncher(lifecycle: self)
  }
}
