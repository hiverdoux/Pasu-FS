import Darwin
import Foundation
import os

/// How a process that read the installation states ended, and what it wrote to its standard
/// output.
public struct InstallationStateChildTermination: Equatable, Sendable {
  public enum Reason: Equatable, Sendable {
    /// The process exited with this status.
    case exited(Int32)
    /// A signal ended the process.
    case signaled(Int32)
  }

  public var reason: Reason
  public var standardOutput: Data
  /// Whether the process wrote more than `InstallationStateReport.maximumEncodedSize` bytes;
  /// `standardOutput` then holds only the first ones.
  public var outputWasTruncated: Bool

  public init(reason: Reason, standardOutput: Data, outputWasTruncated: Bool = false) {
    self.reason = reason
    self.standardOutput = standardOutput
    self.outputWasTruncated = outputWasTruncated
  }
}

/// A running process that reads the installation states once and exits.
public protocol InstallationStateChild: Sendable {
  /// Waits until the process has ended.
  func waitForTermination() async -> InstallationStateChildTermination
  /// Ends the process at once with SIGKILL. Does nothing once it has ended.
  func kill()
}

public protocol InstallationStateChildLaunching: Sendable {
  /// Starts a process that reads the installation states.
  func launch() throws -> any InstallationStateChild
}

public struct InstallationStateLaunchError: Error, Equatable, Sendable, CustomStringConvertible {
  public var description: String

  public init(_ description: String) {
    self.description = description
  }
}

/// Starts the app's own executable with the installation state command, without a shell: the
/// process must be the app's main executable, whose entitlements allow system extension requests.
public struct InstallationStateChildProcessLauncher: InstallationStateChildLaunching {
  /// The arguments of the command that follow the host command marker.
  public static let commandArguments = ["--installation-states", "--json"]
  public static let arguments = ["--pasu-fs-host"] + commandArguments

  public let executableURL: URL?

  public init(executableURL: URL? = Bundle.main.executableURL) {
    self.executableURL = executableURL
  }

  public func launch() throws -> any InstallationStateChild {
    guard let executableURL, executableURL.isFileURL,
      executableURL.deletingLastPathComponent().path.hasSuffix(".app/Contents/MacOS")
    else {
      throw InstallationStateLaunchError("The app’s executable could not be found.")
    }
    return try SpawnedInstallationStateChild(
      executablePath: executableURL.path, arguments: Self.arguments)
  }
}

/// A process started with `posix_spawn`, whose standard output the parent reads.
///
/// Its standard input and error are `/dev/null`, it inherits no other descriptors, and its signals
/// start with their default actions. A thread reads the output until the process closes it, waits
/// until the process has ended without reaping it, so that its process ID can't be reused while
/// `kill()` may still signal it, and then reaps it.
final class SpawnedInstallationStateChild: InstallationStateChild, @unchecked Sendable {
  private struct State {
    /// True once the process has ended: `kill()` then sends nothing.
    var hasEnded = false
    var termination: InstallationStateChildTermination?
    var waiters: [CheckedContinuation<InstallationStateChildTermination, Never>] = []
  }

  let processIdentifier: pid_t
  private let state = OSAllocatedUnfairLock(initialState: State())

  init(executablePath: String, arguments: [String]) throws {
    var descriptors: [Int32] = [-1, -1]
    guard pipe(&descriptors) == 0 else { throw Self.error("pipe", errno) }
    let readDescriptor = descriptors[0]
    let writeDescriptor = descriptors[1]
    _ = fcntl(readDescriptor, F_SETFD, FD_CLOEXEC)
    _ = fcntl(writeDescriptor, F_SETFD, FD_CLOEXEC)

    var actions: posix_spawn_file_actions_t?
    posix_spawn_file_actions_init(&actions)
    defer { posix_spawn_file_actions_destroy(&actions) }
    posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, "/dev/null", O_RDONLY, 0)
    posix_spawn_file_actions_adddup2(&actions, writeDescriptor, STDOUT_FILENO)
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0)

    var attributes: posix_spawnattr_t?
    posix_spawnattr_init(&attributes)
    defer { posix_spawnattr_destroy(&attributes) }
    var emptyMask = sigset_t()
    sigemptyset(&emptyMask)
    var defaultSignals = sigset_t()
    sigfillset(&defaultSignals)
    sigdelset(&defaultSignals, SIGKILL)
    sigdelset(&defaultSignals, SIGSTOP)
    posix_spawnattr_setsigmask(&attributes, &emptyMask)
    posix_spawnattr_setsigdefault(&attributes, &defaultSignals)
    posix_spawnattr_setflags(
      &attributes,
      Int16(POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF))

    let argumentStrings = ([executablePath] + arguments).map { strdup($0) }
    let environmentStrings = ProcessInfo.processInfo.environment.map {
      strdup("\($0.key)=\($0.value)")
    }
    defer {
      for string in argumentStrings + environmentStrings { free(string) }
    }
    var pid: pid_t = 0
    let result = posix_spawn(
      &pid, executablePath, &actions, &attributes, argumentStrings + [nil],
      environmentStrings + [nil])
    close(writeDescriptor)
    guard result == 0 else {
      close(readDescriptor)
      throw Self.error("posix_spawn", result)
    }
    processIdentifier = pid
    Thread.detachNewThread { [self] in
      collect(from: readDescriptor)
    }
  }

  func waitForTermination() async -> InstallationStateChildTermination {
    await withCheckedContinuation { continuation in
      let termination = state.withLock { state -> InstallationStateChildTermination? in
        if let termination = state.termination { return termination }
        state.waiters.append(continuation)
        return nil
      }
      if let termination { continuation.resume(returning: termination) }
    }
  }

  func kill() {
    state.withLock { state in
      guard !state.hasEnded else { return }
      _ = Darwin.kill(processIdentifier, SIGKILL)
    }
  }

  private func collect(from descriptor: Int32) {
    let limit = InstallationStateReport.maximumEncodedSize
    var output = Data()
    var truncated = false
    var buffer = [UInt8](repeating: 0, count: 16_384)
    while true {
      let count = read(descriptor, &buffer, buffer.count)
      if count > 0 {
        let kept = min(count, limit - output.count)
        if kept > 0 { output.append(contentsOf: buffer[0..<kept]) }
        if kept < count { truncated = true }
      } else if count == 0 || errno != EINTR {
        break
      }
    }
    close(descriptor)

    var information = siginfo_t()
    while waitid(P_PID, id_t(processIdentifier), &information, WEXITED | WNOWAIT) == -1,
      errno == EINTR
    {}
    state.withLock { $0.hasEnded = true }
    var status: Int32 = 0
    var reaped: pid_t
    repeat {
      reaped = waitpid(processIdentifier, &status, 0)
    } while reaped == -1 && errno == EINTR
    let reason: InstallationStateChildTermination.Reason =
      reaped == processIdentifier ? Self.reason(status) : .exited(-1)

    let termination = InstallationStateChildTermination(
      reason: reason, standardOutput: output, outputWasTruncated: truncated)
    let waiters = state.withLock { state in
      state.termination = termination
      defer { state.waiters = [] }
      return state.waiters
    }
    for waiter in waiters { waiter.resume(returning: termination) }
  }

  /// The `WIFEXITED`, `WEXITSTATUS` and `WTERMSIG` macros, which Swift doesn't import.
  private static func reason(_ status: Int32) -> InstallationStateChildTermination.Reason {
    let signal = status & 0x7f
    return signal == 0 ? .exited((status >> 8) & 0xff) : .signaled(signal)
  }

  private static func error(_ call: String, _ code: Int32) -> InstallationStateLaunchError {
    InstallationStateLaunchError("\(call): \(String(cString: strerror(code)))")
  }
}
