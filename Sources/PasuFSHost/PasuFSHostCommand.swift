import Darwin
import Foundation

// Restricted entitlements belong to the containing app's main executable.
// Replace this process so stdout, stderr, signals and exit status remain terminal-native.
@main
private enum PasuFSHostCommand {
  static func main() {
    var size: UInt32 = 0
    _ = _NSGetExecutablePath(nil, &size)
    var buffer = [CChar](repeating: 0, count: Int(size))
    guard _NSGetExecutablePath(&buffer, &size) == 0 else {
      fail("Cannot locate the CLI executable.")
    }
    let executable = buffer.withUnsafeBufferPointer { String(cString: $0.baseAddress!) }
    let appExecutable = URL(fileURLWithPath: executable).resolvingSymlinksInPath()
      .deletingLastPathComponent().appendingPathComponent("pasu-fs-app").path
    let arguments = [appExecutable, "--pasu-fs-host"] + CommandLine.arguments.dropFirst()
    let pointers = arguments.map { strdup($0) }
    defer {
      for pointer in pointers { free(pointer) }
    }
    var argv = pointers + [nil]
    appExecutable.withCString { path in
      _ = argv.withUnsafeMutableBufferPointer { execv(path, $0.baseAddress!) }
    }
    let reason = String(cString: strerror(errno))
    fail("Cannot execute the containing Pasu FS app: \(reason)")
  }

  private static func fail(_ message: String) -> Never {
    fputs("\(message)\n", stderr)
    exit(EXIT_FAILURE)
  }
}
