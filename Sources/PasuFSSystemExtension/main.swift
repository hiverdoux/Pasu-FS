import Darwin
import Foundation

do {
  let runtime = try ExtensionRuntime()
  runtime.start()
  dispatchMain()
} catch {
  fputs("Pasu FS system extension failed to start: \(error)\n", stderr)
  exit(EXIT_FAILURE)
}
