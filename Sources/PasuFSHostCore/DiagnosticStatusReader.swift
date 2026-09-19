import Foundation
import PasuFSConfiguration
import PasuFSIPC

public struct DiagnosticStatusReader: Sendable {
  public init() {}

  public func read() throws -> ExtensionStatusSnapshot {
    let locations = try ExtensionStorageLocations.localSystemDefault()
    let store = SecureAtomicFileStore(
      rootDirectory: locations.rootDirectory,
      requiredOwnerUserID: 0
    )
    let data = try store.read("status.json", maximumSize: 64 * 1_024)
    return try XPCJSONCodec.decode(ExtensionStatusSnapshot.self, from: data)
  }
}
