import Foundation

public enum LegacyPolicyRetirementResult: Equatable, Sendable {
  case notFound
  case removed
  case unrecognized
}

public enum LegacyPolicyRetirement {
  /// Permanently removes only a confirmed schema v1 policy file. Unknown data
  /// is retained so a malformed or future file is never silently destroyed.
  public static func run(
    store: SecureAtomicFileStore,
    filename: String = ExtensionStorageLocations.legacyPolicyFilename
  ) throws -> LegacyPolicyRetirementResult {
    let data: Data
    do {
      data = try store.read(
        filename,
        maximumSize: PolicySetDocumentCodec.maximumDocumentSize
      )
    } catch SecureFileStoreError.fileNotFound {
      return .notFound
    }

    guard PolicySetDocumentCodec.isLegacyV1Document(data) else {
      return .unrecognized
    }
    try store.remove(filename)
    return .removed
  }
}
