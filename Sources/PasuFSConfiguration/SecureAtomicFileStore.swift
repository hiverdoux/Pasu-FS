import Darwin
import Foundation

public enum SecureFileStoreError: Error, Equatable, CustomStringConvertible, Sendable {
  case invalidFilename
  case untrustedDirectory(String)
  case fileNotFound(String)
  case notRegularFile(String)
  case ownerMismatch(path: String, expected: UInt32, actual: UInt32)
  case unsafePermissions(String)
  case fileTooLarge(path: String, size: Int, maximum: Int)
  case systemCall(operation: String, code: Int32)

  public var description: String {
    switch self {
    case .invalidFilename:
      "A secure-store filename must be one non-empty path component."
    case .untrustedDirectory(let path):
      "The secure-store directory is not a trusted real directory: \(path)."
    case .fileNotFound(let path):
      "Secure-store file does not exist: \(path)."
    case .notRegularFile(let path):
      "Secure-store entry is not a regular file: \(path)."
    case .ownerMismatch(let path, let expected, let actual):
      "Secure-store owner mismatch for \(path): expected \(expected), found \(actual)."
    case .unsafePermissions(let path):
      "Secure-store entry is writable by a group or other users: \(path)."
    case .fileTooLarge(let path, let size, let maximum):
      "Secure-store file \(path) is \(size) bytes; maximum is \(maximum)."
    case .systemCall(let operation, let code):
      "\(operation) failed with errno \(code): \(String(cString: strerror(code)))."
    }
  }
}

/// How far a write is made durable before `SecureAtomicFileStore.write` returns.
public enum SecureFileDurability: Sendable {
  /// `fsync` on the file and on its directory. The data reaches the storage device, which may
  /// still keep it in its own cache, so a sudden loss of power can lose a recent write.
  case fileSystem
  /// `fsync` and then `fcntl(F_FULLFSYNC)` on the file and on its directory, which asks the device
  /// to write its cache out, so a write that returned survives a sudden loss of power. On a
  /// volume that doesn't support `F_FULLFSYNC` (`ENOTSUP` or `EINVAL`) the write keeps the
  /// `fsync` result, and the store reports it through `fullSynchronizationUnavailable`.
  case storageDevice
}

/// The synchronization calls of a store. Tests replace them to observe their order and to fail
/// them; each returns the system call's result and leaves its error in `errno`.
public struct SecureFileSynchronization: Sendable {
  public var fsync: @Sendable (Int32) -> Int32
  public var fullFsync: @Sendable (Int32) -> Int32

  public init(
    fsync: @escaping @Sendable (Int32) -> Int32,
    fullFsync: @escaping @Sendable (Int32) -> Int32
  ) {
    self.fsync = fsync
    self.fullFsync = fullFsync
  }

  public static let system = SecureFileSynchronization(
    fsync: { Darwin.fsync($0) },
    fullFsync: { fcntl($0, F_FULLFSYNC) })
}

public final class SecureAtomicFileStore: @unchecked Sendable {
  public let rootDirectory: URL
  public let requiredOwnerUserID: UInt32?
  private let synchronization: SecureFileSynchronization
  /// Called with the operation and `errno` when `F_FULLFSYNC` is not supported and a
  /// `storageDevice` write keeps the `fsync` result instead.
  private let fullSynchronizationUnavailable: (@Sendable (String, Int32) -> Void)?

  /// The parents of the root are kept as their physical path so descriptor-relative removal of
  /// the same files never meets a symbolic-link alias such as `/tmp` or `/var`. The root itself
  /// is not resolved: a root that is a symbolic link is refused when it is opened.
  public init(
    rootDirectory: URL, requiredOwnerUserID: UInt32?,
    synchronization: SecureFileSynchronization = .system,
    fullSynchronizationUnavailable: (@Sendable (String, Int32) -> Void)? = nil
  ) {
    self.rootDirectory = PhysicalPath.resolve(rootDirectory)
    self.requiredOwnerUserID = requiredOwnerUserID
    self.synchronization = synchronization
    self.fullSynchronizationUnavailable = fullSynchronizationUnavailable
  }

  public func prepareDirectory(mode: mode_t = 0o755) throws {
    try FileManager.default.createDirectory(
      at: rootDirectory,
      withIntermediateDirectories: true
    )

    var metadata = stat()
    guard lstat(rootDirectory.path, &metadata) == 0 else {
      throw systemCall("lstat directory")
    }
    guard metadata.st_mode & S_IFMT == S_IFDIR else {
      throw SecureFileStoreError.untrustedDirectory(rootDirectory.path)
    }
    try validateOwner(metadata, path: rootDirectory.path)
    guard chmod(rootDirectory.path, mode) == 0 else {
      throw systemCall("chmod directory")
    }

    let directoryDescriptor = try openDirectory()
    close(directoryDescriptor)
  }

  public func write(
    _ data: Data,
    to filename: String,
    mode: mode_t,
    durability: SecureFileDurability = .fileSystem
  ) throws {
    try validateFilename(filename)
    let directoryDescriptor = try openDirectory()
    defer { close(directoryDescriptor) }

    let temporaryName = ".\(filename).\(UUID().uuidString).tmp"
    let fileDescriptor = temporaryName.withCString {
      openat(
        directoryDescriptor,
        $0,
        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
        mode
      )
    }
    guard fileDescriptor >= 0 else {
      throw systemCall("openat temporary file")
    }

    var shouldRemoveTemporaryFile = true
    defer {
      close(fileDescriptor)
      if shouldRemoveTemporaryFile {
        _ = temporaryName.withCString { unlinkat(directoryDescriptor, $0, 0) }
      }
    }

    try data.withUnsafeBytes { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      var offset = 0
      while offset < buffer.count {
        let written = Darwin.write(
          fileDescriptor,
          baseAddress.advanced(by: offset),
          buffer.count - offset
        )
        guard written >= 0 else {
          if errno == EINTR { continue }
          throw systemCall("write temporary file")
        }
        offset += written
      }
    }
    guard fchmod(fileDescriptor, mode) == 0 else {
      throw systemCall("fchmod temporary file")
    }
    try synchronize(fileDescriptor, durability: durability, what: "temporary file")

    let renameResult = temporaryName.withCString { temporaryPointer in
      filename.withCString { destinationPointer in
        renameat(
          directoryDescriptor,
          temporaryPointer,
          directoryDescriptor,
          destinationPointer
        )
      }
    }
    guard renameResult == 0 else {
      throw systemCall("renameat secure-store file")
    }
    shouldRemoveTemporaryFile = false
    try synchronize(directoryDescriptor, durability: durability, what: "secure-store directory")
  }

  public func read(
    _ filename: String,
    maximumSize: Int,
    rejectGroupOrOtherWritable: Bool = true
  ) throws -> Data {
    try validateFilename(filename)
    let directoryDescriptor = try openDirectory()
    defer { close(directoryDescriptor) }

    let fileDescriptor = filename.withCString {
      openat(directoryDescriptor, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard fileDescriptor >= 0 else {
      if errno == ENOENT {
        throw SecureFileStoreError.fileNotFound(filename)
      }
      throw systemCall("openat secure-store file")
    }
    defer { close(fileDescriptor) }

    var metadata = stat()
    guard fstat(fileDescriptor, &metadata) == 0 else {
      throw systemCall("fstat secure-store file")
    }
    guard metadata.st_mode & S_IFMT == S_IFREG else {
      throw SecureFileStoreError.notRegularFile(filename)
    }
    try validateOwner(metadata, path: filename)
    if rejectGroupOrOtherWritable,
      metadata.st_mode & (S_IWGRP | S_IWOTH) != 0
    {
      throw SecureFileStoreError.unsafePermissions(filename)
    }

    let size = Int(metadata.st_size)
    guard size >= 0, size <= maximumSize else {
      throw SecureFileStoreError.fileTooLarge(
        path: filename,
        size: max(size, 0),
        maximum: maximumSize
      )
    }
    var data = Data(count: size)
    try data.withUnsafeMutableBytes { buffer in
      guard let baseAddress = buffer.baseAddress else { return }
      var offset = 0
      while offset < size {
        let count = Darwin.read(
          fileDescriptor,
          baseAddress.advanced(by: offset),
          size - offset
        )
        guard count >= 0 else {
          if errno == EINTR { continue }
          throw systemCall("read secure-store file")
        }
        guard count > 0 else { break }
        offset += count
      }
      guard offset == size else {
        throw SecureFileStoreError.systemCall(operation: "short read", code: EIO)
      }
    }
    return data
  }

  /// Removes one validated regular file without following a symbolic link.
  /// The containing directory is fsynced so the retirement survives a crash.
  public func remove(_ filename: String, ifExists: Bool = false) throws {
    try validateFilename(filename)
    let directoryDescriptor = try openDirectory()
    defer { close(directoryDescriptor) }

    var metadata = stat()
    let statusResult = filename.withCString {
      fstatat(directoryDescriptor, $0, &metadata, AT_SYMLINK_NOFOLLOW)
    }
    guard statusResult == 0 else {
      if errno == ENOENT, ifExists { return }
      if errno == ENOENT {
        throw SecureFileStoreError.fileNotFound(filename)
      }
      throw systemCall("fstatat secure-store file")
    }
    guard metadata.st_mode & S_IFMT == S_IFREG else {
      throw SecureFileStoreError.notRegularFile(filename)
    }
    try validateOwner(metadata, path: filename)
    guard metadata.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
      throw SecureFileStoreError.unsafePermissions(filename)
    }

    let unlinkResult = filename.withCString { unlinkat(directoryDescriptor, $0, 0) }
    guard unlinkResult == 0 else {
      throw systemCall("unlinkat secure-store file")
    }
    try synchronize(directoryDescriptor, durability: .fileSystem, what: "secure-store directory")
  }

  /// `fsync`, then for `storageDevice` `F_FULLFSYNC`. An unsupported `F_FULLFSYNC` keeps the
  /// `fsync` result; any other failure is an error.
  private func synchronize(
    _ descriptor: Int32, durability: SecureFileDurability, what: String
  ) throws {
    guard synchronization.fsync(descriptor) == 0 else {
      throw systemCall("fsync \(what)")
    }
    guard durability == .storageDevice, synchronization.fullFsync(descriptor) != 0 else { return }
    let code = errno
    guard code == ENOTSUP || code == EINVAL else {
      throw SecureFileStoreError.systemCall(operation: "F_FULLFSYNC \(what)", code: code)
    }
    fullSynchronizationUnavailable?("F_FULLFSYNC \(what)", code)
  }

  private func openDirectory() throws -> Int32 {
    let descriptor = open(
      rootDirectory.path,
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
    guard descriptor >= 0 else {
      throw systemCall("open secure-store directory")
    }

    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0 else {
      let savedError = errno
      close(descriptor)
      throw SecureFileStoreError.systemCall(operation: "fstat directory", code: savedError)
    }
    guard metadata.st_mode & S_IFMT == S_IFDIR else {
      close(descriptor)
      throw SecureFileStoreError.untrustedDirectory(rootDirectory.path)
    }
    do {
      try validateOwner(metadata, path: rootDirectory.path)
    } catch {
      close(descriptor)
      throw error
    }
    guard metadata.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
      close(descriptor)
      throw SecureFileStoreError.unsafePermissions(rootDirectory.path)
    }
    return descriptor
  }

  private func validateOwner(_ metadata: stat, path: String) throws {
    guard let requiredOwnerUserID else { return }
    guard metadata.st_uid == requiredOwnerUserID else {
      throw SecureFileStoreError.ownerMismatch(
        path: path,
        expected: requiredOwnerUserID,
        actual: metadata.st_uid
      )
    }
  }

  private func validateFilename(_ filename: String) throws {
    guard !filename.isEmpty, filename != ".", filename != "..", !filename.contains("/") else {
      throw SecureFileStoreError.invalidFilename
    }
  }

  private func systemCall(_ operation: String) -> SecureFileStoreError {
    SecureFileStoreError.systemCall(operation: operation, code: errno)
  }
}
