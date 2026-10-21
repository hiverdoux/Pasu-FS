import Foundation

/// Identifies a folder independently of its path: the volume it lies on and its object number
/// (inode) there. Renaming or moving the folder within its volume keeps this identity, so the
/// extension can find a policy folder again after it was moved.
public struct FolderIdentity: Codable, Equatable, Hashable, Sendable {
  /// Both words of the volume's `f_fsid` when the identity was taken, `val[0]` in the low and
  /// `val[1]` in the high 32 bits. macOS can assign another value when the volume is mounted
  /// again, so `volumeUUID` identifies the volume whenever the file system reports one.
  public var fileSystemID: UInt64
  /// The volume's UUID, when its file system reports one.
  public var volumeUUID: String?
  /// The folder's object number on its volume (`st_ino`).
  public var objectID: UInt64

  public init(fileSystemID: UInt64, volumeUUID: String?, objectID: UInt64) {
    self.fileSystemID = fileSystemID
    self.volumeUUID = volumeUUID
    self.objectID = objectID
  }

  /// Packs the two words of an `fsid_t`.
  public static func packFileSystemID(_ first: Int32, _ second: Int32) -> UInt64 {
    UInt64(UInt32(bitPattern: first)) | (UInt64(UInt32(bitPattern: second)) << 32)
  }

  /// The two words of `fileSystemID` in `fsid_t` order.
  public var fileSystemIDWords: (Int32, Int32) {
    (
      Int32(bitPattern: UInt32(truncatingIfNeeded: fileSystemID)),
      Int32(bitPattern: UInt32(truncatingIfNeeded: fileSystemID >> 32))
    )
  }
}

extension PolicySetDocument {
  /// The next revision of this set with the folders of the listed policies replaced. Used when
  /// a policy follows its folder to a new location; nothing else changes.
  public func movingFolders(_ folders: [UUID: String]) throws -> PolicySetDocument {
    guard revision < UInt64.max else { throw PolicyValidationError.invalidRevision }
    var next = self
    next.revision = revision + 1
    for index in next.policies.indices {
      if let folder = folders[next.policies[index].id] {
        next.policies[index].protectedRootPath = folder
      }
    }
    return next
  }
}
