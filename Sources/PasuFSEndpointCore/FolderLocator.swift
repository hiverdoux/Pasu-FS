import Darwin
import Foundation
import PasuFSConfiguration

/// Looks up policy folders on disk by path and by identity. Never used while answering an
/// authorization request: only when policies are stored, after a rename was reported and on
/// the periodic status check.
public protocol FolderLocating: Sendable {
  /// The identity of the folder at `path`, or nil when nothing, or something other than a
  /// folder, is there. A symbolic link at `path` is not followed.
  func identity(ofFolderAt path: String) -> FolderIdentity?
  /// `expected` with its volume ID brought up to date when the folder at `path` is the folder
  /// it identifies; nil when the folder at `path` is another one or there is none.
  func confirmedIdentity(ofFolderAt path: String, expected: FolderIdentity) -> FolderIdentity?
  /// The current path of the folder that `identity` names, or nil when it no longer exists, is
  /// no longer a folder or its volume is not mounted.
  func path(of identity: FolderIdentity) -> String?
  /// The path of the folder at `path` as the file system spells it, with symbolic links
  /// resolved, or nil when nothing is there.
  func spelling(ofFolderAt path: String) -> String?
}

extension FolderLocating {
  /// Locators that don't read spellings report none, so a folder is never followed by them.
  public func spelling(ofFolderAt path: String) -> String? { nil }
}

/// Reads folder identities with `lstat` and `statfs`, and finds a folder by identity with
/// `fsgetpath`, which returns the path of an object from its volume ID and object number.
public struct SystemFolderLocator: FolderLocating {
  public init() {}

  public func identity(ofFolderAt path: String) -> FolderIdentity? {
    guard let facts = Self.folderFacts(path) else { return nil }
    return FolderIdentity(
      fileSystemID: facts.fileSystemID, volumeUUID: Self.volumeUUID(path),
      objectID: facts.objectID)
  }

  public func confirmedIdentity(ofFolderAt path: String, expected: FolderIdentity)
    -> FolderIdentity?
  {
    guard let facts = Self.folderFacts(path), facts.objectID == expected.objectID else {
      return nil
    }
    if facts.fileSystemID == expected.fileSystemID { return expected }
    // The volume was mounted again and received another ID; its UUID still names it.
    guard let uuid = expected.volumeUUID, Self.volumeUUID(path) == uuid else { return nil }
    var refreshed = expected
    refreshed.fileSystemID = facts.fileSystemID
    return refreshed
  }

  public func spelling(ofFolderAt path: String) -> String? {
    SystemTargetPathResolver().spelling(of: path)
  }

  public func path(of identity: FolderIdentity) -> String? {
    for fileSystemID in Self.candidateFileSystemIDs(for: identity) {
      let words = FolderIdentity(
        fileSystemID: fileSystemID, volumeUUID: nil, objectID: 0
      ).fileSystemIDWords
      var volume = fsid_t(val: (words.0, words.1))
      var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
      let length = fsgetpath(&buffer, buffer.count, &volume, identity.objectID)
      guard length > 0 else { continue }
      let path = String(cString: buffer)
      var expected = identity
      expected.fileSystemID = fileSystemID
      if confirmedIdentity(ofFolderAt: path, expected: expected) != nil { return path }
    }
    return nil
  }

  /// The volume IDs to search: the mounted volume that has the stored UUID, preferring the one
  /// with the stored volume ID, or the stored volume ID when the file system has no UUID.
  static func candidateFileSystemIDs(for identity: FolderIdentity) -> [UInt64] {
    guard let uuid = identity.volumeUUID else { return [identity.fileSystemID] }
    let mounts = mountedFileSystems()
    if let stored = mounts.first(where: { $0.fileSystemID == identity.fileSystemID }),
      volumeUUID(stored.mountPoint) == uuid
    {
      return [stored.fileSystemID]
    }
    for mount in mounts where volumeUUID(mount.mountPoint) == uuid {
      return [mount.fileSystemID]
    }
    return []
  }

  /// The volume ID and object number of the folder at `path`, read with one `getattrlist`
  /// call that does not follow a symbolic link at `path`. Nil when no folder is there.
  static func folderFacts(_ path: String) -> (fileSystemID: UInt64, objectID: UInt64)? {
    var request = attrlist()
    request.bitmapcount = u_short(ATTR_BIT_MAP_COUNT)
    request.commonattr =
      attrgroup_t(ATTR_CMN_FSID) | attrgroup_t(ATTR_CMN_OBJTYPE)
      | attrgroup_t(ATTR_CMN_FILEID)
    // The reply holds its length, then the attributes in bit order: fsid_t (two 32-bit words),
    // the object type (32 bits) and the file ID (64 bits).
    var reply = [UInt8](repeating: 0, count: 64)
    let status = reply.withUnsafeMutableBytes {
      getattrlist(path, &request, $0.baseAddress, $0.count, UInt32(FSOPT_NOFOLLOW))
    }
    guard status == 0 else { return nil }
    return reply.withUnsafeBytes { bytes -> (UInt64, UInt64)? in
      guard bytes.load(fromByteOffset: 0, as: UInt32.self) >= 24 else { return nil }
      let first = bytes.loadUnaligned(fromByteOffset: 4, as: Int32.self)
      let second = bytes.loadUnaligned(fromByteOffset: 8, as: Int32.self)
      let type = bytes.loadUnaligned(fromByteOffset: 12, as: UInt32.self)
      let fileID = bytes.loadUnaligned(fromByteOffset: 16, as: UInt64.self)
      guard type == UInt32(VDIR.rawValue) else { return nil }
      return (FolderIdentity.packFileSystemID(first, second), fileID)
    }
  }

  static func volumeUUID(_ path: String) -> String? {
    try? URL(fileURLWithPath: path).resourceValues(forKeys: [.volumeUUIDStringKey])
      .volumeUUIDString
  }

  private static func mountedFileSystems() -> [(fileSystemID: UInt64, mountPoint: String)] {
    let count = getfsstat(nil, 0, MNT_NOWAIT)
    guard count > 0 else { return [] }
    // Room for volumes mounted between the two calls.
    let capacity = Int(count) + 8
    var records = [Darwin.statfs](repeating: Darwin.statfs(), count: capacity)
    let filled = records.withUnsafeMutableBufferPointer {
      getfsstat($0.baseAddress, Int32(capacity * MemoryLayout<Darwin.statfs>.stride), MNT_NOWAIT)
    }
    guard filled > 0 else { return [] }
    return records.prefix(Int(filled)).map { record in
      var record = record
      let mountPoint = withUnsafePointer(to: &record.f_mntonname) {
        $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXPATHLEN)) { String(cString: $0) }
      }
      return (
        FolderIdentity.packFileSystemID(record.f_fsid.val.0, record.f_fsid.val.1), mountPoint
      )
    }
  }
}
