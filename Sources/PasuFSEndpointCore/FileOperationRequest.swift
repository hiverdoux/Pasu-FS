import EndpointSecurity
import Foundation
import PasuFSConfiguration

/// The authorization events the extension answers. Raw values are the recorded event types.
public enum FileOperationKind: String, CaseIterable, Equatable, Sendable {
  case open = "AUTH_OPEN"
  case create = "AUTH_CREATE"
  case rename = "AUTH_RENAME"
  case unlink = "AUTH_UNLINK"
  case link = "AUTH_LINK"
  case clone = "AUTH_CLONE"
  case copyFile = "AUTH_COPYFILE"
  case truncate = "AUTH_TRUNCATE"
  case exchangeData = "AUTH_EXCHANGEDATA"
  case setMode = "AUTH_SETMODE"
  case setOwner = "AUTH_SETOWNER"
  case setFlags = "AUTH_SETFLAGS"
  case setACL = "AUTH_SETACL"
  case setExtendedAttribute = "AUTH_SETEXTATTR"
  case deleteExtendedAttribute = "AUTH_DELETEEXTATTR"
  case setAttributeList = "AUTH_SETATTRLIST"
  case setTimes = "AUTH_UTIMES"
  case mount = "AUTH_MOUNT"

  public var eventType: es_event_type_t {
    switch self {
    case .open: ES_EVENT_TYPE_AUTH_OPEN
    case .create: ES_EVENT_TYPE_AUTH_CREATE
    case .rename: ES_EVENT_TYPE_AUTH_RENAME
    case .unlink: ES_EVENT_TYPE_AUTH_UNLINK
    case .link: ES_EVENT_TYPE_AUTH_LINK
    case .clone: ES_EVENT_TYPE_AUTH_CLONE
    case .copyFile: ES_EVENT_TYPE_AUTH_COPYFILE
    case .truncate: ES_EVENT_TYPE_AUTH_TRUNCATE
    case .exchangeData: ES_EVENT_TYPE_AUTH_EXCHANGEDATA
    case .setMode: ES_EVENT_TYPE_AUTH_SETMODE
    case .setOwner: ES_EVENT_TYPE_AUTH_SETOWNER
    case .setFlags: ES_EVENT_TYPE_AUTH_SETFLAGS
    case .setACL: ES_EVENT_TYPE_AUTH_SETACL
    case .setExtendedAttribute: ES_EVENT_TYPE_AUTH_SETEXTATTR
    case .deleteExtendedAttribute: ES_EVENT_TYPE_AUTH_DELETEEXTATTR
    case .setAttributeList: ES_EVENT_TYPE_AUTH_SETATTRLIST
    case .setTimes: ES_EVENT_TYPE_AUTH_UTIMES
    case .mount: ES_EVENT_TYPE_AUTH_MOUNT
    }
  }

  public init?(eventType: es_event_type_t) {
    guard let kind = Self.allCases.first(where: { $0.eventType == eventType }) else { return nil }
    self = kind
  }

  /// Only `AUTH_OPEN` answers with permitted open flags; every other event answers allow or deny.
  public var answersWithFlags: Bool { self == .open }

  /// A mount is performed by a system daemon on behalf of whoever asked for it, so the program
  /// lists cannot describe the requester. The mount point alone decides.
  public var isDecidedByPathAlone: Bool { self == .mount }

  /// A change to the metadata of one existing file or folder: its permissions, owner, file
  /// flags, access control list, extended attributes, attributes set with `setattrlist`, or
  /// access and modification times. `AUTH_SETTIME`, which sets the system clock, names no file
  /// and is not one of them.
  public var changesMetadata: Bool {
    switch self {
    case .setMode, .setOwner, .setFlags, .setACL, .setExtendedAttribute,
      .deleteExtendedAttribute, .setAttributeList, .setTimes:
      true
    case .open, .create, .rename, .unlink, .link, .clone, .copyFile, .truncate, .exchangeData,
      .mount:
      false
    }
  }

  /// Whether Endpoint Security can select requests of this kind by their target paths, so that
  /// only requests at registered paths are delivered. A mount names a mount point, not a file,
  /// and every mount is delivered.
  public var isSelectedByTargetPath: Bool { self != .mount }

  /// Whether a request of this kind can involve a folder that contains a policy folder or a
  /// retired path: it acts on an object as a whole (the source of a rename, clone or copy, a
  /// deletion, a data exchange or a mount) or places an object at a path (a creation, hard link,
  /// clone, copy or the destination of a rename).
  public var reachesEnclosingFolders: Bool {
    switch self {
    case .create, .rename, .unlink, .link, .clone, .copyFile, .exchangeData, .mount:
      true
    case .open, .truncate, .setMode, .setOwner, .setFlags, .setACL, .setExtendedAttribute,
      .deleteExtendedAttribute, .setAttributeList, .setTimes:
      false
    }
  }

  /// The subscription list, in the catalog's order.
  public static var subscribedEventTypes: [es_event_type_t] {
    AuthorizationEventCatalog.supportedEventNames.compactMap { FileOperationKind(rawValue: $0) }
      .map(\.eventType)
  }
}

/// One path of a request together with how it is matched against a policy folder.
public struct CheckedPath: Equatable, Sendable {
  public let path: String
  public let wasTruncated: Bool
  /// When true, the request acts on the object at this path as a whole, so a policy whose
  /// folder is this path or lies below it is also affected: renaming, deleting, exchanging,
  /// cloning or copying a parent folder moves, removes or copies the protected folder with it.
  public let affectsEnclosedFolders: Bool

  public init(path: String, wasTruncated: Bool = false, affectsEnclosedFolders: Bool = false) {
    self.path = path
    self.wasTruncated = wasTruncated
    self.affectsEnclosedFolders = affectsEnclosedFolders
  }

  public init(_ file: EndpointFileSnapshot, affectsEnclosedFolders: Bool = false) {
    self.init(
      path: file.path, wasTruncated: file.pathWasTruncated,
      affectsEnclosedFolders: affectsEnclosedFolders)
  }

  /// A new entry named inside a directory the kernel reported.
  public init(directory: EndpointFileSnapshot, name: String?) {
    let name = name ?? ""
    let path = directory.path.hasSuffix("/") ? directory.path + name : directory.path + "/" + name
    self.init(path: path, wasTruncated: directory.pathWasTruncated, affectsEnclosedFolders: false)
  }

  func affects(_ scope: ProtectedPathScope) -> Bool {
    scope.contains(path) || (affectsEnclosedFolders && scope.rootIsInside(path))
  }
}

/// A decoded authorization request: which operation, and every path a policy must be matched
/// against. The kernel's own path strings are used; nothing is resolved during authorization.
public struct FileOperationRequest: Equatable, Sendable {
  public let kind: FileOperationKind
  /// The path a log record names as the target.
  public let primaryPath: CheckedPath
  /// The second location of a request that names two, recorded as the destination.
  public let destinationPath: CheckedPath?
  /// Every path compared with policy folders, including the two above.
  public let checkedPaths: [CheckedPath]
  /// The `fflag` value of an open request; nil for other kinds.
  public let requestedOpenFlags: UInt32?
  /// Whether the kernel reported the destination of a rename as an existing file. The path is
  /// then the existing entry's, so it does not show the spelling the renamed object takes: a
  /// rename that changes only the letter case or Unicode composition of a name reports the
  /// source's own path as its destination.
  public let destinationIsExistingFile: Bool

  public init(
    kind: FileOperationKind, primaryPath: CheckedPath, destinationPath: CheckedPath? = nil,
    additionalPaths: [CheckedPath] = [], requestedOpenFlags: UInt32? = nil,
    destinationIsChecked: Bool = true, destinationIsExistingFile: Bool = false
  ) {
    self.kind = kind
    self.primaryPath = primaryPath
    self.destinationPath = destinationPath
    self.checkedPaths =
      [primaryPath] + (destinationIsChecked ? destinationPath.map { [$0] } ?? [] : [])
      + additionalPaths
    self.requestedOpenFlags = requestedOpenFlags
    self.destinationIsExistingFile = destinationIsExistingFile
  }

  public var pathWasTruncated: Bool { checkedPaths.contains(where: \.wasTruncated) }

  /// The path at which the request makes an object appear: the new entry of a create, hard
  /// link, clone or copy, or the new name of a rename. A folder placed there brings along
  /// everything below it. Nil for requests that place nothing.
  public var newObjectPath: CheckedPath? {
    switch kind {
    case .create: primaryPath
    case .rename, .link, .clone, .copyFile: destinationPath
    case .open, .unlink, .truncate, .exchangeData, .mount, .setMode, .setOwner, .setFlags,
      .setACL, .setExtendedAttribute, .deleteExtendedAttribute, .setAttributeList, .setTimes:
      nil
    }
  }

  public static func open(_ file: EndpointFileSnapshot, flags: UInt32) -> FileOperationRequest {
    FileOperationRequest(
      kind: .open, primaryPath: CheckedPath(file), requestedOpenFlags: flags)
  }

  public static func open(path: String, wasTruncated: Bool = false, flags: UInt32 = 0)
    -> FileOperationRequest
  {
    open(EndpointFileSnapshot(path: path, pathWasTruncated: wasTruncated), flags: flags)
  }

  /// A new object named inside `directory`, or an existing object the kernel reported.
  public static func create(existing file: EndpointFileSnapshot) -> FileOperationRequest {
    FileOperationRequest(kind: .create, primaryPath: CheckedPath(file))
  }

  public static func create(in directory: EndpointFileSnapshot, name: String?)
    -> FileOperationRequest
  {
    FileOperationRequest(
      kind: .create, primaryPath: CheckedPath(directory: directory, name: name),
      additionalPaths: [CheckedPath(directory)])
  }

  public static func rename(
    source: EndpointFileSnapshot, destination: CheckedPath, destinationIsExistingFile: Bool = false
  ) -> FileOperationRequest {
    FileOperationRequest(
      kind: .rename, primaryPath: CheckedPath(source, affectsEnclosedFolders: true),
      destinationPath: destination, destinationIsExistingFile: destinationIsExistingFile)
  }

  public static func unlink(target: EndpointFileSnapshot) -> FileOperationRequest {
    FileOperationRequest(
      kind: .unlink, primaryPath: CheckedPath(target, affectsEnclosedFolders: true))
  }

  public static func link(
    source: EndpointFileSnapshot, targetDirectory: EndpointFileSnapshot, name: String?
  ) -> FileOperationRequest {
    FileOperationRequest(
      kind: .link, primaryPath: CheckedPath(source),
      destinationPath: CheckedPath(directory: targetDirectory, name: name))
  }

  public static func clone(
    source: EndpointFileSnapshot, targetDirectory: EndpointFileSnapshot, name: String?
  ) -> FileOperationRequest {
    FileOperationRequest(
      kind: .clone, primaryPath: CheckedPath(source, affectsEnclosedFolders: true),
      destinationPath: CheckedPath(directory: targetDirectory, name: name))
  }

  public static func copyFile(
    source: EndpointFileSnapshot, existingTarget: EndpointFileSnapshot?,
    targetDirectory: EndpointFileSnapshot, name: String?
  ) -> FileOperationRequest {
    FileOperationRequest(
      kind: .copyFile, primaryPath: CheckedPath(source, affectsEnclosedFolders: true),
      destinationPath: CheckedPath(directory: targetDirectory, name: name),
      additionalPaths: [CheckedPath(targetDirectory)]
        + (existingTarget.map { [CheckedPath($0)] } ?? [])
    )
  }

  public static func truncate(target: EndpointFileSnapshot) -> FileOperationRequest {
    FileOperationRequest(kind: .truncate, primaryPath: CheckedPath(target))
  }

  public static func exchangeData(_ first: EndpointFileSnapshot, _ second: EndpointFileSnapshot)
    -> FileOperationRequest
  {
    FileOperationRequest(
      kind: .exchangeData, primaryPath: CheckedPath(first, affectsEnclosedFolders: true),
      destinationPath: CheckedPath(second, affectsEnclosedFolders: true))
  }

  /// A metadata change of `target`, which macOS reports as the file or folder itself, also when
  /// the request names it through a file descriptor. The change affects only that object:
  /// changing a folder's permissions or attributes changes nothing below it, so a folder that
  /// contains a policy folder is not part of the request.
  public static func metadataChange(_ kind: FileOperationKind, target: EndpointFileSnapshot)
    -> FileOperationRequest
  {
    assert(kind.changesMetadata, "\(kind.rawValue) is not a metadata change")
    return FileOperationRequest(kind: kind, primaryPath: CheckedPath(target))
  }

  /// A file system about to be mounted at `mountPoint`. While it is mounted, the folder at the
  /// mount point and everything below it are hidden behind the new volume, so the request acts
  /// on the enclosed folders. `volumeSource` (the device or share, `f_mntfromname`) is recorded
  /// as the destination but is not a path on this volume and is not compared with policies.
  public static func mount(mountPoint: String, volumeSource: String?) -> FileOperationRequest {
    FileOperationRequest(
      kind: .mount, primaryPath: CheckedPath(path: mountPoint, affectsEnclosedFolders: true),
      destinationPath: volumeSource.map { CheckedPath(path: $0) }, destinationIsChecked: false)
  }
}
