import Darwin
import EndpointSecurity
import Foundation
import PasuFSConfiguration
import os

/// How Endpoint Security compares a registered path with the target paths of a request.
public enum TargetPathMatch: String, Hashable, Sendable {
  /// The target path begins with the registered path. The comparison is by bytes, so `/a/bc`
  /// also begins with `/a/b`.
  case prefix
  /// The target path is the registered path.
  case literal
}

/// A path compared the way Endpoint Security compares it: byte for byte. Swift strings compare
/// by canonical equivalence, so two spellings of a name in different Unicode composition forms
/// are equal strings, yet the kernel matches only the spelling it was given.
public struct TargetPathString: Hashable, Sendable, CustomStringConvertible {
  public let bytes: [UInt8]

  public init(_ string: String) {
    bytes = Array(string.utf8)
  }

  public init(bytes: [UInt8]) {
    self.bytes = bytes
  }

  public var string: String { String(decoding: bytes, as: UTF8.self) }
  public var description: String { string }
}

/// One element of the client's target path set: requests of `eventType` whose target path
/// matches `path` are delivered.
public struct TargetPathEntry: Hashable, Sendable {
  public let path: TargetPathString
  public let match: TargetPathMatch
  public let eventType: UInt32

  public init(path: TargetPathString, match: TargetPathMatch, eventType: UInt32) {
    self.path = path
    self.match = match
    self.eventType = eventType
  }

  static func entries(_ path: String, _ match: TargetPathMatch, _ events: [es_event_type_t])
    -> Set<TargetPathEntry>
  {
    let path = TargetPathString(path)
    return Set(events.map { TargetPathEntry(path: path, match: match, eventType: $0.rawValue) })
  }
}

/// The event types registered for each kind of path.
public enum TargetPathEvents {
  /// For a policy folder, a pending location or a retired path and everything below it: every
  /// subscribed authorization event that Endpoint Security selects by target path, and the
  /// rename notification that starts a folder check.
  public static let inside: [es_event_type_t] =
    FileOperationKind.allCases.filter(\.isSelectedByTargetPath).map(\.eventType)
    + [ES_EVENT_TYPE_NOTIFY_RENAME]

  /// For a folder that contains one of them: the requests that act on the folder as a whole or
  /// place an object at its path, and the rename notification.
  public static let enclosing: [es_event_type_t] =
    FileOperationKind.allCases.filter { $0.isSelectedByTargetPath && $0.reachesEnclosingFolders }
    .map(\.eventType) + [ES_EVENT_TYPE_NOTIFY_RENAME]

  /// Process starts, from which the execution histories are built. Forks and exits name no
  /// target path and are always delivered.
  public static let execution: [es_event_type_t] = [ES_EVENT_TYPE_NOTIFY_EXEC]
}

/// Reads how the file system spells existing paths. Used only while preparing the registered
/// set on the extension's configuration queue, never while answering a request.
public protocol TargetPathResolving: Sendable {
  /// The path of the object at `path` as the file system spells it, with symbolic links
  /// resolved, or nil when nothing is there.
  func spelling(of path: String) -> String?
}

/// Reads spellings with `realpath`, which returns each existing name as it is stored.
public struct SystemTargetPathResolver: TargetPathResolving {
  public init() {}

  public func spelling(of path: String) -> String? {
    guard let resolved = realpath(path, nil) else { return nil }
    defer { free(resolved) }
    return String(cString: resolved)
  }
}

/// The target paths to register so that Endpoint Security delivers every request a policy can
/// take part in. The kernel compares the bytes of each request's target path, reported in the
/// spelling stored on disk for existing objects and in the requester's spelling for a new name.
public enum TargetPathPlan {
  /// Keeps process starts delivered.
  public static var executionEntries: Set<TargetPathEntry> {
    TargetPathEntry.entries("/", .prefix, TargetPathEvents.execution)
  }

  /// Delivers every request and process start that Endpoint Security selects by target path;
  /// registered when a narrower set could not be.
  public static var allRequestEntries: Set<TargetPathEntry> {
    TargetPathEntry.entries("/", .prefix, TargetPathEvents.inside + TargetPathEvents.execution)
  }

  /// The entries for policy folders and retired paths, each `location`:
  ///
  /// - the location as a prefix, for every request inside it;
  /// - each folder on the way to it, except `/`, as a literal path, for the requests that act
  ///   on a folder containing it or place an object there;
  /// - when it exists in another spelling of the same name (letter case or Unicode
  ///   composition, after a rename that changed only that), the stored spelling as well;
  /// - when it doesn't exist, the deepest folder on the way to it that does, as a prefix for
  ///   the requests that place an object, because a new name keeps the requester's spelling:
  ///   creating a differently cased name there would otherwise go unseen.
  ///
  /// `resolver` reads the disk; without one only the first two are included.
  public static func entries(
    for locations: [ProtectedPathScope], resolver: (any TargetPathResolving)?
  ) -> Set<TargetPathEntry> {
    var result = Set<TargetPathEntry>()
    for location in locations {
      result.formUnion(locationEntries(location.root))
      guard let resolver else { continue }
      if let spelled = resolver.spelling(of: location.root) {
        if !spelled.utf8.elementsEqual(location.root.utf8),
          location.namesSameLocation(
            as: ProtectedPathScope(canonicalRoot: spelled, caseSensitive: location.caseSensitive))
        {
          result.formUnion(locationEntries(spelled))
        }
        continue
      }
      for ancestor in ancestors(of: location.root).reversed() + ["/"] {
        guard let spelled = resolver.spelling(of: ancestor) else { continue }
        // A folder reached through a symbolic link is not on the way to the location as the
        // policy compares paths; its own path is used then.
        let existing = location.rootIsInside(spelled) ? spelled : ancestor
        result.formUnion(newEntryPrefix(below: existing))
        if existing != "/" {
          result.formUnion(TargetPathEntry.entries(existing, .literal, TargetPathEvents.enclosing))
          for folder in ancestors(of: existing) {
            result.formUnion(TargetPathEntry.entries(folder, .literal, TargetPathEvents.enclosing))
          }
        }
        break
      }
    }
    return result
  }

  /// The entries for a rename the extension allowed and has not confirmed, computed from the
  /// request's paths alone because no file system call is made while answering it: the
  /// folder's new location and the retired paths that moved with it, registered like the
  /// entries above. A retired path below the renamed folder may still be missing, so the
  /// destination is also registered as a prefix for requests that place an object. When the
  /// kernel reported the destination as an existing file, its path does not show the spelling
  /// the folder takes, and the folder containing the destination is registered as a prefix
  /// for every request until the extension has read the new spelling.
  public static func entries(for move: PendingFolderMove) -> Set<TargetPathEntry> {
    var result = locationEntries(move.scope.root)
    for retired in move.retiredScopes {
      result.formUnion(locationEntries(retired.root))
    }
    if !move.retiredScopes.isEmpty {
      result.formUnion(newEntryPrefix(below: move.destination))
    }
    if move.destinationIsExistingFile {
      let parent = ancestors(of: move.destination).last ?? "/"
      result.formUnion(
        TargetPathEntry.entries(prefixBelow(parent), .prefix, TargetPathEvents.inside))
    }
    return result
  }

  static func locationEntries(_ root: String) -> Set<TargetPathEntry> {
    var result = TargetPathEntry.entries(root, .prefix, TargetPathEvents.inside)
    for folder in ancestors(of: root) {
      result.formUnion(TargetPathEntry.entries(folder, .literal, TargetPathEvents.enclosing))
    }
    return result
  }

  static func newEntryPrefix(below folder: String) -> Set<TargetPathEntry> {
    TargetPathEntry.entries(prefixBelow(folder), .prefix, TargetPathEvents.enclosing)
  }

  /// `folder` followed by a slash, so that the prefix matches what lies below it and not a
  /// sibling whose name begins the same way.
  static func prefixBelow(_ folder: String) -> String {
    folder.hasSuffix("/") ? folder : folder + "/"
  }

  /// The folders on the way to `path`, outermost first, excluding `/` and `path` itself. Split
  /// by bytes so that each name keeps its exact spelling.
  static func ancestors(of path: String) -> [String] {
    let components = path.utf8.split(separator: UInt8(ascii: "/"))
    guard components.count > 1 else { return [] }
    var result: [String] = []
    var current: [UInt8] = []
    for component in components.dropLast() {
      current.append(UInt8(ascii: "/"))
      current.append(contentsOf: component)
      result.append(String(decoding: current, as: UTF8.self))
    }
    return result
  }
}

/// Adds and removes entries of the client's target path set.
public protocol TargetPathMuting: Sendable {
  func add(_ path: TargetPathString, match: TargetPathMatch, events: [UInt32]) -> Bool
  func remove(_ path: TargetPathString, match: TargetPathMatch, events: [UInt32]) -> Bool
}

/// The target paths registered with the Endpoint Security client. While target path muting is
/// inverted, the kernel delivers only requests whose target path matches a registered entry, so
/// an entry is always registered before anything relies on it and removed only after:
/// `extend(_:)` adds a new set without removing anything, `settle(_:)` then removes what the
/// new set no longer needs. The entries of pending moves are pinned separately, from the
/// Endpoint Security delivery thread, before the rename is answered.
///
/// When an entry can't be registered, `/` is registered as a prefix for every request instead,
/// so that requests are delivered as without inversion, and the error is kept for the status.
/// Each later `settle(_:)` tries again and removes that fallback once the full set is in place.
public final class TargetPathRegistry: @unchecked Sendable {
  private static let log = Logger(
    subsystem: "com.example.pasu.fs.endpointsecurity", category: "target-paths")

  private struct State {
    var base: Set<TargetPathEntry> = TargetPathPlan.executionEntries
    var pinned: [UUID: Set<TargetPathEntry>] = [:]
    var registered: Set<TargetPathEntry> = []
    var deliversAllRequests = false
    var lastError: String?
    var lastErrorAt: Date?

    var needed: Set<TargetPathEntry> {
      var result = base
      for entries in pinned.values { result.formUnion(entries) }
      if deliversAllRequests { result.formUnion(TargetPathPlan.allRequestEntries) }
      return result
    }
  }

  /// Whether the kernel selects requests by target path. When it doesn't, every request is
  /// delivered and nothing is registered.
  public let isInverted: Bool
  private let muting: (any TargetPathMuting)?
  private let state: OSAllocatedUnfairLock<State>
  private let now: @Sendable () -> Date

  /// A registry for a client whose target path muting is inverted. Registers the execution
  /// entry; `deliversProcessStarts` tells whether it could.
  public init(muting: any TargetPathMuting, now: @escaping @Sendable () -> Date = { Date() }) {
    isInverted = true
    self.muting = muting
    self.now = now
    state = OSAllocatedUnfairLock(initialState: State())
    state.withLock { state in
      _ = add(TargetPathPlan.executionEntries, to: &state)
    }
  }

  /// A registry for a client that delivers every request, because inverting target path
  /// muting failed with `reason`.
  public init(notInvertedBecause reason: String?, now: @escaping @Sendable () -> Date = { Date() })
  {
    isInverted = false
    muting = nil
    self.now = now
    var initial = State()
    initial.base = []
    initial.lastError = reason
    initial.lastErrorAt = reason == nil ? nil : now()
    state = OSAllocatedUnfairLock(initialState: initial)
  }

  /// Registers what `base` adds to the registered set, removing nothing. Returns whether every
  /// request that `base` selects is delivered: its entries are registered, or every request is.
  @discardableResult
  public func extend(_ base: Set<TargetPathEntry>) -> Bool {
    guard isInverted else { return true }
    return state.withLock { state in
      add(base.union(TargetPathPlan.executionEntries), to: &state)
    }
  }

  /// Makes `base`, together with the pinned entries, the registered set: registers what is
  /// missing, then removes what is no longer needed, including the fallback once the set is
  /// complete. Returns whether every request the set selects is delivered.
  @discardableResult
  public func settle(_ base: Set<TargetPathEntry>) -> Bool {
    guard isInverted else { return true }
    return state.withLock { state in
      state.base = base.union(TargetPathPlan.executionEntries)
      let delivered: Bool
      if state.deliversAllRequests {
        // Without the fallback in `needed`, the result says whether the full set is in place.
        state.deliversAllRequests = false
        delivered = add(state.needed, to: &state, fallBack: false)
        if !delivered { state.deliversAllRequests = true }
      } else {
        delivered = add(state.needed, to: &state)
      }
      removeUnneeded(from: &state)
      return delivered || state.deliversAllRequests
    }
  }

  /// Registers the entries of a pending move before the rename is answered. Returns false when
  /// neither they nor the fallback could be registered; the rename must then be denied.
  public func pin(_ identifier: UUID, _ entries: Set<TargetPathEntry>) -> Bool {
    guard isInverted else { return true }
    return state.withLock { state in
      state.pinned[identifier] = entries
      if add(entries, to: &state) { return true }
      state.pinned[identifier] = nil
      return false
    }
  }

  /// Releases the entries of pending moves that were withdrawn.
  public func unpin(_ identifiers: Set<UUID>) {
    guard isInverted, !identifiers.isEmpty else { return }
    state.withLock { state in
      var changed = false
      for identifier in identifiers where state.pinned.removeValue(forKey: identifier) != nil {
        changed = true
      }
      if changed { removeUnneeded(from: &state) }
    }
  }

  /// Releases every pinned entry except those of `identifiers`, the pending moves that remain.
  public func retainPins(_ identifiers: Set<UUID>) {
    let stale = state.withLock { Set($0.pinned.keys).subtracting(identifiers) }
    unpin(stale)
  }

  /// Compares the bookkeeping with the set the kernel reports. Only entries that were
  /// registered before the kernel's set was read, `registeredBefore`, and still are, can be
  /// missing: a pending move may register or release entries meanwhile. An entry the kernel
  /// lacks is registered again; if that fails, every request is delivered.
  public func verify(
    kernelEntries: Set<TargetPathEntry>, registeredBefore: Set<TargetPathEntry>
  ) {
    guard isInverted else { return }
    state.withLock { state in
      let missing = state.registered.intersection(registeredBefore).subtracting(kernelEntries)
      guard !missing.isEmpty else { return }
      record(
        "Endpoint Security lacks \(missing.count) registered target path entries.", in: &state)
      state.registered.subtract(missing)
      _ = add(state.needed, to: &state)
    }
  }

  /// The registered entries, for diagnostics and tests.
  public var registeredEntries: Set<TargetPathEntry> { state.withLock { $0.registered } }

  /// Whether process starts are delivered. Without them the execution histories would be
  /// wrong, so a client whose execution entry could not be registered must not stay inverted.
  public var deliversProcessStarts: Bool {
    !isInverted || state.withLock { $0.registered.isSuperset(of: TargetPathPlan.executionEntries) }
  }

  public var deliversAllRequests: Bool {
    !isInverted || state.withLock { $0.deliversAllRequests }
  }

  /// The status, with the counts of registered prefixes and literal paths taken from
  /// `kernelEntries` when the kernel's set could be read, or else from the bookkeeping.
  public func status(kernelEntries: Set<TargetPathEntry>?) -> TargetPathMutingStatus {
    state.withLock { state in
      let entries = isInverted ? (kernelEntries ?? state.registered) : []
      let paths = Set(entries.map { TargetPathKey(path: $0.path, match: $0.match) })
      return TargetPathMutingStatus(
        isInverted: isInverted,
        deliversAllRequests: !isInverted || state.deliversAllRequests,
        prefixCount: paths.filter { $0.match == .prefix }.count,
        literalCount: paths.filter { $0.match == .literal }.count,
        lastError: state.lastError, lastErrorAt: state.lastErrorAt)
    }
  }

  private struct TargetPathKey: Hashable {
    let path: TargetPathString
    let match: TargetPathMatch
  }

  /// Registers the entries of `entries` that are not registered yet, one call per path. When
  /// one fails and `fallBack` is set, registers the fallback. Returns whether every request
  /// the entries select is now delivered.
  private func add(
    _ entries: Set<TargetPathEntry>, to state: inout State, fallBack: Bool = true
  ) -> Bool {
    guard let muting else { return true }
    var failed = false
    for (key, events) in Self.grouped(entries.subtracting(state.registered)) {
      if muting.add(key.path, match: key.match, events: events) {
        for event in events {
          state.registered.insert(
            TargetPathEntry(path: key.path, match: key.match, eventType: event))
        }
      } else {
        failed = true
        record("Could not register \(key.match.rawValue) \(key.path).", in: &state)
      }
    }
    guard failed else { return true }
    guard fallBack else { return false }
    if state.deliversAllRequests { return true }
    let fallbackEntries = TargetPathPlan.allRequestEntries.subtracting(state.registered)
    let fallbackEvents = fallbackEntries.map(\.eventType).sorted()
    if fallbackEntries.isEmpty
      || muting.add(TargetPathString("/"), match: .prefix, events: fallbackEvents)
    {
      state.registered.formUnion(fallbackEntries)
      state.deliversAllRequests = true
      return true
    }
    record("Could not register / for every request.", in: &state)
    return false
  }

  /// Removes the registered entries that nothing needs. A removal that fails leaves the entry
  /// registered, which only delivers more requests than needed.
  private func removeUnneeded(from state: inout State) {
    guard let muting else { return }
    let unneeded = state.registered.subtracting(state.needed)
    for (key, events) in Self.grouped(unneeded) {
      if muting.remove(key.path, match: key.match, events: events) {
        for event in events {
          state.registered.remove(
            TargetPathEntry(path: key.path, match: key.match, eventType: event))
        }
      } else {
        record("Could not remove \(key.match.rawValue) \(key.path).", in: &state)
      }
    }
  }

  private func record(_ error: String, in state: inout State) {
    state.lastError = error
    state.lastErrorAt = now()
    Self.log.error("\(error, privacy: .private)")
  }

  /// Entries grouped by path and match, in a stable order, with their event types sorted.
  private static func grouped(_ entries: Set<TargetPathEntry>) -> [(
    key: TargetPathKey, events: [UInt32]
  )] {
    Dictionary(grouping: entries) { TargetPathKey(path: $0.path, match: $0.match) }
      .map { (key: $0.key, events: $0.value.map(\.eventType).sorted()) }
      .sorted {
        $0.key.path.bytes.lexicographicallyPrecedes($1.key.path.bytes)
          || ($0.key.path == $1.key.path && $0.key.match.rawValue < $1.key.match.rawValue)
      }
  }
}
