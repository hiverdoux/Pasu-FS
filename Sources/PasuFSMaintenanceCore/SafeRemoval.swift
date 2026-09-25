import Darwin
import Foundation

/// Descriptor-relative deletion. Never resolves a symlink, crosses a mount, or obtains paths from policy data.
/// Callers pass physical paths (see `PhysicalPath`): a symbolic link anywhere in the path,
/// including the `/tmp` and `/var` aliases, is refused by design.
public enum SafeRemoval {
  public static func remove(_ url: URL, requiredOwner: uid_t = 0) throws {
    let components = url.pathComponents.filter { $0 != "/" }
    guard url.path.hasPrefix("/"), !components.isEmpty,
      !components.contains(".."), !components.contains(".")
    else { throw MaintenanceError(.unsafeRemovalPath) }
    var parent = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC)
    guard parent >= 0 else { throw systemError("open root") }
    defer { close(parent) }
    for component in components.dropLast() {
      let next = openat(parent, component, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      if next < 0, errno == ENOENT { return }
      guard next >= 0 else { throw systemError("open removal parent \(component)") }
      close(parent)
      parent = next
    }
    try removeEntry(parent: parent, name: components.last!, owner: requiredOwner, device: nil)
  }

  public static func validateRoot(_ url: URL, requiredOwner: uid_t = 0) throws {
    var info = stat()
    let result = lstat(url.path, &info)
    if result < 0, errno == ENOENT { return }
    guard result == 0 else { throw systemError("inspect removal target") }
    guard info.st_uid == requiredOwner, info.st_mode & S_IFMT != S_IFLNK else {
      throw MaintenanceError(.removalTargetUntrusted, detail: url.path)
    }
  }

  private static func removeEntry(parent: Int32, name: String, owner: uid_t, device: dev_t?) throws
  {
    var info = stat()
    if fstatat(parent, name, &info, AT_SYMLINK_NOFOLLOW) < 0 {
      if errno == ENOENT { return }
      throw systemError("inspect entry")
    }
    guard info.st_uid == owner else {
      throw MaintenanceError(.unexpectedOwner, detail: name)
    }
    if let device, info.st_dev != device {
      throw MaintenanceError(.mountCrossingRefused)
    }
    if info.st_mode & S_IFMT == S_IFDIR {
      let directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard directory >= 0 else { throw systemError("open removal directory") }
      defer { close(directory) }
      var opened = stat()
      guard fstat(directory, &opened) == 0, sameFile(info, opened) else {
        throw MaintenanceError(.removalTargetChanged, detail: "while opening it")
      }
      let duplicate = dup(directory)
      guard duplicate >= 0 else { throw systemError("duplicate directory") }
      guard let stream = fdopendir(duplicate) else {
        close(duplicate)
        throw systemError("read directory")
      }
      defer { closedir(stream) }
      while true {
        errno = 0
        guard let entry = readdir(stream) else {
          guard errno == 0 else { throw systemError("read directory entry") }
          break
        }
        let child = withUnsafePointer(to: &entry.pointee.d_name) {
          $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
            String(cString: $0)
          }
        }
        if child == "." || child == ".." { continue }
        try removeEntry(parent: directory, name: child, owner: owner, device: opened.st_dev)
      }
      var current = stat()
      guard fstatat(parent, name, &current, AT_SYMLINK_NOFOLLOW) == 0, sameFile(opened, current)
      else {
        throw MaintenanceError(.removalTargetChanged, detail: "before unlinking it")
      }
      guard unlinkat(parent, name, AT_REMOVEDIR) == 0 else { throw systemError("remove directory") }
    } else {
      // unlinkat removes a symlink itself, never its destination.
      guard unlinkat(parent, name, 0) == 0 else { throw systemError("remove entry") }
    }
  }

  private static func sameFile(_ lhs: stat, _ rhs: stat) -> Bool {
    lhs.st_dev == rhs.st_dev && lhs.st_ino == rhs.st_ino && lhs.st_uid == rhs.st_uid
  }
  private static func systemError(_ operation: String) -> MaintenanceError {
    MaintenanceError(
      .systemCallFailed, detail: "\(operation) failed: \(String(cString: strerror(errno)))")
  }
}
