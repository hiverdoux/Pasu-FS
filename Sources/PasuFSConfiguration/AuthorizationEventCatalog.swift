import Foundation

/// The Endpoint Security authorization events the extension subscribes to when at least one
/// policy is active. The order is the order the extension reports and the app shows.
public enum AuthorizationEventCatalog {
  public static let supportedEventNames: [String] = [
    "AUTH_OPEN", "AUTH_CREATE", "AUTH_RENAME", "AUTH_UNLINK", "AUTH_LINK", "AUTH_CLONE",
    "AUTH_COPYFILE", "AUTH_TRUNCATE", "AUTH_EXCHANGEDATA", "AUTH_SETMODE", "AUTH_SETOWNER",
    "AUTH_SETFLAGS", "AUTH_SETACL", "AUTH_SETEXTATTR", "AUTH_DELETEEXTATTR", "AUTH_SETATTRLIST",
    "AUTH_UTIMES", "AUTH_MOUNT",
  ]

  /// Whether a recorded event type is a file request the extension answered, as opposed to a
  /// process lifecycle notification.
  public static func isAuthorizationEvent(_ eventType: String) -> Bool {
    eventType.hasPrefix("AUTH_")
  }
}
