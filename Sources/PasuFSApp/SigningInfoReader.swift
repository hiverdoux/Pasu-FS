import Foundation
import Security

struct ApplicationSigningInfo: Equatable {
  var teamIdentifier: String?
  var signingIdentifier: String
  var isPlatformBinary: Bool
}

enum SigningInfoReaderError: Error, CustomStringConvertible {
  case unreadable(OSStatus)
  case unsigned

  var description: String {
    switch self {
    case .unreadable(let status):
      "The application's code signature could not be read (OSStatus \(status))."
    case .unsigned:
      "The application has no signing identifier. Unsigned programs can't be allowed in v0.2."
    }
  }
}

enum SigningInfoReader {
  static func read(fromApplicationAt url: URL) throws -> ApplicationSigningInfo {
    var staticCode: SecStaticCode?
    let createStatus = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
    guard createStatus == errSecSuccess, let staticCode else {
      throw SigningInfoReaderError.unreadable(createStatus)
    }

    var information: CFDictionary?
    let copyStatus = SecCodeCopySigningInformation(
      staticCode,
      SecCSFlags(rawValue: kSecCSSigningInformation),
      &information
    )
    guard copyStatus == errSecSuccess, let info = information as? [String: Any] else {
      throw SigningInfoReaderError.unreadable(copyStatus)
    }
    guard let signingIdentifier = info[kSecCodeInfoIdentifier as String] as? String,
      !signingIdentifier.isEmpty
    else {
      throw SigningInfoReaderError.unsigned
    }

    let platformIdentifier =
      (info[kSecCodeInfoPlatformIdentifier as String] as? NSNumber)?.intValue ?? 0
    return ApplicationSigningInfo(
      teamIdentifier: info[kSecCodeInfoTeamIdentifier as String] as? String,
      signingIdentifier: signingIdentifier,
      isPlatformBinary: platformIdentifier != 0
    )
  }
}
