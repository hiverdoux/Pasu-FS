import Foundation
import PasuFSConfiguration
import Security

public enum ProgramRuleReaderError: Error, Equatable, Sendable {
  case invalidSignature(OSStatus)
  case unsupportedIdentity
}

/// Reads a candidate for either list from a selected app or executable. These
/// values configure exact signature matches; the extension still authorizes
/// every request using the kernel's process facts and observed history.
public enum ProgramRuleReader {
  public static func read(at url: URL, ruleIdentifier: String = UUID().uuidString) throws
    -> PolicyRule
  {
    var code: SecStaticCode?
    let created = SecStaticCodeCreateWithPath(url as CFURL, [], &code)
    guard created == errSecSuccess, let code else {
      throw ProgramRuleReaderError.invalidSignature(created)
    }
    let valid = SecStaticCodeCheckValidity(code, [], nil)
    // A file without any signature, such as a shell script, can't be added for the same reason
    // as an ad-hoc signed one, rather than because its signature is damaged.
    if valid == errSecCSUnsigned { throw ProgramRuleReaderError.unsupportedIdentity }
    guard valid == errSecSuccess else { throw ProgramRuleReaderError.invalidSignature(valid) }
    var information: CFDictionary?
    let copied = SecCodeCopySigningInformation(
      code, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
    guard copied == errSecSuccess, let info = information as? [String: Any] else {
      throw ProgramRuleReaderError.invalidSignature(copied)
    }
    let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
    // An ad-hoc signature has no Team ID, so it can't name a program rule.
    guard flags & SystemCompatibilityCodeSigning.adhoc == 0 else {
      throw ProgramRuleReaderError.unsupportedIdentity
    }
    guard let identifier = info[kSecCodeInfoIdentifier as String] as? String,
      !identifier.isEmpty
    else { throw ProgramRuleReaderError.unsupportedIdentity }
    if (info[kSecCodeInfoPlatformIdentifier as String] as? NSNumber)?.intValue ?? 0 != 0 {
      return .platformBinary(
        id: ruleIdentifier, signingIdentifier: identifier, allowsDescendants: false)
    }
    guard let team = info[kSecCodeInfoTeamIdentifier as String] as? String, !team.isEmpty else {
      throw ProgramRuleReaderError.unsupportedIdentity
    }
    return .teamSigned(
      id: ruleIdentifier, teamIdentifier: team, signingIdentifier: identifier,
      allowsDescendants: false)
  }
}
