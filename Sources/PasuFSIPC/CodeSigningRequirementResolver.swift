import Darwin
import Foundation
import Security

public enum CodeSigningRequirementError: Error, Equatable, CustomStringConvertible, Sendable {
  case codeLocationMissing(String)
  case codeLocationNotRootOwned(String)
  case codeLocationWritable(String)
  case securityCall(operation: String, status: OSStatus)
  case requirementStringMissing

  public var description: String {
    switch self {
    case .codeLocationMissing(let path):
      "Signed code is missing at \(path)."
    case .codeLocationNotRootOwned(let path):
      "Expected root-owned signed code at \(path)."
    case .codeLocationWritable(let path):
      "Signed code location is writable by a group or other users: \(path)."
    case .securityCall(let operation, let status):
      "\(operation) failed with Security status \(status)."
    case .requirementStringMissing:
      "The code-signing requirement did not produce a string."
    }
  }
}

public enum CodeSigningRequirementResolver {
  public static func designatedRequirement(
    forCodeAt url: URL,
    requireRootOwnedBundle: Bool = false
  ) throws -> String {
    let standardizedURL = url.standardizedFileURL
    if requireRootOwnedBundle {
      try validateRootOwnedBundle(at: standardizedURL)
    }

    var code: SecStaticCode?
    var status = SecStaticCodeCreateWithPath(
      standardizedURL as CFURL,
      SecCSFlags(),
      &code
    )
    guard status == errSecSuccess, let code else {
      throw CodeSigningRequirementError.securityCall(
        operation: "SecStaticCodeCreateWithPath",
        status: status
      )
    }

    let validationFlags = SecCSFlags(
      rawValue: kSecCSCheckAllArchitectures | kSecCSStrictValidate
    )
    status = SecStaticCodeCheckValidity(code, validationFlags, nil)
    guard status == errSecSuccess else {
      throw CodeSigningRequirementError.securityCall(
        operation: "SecStaticCodeCheckValidity",
        status: status
      )
    }

    var requirement: SecRequirement?
    status = SecCodeCopyDesignatedRequirement(code, SecCSFlags(), &requirement)
    guard status == errSecSuccess, let requirement else {
      throw CodeSigningRequirementError.securityCall(
        operation: "SecCodeCopyDesignatedRequirement",
        status: status
      )
    }

    var requirementText: CFString?
    status = SecRequirementCopyString(requirement, SecCSFlags(), &requirementText)
    guard status == errSecSuccess else {
      throw CodeSigningRequirementError.securityCall(
        operation: "SecRequirementCopyString",
        status: status
      )
    }
    guard let requirementText else {
      throw CodeSigningRequirementError.requirementStringMissing
    }
    return requirementText as String
  }

  public static func embeddedExtensionURL(in hostBundleURL: URL) -> URL {
    hostBundleURL
      .appendingPathComponent("Contents/Library/SystemExtensions", isDirectory: true)
      .appendingPathComponent(
        "\(PasuFSXPC.extensionBundleIdentifier).systemextension",
        isDirectory: true
      )
  }

  private static func validateRootOwnedBundle(at url: URL) throws {
    var metadata = stat()
    guard lstat(url.path, &metadata) == 0 else {
      throw CodeSigningRequirementError.codeLocationMissing(url.path)
    }
    let fileType = metadata.st_mode & S_IFMT
    guard fileType == S_IFDIR || fileType == S_IFREG, metadata.st_uid == 0 else {
      throw CodeSigningRequirementError.codeLocationNotRootOwned(url.path)
    }
    guard metadata.st_mode & (S_IWGRP | S_IWOTH) == 0 else {
      throw CodeSigningRequirementError.codeLocationWritable(url.path)
    }
  }
}
