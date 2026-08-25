import Foundation

public enum PasuFSXPC {
  public static let machServiceName = "com.dennis.pasu.fs.endpointsecurity.xpc"
  public static let hostBundleIdentifier = "com.dennis.pasu.fs"
  public static let extensionBundleIdentifier = "com.dennis.pasu.fs.endpointsecurity"
  public static let expectedHostApplicationPathInfoKey = "PasuFSExpectedHostApplicationPath"
}

@objc(PasuFSExtensionXPCProtocol)
public protocol PasuFSExtensionXPCProtocol: NSObjectProtocol {
  func handshake(_ requestData: Data, withReply reply: @escaping (Data?, NSError?) -> Void)
  func applyPolicy(_ policyData: Data, withReply reply: @escaping (Data?, NSError?) -> Void)
  func queryPolicy(withReply reply: @escaping (Data?, NSError?) -> Void)
  func queryStatus(withReply reply: @escaping (Data?, NSError?) -> Void)
  func readAuditLog(
    _ maximumLineCount: NSNumber,
    withReply reply: @escaping (Data?, NSError?) -> Void
  )
}

public enum PasuFSXPCErrorCode: Int {
  case unavailable = 1
  case authenticationFailed = 2
  case invalidRequest = 3
  case policyRejected = 4
  case internalFailure = 5
  case timeout = 6
}

public enum PasuFSXPCError {
  public static let domain = "com.dennis.pasu.fs.xpc"

  public static func make(
    _ code: PasuFSXPCErrorCode,
    description: String
  ) -> NSError {
    NSError(
      domain: domain,
      code: code.rawValue,
      userInfo: [NSLocalizedDescriptionKey: description]
    )
  }

  public static func wrap(_ error: any Error, code: PasuFSXPCErrorCode) -> NSError {
    let nsError = error as NSError
    if nsError.domain == domain {
      return nsError
    }
    return make(code, description: String(describing: error))
  }
}
