import Foundation
@preconcurrency import SystemExtensions
import os

public struct ExtensionInstallationProperties: Codable, Equatable, Sendable {
  public var bundleIdentifier: String
  public var bundleVersion: String
  public var bundleShortVersion: String
  public var isEnabled: Bool
  public var isAwaitingUserApproval: Bool
  public var isUninstalling: Bool

  public init(
    bundleIdentifier: String,
    bundleVersion: String,
    bundleShortVersion: String,
    isEnabled: Bool,
    isAwaitingUserApproval: Bool,
    isUninstalling: Bool
  ) {
    self.bundleIdentifier = bundleIdentifier
    self.bundleVersion = bundleVersion
    self.bundleShortVersion = bundleShortVersion
    self.isEnabled = isEnabled
    self.isAwaitingUserApproval = isAwaitingUserApproval
    self.isUninstalling = isUninstalling
  }

  init(_ properties: OSSystemExtensionProperties) {
    self.init(
      bundleIdentifier: properties.bundleIdentifier,
      bundleVersion: properties.bundleVersion,
      bundleShortVersion: properties.bundleShortVersion,
      isEnabled: properties.isEnabled,
      isAwaitingUserApproval: properties.isAwaitingUserApproval,
      isUninstalling: properties.isUninstalling
    )
  }
}

public enum ActivationEvent: Equatable, Sendable {
  case submitted(action: String)
  case waitingForUserApproval
  case replacing(existingVersion: String, newVersion: String)
  case completed(rebootRequired: Bool)
  case properties([ExtensionInstallationProperties])
  case failed(domain: String, code: Int, description: String)
}

public protocol ExtensionLifecycleControlling: Sendable {
  func activationEvents() -> AsyncStream<ActivationEvent>
  func deactivationEvents() -> AsyncStream<ActivationEvent>
  /// Sends one properties request in this process. A long-running app reads the installation
  /// states through `installationStateLauncher()` instead; see `InstallationStateQueryManager`.
  func propertiesEvents() -> AsyncStream<ActivationEvent>
  /// Starts the short-lived processes that read the installation states for a long-running app.
  func installationStateLauncher() -> any InstallationStateChildLaunching
}

public final class ActivationController: NSObject, OSSystemExtensionRequestDelegate,
  ExtensionLifecycleControlling, @unchecked Sendable
{
  public static let extensionIdentifier = "com.example.pasu.fs.endpointsecurity"

  private struct RequestState {
    var continuation: AsyncStream<ActivationEvent>.Continuation
  }

  private let requests = OSAllocatedUnfairLock(initialState: [ObjectIdentifier: RequestState]())

  /// The queue on which macOS calls the delegate. When a deactivation needs an administrator's
  /// approval, the framework asks for it on this queue and waits there until the person answers
  /// the password dialog, so it must not be the main queue, where the app's status checks run.
  /// The delegate methods only use `requests` and the streams' continuations.
  private let requestQueue = DispatchQueue(label: "com.example.pasu.fs.extension-requests")

  public func activationEvents() -> AsyncStream<ActivationEvent> {
    submit(action: "activate") { queue in
      .activationRequest(
        forExtensionWithIdentifier: Self.extensionIdentifier,
        queue: queue
      )
    }
  }

  public func deactivationEvents() -> AsyncStream<ActivationEvent> {
    submit(action: "deactivate") { queue in
      .deactivationRequest(
        forExtensionWithIdentifier: Self.extensionIdentifier,
        queue: queue
      )
    }
  }

  public func propertiesEvents() -> AsyncStream<ActivationEvent> {
    submit(action: "properties") { queue in
      .propertiesRequest(
        forExtensionWithIdentifier: Self.extensionIdentifier,
        queue: queue
      )
    }
  }

  /// The app's own executable, run with the installation state command.
  public func installationStateLauncher() -> any InstallationStateChildLaunching {
    InstallationStateChildProcessLauncher()
  }

  public func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
    continuation(for: request)?.yield(.waitingForUserApproval)
  }

  public func request(
    _ request: OSSystemExtensionRequest,
    actionForReplacingExtension existing: OSSystemExtensionProperties,
    withExtension ext: OSSystemExtensionProperties
  ) -> OSSystemExtensionRequest.ReplacementAction {
    continuation(for: request)?.yield(
      .replacing(
        existingVersion: existing.bundleShortVersion,
        newVersion: ext.bundleShortVersion
      )
    )
    return .replace
  }

  public func request(
    _ request: OSSystemExtensionRequest,
    didFinishWithResult result: OSSystemExtensionRequest.Result
  ) {
    finish(
      request,
      event: .completed(rebootRequired: result == .willCompleteAfterReboot)
    )
  }

  public func request(
    _ request: OSSystemExtensionRequest,
    didFailWithError error: any Error
  ) {
    let error = error as NSError
    finish(
      request,
      event: .failed(
        domain: error.domain,
        code: error.code,
        description: error.localizedDescription
      )
    )
  }

  /// The answer ends a properties request: macOS calls neither `didFinishWithResult` nor
  /// `didFailWithError` after it. OSSystemExtensionManager keeps the request, so the delegate does
  /// not. On macOS 27.2 the framework also keeps the request's connection to `sysextd` open after
  /// this answer, until the process exits; see `InstallationStateQueryManager`.
  public func request(
    _ request: OSSystemExtensionRequest,
    foundProperties properties: [OSSystemExtensionProperties]
  ) {
    finish(request, event: .properties(properties.map(ExtensionInstallationProperties.init)))
  }

  private func submit(
    action: String,
    request: @escaping (DispatchQueue) -> OSSystemExtensionRequest
  ) -> AsyncStream<ActivationEvent> {
    AsyncStream { continuation in
      let systemRequest = request(requestQueue)
      systemRequest.delegate = self
      let identifier = ObjectIdentifier(systemRequest)
      requests.withLock { $0[identifier] = RequestState(continuation: continuation) }
      continuation.onTermination = { [weak self] _ in
        guard let self else { return }
        _ = self.requests.withLock { $0.removeValue(forKey: identifier) }
      }
      continuation.yield(.submitted(action: action))
      OSSystemExtensionManager.shared.submitRequest(systemRequest)
    }
  }

  private func continuation(
    for request: OSSystemExtensionRequest
  ) -> AsyncStream<ActivationEvent>.Continuation? {
    let identifier = ObjectIdentifier(request)
    return requests.withLock { $0[identifier]?.continuation }
  }

  private func finish(_ request: OSSystemExtensionRequest, event: ActivationEvent) {
    let identifier = ObjectIdentifier(request)
    let state = requests.withLock { $0.removeValue(forKey: identifier) }
    state?.continuation.yield(event)
    state?.continuation.finish()
  }
}
