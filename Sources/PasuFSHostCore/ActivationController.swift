import Foundation
@preconcurrency import SystemExtensions
import os

public struct ExtensionInstallationProperties: Equatable, Sendable {
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

public final class ActivationController: NSObject, OSSystemExtensionRequestDelegate,
  @unchecked Sendable
{
  public static let extensionIdentifier = "com.dennis.pasu.fs.endpointsecurity"

  private struct RequestState {
    var continuation: AsyncStream<ActivationEvent>.Continuation
  }

  private let requests = OSAllocatedUnfairLock(initialState: [ObjectIdentifier: RequestState]())

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
      let systemRequest = request(.main)
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
