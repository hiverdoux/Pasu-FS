import Foundation

/// The system-compatibility profiles this version of Pasu FS offers. A profile does nothing
/// until it is turned on for a policy; see `ResolvedSystemCompatibilityProfile` for the
/// conditions every actor must meet. Each actor may make only its listed requests and use only
/// its permitted open flags.
public enum BuiltInSystemCompatibilityCatalog {
  public static let containerManagementIdentifier = "container-management"
  public static let xprotectRemediationIdentifier = "xprotect-remediation"
  public static let finderCopyIdentifier = "finder-copy"

  public static let catalog = SystemCompatibilityCatalog(profiles: [
    containerManagement, xprotectRemediation, finderCopy,
  ])

  /// macOS 26 and 27, the versions on which the actors were observed.
  static let testedRange = SystemCompatibilityOSRange(
    minimum: SystemCompatibilityOSVersion(major: 26),
    maximumExclusive: SystemCompatibilityOSVersion(major: 28))
  /// macOS 26.6.2 and macOS 27.2.
  static let observedBuilds = ["25G83", "26B5101f"]

  static let containerManagement = SystemCompatibilityProfile(
    id: containerManagementIdentifier,
    displayName: "App Container Management",
    roleDescription:
      "Lets the macOS services that prepare an app's container, some running as the folder's owner, read it so the app can start.",
    consequence: "Apple's container services can read this app container.",
    evidence: SystemCompatibilityProfileEvidence(
      capabilityClass: .singlePurposeAutonomousService,
      acceptsArbitraryThirdPartyCommandsOrPaths: false,
      observedOSBuilds: observedBuilds,
      observedDate: "2026-10-10",
      evidenceReference:
        "See docs/architecture.md#system-compatibility-profiles and docs/threat-model.md#known-limitations.",
      capabilityAssessment:
        "App container preparation uses containermanagerd and secinitd under the folder owner's account, and containermanagerd_system and apfsd as root. This profile permits only non-modifying opens within app or group containers. Each request must satisfy the profile's Apple signature, process ancestry and effective-user conditions; a matching block rule still denies it. This exception gives these system services read access to the container, not a general permission for the app that uses it."
    ),
    pathForm: .appContainer,
    actors: [
      actor("com.apple.containermanagerd", users: .rootOrFolderOwner),
      actor("com.apple.containermanagerd_system", users: .root),
      actor("com.apple.secinitd", users: .rootOrFolderOwner),
      actor("com.apple.apfsd", users: .root),
    ]
  )

  static let xprotectRemediators = [
    "Adload", "BadGacha", "BlueTop", "Bundlore", "CardboardCutout", "ColdSnap", "Conductor",
    "Crapyrator", "Dolittle", "DubRobber", "Eicar", "FloppyFlipper", "Genieo", "GreenAcre",
    "KeySteal", "MRTv3", "Pirrit", "RankStank", "RoachFlight", "SheepSwap", "SnowBeagle",
    "SnowDrift", "ToyDrop", "Trovi", "WaterNet",
  ]

  /// macOS 26.6.2, 27.0.1 and 27.2, on which the analysis service was observed.
  static let xprotectObservedBuilds = ["25G83", "26A434", "26B5101f"]

  static let xprotectRemediation = SystemCompatibilityProfile(
    id: xprotectRemediationIdentifier,
    displayName: "XProtect Malware Scanning",
    roleDescription:
      "Lets the macOS malware scanner XProtect read this folder: its remediator plug-ins, running as root or as the folder's owner, while they scan it, and its analysis service, running as root, when Gatekeeper checks an item.",
    consequence: "Apple's malware scanner can read this folder.",
    evidence: SystemCompatibilityProfileEvidence(
      capabilityClass: .platformClientBroker,
      acceptsArbitraryThirdPartyCommandsOrPaths: false,
      observedOSBuilds: xprotectObservedBuilds,
      observedDate: "2026-10-12",
      evidenceReference:
        "See docs/architecture.md#system-compatibility-profiles and docs/threat-model.md#known-limitations.",
      capabilityAssessment:
        "XProtect remediator plug-ins may open the policy folder for reading as root or its owner. The analysis service's root instances serve Gatekeeper assessments; this profile admits only those root instances, not its user-session instances. The extension verifies the service's identity, ancestry and effective user, but does not authenticate its client or choose the item it analyzes. The exception therefore relies on macOS to control access to the service. The plug-in launcher receives no file access itself."
    ),
    actors: [
      launcher("com.apple.XprotectFramework.PluginService"),
      actor(
        "com.apple.XprotectFramework.AnalysisService", users: .root,
        observedOSBuilds: xprotectObservedBuilds),
    ]
      + xprotectRemediators.map {
        actor("com.apple.XProtectFramework.plugins.\($0)", users: .rootOrFolderOwner)
      }
  )

  /// macOS 26.6.2 and macOS 27.0.1, on which Finder's copies were observed.
  static let finderCopyObservedBuilds = ["25G83", "26A434"]

  /// The helper may read or write with these open flags. `O_CREAT`, `O_TRUNC`, `O_APPEND` and
  /// `O_EXCL` are excluded; creating or truncating an item uses a separately listed request.
  static let finderCopyOpenFlags =
    UInt32(FREAD) | UInt32(FWRITE) | UInt32(O_NONBLOCK) | UInt32(O_EVTONLY)
    | UInt32(O_DIRECTORY) | UInt32(O_CLOEXEC)

  static let finderCopy = SystemCompatibilityProfile(
    id: finderCopyIdentifier,
    displayName: "Finder Copy",
    roleDescription:
      "Lets the macOS service that carries out Finder's copies, duplicates and restores from the Time Machine screen, running as root or as the folder's owner, copy files and folders into and out of this folder.",
    consequence:
      "Finder can copy items into this folder, and copy its items or the whole folder out of it.",
    evidence: SystemCompatibilityProfileEvidence(
      capabilityClass: .platformClientBroker,
      acceptsArbitraryThirdPartyCommandsOrPaths: false,
      observedOSBuilds: finderCopyObservedBuilds,
      observedDate: "2026-10-11",
      evidenceReference:
        "See docs/architecture.md#system-compatibility-profiles and docs/threat-model.md#known-limitations.",
      capabilityAssessment:
        "DesktopServicesHelper carries out Finder copies, duplicates and Time Machine restores. This profile permits its listed copy and attribute-changing requests as root or the folder's owner, including copies into, within and out of the policy folder and copies of the whole folder. The extension authenticates the helper, not Finder as its client, and does not distinguish other Apple clients that could use the helper; macOS controls client access. Finder's own requests still require ordinary program rules. Finder scripting helpers are excluded."
    ),
    actors: [
      actor(
        "com.apple.DesktopServicesHelper", users: .rootOrFolderOwner,
        requests: [
          .create, .open, .truncate, .clone, .setAttributeList, .setExtendedAttribute,
          .deleteExtendedAttribute,
        ],
        openFlags: finderCopyOpenFlags, observedOSBuilds: finderCopyObservedBuilds)
    ]
  )

  /// An actor that may only make the given requests, by default opens for reading.
  static func actor(
    _ signingIdentifier: String, users: SystemCompatibilityEffectiveUser,
    requests: [SystemCompatibilityRequestKind] = [.open],
    openFlags: UInt32 = SystemCompatibilityOpenFlags.readOnly,
    observedOSBuilds: [String] = observedBuilds
  ) -> SystemCompatibilityProfileActor {
    SystemCompatibilityProfileActor(
      signingIdentifier: signingIdentifier,
      allowedRequests: requests,
      allowedOpenFlags: openFlags,
      requiredCodeSigningFlags: SystemCompatibilityCodeSigning.minimumRequired
        | SystemCompatibilityCodeSigning.kill,
      allowedEffectiveUsers: users,
      supportedOSRange: testedRange,
      observedOSBuilds: observedOSBuilds)
  }

  /// A program that starts the profile's actors and gets no access itself.
  static func launcher(_ signingIdentifier: String) -> SystemCompatibilityProfileActor {
    SystemCompatibilityProfileActor(
      signingIdentifier: signingIdentifier,
      allowedRequests: [],
      allowedOpenFlags: 0,
      requiredCodeSigningFlags: SystemCompatibilityCodeSigning.minimumRequired
        | SystemCompatibilityCodeSigning.kill,
      allowedEffectiveUsers: .rootOrFolderOwner,
      supportedOSRange: testedRange,
      observedOSBuilds: observedBuilds)
  }
}
