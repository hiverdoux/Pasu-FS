import CryptoKit
import Darwin
import Foundation
import PasuFSPolicy

public enum SystemCompatibilityDigest {
  public static func isCanonicalSHA256(_ value: String) -> Bool {
    value.count == 64
      && value.unicodeScalars.allSatisfy {
        (0x30...0x39).contains($0.value) || (0x61...0x66).contains($0.value)
      }
  }
}

public struct SystemCompatibilityOSVersion: Codable, Equatable, Hashable, Sendable,
  Comparable
{
  public var major: Int
  public var minor: Int
  public var patch: Int

  public init(major: Int, minor: Int = 0, patch: Int = 0) {
    self.major = major
    self.minor = minor
    self.patch = patch
  }

  public init(_ version: OperatingSystemVersion) {
    self.init(
      major: version.majorVersion,
      minor: version.minorVersion,
      patch: version.patchVersion
    )
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    (lhs.major, lhs.minor, lhs.patch) < (rhs.major, rhs.minor, rhs.patch)
  }
}

public struct SystemCompatibilityOSRange: Codable, Equatable, Hashable, Sendable {
  public var minimum: SystemCompatibilityOSVersion
  public var maximumExclusive: SystemCompatibilityOSVersion?

  public init(
    minimum: SystemCompatibilityOSVersion,
    maximumExclusive: SystemCompatibilityOSVersion? = nil
  ) {
    self.minimum = minimum
    self.maximumExclusive = maximumExclusive
  }

  public func contains(_ version: OperatingSystemVersion) -> Bool {
    let candidate = SystemCompatibilityOSVersion(version)
    guard candidate >= minimum else { return false }
    guard let maximumExclusive else { return true }
    return candidate < maximumExclusive
  }
}

public enum SystemCompatibilityOSBuild {
  public static func current() -> String {
    var length: size_t = 0
    guard sysctlbyname("kern.osversion", nil, &length, nil, 0) == 0, length > 1 else {
      return ""
    }
    var bytes = [CChar](repeating: 0, count: length)
    guard sysctlbyname("kern.osversion", &bytes, &length, nil, 0) == 0 else {
      return ""
    }
    return String(
      decoding: bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
      as: UTF8.self
    )
  }
}

public enum SystemCompatibilityCapabilityClass: String, Codable, Equatable, Hashable,
  Sendable
{
  /// A service that does one job of its own accord, on locations it chooses itself.
  case singlePurposeAutonomousService
  /// A service that carries out operations an Apple program asks for, on the paths that
  /// program chooses. The profile assessment documents the limits of client authentication.
  case platformClientBroker
}

/// Public documentation and validation metadata for a profile's programs. It describes the
/// profile to a reader and is checked when the catalog is validated. It is part of the catalog
/// digest but not of the authorization digest, so it does not decide what an accepted profile allows.
public struct SystemCompatibilityProfileEvidence: Codable, Equatable, Hashable, Sendable {
  public var capabilityClass: SystemCompatibilityCapabilityClass
  /// Whether a third-party program can choose what the programs do or which paths they touch.
  /// The catalog accepts a profile only when this is false.
  public var acceptsArbitraryThirdPartyCommandsOrPaths: Bool
  /// The macOS builds, as `kern.osversion` reports them, on which the behavior was observed.
  /// The builds an actor lists must be among them.
  public var observedOSBuilds: [String]
  /// The calendar date (ISO 8601, `YYYY-MM-DD`) on which this evidence was last collected. It
  /// tells a reader how old the evidence is and has no effect on what the profile allows.
  public var observedDate: String
  /// A public documentation reference, such as a repository-relative path with a section anchor.
  /// An absolute local path or `file://` URL is refused.
  public var evidenceReference: String
  /// The programs' roles, permitted operations and trust limitations, as display text.
  public var capabilityAssessment: String

  public init(
    capabilityClass: SystemCompatibilityCapabilityClass,
    acceptsArbitraryThirdPartyCommandsOrPaths: Bool,
    observedOSBuilds: [String],
    observedDate: String,
    evidenceReference: String,
    capabilityAssessment: String
  ) {
    self.capabilityClass = capabilityClass
    self.acceptsArbitraryThirdPartyCommandsOrPaths =
      acceptsArbitraryThirdPartyCommandsOrPaths
    self.observedOSBuilds = observedOSBuilds
    self.observedDate = observedDate
    self.evidenceReference = evidenceReference
    self.capabilityAssessment = capabilityAssessment
  }
}

/// The requests a profile can allow, named like the authorization events. A mount is decided by
/// its mount point alone and is never part of a profile.
public enum SystemCompatibilityRequestKind: String, Codable, CaseIterable, Comparable, Hashable,
  Sendable
{
  case open = "AUTH_OPEN"
  case create = "AUTH_CREATE"
  case rename = "AUTH_RENAME"
  case unlink = "AUTH_UNLINK"
  case link = "AUTH_LINK"
  case clone = "AUTH_CLONE"
  case copyFile = "AUTH_COPYFILE"
  case truncate = "AUTH_TRUNCATE"
  case exchangeData = "AUTH_EXCHANGEDATA"
  case setMode = "AUTH_SETMODE"
  case setOwner = "AUTH_SETOWNER"
  case setFlags = "AUTH_SETFLAGS"
  case setACL = "AUTH_SETACL"
  case setExtendedAttribute = "AUTH_SETEXTATTR"
  case deleteExtendedAttribute = "AUTH_DELETEEXTATTR"
  case setAttributeList = "AUTH_SETATTRLIST"
  case setTimes = "AUTH_UTIMES"

  public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

/// Code-signing flags as Endpoint Security reports them (`cs_blobs.h`).
public enum SystemCompatibilityCodeSigning {
  public static let valid: UInt32 = 0x0000_0001
  public static let adhoc: UInt32 = 0x0000_0002
  public static let getTaskAllow: UInt32 = 0x0000_0004
  public static let invalidAllowed: UInt32 = 0x0000_0020
  public static let kill: UInt32 = 0x0000_0200
  public static let platformBinary: UInt32 = 0x0400_0000
  public static let debugged: UInt32 = 0x1000_0000
  public static let signed: UInt32 = 0x2000_0000
  public static let devCode: UInt32 = 0x4000_0000

  /// Every actor requires at least a valid, signed Apple platform binary.
  public static let minimumRequired = valid | signed | platformBinary
  /// Every actor rejects at least ad hoc signatures and code that can be debugged or whose
  /// signature may be invalid.
  public static let minimumForbidden = adhoc | getTaskAllow | invalidAllowed | debugged | devCode
}

/// The `fflag` bits of an `AUTH_OPEN` request, which use the kernel's file flags.
public enum SystemCompatibilityOpenFlags {
  /// `FWRITE`, `O_APPEND`, `O_CREAT`, `O_TRUNC` and `O_EXCL`: the flags with which an open can
  /// change a file.
  public static let modifying: UInt32 = 0x0002 | 0x0008 | 0x0200 | 0x0400 | 0x0800
  /// Every flag except the modifying ones.
  public static let readOnly: UInt32 = ~modifying
  public static let any: UInt32 = .max
}

/// The effective users an actor may run as.
public enum SystemCompatibilityEffectiveUser: String, Codable, Equatable, Hashable, Sendable {
  /// Only root (user ID 0).
  case root
  /// Root, or the account that owns the policy's folder. Some Apple services, such as the
  /// container manager of a logged-in user, run as that user rather than as root.
  case rootOrFolderOwner
}

/// The paths a profile's requests may name.
public enum SystemCompatibilityPathForm: String, Codable, Equatable, Hashable, Sendable {
  /// Any path inside the policy's folder.
  case anyPath
  /// Only paths inside an app container or group container of the account that owns the
  /// policy's folder: `<home>/Library/Containers/<name>` or
  /// `<home>/Library/Group Containers/<name>`, or below them.
  case appContainer

  /// Whether `path`, as Endpoint Security reports it, has this form. `ownerHome` is the
  /// folder owner's home folder with symbolic links resolved.
  public func admits(_ path: String, ownerHome: String?, caseSensitive: Bool) -> Bool {
    switch self {
    case .anyPath:
      return true
    case .appContainer:
      guard let ownerHome, path.hasPrefix("/"), ownerHome.hasPrefix("/") else { return false }
      let components = path.split(separator: "/")
      let home = ownerHome.split(separator: "/")
      guard !components.contains(where: { $0 == "." || $0 == ".." }),
        components.count >= home.count + 3
      else { return false }
      func same(_ lhs: Substring, _ rhs: Substring) -> Bool {
        caseSensitive ? lhs == rhs : lhs.lowercased() == rhs.lowercased()
      }
      guard zip(components, home).allSatisfy(same) else { return false }
      let folder = components[home.count + 1]
      return same(components[home.count], "Library")
        && (same(folder, "Containers") || same(folder, "Group Containers"))
    }
  }
}

/// One Apple system program a profile names, and what it may do in a policy's folder. An
/// actor without requests is a launcher: it gets no access itself, but the programs of the
/// profile that it starts count as started through the profile (see
/// `ResolvedSystemCompatibilityProfile`).
public struct SystemCompatibilityProfileActor: Codable, Equatable, Hashable, Sendable {
  public var signingIdentifier: String
  public var allowedRequests: [SystemCompatibilityRequestKind]
  /// The flags an `AUTH_OPEN` request may ask for; 0 when opens are not allowed.
  public var allowedOpenFlags: UInt32
  public var requiredCodeSigningFlags: UInt32
  public var forbiddenCodeSigningFlags: UInt32
  public var allowedEffectiveUsers: SystemCompatibilityEffectiveUser
  /// The macOS versions on which the actor is trusted.
  public var supportedOSRange: SystemCompatibilityOSRange
  /// The macOS builds on which the actor's behavior was observed; evidence, not a condition.
  public var observedOSBuilds: [String]

  public init(
    signingIdentifier: String,
    allowedRequests: [SystemCompatibilityRequestKind],
    allowedOpenFlags: UInt32,
    requiredCodeSigningFlags: UInt32 = SystemCompatibilityCodeSigning.minimumRequired,
    forbiddenCodeSigningFlags: UInt32 = SystemCompatibilityCodeSigning.minimumForbidden,
    allowedEffectiveUsers: SystemCompatibilityEffectiveUser = .root,
    supportedOSRange: SystemCompatibilityOSRange,
    observedOSBuilds: [String]
  ) {
    self.signingIdentifier = signingIdentifier
    self.allowedRequests = allowedRequests
    self.allowedOpenFlags = allowedOpenFlags
    self.requiredCodeSigningFlags = requiredCodeSigningFlags
    self.forbiddenCodeSigningFlags = forbiddenCodeSigningFlags
    self.allowedEffectiveUsers = allowedEffectiveUsers
    self.supportedOSRange = supportedOSRange
    self.observedOSBuilds = observedOSBuilds
  }

  public var isLauncher: Bool { allowedRequests.isEmpty }

  /// Whether the process is this program: an Apple platform binary with this signing identifier
  /// and acceptable code-signing flags.
  public func matches(_ process: ProcessFacts) -> Bool {
    matches(
      isPlatformBinary: process.isPlatformBinary, signingIdentifier: process.signingIdentifier,
      codeSigningFlags: process.codeSigningFlags)
  }

  /// The same check for a program recorded in an execution history.
  public func matches(_ program: ExecutionProgram) -> Bool {
    matches(
      isPlatformBinary: program.isPlatformBinary, signingIdentifier: program.signingIdentifier,
      codeSigningFlags: program.codeSigningFlags)
  }

  private func matches(
    isPlatformBinary: Bool, signingIdentifier candidate: String?, codeSigningFlags: UInt32
  ) -> Bool {
    isPlatformBinary
      && candidate == signingIdentifier
      && codeSigningFlags & requiredCodeSigningFlags == requiredCodeSigningFlags
      && codeSigningFlags & forbiddenCodeSigningFlags == 0
  }

  /// Whether a process running as `effectiveUserID` may act as this actor in a folder owned
  /// by `folderOwnerUserID`.
  public func allowsEffectiveUser(_ effectiveUserID: UInt32?, folderOwnerUserID: UInt32?)
    -> Bool
  {
    guard let effectiveUserID else { return false }
    if effectiveUserID == 0 { return true }
    guard allowedEffectiveUsers == .rootOrFolderOwner, let folderOwnerUserID else {
      return false
    }
    return effectiveUserID == folderOwnerUserID
  }

  /// Whether the actor may make this request. An open must not ask for a flag outside
  /// `allowedOpenFlags`.
  public func allows(_ request: SystemCompatibilityRequestKind, openFlags: UInt32?) -> Bool {
    guard allowedRequests.contains(request) else { return false }
    guard request == .open else { return true }
    guard let openFlags else { return false }
    return openFlags & ~allowedOpenFlags == 0
  }
}

public struct SystemCompatibilityProfile: Codable, Equatable, Hashable, Identifiable,
  Sendable
{
  public var id: String
  public var displayName: String
  public var roleDescription: String
  public var consequence: String
  public var evidence: SystemCompatibilityProfileEvidence
  public var pathForm: SystemCompatibilityPathForm
  public var actors: [SystemCompatibilityProfileActor]

  public init(
    id: String,
    displayName: String,
    roleDescription: String,
    consequence: String,
    evidence: SystemCompatibilityProfileEvidence,
    pathForm: SystemCompatibilityPathForm = .anyPath,
    actors: [SystemCompatibilityProfileActor]
  ) {
    self.id = id
    self.displayName = displayName
    self.roleDescription = roleDescription
    self.consequence = consequence
    self.evidence = evidence
    self.pathForm = pathForm
    self.actors = actors
  }
}

/// A profile turned on for a policy and active on this Mac, with the actors trusted on the
/// running macOS version.
///
/// A process acts under the profile when all of these hold, whatever the policy's program lists
/// say and even without an observed execution history:
/// - it is one of the actors: an Apple platform binary with the actor's signing identifier and
///   code-signing flags, and the request is one the actor may make;
/// - its effective user is root, or, for an actor that allows it, the account that owns the
///   policy's folder;
/// - every path of the request has the profile's path form (checked by the caller);
/// - launchd started it, without a program of the user's session in between. With a complete
///   observed history, the first program after launchd must itself be an actor or launcher of
///   this profile, so the process is that daemon or a helper it started. Without a complete
///   history, such as for a daemon that started before the extension, the kernel must report
///   launchd (PID 1) as the process that forked it, or the process that forked it must still be
///   its parent and be an actor or launcher of this profile that launchd forked, running as a
///   user that program allows. This admits the plug-ins of a service that predates the
///   extension, but not a longer chain.
///
/// A program in the policy's block list anywhere in the observed history still denies the
/// request; the caller checks that first.
public struct ResolvedSystemCompatibilityProfile: Equatable, Sendable {
  public var profileIdentifier: String
  public var authorizationDigest: String
  public var pathForm: SystemCompatibilityPathForm
  public var actors: [SystemCompatibilityProfileActor]

  public init(
    profileIdentifier: String,
    authorizationDigest: String,
    pathForm: SystemCompatibilityPathForm = .anyPath,
    actors: [SystemCompatibilityProfileActor]
  ) {
    self.profileIdentifier = profileIdentifier
    self.authorizationDigest = authorizationDigest
    self.pathForm = pathForm
    self.actors = actors
  }

  public func admits(
    process: ProcessFacts,
    request: SystemCompatibilityRequestKind,
    openFlags: UInt32?,
    origin: ExecutionOriginDecision,
    parent: ExecutionProgram? = nil,
    folderOwnerUserID: UInt32?
  ) -> Bool {
    guard
      let actor = actors.first(where: {
        !$0.isLauncher && $0.matches(process)
          && $0.allowsEffectiveUser(
            process.effectiveUserID, folderOwnerUserID: folderOwnerUserID)
      }),
      actor.allows(request, openFlags: openFlags)
    else { return false }
    return wasStartedByLaunchd(
      process, origin: origin, parent: parent, folderOwnerUserID: folderOwnerUserID)
  }

  /// `parent` is the program recorded for the process's current parent.
  private func wasStartedByLaunchd(
    _ process: ProcessFacts, origin: ExecutionOriginDecision, parent: ExecutionProgram?,
    folderOwnerUserID: UInt32?
  ) -> Bool {
    guard origin.uncertainty == nil else {
      if process.originalParentProcessID == 1 { return true }
      // The parent that forked the process, still its parent, is a program of this profile
      // that launchd forked.
      guard let parent, let forker = process.originalParentProcessID, forker > 1,
        process.parentProcessInstance == parent.instance, parent.instance.processID == forker,
        parent.originalParentProcessID == 1
      else { return false }
      return actors.contains {
        $0.matches(parent)
          && $0.allowsEffectiveUser(
            process.parentEffectiveUserID, folderOwnerUserID: folderOwnerUserID)
      }
    }
    // A complete history begins at launchd, so its first program is the one launchd started.
    guard let first = origin.origin, first.identity != nil else { return false }
    return actors.contains { $0.matches(first) }
  }
}

public struct SystemCompatibilityCatalog: Codable, Equatable, Sendable {
  /// Schema 3 profiles have a path form, and their actors allowed requests and users. The
  /// catalog is built in; its schema is part of the catalog digest but not of the profile
  /// authorization digests that policies store.
  public static let currentSchemaVersion = 3
  public static let maximumProfileCount = 256
  public static let maximumActorCount = 1_024
  /// Additional protection against programs that can act on another app's behalf.
  /// This list is not exhaustive; each profile also needs a review of its interfaces.
  /// Shells, interpreters, launchers and general file tools can accept caller-selected
  /// commands or paths. Giving them a compatibility exception could let an otherwise
  /// denied app use that exception indirectly. These are defensive exclusions, not
  /// a claim that every identifier exists on every supported OS. Ordinary user rules
  /// remain separate from these system-service exceptions.
  public static let forbiddenCapabilityConduitSigningIdentifiers: Set<String> = [
    "com.apple.arch",
    "com.apple.automator",
    "com.apple.awk",
    "com.apple.bash",
    "com.apple.bsdtar",
    "com.apple.bzegrep",
    "com.apple.cat",
    "com.apple.cp",
    "com.apple.csh",
    "com.apple.curl",
    "com.apple.dash",
    "com.apple.dd",
    "com.apple.defaults",
    // Carries out the Finder operations that scripts send to Finder.
    "com.apple.desktopservices.desktopservicesscriptinghelper",
    "com.apple.ditto",
    "com.apple.dt.xcode",
    "com.apple.dt.xcode_select.tool-shim-public",
    "com.apple.env",
    "com.apple.find",
    "com.apple.finder",
    "com.apple.foundation.plutil",
    "com.apple.head",
    "com.apple.less",
    "com.apple.ls",
    "com.apple.machine",
    "com.apple.more",
    "com.apple.mv",
    "com.apple.nohup",
    "com.apple.open",
    "com.apple.openssl",
    "com.apple.osascript",
    "com.apple.perl",
    "com.apple.pico",
    "com.apple.rsync",
    "com.apple.ruby",
    "com.apple.scripteditor2",
    "com.apple.script",
    "com.apple.scp",
    "com.apple.sed",
    "com.apple.sftp",
    "com.apple.sh",
    "com.apple.shortcuts",
    "com.apple.sort",
    "com.apple.sqlite3",
    "com.apple.ssh",
    "com.apple.tail",
    "com.apple.tee",
    "com.apple.terminal",
    "com.apple.tmutil",
    "com.apple.unlink",
    "com.apple.unzip",
    "com.apple.vim",
    "com.apple.wc",
    "com.apple.xargs",
    "com.apple.xcode-select",
    "com.apple.xcrun",
    "com.apple.xpc.launchctl",
    "com.apple.xxd",
    "com.apple.zegrep",
    "com.apple.zsh",
    "com.apple.zip",
  ]

  public var schemaVersion: Int
  public var profiles: [SystemCompatibilityProfile]

  public init(
    schemaVersion: Int = Self.currentSchemaVersion,
    profiles: [SystemCompatibilityProfile]
  ) {
    self.schemaVersion = schemaVersion
    self.profiles = profiles
  }

  public func validate() throws {
    guard schemaVersion == Self.currentSchemaVersion else {
      throw SystemCompatibilityValidationError.unsupportedCatalogSchemaVersion(schemaVersion)
    }
    guard profiles.count <= Self.maximumProfileCount else {
      throw SystemCompatibilityValidationError.tooManyProfiles(profiles.count)
    }
    let actorCount = profiles.reduce(into: 0) { $0 += $1.actors.count }
    guard actorCount <= Self.maximumActorCount else {
      throw SystemCompatibilityValidationError.tooManyActors(actorCount)
    }

    var profileIdentifiers = Set<String>()
    for profile in profiles {
      try Self.validateIdentifier(profile.id, field: "profile identifier")
      try Self.validateDisplayText(profile.displayName, field: "profile display name")
      try Self.validateDisplayText(profile.roleDescription, field: "profile role description")
      try Self.validateDisplayText(profile.consequence, field: "profile consequence")
      try Self.validate(profile.evidence, profile: profile.id)
      guard profileIdentifiers.insert(profile.id).inserted else {
        throw SystemCompatibilityValidationError.duplicateProfileIdentifier(profile.id)
      }
      guard profile.actors.contains(where: { !$0.isLauncher }) else {
        throw SystemCompatibilityValidationError.profileRequiresActor(profile.id)
      }

      var signingIdentifiers = Set<String>()
      for actor in profile.actors {
        try Self.validate(actor, profile: profile)
        guard signingIdentifiers.insert(actor.signingIdentifier).inserted else {
          throw SystemCompatibilityValidationError.duplicateActorIdentity(
            profile: profile.id,
            signingIdentifier: actor.signingIdentifier
          )
        }
      }
    }
  }

  private static func validate(
    _ actor: SystemCompatibilityProfileActor, profile: SystemCompatibilityProfile
  ) throws {
    try validateIdentifier(actor.signingIdentifier, field: "actor signing identifier")
    guard
      !forbiddenCapabilityConduitSigningIdentifiers.contains(
        actor.signingIdentifier.lowercased())
    else {
      throw SystemCompatibilityValidationError.forbiddenCapabilityConduit(
        profile: profile.id,
        signingIdentifier: actor.signingIdentifier
      )
    }
    guard Set(actor.allowedRequests).count == actor.allowedRequests.count,
      actor.allowedRequests.contains(.open) == (actor.allowedOpenFlags != 0)
    else {
      throw SystemCompatibilityValidationError.invalidAllowedRequests(
        profile: profile.id,
        signingIdentifier: actor.signingIdentifier
      )
    }
    let minimumRequired = SystemCompatibilityCodeSigning.minimumRequired
    let minimumForbidden = SystemCompatibilityCodeSigning.minimumForbidden
    guard actor.requiredCodeSigningFlags & minimumRequired == minimumRequired,
      actor.forbiddenCodeSigningFlags & minimumForbidden == minimumForbidden
    else {
      throw SystemCompatibilityValidationError.weakCodeSigningRequirement(
        profile: profile.id,
        signingIdentifier: actor.signingIdentifier
      )
    }
    guard actor.requiredCodeSigningFlags & actor.forbiddenCodeSigningFlags == 0 else {
      throw SystemCompatibilityValidationError.conflictingCodeSigningFlags(
        profile: profile.id,
        signingIdentifier: actor.signingIdentifier
      )
    }
    try validate(actor.supportedOSRange, profile: profile.id)
    guard actor.supportedOSRange.maximumExclusive != nil else {
      throw SystemCompatibilityValidationError.openEndedOSRange(profile.id)
    }
    try validateOSBuilds(
      actor.observedOSBuilds,
      field: "actor observed OS builds",
      profile: profile.id
    )
    guard Set(actor.observedOSBuilds).isSubset(of: Set(profile.evidence.observedOSBuilds)) else {
      throw SystemCompatibilityValidationError.unsupportedBuildLacksEvidence(profile.id)
    }
  }

  public func profile(identifier: String) -> SystemCompatibilityProfile? {
    profiles.first { $0.id == identifier }
  }

  public func authorizationDigest(for profile: SystemCompatibilityProfile) throws -> String {
    try validate()
    guard self.profile(identifier: profile.id) == profile else {
      throw SystemCompatibilityValidationError.profileNotInCatalog(profile.id)
    }
    return Self.authorizationDigestUnchecked(for: profile)
  }

  public func authorizationDigest(profileIdentifier: String) throws -> String {
    guard let profile = profile(identifier: profileIdentifier) else {
      throw SystemCompatibilityValidationError.profileNotInCatalog(profileIdentifier)
    }
    return try authorizationDigest(for: profile)
  }

  /// The entry that turns a catalog profile on for a policy.
  public func policyEntry(profileIdentifier: String) throws -> PolicySystemCompatibilityProfile {
    PolicySystemCompatibilityProfile(
      profileIdentifier: profileIdentifier,
      authorizationDigest: try authorizationDigest(profileIdentifier: profileIdentifier))
  }

  public func catalogDigest() throws -> String {
    try validate()
    var builder = StableDigestBuilder(domain: "pasu-fs-system-catalog-v3")
    builder.append(schemaVersion)
    builder.append(profiles.count)
    for profile in profiles.sorted(by: { $0.id < $1.id }) {
      builder.append(profile.id)
      builder.append(profile.displayName)
      builder.append(profile.roleDescription)
      builder.append(profile.consequence)
      builder.append(profile.evidence.capabilityClass.rawValue)
      builder.append(profile.evidence.acceptsArbitraryThirdPartyCommandsOrPaths)
      builder.append(profile.evidence.observedOSBuilds.count)
      for build in profile.evidence.observedOSBuilds.sorted() {
        builder.append(build)
      }
      builder.append(profile.evidence.observedDate)
      builder.append(profile.evidence.evidenceReference)
      builder.append(profile.evidence.capabilityAssessment)
      for actor in profile.actors.sorted(by: { $0.signingIdentifier < $1.signingIdentifier }) {
        builder.append(actor.signingIdentifier)
        builder.append(actor.observedOSBuilds.count)
        for build in actor.observedOSBuilds.sorted() {
          builder.append(build)
        }
      }
      builder.append(Self.authorizationDigestUnchecked(for: profile))
    }
    return builder.digest()
  }

  /// Covers everything that decides what the profile allows, and nothing else: changing a name,
  /// a description or the evidence keeps the digest, so the approval stays valid.
  private static func authorizationDigestUnchecked(
    for profile: SystemCompatibilityProfile
  ) -> String {
    var builder = StableDigestBuilder(domain: "pasu-fs-system-profile-authorization-v3")
    builder.append(profile.id)
    builder.append(true)  // requires an Apple platform binary
    builder.append(true)  // requires root, or the folder owner where an actor allows it
    builder.append(true)  // requires a launchd lineage without a user-session program
    builder.append(profile.pathForm.rawValue)
    builder.append(profile.actors.count)
    for actor in profile.actors.sorted(by: { $0.signingIdentifier < $1.signingIdentifier }) {
      builder.append(actor.signingIdentifier)
      builder.append(actor.allowedRequests.count)
      for request in actor.allowedRequests.sorted() {
        builder.append(request.rawValue)
      }
      builder.append(actor.allowedOpenFlags)
      builder.append(actor.requiredCodeSigningFlags)
      builder.append(actor.forbiddenCodeSigningFlags)
      builder.append(actor.allowedEffectiveUsers.rawValue)
      builder.append(actor.supportedOSRange.minimum.major)
      builder.append(actor.supportedOSRange.minimum.minor)
      builder.append(actor.supportedOSRange.minimum.patch)
      if let maximum = actor.supportedOSRange.maximumExclusive {
        builder.append(true)
        builder.append(maximum.major)
        builder.append(maximum.minor)
        builder.append(maximum.patch)
      } else {
        builder.append(false)
      }
    }
    return builder.digest()
  }

  private static func validate(
    _ range: SystemCompatibilityOSRange,
    profile: String
  ) throws {
    let values =
      [range.minimum.major, range.minimum.minor, range.minimum.patch]
      + (range.maximumExclusive.map { [$0.major, $0.minor, $0.patch] } ?? [])
    guard values.allSatisfy({ $0 >= 0 }) else {
      throw SystemCompatibilityValidationError.invalidOSRange(profile)
    }
    if let maximumExclusive = range.maximumExclusive, maximumExclusive <= range.minimum {
      throw SystemCompatibilityValidationError.invalidOSRange(profile)
    }
  }

  private static func validate(
    _ evidence: SystemCompatibilityProfileEvidence,
    profile: String
  ) throws {
    // Either class qualifies only while no third-party program can choose what it does.
    guard !evidence.acceptsArbitraryThirdPartyCommandsOrPaths else {
      throw SystemCompatibilityValidationError.acceptsThirdPartyChoices(profile)
    }
    try validateOSBuilds(
      evidence.observedOSBuilds,
      field: "evidence OS builds",
      profile: profile
    )
    guard isISOCalendarDate(evidence.observedDate) else {
      throw SystemCompatibilityValidationError.invalidEvidenceDate(profile)
    }
    try validateDisplayText(evidence.evidenceReference, field: "evidence reference")
    guard !evidence.evidenceReference.hasPrefix("/"),
      !evidence.evidenceReference.localizedCaseInsensitiveContains("file://")
    else {
      throw SystemCompatibilityValidationError.localEvidenceReferenceForbidden(profile)
    }
    try validateDisplayText(
      evidence.capabilityAssessment,
      field: "capability assessment"
    )
  }

  private static func validateOSBuilds(
    _ builds: [String],
    field: String,
    profile: String
  ) throws {
    guard !builds.isEmpty, Set(builds).count == builds.count else {
      throw SystemCompatibilityValidationError.invalidOSBuildEvidence(profile)
    }
    for build in builds {
      try validateIdentifier(build, field: field)
      guard
        build.unicodeScalars.allSatisfy({
          (0x30...0x39).contains($0.value)
            || (0x41...0x5A).contains($0.value)
            || (0x61...0x7A).contains($0.value)
            || $0 == "." || $0 == "-" || $0 == "_"
        })
      else {
        throw SystemCompatibilityValidationError.invalidOSBuildEvidence(profile)
      }
    }
  }

  private static func isISOCalendarDate(_ value: String) -> Bool {
    guard value.range(of: #"^\d{4}-\d{2}-\d{2}$"#, options: .regularExpression) != nil
    else {
      return false
    }
    let formatter = DateFormatter()
    formatter.calendar = Calendar(identifier: .gregorian)
    formatter.locale = Locale(identifier: "en_US_POSIX")
    formatter.dateFormat = "yyyy-MM-dd"
    formatter.isLenient = false
    return formatter.date(from: value) != nil
  }

  private static func validateIdentifier(_ value: String, field: String) throws {
    guard !value.isEmpty, value.count <= 512,
      value == value.trimmingCharacters(in: .whitespacesAndNewlines),
      value.unicodeScalars.allSatisfy({ !CharacterSet.controlCharacters.contains($0) })
    else {
      throw SystemCompatibilityValidationError.invalidField(field)
    }
  }

  private static func validateDisplayText(_ value: String, field: String) throws {
    guard !value.isEmpty, value.count <= 2_048,
      value == value.trimmingCharacters(in: .whitespacesAndNewlines),
      value.unicodeScalars.allSatisfy({
        $0.value == 0x0A || $0.value == 0x09
          || !CharacterSet.controlCharacters.contains($0)
      })
    else {
      throw SystemCompatibilityValidationError.invalidField(field)
    }
  }
}

public enum SystemCompatibilityProfileState: String, Codable, Equatable, Sendable {
  case active
  /// The catalog changed what the profile allows since it was turned on for the policy.
  case needsReview
  /// The catalog no longer has the profile.
  case missingProfile
  /// None of the profile's actors is trusted on the running macOS version.
  case unsupportedOS
}

public struct SystemCompatibilityProfileResolution: Codable, Equatable, Sendable {
  public var policyIdentifier: UUID
  public var profileIdentifier: String
  public var state: SystemCompatibilityProfileState
  public var approvedAuthorizationDigest: String
  public var currentAuthorizationDigest: String?

  public init(
    policyIdentifier: UUID,
    profileIdentifier: String,
    state: SystemCompatibilityProfileState,
    approvedAuthorizationDigest: String,
    currentAuthorizationDigest: String? = nil
  ) {
    self.policyIdentifier = policyIdentifier
    self.profileIdentifier = profileIdentifier
    self.state = state
    self.approvedAuthorizationDigest = approvedAuthorizationDigest
    self.currentAuthorizationDigest = currentAuthorizationDigest
  }
}

public struct SystemCompatibilityResolution: Equatable, Sendable {
  public var activeProfilesByPolicy: [UUID: [ResolvedSystemCompatibilityProfile]]
  public var profileResolutions: [SystemCompatibilityProfileResolution]

  public init(
    activeProfilesByPolicy: [UUID: [ResolvedSystemCompatibilityProfile]] = [:],
    profileResolutions: [SystemCompatibilityProfileResolution] = []
  ) {
    self.activeProfilesByPolicy = activeProfilesByPolicy
    self.profileResolutions = profileResolutions
  }

  public var activeProfileCount: Int {
    profileResolutions.lazy.filter { $0.state == .active }.count
  }

  /// A status warning naming the profiles that are turned on but inactive, or nil.
  public var inactiveProfileWarning: String? {
    let inactive = profileResolutions.filter { $0.state != .active }
    guard let first = inactive.first else { return nil }
    if inactive.count == 1 {
      return
        "System-compatibility profile \(first.profileIdentifier) is inactive: \(first.state.rawValue)."
    }
    return "\(inactive.count) enabled system-compatibility profiles are inactive."
  }
}

/// Decides which of the profiles turned on in a policy set are active on this Mac.
public enum SystemCompatibilityResolver {
  public static func resolve(
    policySet: PolicySetDocument,
    catalog: SystemCompatibilityCatalog,
    operatingSystemVersion: OperatingSystemVersion = ProcessInfo.processInfo
      .operatingSystemVersion
  ) throws -> SystemCompatibilityResolution {
    try policySet.validate()
    try catalog.validate()
    var result = SystemCompatibilityResolution()
    for policy in policySet.policies {
      for entry in policy.systemCompatibilityProfiles {
        let (resolution, active) = try resolve(
          entry, policyIdentifier: policy.id, catalog: catalog,
          operatingSystemVersion: operatingSystemVersion)
        result.profileResolutions.append(resolution)
        if let active {
          result.activeProfilesByPolicy[policy.id, default: []].append(active)
        }
      }
    }
    return result
  }

  /// Rejects a set that turns on a profile that would not be active on this Mac, so a profile
  /// is never saved as on while it does nothing. An entry kept unchanged from `stored` may stay
  /// inactive, for example after a catalog change; it then needs to be turned on again.
  public static func validateNewlyTurnedOn(
    candidate: PolicySetDocument, comparedTo stored: PolicySetDocument?,
    resolution: SystemCompatibilityResolution
  ) throws {
    var previous: [UUID: Set<PolicySystemCompatibilityProfile>] = [:]
    for policy in stored?.policies ?? [] {
      previous[policy.id] = Set(policy.systemCompatibilityProfiles)
    }
    for policy in candidate.policies {
      for entry in policy.systemCompatibilityProfiles
      where previous[policy.id]?.contains(entry) != true {
        guard
          let state = resolution.profileResolutions.first(where: {
            $0.policyIdentifier == policy.id && $0.profileIdentifier == entry.profileIdentifier
          })?.state, state != .active
        else { continue }
        throw SystemCompatibilityValidationError.profileCannotBeTurnedOn(
          entry.profileIdentifier, state)
      }
    }
  }

  /// The state of one entry, and the profile to apply when it is active.
  public static func resolve(
    _ entry: PolicySystemCompatibilityProfile,
    policyIdentifier: UUID,
    catalog: SystemCompatibilityCatalog,
    operatingSystemVersion: OperatingSystemVersion = ProcessInfo.processInfo
      .operatingSystemVersion
  ) throws -> (SystemCompatibilityProfileResolution, ResolvedSystemCompatibilityProfile?) {
    func resolution(_ state: SystemCompatibilityProfileState, _ digest: String? = nil)
      -> SystemCompatibilityProfileResolution
    {
      SystemCompatibilityProfileResolution(
        policyIdentifier: policyIdentifier, profileIdentifier: entry.profileIdentifier,
        state: state, approvedAuthorizationDigest: entry.authorizationDigest,
        currentAuthorizationDigest: digest)
    }
    guard let profile = catalog.profile(identifier: entry.profileIdentifier) else {
      return (resolution(.missingProfile), nil)
    }
    let digest = try catalog.authorizationDigest(for: profile)
    guard entry.authorizationDigest == digest else {
      return (resolution(.needsReview, digest), nil)
    }
    let actors = profile.actors.filter {
      $0.supportedOSRange.contains(operatingSystemVersion)
    }
    guard !actors.isEmpty else {
      return (resolution(.unsupportedOS, digest), nil)
    }
    return (
      resolution(.active, digest),
      ResolvedSystemCompatibilityProfile(
        profileIdentifier: profile.id, authorizationDigest: digest, pathForm: profile.pathForm,
        actors: actors)
    )
  }
}

public enum SystemCompatibilityValidationError: Error, Equatable, CustomStringConvertible,
  Sendable
{
  case unsupportedCatalogSchemaVersion(Int)
  case tooManyProfiles(Int)
  case tooManyActors(Int)
  case invalidField(String)
  case duplicateProfileIdentifier(String)
  case profileRequiresActor(String)
  case duplicateActorIdentity(profile: String, signingIdentifier: String)
  case invalidAllowedRequests(profile: String, signingIdentifier: String)
  case weakCodeSigningRequirement(profile: String, signingIdentifier: String)
  case conflictingCodeSigningFlags(profile: String, signingIdentifier: String)
  case invalidOSRange(String)
  case openEndedOSRange(String)
  case invalidOSBuildEvidence(String)
  case unsupportedBuildLacksEvidence(String)
  case acceptsThirdPartyChoices(String)
  case forbiddenCapabilityConduit(profile: String, signingIdentifier: String)
  case invalidEvidenceDate(String)
  case localEvidenceReferenceForbidden(String)
  case profileNotInCatalog(String)
  case profileCannotBeTurnedOn(String, SystemCompatibilityProfileState)

  public var description: String {
    switch self {
    case .unsupportedCatalogSchemaVersion(let version):
      "Unsupported system-compatibility catalog schema version: \(version)."
    case .tooManyProfiles(let count):
      "System-compatibility catalog contains too many profiles: \(count)."
    case .tooManyActors(let count):
      "System-compatibility catalog contains too many actors: \(count)."
    case .invalidField(let field):
      "The \(field) is empty, too long, padded, or contains an unsupported character."
    case .duplicateProfileIdentifier(let identifier):
      "Duplicate system-compatibility profile identifier: \(identifier)."
    case .profileRequiresActor(let identifier):
      "System-compatibility profile \(identifier) requires at least one actor with requests."
    case .duplicateActorIdentity(let profile, let signingIdentifier):
      "System-compatibility profile \(profile) repeats actor \(signingIdentifier)."
    case .invalidAllowedRequests(let profile, let signingIdentifier):
      "System-compatibility profile \(profile) actor \(signingIdentifier) has no requests, repeats one, or has open flags that do not match its requests."
    case .weakCodeSigningRequirement(let profile, let signingIdentifier):
      "System-compatibility profile \(profile) actor \(signingIdentifier) does not require a valid Apple platform signature."
    case .conflictingCodeSigningFlags(let profile, let signingIdentifier):
      "System-compatibility profile \(profile) actor \(signingIdentifier) requires and forbids the same code-signing flag."
    case .invalidOSRange(let profile):
      "System-compatibility profile \(profile) has an invalid supported OS range."
    case .openEndedOSRange(let profile):
      "System-compatibility profile \(profile) must have a closed tested OS range."
    case .invalidOSBuildEvidence(let profile):
      "System-compatibility profile \(profile) has missing, duplicate, or invalid OS build evidence."
    case .unsupportedBuildLacksEvidence(let profile):
      "System-compatibility profile \(profile) names an observed OS build without matching evidence."
    case .acceptsThirdPartyChoices(let profile):
      "System-compatibility profile \(profile) accepts arbitrary third-party commands or paths."
    case .forbiddenCapabilityConduit(let profile, let signingIdentifier):
      "System-compatibility profile \(profile) cannot catalog capability conduit \(signingIdentifier)."
    case .invalidEvidenceDate(let profile):
      "System-compatibility profile \(profile) has an invalid evidence date."
    case .localEvidenceReferenceForbidden(let profile):
      "System-compatibility profile \(profile) evidence must not contain a local absolute path."
    case .profileNotInCatalog(let identifier):
      "System-compatibility profile is not in the built-in catalog: \(identifier)."
    case .profileCannotBeTurnedOn(let identifier, let state):
      "System-compatibility profile \(identifier) cannot be turned on: \(state.rawValue)."
    }
  }
}

private struct StableDigestBuilder {
  private var data = Data()

  init(domain: String) {
    append(domain)
  }

  mutating func append(_ value: String) {
    let bytes = Data(value.utf8)
    append(UInt64(bytes.count))
    data.append(bytes)
  }

  mutating func append(_ value: Bool) {
    data.append(value ? 1 : 0)
  }

  mutating func append(_ value: Int) {
    append(Int64(value))
  }

  mutating func append(_ value: UInt32) {
    append(UInt64(value))
  }

  private mutating func append(_ value: Int64) {
    append(UInt64(bitPattern: value))
  }

  private mutating func append(_ value: UInt64) {
    var bigEndian = value.bigEndian
    withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
  }

  func digest() -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }
}
