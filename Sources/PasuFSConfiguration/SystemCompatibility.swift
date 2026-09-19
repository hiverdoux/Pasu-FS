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
  case singlePurposeAutonomousService
}

public struct SystemCompatibilityProfileEvidence: Codable, Equatable, Hashable, Sendable {
  public var capabilityClass: SystemCompatibilityCapabilityClass
  public var acceptsArbitraryThirdPartyCommandsOrPaths: Bool
  public var observedOSBuilds: [String]
  public var observedDate: String
  public var evidenceReference: String
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

public struct SystemCompatibilityProfileActor: Codable, Equatable, Hashable, Sendable {
  public var signingIdentifier: String
  public var allowedOpenFlags: UInt32
  public var requiredCodeSigningFlags: UInt32
  public var forbiddenCodeSigningFlags: UInt32
  public var supportedOSRange: SystemCompatibilityOSRange
  public var supportedOSBuilds: [String]

  public init(
    signingIdentifier: String,
    allowedOpenFlags: UInt32,
    requiredCodeSigningFlags: UInt32 = 0,
    forbiddenCodeSigningFlags: UInt32 = 0,
    supportedOSRange: SystemCompatibilityOSRange,
    supportedOSBuilds: [String]
  ) {
    self.signingIdentifier = signingIdentifier
    self.allowedOpenFlags = allowedOpenFlags
    self.requiredCodeSigningFlags = requiredCodeSigningFlags
    self.forbiddenCodeSigningFlags = forbiddenCodeSigningFlags
    self.supportedOSRange = supportedOSRange
    self.supportedOSBuilds = supportedOSBuilds
  }

  public func allows(
    process: ProcessFacts,
    requestedOpenFlags: UInt32
  ) -> Bool {
    requestedOpenFlags != 0
      && process.isPlatformBinary
      && process.signingIdentifier == signingIdentifier
      && process.codeSigningFlags & requiredCodeSigningFlags == requiredCodeSigningFlags
      && process.codeSigningFlags & forbiddenCodeSigningFlags == 0
      && requestedOpenFlags & ~allowedOpenFlags == 0
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
  public var actors: [SystemCompatibilityProfileActor]

  public init(
    id: String,
    displayName: String,
    roleDescription: String,
    consequence: String,
    evidence: SystemCompatibilityProfileEvidence,
    actors: [SystemCompatibilityProfileActor]
  ) {
    self.id = id
    self.displayName = displayName
    self.roleDescription = roleDescription
    self.consequence = consequence
    self.evidence = evidence
    self.actors = actors
  }
}

public struct ResolvedSystemCompatibilityProfile: Equatable, Sendable {
  public var profileIdentifier: String
  public var authorizationDigest: String
  public var actors: [SystemCompatibilityProfileActor]

  public init(
    profileIdentifier: String,
    authorizationDigest: String,
    actors: [SystemCompatibilityProfileActor]
  ) {
    self.profileIdentifier = profileIdentifier
    self.authorizationDigest = authorizationDigest
    self.actors = actors
  }

  public func allows(
    process: ProcessFacts,
    requestedOpenFlags: UInt32
  ) -> Bool {
    actors.contains {
      $0.allows(process: process, requestedOpenFlags: requestedOpenFlags)
    }
  }
}

public struct SystemCompatibilityCatalog: Codable, Equatable, Sendable {
  public static let currentSchemaVersion = 2
  public static let maximumProfileCount = 256
  public static let maximumActorCount = 1_024
  /// Additional protection against programs that can act on another app's behalf.
  /// This list is not exhaustive; each profile also needs a review of its interfaces.
  /// Shells, interpreters, launchers and general file tools can accept caller-selected
  /// commands or paths. Giving them a compatibility exception could let an otherwise
  /// denied app use that exception indirectly. These are defensive exclusions, not
  /// a claim that every identifier exists on every supported OS. Ordinary user rules
  /// remain separate from these automatically applied system-service exceptions.
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
    "com.apple.unlink",
    "com.apple.unzip",
    "com.apple.vim",
    "com.apple.wc",
    "com.apple.xargs",
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
      guard !profile.actors.isEmpty else {
        throw SystemCompatibilityValidationError.profileRequiresActor(profile.id)
      }

      var signingIdentifiers = Set<String>()
      for actor in profile.actors {
        try Self.validateIdentifier(actor.signingIdentifier, field: "actor signing identifier")
        guard
          !Self.forbiddenCapabilityConduitSigningIdentifiers.contains(
            actor.signingIdentifier.lowercased()
          )
        else {
          throw SystemCompatibilityValidationError.forbiddenCapabilityConduit(
            profile: profile.id,
            signingIdentifier: actor.signingIdentifier
          )
        }
        guard actor.allowedOpenFlags != 0 else {
          throw SystemCompatibilityValidationError.emptyAllowedOpenFlags(
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
        guard signingIdentifiers.insert(actor.signingIdentifier).inserted else {
          throw SystemCompatibilityValidationError.duplicateActorIdentity(
            profile: profile.id,
            signingIdentifier: actor.signingIdentifier
          )
        }
        try Self.validate(actor.supportedOSRange, profile: profile.id)
        guard actor.supportedOSRange.maximumExclusive != nil else {
          throw SystemCompatibilityValidationError.openEndedOSRange(profile.id)
        }
        try Self.validateOSBuilds(
          actor.supportedOSBuilds,
          field: "actor supported OS builds",
          profile: profile.id
        )
        guard
          Set(actor.supportedOSBuilds).isSubset(
            of: Set(profile.evidence.observedOSBuilds)
          )
        else {
          throw SystemCompatibilityValidationError.unsupportedBuildLacksEvidence(profile.id)
        }
      }
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

  public func catalogDigest() throws -> String {
    try validate()
    var builder = StableDigestBuilder(domain: "pasu-fs-system-catalog-v2")
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
      builder.append(Self.authorizationDigestUnchecked(for: profile))
    }
    return builder.digest()
  }

  private static func authorizationDigestUnchecked(
    for profile: SystemCompatibilityProfile
  ) -> String {
    var builder = StableDigestBuilder(domain: "pasu-fs-system-profile-authorization-v2")
    builder.append(profile.id)
    builder.append(true)  // requires Apple platform binary
    builder.append(true)  // direct actor only; no descendant inheritance
    builder.append(profile.actors.count)
    for actor in profile.actors.sorted(by: { $0.signingIdentifier < $1.signingIdentifier }) {
      builder.append(actor.signingIdentifier)
      builder.append(actor.allowedOpenFlags)
      builder.append(actor.requiredCodeSigningFlags)
      builder.append(actor.forbiddenCodeSigningFlags)
      builder.append(actor.supportedOSBuilds.count)
      for build in actor.supportedOSBuilds.sorted() {
        builder.append(build)
      }
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
    guard evidence.capabilityClass == .singlePurposeAutonomousService,
      !evidence.acceptsArbitraryThirdPartyCommandsOrPaths
    else {
      throw SystemCompatibilityValidationError.ineligibleCapabilityClass(profile)
    }
    try validateOSBuilds(
      evidence.observedOSBuilds,
      field: "evidence OS builds",
      profile: profile
    )
    guard isISOCalendarDate(evidence.observedDate) else {
      throw SystemCompatibilityValidationError.invalidEvidenceDate(profile)
    }
    try validateIdentifier(evidence.evidenceReference, field: "evidence reference")
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

public enum BuiltInSystemCompatibilityCatalog {
  /// No system process is trusted before its exact Endpoint Security behavior
  /// has been observed on every supported host configuration.
  public static let catalog = SystemCompatibilityCatalog(profiles: [])
}

public struct ApprovedSystemCompatibilityProfile: Codable, Equatable, Hashable, Sendable {
  public var profileIdentifier: String
  public var approvedAuthorizationDigest: String
  public var isEnabled: Bool

  public init(
    profileIdentifier: String,
    approvedAuthorizationDigest: String,
    isEnabled: Bool
  ) {
    self.profileIdentifier = profileIdentifier
    self.approvedAuthorizationDigest = approvedAuthorizationDigest
    self.isEnabled = isEnabled
  }
}

public struct PolicySystemCompatibilityBinding: Codable, Equatable, Sendable {
  public var policyIdentifier: UUID
  public var approvedPolicyMode: PolicyMode
  public var approvedPolicyType: PolicyType
  public var approvedCanonicalProtectedRoot: String
  public var profiles: [ApprovedSystemCompatibilityProfile]

  public init(
    policyIdentifier: UUID,
    approvedPolicyMode: PolicyMode,
    approvedPolicyType: PolicyType,
    approvedCanonicalProtectedRoot: String,
    profiles: [ApprovedSystemCompatibilityProfile]
  ) {
    self.policyIdentifier = policyIdentifier
    self.approvedPolicyMode = approvedPolicyMode
    self.approvedPolicyType = approvedPolicyType
    self.approvedCanonicalProtectedRoot = approvedCanonicalProtectedRoot
    self.profiles = profiles
  }

  public init(policy: DirectoryPolicy, profiles: [ApprovedSystemCompatibilityProfile]) {
    self.init(
      policyIdentifier: policy.id,
      approvedPolicyMode: policy.mode,
      approvedPolicyType: policy.policyType,
      approvedCanonicalProtectedRoot: PolicySetDocument.canonicalPathComparisonKey(
        policy.protectedRootPath
      ),
      profiles: profiles
    )
  }

  public func matchesContext(of policy: DirectoryPolicy) -> Bool {
    policyIdentifier == policy.id
      && approvedPolicyMode == policy.mode
      && approvedPolicyType == policy.policyType
      && approvedCanonicalProtectedRoot
        == PolicySetDocument.canonicalPathComparisonKey(policy.protectedRootPath)
  }
}

public struct SystemCompatibilitySettingsDocument: Codable, Equatable, Sendable {
  public static let currentSchemaVersion = 1
  public static let maximumBindingCount = PolicySetDocument.maximumPolicyCount
  public static let maximumApprovalCount = 1_024

  public var schemaVersion: Int
  public var settingsIdentifier: UUID
  public var revision: UInt64
  public var policySetIdentifier: UUID
  public var bindings: [PolicySystemCompatibilityBinding]

  public init(
    schemaVersion: Int = Self.currentSchemaVersion,
    settingsIdentifier: UUID,
    revision: UInt64,
    policySetIdentifier: UUID,
    bindings: [PolicySystemCompatibilityBinding]
  ) {
    self.schemaVersion = schemaVersion
    self.settingsIdentifier = settingsIdentifier
    self.revision = revision
    self.policySetIdentifier = policySetIdentifier
    self.bindings = bindings
  }

  public func validateStructure() throws {
    guard schemaVersion == Self.currentSchemaVersion else {
      throw SystemCompatibilityValidationError.unsupportedSettingsSchemaVersion(schemaVersion)
    }
    guard revision > 0 else {
      throw SystemCompatibilityValidationError.invalidSettingsRevision
    }
    guard bindings.count <= Self.maximumBindingCount else {
      throw SystemCompatibilityValidationError.tooManyBindings(bindings.count)
    }
    let approvalCount = bindings.reduce(into: 0) { $0 += $1.profiles.count }
    guard approvalCount <= Self.maximumApprovalCount else {
      throw SystemCompatibilityValidationError.tooManyApprovals(approvalCount)
    }

    var policyIdentifiers = Set<UUID>()
    for binding in bindings {
      guard policyIdentifiers.insert(binding.policyIdentifier).inserted else {
        throw SystemCompatibilityValidationError.duplicatePolicyBinding(
          binding.policyIdentifier
        )
      }
      guard binding.approvedPolicyType == .whitelist else {
        throw SystemCompatibilityValidationError.blacklistBindingForbidden(
          binding.policyIdentifier
        )
      }
      guard !binding.approvedCanonicalProtectedRoot.isEmpty,
        binding.approvedCanonicalProtectedRoot.hasPrefix("/")
      else {
        throw SystemCompatibilityValidationError.invalidApprovedRoot(
          binding.policyIdentifier
        )
      }

      var profileIdentifiers = Set<String>()
      for approval in binding.profiles {
        guard !approval.profileIdentifier.isEmpty,
          approval.profileIdentifier.count <= 512
        else {
          throw SystemCompatibilityValidationError.invalidField("approved profile identifier")
        }
        guard
          SystemCompatibilityDigest.isCanonicalSHA256(
            approval.approvedAuthorizationDigest
          )
        else {
          throw SystemCompatibilityValidationError.invalidAuthorizationDigest(
            approval.profileIdentifier
          )
        }
        guard profileIdentifiers.insert(approval.profileIdentifier).inserted else {
          throw SystemCompatibilityValidationError.duplicateProfileApproval(
            policy: binding.policyIdentifier,
            profile: approval.profileIdentifier
          )
        }
      }
    }
  }

}

public enum SystemCompatibilityProfileState: String, Codable, Equatable, Sendable {
  case active
  case disabled
  case needsReview
  case missingProfile
  case unsupportedOS
  case policyContextChanged
  case policyMissing
}

public struct SystemCompatibilityProfileResolution: Codable, Equatable, Sendable {
  public var policyIdentifier: UUID
  public var profileIdentifier: String
  public var isEnabled: Bool
  public var state: SystemCompatibilityProfileState
  public var approvedAuthorizationDigest: String
  public var currentAuthorizationDigest: String?

  public init(
    policyIdentifier: UUID,
    profileIdentifier: String,
    isEnabled: Bool,
    state: SystemCompatibilityProfileState,
    approvedAuthorizationDigest: String,
    currentAuthorizationDigest: String? = nil
  ) {
    self.policyIdentifier = policyIdentifier
    self.profileIdentifier = profileIdentifier
    self.isEnabled = isEnabled
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
}

public enum SystemCompatibilityResolver {
  public static func resolve(
    settings: SystemCompatibilitySettingsDocument?,
    policySet: PolicySetDocument,
    catalog: SystemCompatibilityCatalog,
    operatingSystemVersion: OperatingSystemVersion = ProcessInfo.processInfo
      .operatingSystemVersion,
    operatingSystemBuild: String = SystemCompatibilityOSBuild.current()
  ) throws -> SystemCompatibilityResolution {
    try policySet.validate()
    try catalog.validate()
    guard let settings else { return SystemCompatibilityResolution() }
    try settings.validateStructure()
    guard settings.policySetIdentifier == policySet.setIdentifier else {
      return SystemCompatibilityResolution(
        profileResolutions: settings.bindings.flatMap { binding in
          binding.profiles.map { approval in
            resolution(
              binding,
              approval,
              state: .policyContextChanged
            )
          }
        }
      )
    }

    let policiesByID = Dictionary(uniqueKeysWithValues: policySet.policies.map { ($0.id, $0) })
    var activeProfilesByPolicy: [UUID: [ResolvedSystemCompatibilityProfile]] = [:]
    var profileResolutions: [SystemCompatibilityProfileResolution] = []

    for binding in settings.bindings {
      let policy = policiesByID[binding.policyIdentifier]
      for approval in binding.profiles {
        guard let policy else {
          profileResolutions.append(
            resolution(binding, approval, state: .policyMissing)
          )
          continue
        }
        guard binding.matchesContext(of: policy) else {
          profileResolutions.append(
            resolution(binding, approval, state: .policyContextChanged)
          )
          continue
        }
        guard let profile = catalog.profile(identifier: approval.profileIdentifier) else {
          profileResolutions.append(
            resolution(binding, approval, state: .missingProfile)
          )
          continue
        }
        let currentDigest = try catalog.authorizationDigest(for: profile)
        guard approval.approvedAuthorizationDigest == currentDigest else {
          profileResolutions.append(
            resolution(
              binding,
              approval,
              state: .needsReview,
              currentDigest: currentDigest
            )
          )
          continue
        }
        guard approval.isEnabled else {
          profileResolutions.append(
            resolution(
              binding,
              approval,
              state: .disabled,
              currentDigest: currentDigest
            )
          )
          continue
        }
        let supportedActors = profile.actors.filter {
          $0.supportedOSRange.contains(operatingSystemVersion)
            && $0.supportedOSBuilds.contains(operatingSystemBuild)
        }
        guard !supportedActors.isEmpty else {
          profileResolutions.append(
            resolution(
              binding,
              approval,
              state: .unsupportedOS,
              currentDigest: currentDigest
            )
          )
          continue
        }

        activeProfilesByPolicy[binding.policyIdentifier, default: []].append(
          ResolvedSystemCompatibilityProfile(
            profileIdentifier: profile.id,
            authorizationDigest: currentDigest,
            actors: supportedActors
          )
        )
        profileResolutions.append(
          resolution(
            binding,
            approval,
            state: .active,
            currentDigest: currentDigest
          )
        )
      }
    }

    return SystemCompatibilityResolution(
      activeProfilesByPolicy: activeProfilesByPolicy,
      profileResolutions: profileResolutions
    )
  }

  public static func validateForApply(
    _ settings: SystemCompatibilitySettingsDocument,
    against activeSettings: SystemCompatibilitySettingsDocument? = nil,
    policySet: PolicySetDocument,
    catalog: SystemCompatibilityCatalog,
    operatingSystemVersion: OperatingSystemVersion = ProcessInfo.processInfo
      .operatingSystemVersion,
    operatingSystemBuild: String = SystemCompatibilityOSBuild.current()
  ) throws {
    guard settings.policySetIdentifier == policySet.setIdentifier else {
      throw SystemCompatibilityValidationError.policySetIdentifierMismatch(
        candidate: settings.policySetIdentifier,
        active: policySet.setIdentifier
      )
    }
    let resolution = try resolve(
      settings: settings,
      policySet: policySet,
      catalog: catalog,
      operatingSystemVersion: operatingSystemVersion,
      operatingSystemBuild: operatingSystemBuild
    )
    let invalidEnabledApprovals = resolution.profileResolutions.filter {
      $0.state != .active
        && settings.isEnabled(
          policyIdentifier: $0.policyIdentifier,
          profileIdentifier: $0.profileIdentifier
        )
    }
    let newlyInvalidApprovals = invalidEnabledApprovals.filter {
      !isUnchangedEnabledApproval(
        $0,
        in: settings,
        comparedWith: activeSettings
      )
    }
    guard newlyInvalidApprovals.isEmpty else {
      throw SystemCompatibilityValidationError.enabledApprovalIsNotActive(
        newlyInvalidApprovals[0].profileIdentifier,
        newlyInvalidApprovals[0].state
      )
    }
  }

  private static func isUnchangedEnabledApproval(
    _ resolution: SystemCompatibilityProfileResolution,
    in candidate: SystemCompatibilitySettingsDocument,
    comparedWith active: SystemCompatibilitySettingsDocument?
  ) -> Bool {
    guard let active,
      candidate.settingsIdentifier == active.settingsIdentifier,
      candidate.policySetIdentifier == active.policySetIdentifier,
      let candidateBinding = candidate.bindings.first(where: {
        $0.policyIdentifier == resolution.policyIdentifier
      }),
      let activeBinding = active.bindings.first(where: {
        $0.policyIdentifier == resolution.policyIdentifier
      }),
      candidateBinding.approvedPolicyMode == activeBinding.approvedPolicyMode,
      candidateBinding.approvedPolicyType == activeBinding.approvedPolicyType,
      candidateBinding.approvedCanonicalProtectedRoot
        == activeBinding.approvedCanonicalProtectedRoot,
      let candidateApproval = candidateBinding.profiles.first(where: {
        $0.profileIdentifier == resolution.profileIdentifier
      }),
      let activeApproval = activeBinding.profiles.first(where: {
        $0.profileIdentifier == resolution.profileIdentifier
      })
    else {
      return false
    }
    return candidateApproval == activeApproval && activeApproval.isEnabled
  }

  private static func resolution(
    _ binding: PolicySystemCompatibilityBinding,
    _ approval: ApprovedSystemCompatibilityProfile,
    state: SystemCompatibilityProfileState,
    currentDigest: String? = nil
  ) -> SystemCompatibilityProfileResolution {
    SystemCompatibilityProfileResolution(
      policyIdentifier: binding.policyIdentifier,
      profileIdentifier: approval.profileIdentifier,
      isEnabled: approval.isEnabled,
      state: state,
      approvedAuthorizationDigest: approval.approvedAuthorizationDigest,
      currentAuthorizationDigest: currentDigest
    )
  }
}

public struct SystemCompatibilitySettingsReconciliation: Equatable, Sendable {
  public var document: SystemCompatibilitySettingsDocument
  public var removedPolicyBindingCount: Int
  public var removedProfileApprovalCount: Int

  public init(
    document: SystemCompatibilitySettingsDocument,
    removedPolicyBindingCount: Int,
    removedProfileApprovalCount: Int
  ) {
    self.document = document
    self.removedPolicyBindingCount = removedPolicyBindingCount
    self.removedProfileApprovalCount = removedProfileApprovalCount
  }

  public var removedItemCount: Int {
    removedPolicyBindingCount + removedProfileApprovalCount
  }
}

public enum SystemCompatibilitySettingsReconciler {
  public static func reconcile(
    _ settings: SystemCompatibilitySettingsDocument,
    policySet: PolicySetDocument,
    catalog: SystemCompatibilityCatalog
  ) throws -> SystemCompatibilitySettingsReconciliation {
    try settings.validateStructure()
    try policySet.validate()
    try catalog.validate()
    guard settings.policySetIdentifier == policySet.setIdentifier else {
      throw SystemCompatibilityValidationError.policySetIdentifierMismatch(
        candidate: settings.policySetIdentifier,
        active: policySet.setIdentifier
      )
    }

    let policiesByID = Dictionary(uniqueKeysWithValues: policySet.policies.map { ($0.id, $0) })
    let availableProfileIDs = Set(catalog.profiles.map(\.id))
    var removedBindings = 0
    var removedApprovals = 0
    var reconciledBindings: [PolicySystemCompatibilityBinding] = []

    for var binding in settings.bindings {
      guard let policy = policiesByID[binding.policyIdentifier],
        policy.policyType == .whitelist
      else {
        removedBindings += 1
        continue
      }
      let originalApprovalCount = binding.profiles.count
      binding.profiles.removeAll {
        !availableProfileIDs.contains($0.profileIdentifier)
      }
      removedApprovals += originalApprovalCount - binding.profiles.count
      if binding.profiles.isEmpty {
        removedBindings += 1
      } else {
        reconciledBindings.append(binding)
      }
    }

    var document = settings
    document.bindings = reconciledBindings
    try document.validateStructure()
    return SystemCompatibilitySettingsReconciliation(
      document: document,
      removedPolicyBindingCount: removedBindings,
      removedProfileApprovalCount: removedApprovals
    )
  }
}

extension SystemCompatibilitySettingsDocument {
  fileprivate func isEnabled(policyIdentifier: UUID, profileIdentifier: String) -> Bool {
    bindings.first { $0.policyIdentifier == policyIdentifier }?
      .profiles.first { $0.profileIdentifier == profileIdentifier }?.isEnabled == true
  }
}

public enum SystemCompatibilitySettingsCodec {
  public static let maximumDocumentSize = 262_144

  private static let topLevelKeys: Set<String> = [
    "schemaVersion", "settingsIdentifier", "revision", "policySetIdentifier", "bindings",
  ]
  private static let bindingKeys: Set<String> = [
    "policyIdentifier", "approvedPolicyMode", "approvedPolicyType",
    "approvedCanonicalProtectedRoot", "profiles",
  ]
  private static let approvalKeys: Set<String> = [
    "profileIdentifier", "approvedAuthorizationDigest", "isEnabled",
  ]

  public static func decode(_ data: Data) throws -> SystemCompatibilitySettingsDocument {
    guard data.count <= maximumDocumentSize else {
      throw SystemCompatibilitySettingsCodecError.documentTooLarge(data.count)
    }
    try validateKeys(in: data)
    let document = try JSONDecoder().decode(SystemCompatibilitySettingsDocument.self, from: data)
    try document.validateStructure()
    return document
  }

  public static func encode(
    _ document: SystemCompatibilitySettingsDocument,
    prettyPrinted: Bool = true
  ) throws -> Data {
    try document.validateStructure()
    let encoder = JSONEncoder()
    encoder.outputFormatting = prettyPrinted ? [.prettyPrinted, .sortedKeys] : [.sortedKeys]
    let data = try encoder.encode(document)
    guard data.count <= maximumDocumentSize else {
      throw SystemCompatibilitySettingsCodecError.documentTooLarge(data.count)
    }
    return data
  }

  public static func digest(of document: SystemCompatibilitySettingsDocument) throws -> String {
    let data = try encode(document, prettyPrinted: false)
    return SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
  }

  private static func validateKeys(in data: Data) throws {
    let json = try JSONSerialization.jsonObject(with: data)
    guard let object = json as? [String: Any] else {
      throw SystemCompatibilitySettingsCodecError.topLevelObjectRequired
    }
    let unknownTopLevelKeys = Set(object.keys).subtracting(topLevelKeys).sorted()
    guard unknownTopLevelKeys.isEmpty else {
      throw SystemCompatibilitySettingsCodecError.unknownTopLevelKeys(unknownTopLevelKeys)
    }
    guard let bindings = object["bindings"] as? [Any] else {
      throw SystemCompatibilitySettingsCodecError.bindingsArrayRequired
    }
    for (bindingIndex, value) in bindings.enumerated() {
      guard let binding = value as? [String: Any] else {
        throw SystemCompatibilitySettingsCodecError.bindingObjectRequired(bindingIndex)
      }
      let unknownBindingKeys = Set(binding.keys).subtracting(bindingKeys).sorted()
      guard unknownBindingKeys.isEmpty else {
        throw SystemCompatibilitySettingsCodecError.unknownBindingKeys(
          index: bindingIndex,
          keys: unknownBindingKeys
        )
      }
      guard let profiles = binding["profiles"] as? [Any] else {
        throw SystemCompatibilitySettingsCodecError.profilesArrayRequired(bindingIndex)
      }
      for (profileIndex, value) in profiles.enumerated() {
        guard let approval = value as? [String: Any] else {
          throw SystemCompatibilitySettingsCodecError.approvalObjectRequired(
            binding: bindingIndex,
            approval: profileIndex
          )
        }
        let unknownApprovalKeys = Set(approval.keys).subtracting(approvalKeys).sorted()
        guard unknownApprovalKeys.isEmpty else {
          throw SystemCompatibilitySettingsCodecError.unknownApprovalKeys(
            binding: bindingIndex,
            approval: profileIndex,
            keys: unknownApprovalKeys
          )
        }
      }
    }
  }
}

public enum SystemCompatibilitySettingsUpdateDisposition: Equatable, Sendable {
  case accepted
  case unchanged
}

public enum SystemCompatibilitySettingsApplyResult: String, Codable, Sendable {
  case accepted
  case unchanged
}

public struct SystemCompatibilitySettingsApplyRequest: Codable, Equatable, Sendable {
  public static let maximumEncodedSize = 524_288

  public var catalogDigest: String
  public var settingsData: Data

  public init(catalogDigest: String, settingsData: Data) {
    self.catalogDigest = catalogDigest
    self.settingsData = settingsData
  }
}

public struct SystemCompatibilitySettingsApplyReceipt: Codable, Equatable, Sendable {
  public var result: SystemCompatibilitySettingsApplyResult
  public var acceptedSettingsIdentifier: UUID
  public var acceptedRevision: UInt64
  public var acceptedDigest: String
  public var acceptedAt: Date

  public init(
    result: SystemCompatibilitySettingsApplyResult,
    acceptedSettingsIdentifier: UUID,
    acceptedRevision: UInt64,
    acceptedDigest: String,
    acceptedAt: Date = Date()
  ) {
    self.result = result
    self.acceptedSettingsIdentifier = acceptedSettingsIdentifier
    self.acceptedRevision = acceptedRevision
    self.acceptedDigest = acceptedDigest
    self.acceptedAt = acceptedAt
  }
}

public struct SystemCompatibilityStateSnapshot: Codable, Equatable, Sendable {
  public var catalogDigest: String
  public var settings: SystemCompatibilitySettingsDocument?
  public var settingsDigest: String?
  public var profileResolutions: [SystemCompatibilityProfileResolution]

  public init(
    catalogDigest: String,
    settings: SystemCompatibilitySettingsDocument? = nil,
    settingsDigest: String? = nil,
    profileResolutions: [SystemCompatibilityProfileResolution] = []
  ) {
    self.catalogDigest = catalogDigest
    self.settings = settings
    self.settingsDigest = settingsDigest
    self.profileResolutions = profileResolutions
  }

  public var activeProfileCount: Int {
    profileResolutions.lazy.filter { $0.state == .active }.count
  }
}

public struct SystemCompatibilityWarningState: Equatable, Sendable {
  public static let storageRejectionMessage =
    "Stored system-compatibility settings could not be read, validated, or trusted. No compatibility profiles were activated."

  public private(set) var storageWarning: String?
  public private(set) var resolutionWarning: String?

  public init(
    storageWarning: String? = nil,
    resolutionWarning: String? = nil
  ) {
    self.storageWarning = storageWarning
    self.resolutionWarning = resolutionWarning
  }

  public mutating func recordStorageRejection() {
    storageWarning = Self.storageRejectionMessage
  }

  @available(*, deprecated, message: "Use recordStorageRejection() for the fixed user warning.")
  public mutating func recordStorageRejection(_ warning: String) {
    storageWarning = warning
  }

  public mutating func clearStorageWarning() {
    storageWarning = nil
  }

  public mutating func replaceResolutionWarning(_ warning: String?) {
    resolutionWarning = warning
  }

  public var combinedWarning: String? {
    let warnings = [storageWarning, resolutionWarning].compactMap { $0 }
    return warnings.isEmpty ? nil : warnings.joined(separator: " ")
  }
}

public enum SystemCompatibilitySettingsUpdateValidator {
  public static func validate(
    candidate: SystemCompatibilitySettingsDocument,
    against active: SystemCompatibilitySettingsDocument?
  ) throws -> SystemCompatibilitySettingsUpdateDisposition {
    try candidate.validateStructure()
    guard let active else { return .accepted }
    guard candidate.settingsIdentifier == active.settingsIdentifier else {
      throw SystemCompatibilityValidationError.settingsIdentifierMismatch(
        candidate: candidate.settingsIdentifier,
        active: active.settingsIdentifier
      )
    }
    guard candidate.policySetIdentifier == active.policySetIdentifier else {
      throw SystemCompatibilityValidationError.policySetIdentifierMismatch(
        candidate: candidate.policySetIdentifier,
        active: active.policySetIdentifier
      )
    }
    if candidate.revision < active.revision {
      throw SystemCompatibilityValidationError.settingsRevisionDowngrade(
        candidate: candidate.revision,
        active: active.revision
      )
    }
    if candidate.revision == active.revision {
      guard candidate == active else {
        throw SystemCompatibilityValidationError.settingsRevisionCollision(candidate.revision)
      }
      return .unchanged
    }
    return .accepted
  }
}

public enum SystemCompatibilityValidationError: Error, Equatable, CustomStringConvertible,
  Sendable
{
  case unsupportedCatalogSchemaVersion(Int)
  case unsupportedSettingsSchemaVersion(Int)
  case tooManyProfiles(Int)
  case tooManyActors(Int)
  case tooManyBindings(Int)
  case tooManyApprovals(Int)
  case invalidField(String)
  case duplicateProfileIdentifier(String)
  case profileRequiresActor(String)
  case duplicateActorIdentity(profile: String, signingIdentifier: String)
  case emptyAllowedOpenFlags(profile: String, signingIdentifier: String)
  case conflictingCodeSigningFlags(profile: String, signingIdentifier: String)
  case invalidOSRange(String)
  case openEndedOSRange(String)
  case invalidOSBuildEvidence(String)
  case unsupportedBuildLacksEvidence(String)
  case ineligibleCapabilityClass(String)
  case forbiddenCapabilityConduit(profile: String, signingIdentifier: String)
  case invalidEvidenceDate(String)
  case localEvidenceReferenceForbidden(String)
  case profileNotInCatalog(String)
  case invalidSettingsRevision
  case duplicatePolicyBinding(UUID)
  case blacklistBindingForbidden(UUID)
  case invalidApprovedRoot(UUID)
  case invalidAuthorizationDigest(String)
  case duplicateProfileApproval(policy: UUID, profile: String)
  case policySetIdentifierMismatch(candidate: UUID, active: UUID)
  case settingsIdentifierMismatch(candidate: UUID, active: UUID)
  case settingsRevisionDowngrade(candidate: UInt64, active: UInt64)
  case settingsRevisionCollision(UInt64)
  case enabledApprovalIsNotActive(String, SystemCompatibilityProfileState)

  public var description: String {
    switch self {
    case .unsupportedCatalogSchemaVersion(let version):
      "Unsupported system-compatibility catalog schema version: \(version)."
    case .unsupportedSettingsSchemaVersion(let version):
      "Unsupported system-compatibility settings schema version: \(version)."
    case .tooManyProfiles(let count):
      "System-compatibility catalog contains too many profiles: \(count)."
    case .tooManyActors(let count):
      "System-compatibility catalog contains too many actors: \(count)."
    case .tooManyBindings(let count):
      "System-compatibility settings contain too many policy bindings: \(count)."
    case .tooManyApprovals(let count):
      "System-compatibility settings contain too many profile approvals: \(count)."
    case .invalidField(let field):
      "The \(field) is empty, too long, padded, or contains an unsupported character."
    case .duplicateProfileIdentifier(let identifier):
      "Duplicate system-compatibility profile identifier: \(identifier)."
    case .profileRequiresActor(let identifier):
      "System-compatibility profile \(identifier) requires at least one actor."
    case .duplicateActorIdentity(let profile, let signingIdentifier):
      "System-compatibility profile \(profile) repeats actor \(signingIdentifier)."
    case .emptyAllowedOpenFlags(let profile, let signingIdentifier):
      "System-compatibility profile \(profile) actor \(signingIdentifier) has no allowed open flags."
    case .conflictingCodeSigningFlags(let profile, let signingIdentifier):
      "System-compatibility profile \(profile) actor \(signingIdentifier) requires and forbids the same code-signing flag."
    case .invalidOSRange(let profile):
      "System-compatibility profile \(profile) has an invalid supported OS range."
    case .openEndedOSRange(let profile):
      "System-compatibility profile \(profile) must have a closed tested OS range."
    case .invalidOSBuildEvidence(let profile):
      "System-compatibility profile \(profile) has missing, duplicate, or invalid OS build evidence."
    case .unsupportedBuildLacksEvidence(let profile):
      "System-compatibility profile \(profile) enables an OS build without matching evidence."
    case .ineligibleCapabilityClass(let profile):
      "System-compatibility profile \(profile) is not a single-purpose autonomous service or accepts arbitrary third-party commands or paths."
    case .forbiddenCapabilityConduit(let profile, let signingIdentifier):
      "System-compatibility profile \(profile) cannot catalog capability conduit \(signingIdentifier)."
    case .invalidEvidenceDate(let profile):
      "System-compatibility profile \(profile) has an invalid evidence date."
    case .localEvidenceReferenceForbidden(let profile):
      "System-compatibility profile \(profile) evidence must not contain a local absolute path."
    case .profileNotInCatalog(let identifier):
      "System-compatibility profile is not in the built-in catalog: \(identifier)."
    case .invalidSettingsRevision:
      "System-compatibility settings revision must be greater than zero."
    case .duplicatePolicyBinding(let identifier):
      "Duplicate system-compatibility binding for policy \(identifier.uuidString)."
    case .blacklistBindingForbidden(let identifier):
      "System-compatibility profiles cannot be bound to Blacklist policy \(identifier.uuidString)."
    case .invalidApprovedRoot(let identifier):
      "System-compatibility binding for policy \(identifier.uuidString) has an invalid approved root."
    case .invalidAuthorizationDigest(let identifier):
      "System-compatibility approval for \(identifier) has an invalid authorization digest."
    case .duplicateProfileApproval(let policy, let profile):
      "Policy \(policy.uuidString) repeats system-compatibility approval \(profile)."
    case .policySetIdentifierMismatch(let candidate, let active):
      "System-compatibility settings target policy set \(candidate.uuidString), not active set \(active.uuidString)."
    case .settingsIdentifierMismatch(let candidate, let active):
      "System-compatibility settings identifier \(candidate.uuidString) does not match active settings \(active.uuidString)."
    case .settingsRevisionDowngrade(let candidate, let active):
      "System-compatibility settings revision \(candidate) is older than active revision \(active)."
    case .settingsRevisionCollision(let revision):
      "System-compatibility settings revision \(revision) has different contents from the active settings."
    case .enabledApprovalIsNotActive(let profile, let state):
      "Enabled system-compatibility profile \(profile) cannot become active: \(state.rawValue)."
    }
  }
}

public enum SystemCompatibilitySettingsCodecError: Error, Equatable,
  CustomStringConvertible, Sendable
{
  case documentTooLarge(Int)
  case topLevelObjectRequired
  case bindingsArrayRequired
  case bindingObjectRequired(Int)
  case profilesArrayRequired(Int)
  case approvalObjectRequired(binding: Int, approval: Int)
  case unknownTopLevelKeys([String])
  case unknownBindingKeys(index: Int, keys: [String])
  case unknownApprovalKeys(binding: Int, approval: Int, keys: [String])

  public var description: String {
    switch self {
    case .documentTooLarge(let size):
      "System-compatibility settings exceed the size limit: \(size) bytes."
    case .topLevelObjectRequired:
      "System-compatibility settings must contain one top-level object."
    case .bindingsArrayRequired:
      "System-compatibility settings must contain a bindings array."
    case .bindingObjectRequired(let index):
      "System-compatibility binding \(index) must be an object."
    case .profilesArrayRequired(let index):
      "System-compatibility binding \(index) must contain a profiles array."
    case .approvalObjectRequired(let binding, let approval):
      "System-compatibility approval \(approval) in binding \(binding) must be an object."
    case .unknownTopLevelKeys(let keys):
      "Unknown top-level system-compatibility settings keys: \(keys.joined(separator: ", "))."
    case .unknownBindingKeys(let index, let keys):
      "Unknown keys in system-compatibility binding \(index): \(keys.joined(separator: ", "))."
    case .unknownApprovalKeys(let binding, let approval, let keys):
      "Unknown keys in system-compatibility approval \(approval) of binding \(binding): \(keys.joined(separator: ", "))."
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
