# Pasu FS

[![CI](https://github.com/hiverdoux/Pasu-FS/actions/workflows/ci.yml/badge.svg)](https://github.com/hiverdoux/Pasu-FS/actions/workflows/ci.yml)

> **Development status:** The schema v2 multi-policy GUI, policy engine,
> storage, IPC, and audit contracts are source-built and unit-tested. A signed,
> provisioned end-to-end product deployment has not been validated by the
> public repository checks. Pasu FS is not a distributed product.

Pasu FS is a local-only file access-control prototype for macOS. It is
intended to let the Mac owner select ordinary directories and prevent other
applications running as the same user from accessing those directories unless
the applications are explicitly allowed.

The project uses Apple's Endpoint Security framework. Its enforcement component
runs as an Endpoint Security system extension and makes immediate
allow or deny decisions for supported file authorization events.

This repository documents the intended design and contains a standalone policy
core, a bounded Endpoint Security integration harness, a SwiftUI menu-bar app,
and a product-shaped Endpoint Security system extension. The current extension
enforces only supported `AUTH_OPEN` requests. Other authorization event types
remain explicitly uncovered.

## Project identifiers

| Component | Bundle identifier | Responsibility |
| --- | --- | --- |
| Pasu FS app | `com.dennis.pasu.fs` | Configuration UI, policy management, extension lifecycle, and audit-log presentation |
| Endpoint Security extension | `com.dennis.pasu.fs.endpointsecurity` | File-event authorization, process-lineage tracking, and asynchronous audit-event production |

## The problem

Traditional POSIX file permissions distinguish users and groups. They do not
distinguish two nonsandboxed applications running under the same macOS user ID.
As a result, restricting a directory to mode `0700` protects it from other user
accounts but does not prevent another application running as its owner from
opening the files.

macOS privacy controls protect Apple-defined resources, but they do not provide
a public interface through which a third-party utility can add an arbitrary
directory to a new privacy class. File System Events reports changes after the
fact and cannot authorize an in-flight file operation.

Endpoint Security provides the authorization events required for Pasu FS to
make an additional, process-aware decision before supported operations proceed.

## Goals

Pasu FS is designed to:

- protect user-selected directories that are not already protected by an
  appropriate macOS privacy class;
- deny supported new file operations from unapproved same-user processes while
  the Pasu FS enforcement engine is healthy and active;
- identify processes using kernel-provided audit tokens and code-signing facts,
  rather than relying only on a PID, process name, or path;
- optionally carry a Whitelist allow or Blacklist deny effect to a matched
  process's observed operating-system descendants;
- keep policy, file-event metadata, and audit records on the local Mac;
- make authorization decisions from an in-memory policy without network or
  database access on the authorization path; and
- clearly report the difference between planned, implemented, and validated
  protections.

## Intended policy behavior

A policy set contains multiple named policies. Each policy has exactly one
directory, Protection or Audit mode, Whitelist or Blacklist type, and signed
program rules that can be enabled or disabled independently.

Conceptually:

```text
Policy 1
  mode: Protection
  type: Whitelist
  directory: /Users/example/.private-work

allowed process:
  signing identity: approved by the user
  enabled: yes
  observed descendants: yes

request from allowed process               -> allow
request from observed descendant            -> allow
request from unrelated same-user process    -> deny
request outside protected directories       -> allow
```

A Blacklist reverses the match meaning: a direct or inherited match is denied
and a non-match is allowed. An Audit policy records `wouldAllow`/`wouldDeny` but
never changes the kernel response. If several Protection policies match an
overlapping path, every one of them must allow the request.

The v0.2 enforcement scope is deliberately limited to new opens represented by
`AUTH_OPEN`. Create, rename, unlink, link, clone, truncate, mapping, copy, and
other operations are not claimed as protected until their corresponding event
paths are implemented and validated.

## Current prototype

The repository root is a standalone Swift package containing the first
executable evidence for this design:

- [`PasuFSPolicy`](Sources/PasuFSPolicy/) is a synchronous, in-memory evaluator
  for multiple exact team-signed or platform-binary identity rules and optional
  per-rule descendant inheritance;
- [`PasuFSEndpointCore`](Sources/PasuFSEndpointCore/) adapts Endpoint Security
  process, lifecycle, and `AUTH_OPEN` data to all matching policies and combines
  Protection results with deny-wins semantics;
- [`PasuFSPolicyTests`](Tests/PasuFSPolicyTests/) covers direct allow/deny,
  child and grandchild inheritance, exec preservation, unrelated-process
  denial, exit, and policy revocation;
- [`es-integration-harness`](Sources/ESIntegrationHarness/) connects the core to
  real `AUTH_OPEN`, `NOTIFY_EXEC`, `NOTIFY_FORK`, and `NOTIFY_EXIT` events
  for a dedicated non-system test directory;
- [`PasuFSConfiguration`](Sources/PasuFSConfiguration/) defines the strict schema
  v2 policy set, runtime-status, per-policy audit, and root-owned persistence
  contracts;
- [`PasuFSIPC`](Sources/PasuFSIPC/) defines the XPC interface and derives exact
  code-signing requirements for both peers;
- [`PasuFSHostCore`](Sources/PasuFSHostCore/) provides lifecycle requests,
  authenticated status and policy clients, and the health reducer;
- [`pasu-fs-app`](Sources/PasuFSApp/) is the SwiftUI menu-bar app for activation,
  dynamic multi-policy editing, policy-aware audit presentation, and rule creation
  from observed signed identities; and
- [`pasu-fs-system-extension`](Sources/PasuFSSystemExtension/) owns accepted
  policy-set storage, subscribes to lifecycle plus `AUTH_OPEN` events, and performs
  fail-closed in-scope decisions.

Schema v2 intentionally starts configuration over: on first launch the new
extension permanently deletes a recognized schema v1 `policy.json`, does not
migrate or back it up, and stores new configuration in `policy-set.json`. Existing
rotated audit JSONL remains readable as legacy records.

Run the source checks from the repository root:

```sh
swift format lint --recursive --strict Package.swift Sources Tests
plutil -lint Product/*.plist Product/*.entitlements
swift build
swift test
swift run es-integration-harness --help
```

Running the integration harness beyond `--help` requires an Apple-approved
Endpoint Security entitlement, matching provisioning, root execution, and Full
Disk Access. It is deliberately bounded to a selected non-system test
directory, supports only `AUTH_OPEN`, and fails open for truncated paths or
process-decode errors. The product extension has a different in-scope failure
policy, described in the architecture and threat model.

## Descendant inheritance

When descendant inheritance is enabled, Pasu FS treats a direct rule match as a
**rule root**. It tracks `fork`, `exec`, and `exit` lifecycle events and propagates
that match through the observed process tree.

This is a deliberate policy decision: any program actually launched as a
descendant inherits the rule effect, including after it executes a different
program image. Whitelist descendants are allowed; Blacklist descendants are
blocked.

Pasu FS will not infer ancestry from a process name or PID alone. A service
launched independently by `launchd` or another broker is not automatically a
descendant and requires its own rule unless its lineage can be established by
the enforcement engine.

See [Architecture](docs/architecture.md) for the planned tracking model and
[Threat Model](docs/threat-model.md) for the associated trust assumptions.

## Planned architecture

Pasu FS uses two signed macOS components:

```text
Pasu FS.app
  - manages named directory policies and signed program rules
  - installs and manages the system extension
  - displays health and local audit information
                 |
                 | authenticated local IPC
                 v
Endpoint Security system extension
  - loads a validated policy-set snapshot into memory
  - tracks matched rule roots and descendants per policy
  - authorizes supported file operations
  - emits audit metadata asynchronously
```

The extension will not wait for interactive UI input while an authorization
event is pending. User choices will be converted into policy before enforcement
decisions are required.

## Privacy

The implemented data path is local-only:

- no cloud service is required for policy evaluation;
- no telemetry or analytics service is planned;
- file contents will not be collected for policy decisions;
- audit records will be limited to the metadata required to explain an allow or
  deny result; and
- the current audit file is capped and rotated once; broader retention and
  deletion controls remain required before release.

No release-level privacy guarantee exists yet. Signed end-to-end validation and
independent review remain incomplete.

## Required macOS permissions

The system extension requires Apple's restricted Endpoint Security entitlement.
Installation and operation also require the macOS approvals
applicable to Endpoint Security system extensions, including system-extension
activation and Full Disk Access.

Pasu FS will not disable or bypass System Integrity Protection, TCC, App
Sandbox, code-signing enforcement, or other macOS security mechanisms.

The source targets macOS 14 or later. Source build and unit-test success does
not establish entitlement approval, system-extension activation, Full Disk
Access, or signed end-to-end enforcement.

## Apple platform references

- [Endpoint Security framework](https://developer.apple.com/documentation/endpointsecurity)
- [Apple's Endpoint Security sample](https://developer.apple.com/documentation/endpointsecurity/monitoring-system-events-with-endpoint-security)
- [System Extensions and DriverKit](https://developer.apple.com/system-extensions/)

## Non-goals

Pasu FS does not claim to:

- create a new TCC privacy class;
- defend against the Mac owner, an administrator intentionally disabling the
  product, kernel compromise, Recovery access, or offline disk access;
- retroactively revoke file descriptors or memory mappings opened before
  enforcement began;
- prevent an explicitly allowed process or its allowed descendants from
  disclosing data they are permitted to read;
- observe every individual `read(2)` or `write(2)` call;
- provide a mathematically complete audit trail; or
- provide any protection while its enforcement component is inactive.

These boundaries are intentional and are described in more detail in the
[Threat Model](docs/threat-model.md).

## Project ownership and development process

Pasu FS is a personal project developed and maintained by YEONTAEK LEE. It
does not accept external contributions or pull requests.

The private process for reporting security-relevant problems is listed in
[SECURITY.md](SECURITY.md).

Security-sensitive changes will require owner review, documented
threat-model analysis, automated tests, and validation on supported macOS
versions before release.

## Roadmap

The current plan is:

- [x] document the intended scope, architecture, and threat model;
- [x] add a standalone policy core, tests, and bounded integration harness;
- [ ] obtain the Endpoint Security development capability;
- [ ] validate the intended event model against Apple's sample and supported
  APIs;
- [x] implement a product-shaped menu-bar app and authenticated local control path;
- [x] implement `AUTH_OPEN` audit and enforcement in the system-extension source;
- [x] implement schema v2 multi-policy configuration, Whitelist/Blacklist
  composition, policy-aware audit records, and the dynamic GUI in source;
- [ ] complete signed schema v2 multi-policy end-to-end validation;
- [ ] measure event coverage, process lineage, and deadline behavior under load;
- [ ] implement and validate additional documented authorization event types;
- [ ] complete privacy, security-reporting, update, and removal procedures; and
- [ ] request Developer ID distribution access only after the product is ready
  for independent security validation.

No milestone in this list should be read as completed unless the repository
explicitly marks it as implemented and tested.

## Repository use and licensing

This public repository documents a personal design-stage project; it is not an
invitation to contribute. External contributions and pull requests are not
accepted.

No open-source license is granted at this stage. A distribution license will
be published before any Pasu FS binary is released. Security reports are
accepted through the private process in [SECURITY.md](SECURITY.md).
