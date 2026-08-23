# Pasu FS

[![CI](https://github.com/hiverdoux/Pasu-FS/actions/workflows/ci.yml/badge.svg)](https://github.com/hiverdoux/Pasu-FS/actions/workflows/ci.yml)

> **Development status:** Early prototype and architecture validation.
> Pasu FS is not yet a functional or distributed product.

Pasu FS is a planned, local-only file access-control utility for macOS. It is
intended to let the Mac owner select ordinary directories and prevent other
applications running as the same user from accessing those directories unless
the applications are explicitly allowed.

The project plans to use Apple's Endpoint Security framework. Its enforcement
component will run as an Endpoint Security system extension and make immediate
allow or deny decisions for supported file authorization events.

This repository documents the intended design and contains a tested policy
core, an Endpoint Security integration harness, and a minimal host app and
system-extension activation scaffold. It is not yet the Pasu FS product UI or a
production-ready extension.

## Project identifiers

| Component | Bundle identifier | Responsibility |
| --- | --- | --- |
| Pasu FS app | `com.dennis.pasu.fs` | Configuration UI, policy management, extension lifecycle, and audit-log presentation |
| Endpoint Security extension | `com.dennis.pasu.fs.endpointsecurity` | File-event authorization, process-lineage tracking, and asynchronous audit-event production |

The public rationale for the restricted capability request is documented in
[Endpoint Security Entitlement Request Context](docs/entitlement-request.md).

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
- optionally allow a user-approved process's actual operating-system
  descendants;
- keep policy, file-event metadata, and audit records on the local Mac;
- make authorization decisions from an in-memory policy without network or
  database access on the authorization path; and
- clearly report the difference between planned, implemented, and validated
  protections.

## Intended policy behavior

A policy will associate a protected directory with one or more allowed process
identities. An allow rule may optionally enable descendant inheritance.

Conceptually:

```text
protected directory: /Users/example/.private-work

allowed process:
  signing identity: approved by the user
  allow descendants: yes

request from allowed process               -> allow
request from observed descendant            -> allow
request from unrelated same-user process    -> deny
request outside protected directories       -> allow
```

The initial enforcement scope is expected to include new opens and relevant
file-namespace or mutation operations for which Endpoint Security provides an
authorization event. Exact event coverage will be documented only after it has
been implemented and tested on every supported macOS version.

## Current prototype

The repository root is a standalone Swift package containing executable
evidence for this design:

- [`PasuFSPolicy`](Sources/PasuFSPolicy/) is a synchronous, in-memory evaluator
  for exact signing-identity rules and optional descendant inheritance;
- [`PasuFSEndpointCore`](Sources/PasuFSEndpointCore/) adapts Endpoint Security
  process, lifecycle, and `AUTH_OPEN` data to the policy evaluator;
- the policy and endpoint-core tests cover direct allow/deny, safe path scope,
  child and grandchild inheritance, credential changes, exec PID-version
  changes, unrelated-process denial, exit, and policy revocation;
- [`es-integration-harness`](Sources/ESIntegrationHarness/) connects the core to
  real `AUTH_OPEN`, `NOTIFY_EXEC`, `NOTIFY_FORK`, and `NOTIFY_EXIT` events for a
  dedicated non-system test directory; and
- [`pasu-fs-host`](Sources/PasuFSHost/) and
  [`pasu-fs-system-extension`](Sources/PasuFSSystemExtension/) form a minimal
  activation scaffold. The extension creates an Endpoint Security client but
  does not yet load policy or subscribe to file events.

Run the baseline checks from the repository root:

```sh
swift format lint --recursive --strict Package.swift Sources Tests
swift build
swift test
swift run es-integration-harness --help
```

Running the integration harness requires an Apple-approved Endpoint Security
entitlement, matching provisioning, root execution, and Full Disk Access. It
supports only `AUTH_OPEN` enforcement and fails open for truncated paths or
process-decode errors so that an integration test cannot accidentally become a
system-wide policy engine. These limits do not define the intended production
failure policy.

## Descendant inheritance

When descendant inheritance is enabled for an allow rule, Pasu FS will treat
the approved process as an **allow root**. It will track `fork`, `exec`, and
`exit` lifecycle events and propagate the allow state through the observed
process tree.

This is a deliberate trust decision: any program actually launched as a
descendant of that allow root inherits the directory access granted by the
rule, including after the descendant executes a different program image.

Pasu FS will not infer ancestry from a process name or PID alone. A service
launched independently by `launchd` or another broker is not automatically a
descendant and requires its own rule unless its lineage can be established by
the enforcement engine.

See [Architecture](docs/architecture.md) for the planned tracking model and
[Threat Model](docs/threat-model.md) for the associated trust assumptions.

## Planned architecture

Pasu FS is planned as two signed macOS components:

```text
Pasu FS.app
  - lets the user select protected directories and allowed processes
  - installs and manages the system extension
  - displays health and local audit information
                 |
                 | authenticated local IPC
                 v
Endpoint Security system extension
  - loads a validated policy snapshot into memory
  - tracks allowed process roots and descendants
  - authorizes supported file operations
  - emits audit metadata asynchronously
```

The extension will not wait for interactive UI input while an authorization
event is pending. User choices will be converted into policy before enforcement
decisions are required.

## Privacy

The planned product is local-only:

- no cloud service is required for policy evaluation;
- no telemetry or analytics service is planned;
- file contents will not be collected for policy decisions;
- audit records will be limited to the metadata required to explain an allow or
  deny result; and
- retention and deletion controls will be documented before the first release.

No functional privacy guarantee exists yet because the product has not been
implemented or validated.

## Required macOS permissions

The planned system extension requires Apple's restricted Endpoint Security
entitlement. Installation and operation will also require the macOS approvals
applicable to Endpoint Security system extensions, including system-extension
activation and Full Disk Access.

Pasu FS will not disable or bypass System Integrity Protection, TCC, App
Sandbox, code-signing enforcement, or other macOS security mechanisms.

The exact minimum supported macOS version has not yet been selected. It will be
fixed before implementation based on API availability and validation coverage.

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
- [x] add the policy core, integration harness, tests, and activation scaffold;
- [ ] obtain the Endpoint Security development capability;
- [ ] validate the intended event model against Apple's sample and supported
  APIs;
- [ ] build an audit-only Endpoint Security system-extension prototype;
- [ ] measure event coverage, process lineage, and deadline behavior;
- [ ] implement enforcement for the documented event set;
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
