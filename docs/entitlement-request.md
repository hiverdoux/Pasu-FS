# Endpoint Security Entitlement Request Context

## Requested capability

Pasu FS requests the restricted
`com.apple.developer.endpoint-security.client` entitlement for the Endpoint
Security system extension with bundle identifier
`com.dennis.pasu.fs.endpointsecurity`.

The containing application uses bundle identifier `com.dennis.pasu.fs` and the
System Extensions framework to activate, update, and deactivate the extension.
This repository supports a development entitlement request. Any future
Developer ID distribution request will be made separately after the product is
ready for external security review.

## Product purpose

Pasu FS is a local macOS security utility that lets the Mac owner define named
policies for ordinary directories and explicitly choose which signed
applications are allowed or denied for supported file operations.

The current security objective is to prevent an unapproved application running
under the same logged-in user identity from opening files in a selected
directory while the enforcement component is active and healthy.

## Why Endpoint Security is required

POSIX permissions distinguish users and groups, but do not distinguish two
nonsandboxed applications running as the same user. macOS privacy controls do
not provide a public API for creating a new privacy class for an arbitrary
user-selected directory, and post-event filesystem notifications cannot stop
an operation that is already in progress.

Endpoint Security provides the supported authorization boundary needed to make
an additional process-aware allow or deny decision before covered operations
complete.

## Intended event use

The current product extension and bounded integration target implement:

- `AUTH_OPEN` for bounded read/write-intent authorization in a dedicated test
  directory;
- `NOTIFY_FORK`, `NOTIFY_EXEC`, and `NOTIFY_EXIT` for observed process lineage;
  and
- exact Team ID and Signing ID rules with optional descendant inheritance.

The product system extension subscribes only to events required by the current
policy and lineage model. Additional create, rename, unlink, link, clone,
truncate, mapping, or copy coverage will be claimed only after the
corresponding authorization paths have been implemented and validated on
supported macOS versions.

## Process identity and descendant policy

Direct allow rules use kernel-supplied code-signing facts. Runtime lineage uses
the PID and PID-version pair extracted from audit tokens, rather than PID,
process name, or path alone. Trust propagates only through observed process
lifecycle events.

Descendant inheritance is an explicit user choice. A helper launched
independently by `launchd` or an XPC broker is not silently treated as a child
without supported lineage evidence.

## Data handling and privacy

Policy evaluation is local and performs no network request. Pasu FS does not
collect file contents, command output, environment variables, telemetry, or
analytics for authorization decisions.

Audit records are limited to locally stored metadata needed to explain a
decision, such as timestamp, event type, requested flags, target path, process
identity, and the applicable per-policy results. The current JSONL store is
capped at 10 MiB and rotates once; broader retention and deletion controls
remain incomplete. No audit data is uploaded to a cloud service.

## User control and lifecycle

The user must:

1. install and approve the system extension through macOS;
2. grant the required Full Disk Access permission;
3. select each protected directory;
4. select allowed application identities; and
5. explicitly enable descendant inheritance when desired.

The containing app will expose extension health and will not report a directory
as protected unless client creation, required subscriptions, permission state,
and policy loading have all succeeded. The user can stop protection and request
system-extension deactivation.

## Current implementation boundary

This repository contains:

- a SwiftUI menu-bar app for extension lifecycle, health, policy editing, and
  local audit presentation;
- strict schema v2 multi-policy configuration, authenticated XPC, and root-owned
  policy and audit persistence contracts;
- a synchronous policy and process-lineage core with automated tests;
- a product-shaped Endpoint Security extension that loads accepted policy sets,
  subscribes to selected lifecycle events and `AUTH_OPEN`, and reports
  authenticated runtime state; and
- a deliberately bounded integration harness for a non-system test directory.

The integration harness is not the product extension. It supports only
`AUTH_OPEN`, and truncated paths or process-decode errors fail open to prevent
the integration target from becoming a system-wide policy engine. The product
extension fails closed for ambiguous in-scope Protection decisions.

The public checks establish source formatting, build success, property-list
validity, and unit-test behavior. They do not establish entitlement approval,
matching provisioning, system-extension activation, Full Disk Access, or a
signed end-to-end product deployment.

The repository does not claim protection for pre-opened file descriptors,
individual later `read(2)` or `write(2)` calls, unsupported event types,
administrator or kernel compromise, offline access, or any period when the
extension is inactive. The complete boundaries and residual risks are recorded
in the [architecture](architecture.md) and [threat model](threat-model.md).
