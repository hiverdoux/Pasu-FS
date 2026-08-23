# Pasu FS Architecture

> **Document status:** Planned product architecture with an explicitly bounded
> prototype implementation.

## 1. Purpose

Pasu FS is intended to add process-aware authorization to user-selected macOS
directories that are not covered by a suitable existing privacy control. Its
enforcement goal is deliberately narrow:

> While the Pasu FS Endpoint Security client is active and healthy, deny
> supported new file operations within protected directories unless the
> requesting process is allowed directly or is an observed descendant of an
> allowed process root.

This document describes the proposed component boundaries, policy model, event
flow, process-lineage model, and validation requirements. Implemented prototype
parts are identified separately from planned product behavior.

### Current prototype boundary

The repository now contains a standalone Swift package that implements and
tests the in-memory signing-identity and descendant-lineage policy model. An
integration harness connects that core to selected Endpoint Security lifecycle
events and `AUTH_OPEN` for a dedicated non-system test directory. A minimal host
app plus system-extension scaffold covers activation and client creation only;
it does not load policy, subscribe to events, or provide the planned product
UI. See
[`Current prototype`](../README.md#current-prototype) for the exact boundary and
reproduction commands.

## 2. Design principles

1. **Additive authorization:** an Endpoint Security `ALLOW` decision never
   replaces POSIX permissions, TCC, App Sandbox, SIP, or other macOS controls.
   Pasu FS only adds another possible denial.
2. **Default deny inside the selected scope:** while enforcement is healthy, an
   in-scope operation from an unrecognized process is denied when the operation
   has a supported authorization event.
3. **Default allow outside the selected scope:** Pasu FS must avoid becoming a
   system-wide policy engine for paths the user did not select.
4. **Stable process identity:** policy must not trust a PID, display name, or
   executable path by itself.
5. **Explicit descendant trust:** descendant inheritance is enabled per allow
   rule and has clear consequences visible to the user.
6. **Bounded authorization work:** the Endpoint Security handler performs only
   bounded in-memory operations and responds before the event deadline.
7. **Asynchronous observability:** logging, persistence, and UI updates never
   block authorization responses.
8. **Honest coverage:** unsupported, unavailable, and untested cases remain
   documented rather than being presented as protected.

## 3. Components and identifiers

### 3.1 Pasu FS host application

- Bundle identifier: `com.dennis.pasu.fs`
- Presents configuration and health UI.
- Requests installation, activation, update, and removal of the system
  extension.
- Lets the user select protected directories and process identities.
- Sends complete policy revisions to the extension over authenticated local
  IPC.
- Displays local audit metadata produced by the extension.
- Never makes an allow or deny decision synchronously on behalf of an Endpoint
  Security authorization callback.

### 3.2 Endpoint Security system extension

- Bundle identifier: `com.dennis.pasu.fs.endpointsecurity`
- Holds `com.apple.developer.endpoint-security.client` after Apple approval.
- Creates and maintains the Endpoint Security client.
- Subscribes only to the events required by the active policy and lineage
  tracker.
- Maintains an immutable in-memory policy snapshot.
- Tracks allowed roots and their observed descendants.
- Makes authorization decisions and responds before each deadline.
- Sends audit metadata to a separate asynchronous persistence path.

### 3.3 Shared policy and audit storage

The host and extension require a signed, access-controlled mechanism for
sharing policy and audit metadata. The planned design is an App Group container
whose final identifier will be selected after the Apple Developer Team ID and
provisioning configuration are confirmed.

The stored policy is not authoritative until the extension validates and loads
it. The authorization path reads only the in-memory snapshot, never the
database or filesystem.

Audit storage is append-oriented, bounded by a retention policy, and contains
metadata rather than file contents. The exact database format and retention
period remain undecided.

## 4. High-level data flow

```text
User changes a policy
        |
        v
Pasu FS host validates the proposed rule
        |
        v
Authenticated IPC sends a complete policy revision
        |
        v
System extension validates identities, paths, and schema
        |
        v
Atomic replacement of immutable in-memory policy snapshot


Endpoint Security AUTH event
        |
        v
Fast scope check: is the target protected?
        | no                         | yes
        v                            v
      ALLOW                  identify requester
                                      |
                        direct allow or descendant?
                              | yes          | no
                              v              v
                            ALLOW           DENY
                              \              /
                               v            v
                         asynchronous audit queue
```

## 5. Policy model

The exact serialization format is not yet selected. Conceptually, a policy
revision contains the following objects.

### 5.1 Protected directory

```text
ProtectedDirectory
  id
  user-visible path
  resolved filesystem identity where available
  enabled
  rule references
```

A path string alone is not treated as a complete filesystem identity. The
implementation will use the file information supplied by Endpoint Security and
will conservatively handle truncated or ambiguous paths.

### 5.2 Process allow rule

```text
ProcessRule
  id
  team identifier, when available
  signing identifier, when available
  code-signing requirements or flags
  optional executable constraint
  optional version-pinning constraint
  allow descendants
  enabled
```

The default identity strategy is expected to combine Team ID and Signing ID.
An optional code-directory hash may provide strict version pinning, but it
changes when an application is updated. Unsigned or ad-hoc-signed programs
require an explicit, visibly weaker rule and will not be silently trusted by
path or filename.

### 5.3 Runtime lineage record

```text
LineageRecord
  process PID + PID version extracted from its audit token
  parent PID + PID version extracted from its audit token
  current full audit-token metadata
  originating allow-rule ID
  generation or policy-revision ID
  inherited access state
  lifecycle state
```

Runtime lineage records are not long-lived user configuration. They are removed
on observed process exit and invalidated when the relevant policy is revoked.

## 6. Process identity and descendant inheritance

### 6.1 Allow roots

A process becomes an allow root when its current Endpoint Security process facts
match an enabled user rule. A user may also approve a currently running process,
but the extension must validate its audit token and code-signing facts before
creating the runtime root.

PID values alone are used only as display metadata because macOS reuses them.
Runtime lineage uses the PID and PID-version pair extracted with libbsm's
supported audit-token functions. Full audit-token metadata remains available
for validation and auditing, but mutable credential fields are not part of the
lineage-map key.

### 6.2 Descendant propagation

For a rule with `allow descendants` enabled:

1. an observed `fork` from an allowed process creates an allowed child record;
2. an `exec` by that child preserves inherited access while updating the
   child's executable and signing facts for auditing;
3. further observed forks inherit the same originating rule;
4. an observed exit removes the runtime record; and
5. disabling or deleting the originating rule revokes its runtime lineage
   records for future authorization decisions.

This policy intentionally trusts any actual descendant, even if it executes a
different binary. That behavior matches the user-visible meaning of descendant
inheritance and must be presented clearly before the option is enabled.

### 6.3 What is not a descendant

A process is not automatically trusted merely because it:

- has the same name or executable path as an allowed process;
- has a nearby PID;
- shares a responsible-process token without an observed lineage;
- was started independently by `launchd` or an XPC broker; or
- claims a parent relationship in user-controlled data.

Broker-launched helpers require a direct identity rule unless Pasu FS can
establish the intended relationship through supported kernel-provided facts.

### 6.4 Extension restarts

An extension restart creates a lineage-observation gap. Pasu FS will not claim
that a complete preexisting descendant tree can always be reconstructed.
Until roots and descendants are revalidated, in-scope requests that cannot be
attributed to an active allow rule are treated as unapproved.

## 7. Planned Endpoint Security subscriptions

The following table is an initial design target, not an implemented support
matrix.

| Purpose | Planned events | Intended use |
| --- | --- | --- |
| New file opens | `AUTH_OPEN` | Inspect requested read/write flags and allow or deny the supported open operation |
| Namespace and content mutation | `AUTH_CREATE`, `AUTH_RENAME`, `AUTH_UNLINK`, `AUTH_LINK`, `AUTH_CLONE`, `AUTH_TRUNCATE` | Protect the source, destination, or both, as applicable |
| New file mapping | `AUTH_MMAP` | Authorize supported new mappings; does not monitor later memory accesses |
| Copy operation | `AUTH_COPYFILE`, where available | Protect source and destination for the corresponding supported operation |
| Directory enumeration | `AUTH_READDIR`, where available and required | Restrict supported directory enumeration within protected scope |
| Process lineage | `NOTIFY_FORK`, `NOTIFY_EXEC`, `NOTIFY_EXIT` and any required authorization counterparts | Maintain runtime root and descendant state |
| Audit context | Relevant matching `NOTIFY` events | Explain completed operations without delaying authorization |

The implementation will gate subscriptions by the deployed macOS version and
the active feature set. It will not invent a per-call read authorization event
where Endpoint Security provides none.

## 8. Path and filesystem handling

The protected-directory check must account for more than string prefixes.
Planned safeguards include:

- reject an authorization shortcut when Endpoint Security reports a truncated
  path;
- inspect both source and destination for rename, link, clone, and copy events;
- resolve user-selected directories before policy activation and retain stable
  filesystem facts where supported;
- prevent creation of new hard links or aliases that cross the protected
  boundary when a corresponding authorization event is available;
- treat symlink resolution conservatively and make decisions against the event's
  actual target information rather than only the user-supplied path; and
- invalidate or revalidate policy when a protected directory is replaced,
  unmounted, or moved.

The first prototype must empirically validate the exact path semantics for each
subscribed event on every supported macOS release.

## 9. Authorization decision path

The authorization handler follows a bounded sequence:

1. verify that the message type and version are supported;
2. check whether any source or destination is within a protected scope;
3. allow immediately if the operation is entirely out of scope;
4. identify the requesting process from the message's kernel-provided facts;
5. look for a direct process rule or valid runtime lineage record;
6. apply the event-specific decision, including requested open flags;
7. respond before the message deadline; and
8. enqueue audit metadata without waiting for persistence or UI work.

No network request, disk lookup, synchronous database transaction, code-signing
network validation, or UI prompt is permitted on this path.

For an in-scope event, ambiguity about the requesting process, target, policy
revision, or truncated path produces a denial while the enforcement engine is
otherwise healthy. Unsupported operations are reported as uncovered rather
than silently claimed as protected.

## 10. IPC and policy integrity

The extension must authenticate every control connection using kernel-provided
peer identity and a designated code requirement. A process does not gain policy
control merely because it runs as the same user or knows the IPC service name.

Policy updates are complete, versioned replacements rather than a stream of
partially applied edits. The extension validates:

- schema version and size limits;
- protected-directory validity;
- process-rule identity fields;
- duplicate and conflicting rule identifiers;
- the sender's signed identity; and
- monotonic policy revision where applicable.

After validation, the extension atomically swaps the immutable in-memory
snapshot. An invalid update leaves the previous valid snapshot active.

## 11. Audit model

An audit entry is expected to contain only the metadata required to explain a
decision, such as:

- timestamp and policy revision;
- allow or deny result and reason;
- event type and requested access flags;
- target path as supplied by the supported event, with truncation status;
- process audit-token-derived identifiers;
- executable path and available code-signing facts;
- direct-rule or inherited-rule identifier; and
- sequence-gap or health warnings.

File contents, command output, environment values, and unrelated filesystem
activity are not part of the planned log.

Endpoint Security can drop events under pressure, and not every file-content
access has a corresponding event. Audit logs therefore describe observed
events and detected gaps; they are not represented as complete forensic proof.

## 12. Lifecycle and user-visible health

The host app will expose at least these states:

```text
Not installed
Waiting for system-extension approval
Waiting for Full Disk Access
Starting
Protecting
Degraded
Stopped
```

`Protecting` is shown only after the extension has connected, loaded a valid
policy, subscribed successfully, and reported ready. The UI must not claim that
directories are protected while the extension is stopped or degraded.

## 13. Verification strategy

### 13.1 Policy-engine tests

- direct allow and direct deny;
- read-only and write-intent open decisions;
- protected and unprotected paths;
- source/destination boundary decisions;
- rule revision and revocation;
- unsigned and updated binaries; and
- malformed or ambiguous input.

### 13.2 Lineage tests

- allowed root and direct child;
- multiple descendant generations;
- descendant `exec` into a different binary;
- unrelated instance of the same executable;
- PID reuse;
- parent exit before child;
- rule revocation while descendants are alive;
- launchd- or XPC-brokered helpers; and
- extension restart with existing processes.

### 13.3 Filesystem integration tests

- open for read and write;
- create, rename, unlink, truncate, hard link, clone, mapping, and supported
  copy operations;
- source inside/destination outside and the reverse;
- symlink and preexisting hard-link cases;
- path replacement and mount changes; and
- path truncation handling.

### 13.4 Reliability tests

- event bursts and sequence gaps;
- authorization latency against real deadlines;
- extension crash and restart;
- invalid policy updates;
- audit-storage failure;
- host app termination; and
- extension update and removal.

## 14. Unresolved design decisions

The following items remain intentionally undecided:

- minimum supported macOS version;
- final App Group identifier and persistence format;
- audit retention defaults and maximum size;
- whether any authorization results may be cached for protected paths;
- the exact identity options exposed for unsigned programs;
- adoption strategy for version-specific deadline-miss behavior; and
- the final installation, update, and uninstallation user experience.

They must be resolved through implementation evidence and platform testing, not
by changing this document to imply completed protection.
