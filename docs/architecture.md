# Pasu FS Architecture

> **Document status:** schema v2 multi-policy implementation architecture.
> Source-level build and unit tests cover this revision. Signed, provisioned
> end-to-end enforcement remains a separate validation requirement.

## 1. Purpose

Pasu FS is intended to add process-aware authorization to user-selected macOS
directories that are not covered by a suitable existing privacy control. Its
enforcement goal is deliberately narrow:

> While the Pasu FS Endpoint Security client is active and healthy, evaluate
> every matching Protection policy for a supported file operation and deny when
> any one of them denies. Audit policies record the same hypothetical result but
> never affect the kernel response.

This document describes the implemented component boundaries, policy model,
event flow, process-lineage model, and validation requirements. Public source
checks do not establish entitlement approval, system-extension activation, Full
Disk Access, or signed end-to-end enforcement.

### Current prototype boundary

The repository now contains a standalone Swift package that implements and
tests the in-memory signing-identity and descendant-lineage policy model, a
bounded Endpoint Security integration harness, a SwiftUI menu-bar host, and a
product-shaped system extension. The extension loads a strict policy-set
document, subscribes to process lifecycle plus `AUTH_OPEN`, and reports
authenticated runtime status. Other authorization event types remain planned,
not implemented. See
[`Current prototype`](../README.md#current-prototype) for the exact boundary and
reproduction commands.

## 2. Design principles

1. **Additive authorization:** an Endpoint Security `ALLOW` decision never
   replaces POSIX permissions, TCC, App Sandbox, SIP, or other macOS controls.
   Pasu FS only adds another possible denial.
2. **Explicit list semantics:** a Whitelist allows matches and denies
   non-matches; a Blacklist denies matches and allows non-matches. Every matching
   Protection policy must allow the request.
3. **Default allow outside the selected scope:** Pasu FS must avoid becoming a
   system-wide policy engine for paths the user did not select.
4. **Stable process identity:** policy must not trust a PID, display name, or
   executable path by itself.
5. **Explicit descendant effect:** descendant inheritance is enabled per rule
   and inherits either Whitelist allow or Blacklist deny semantics.
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
- Sends complete policy-set revisions to the extension over authenticated local
  IPC.
- Displays local audit metadata produced by the extension.
- Never makes an allow or deny decision synchronously on behalf of an Endpoint
  Security authorization callback.

### 3.2 Endpoint Security system extension

- Bundle identifier: `com.dennis.pasu.fs.endpointsecurity`
- Holds `com.apple.developer.endpoint-security.client` after Apple approval.
- Creates and maintains the Endpoint Security client.
- Subscribes only to the events required by active policies and lineage
  tracker.
- Maintains an atomically replaceable in-memory policy-set snapshot.
- Tracks matched rule roots and their observed descendants per policy.
- Makes authorization decisions and responds before each deadline.
- Sends audit metadata to a separate asynchronous persistence path.

### 3.3 Policy and audit storage

The host sends a complete schema v2 JSON policy set only over an XPC connection
whose peers are constrained by their actual designated code requirements. The
extension derives the host and CLI requirements from the installed,
administrator-controlled app at `/Applications/Pasu FS.app`; the host derives
the extension requirement from its sealed embedded system extension. There is
no App Group or user-writable authoritative policy file.

After validation, the extension persists the accepted policy set under the local
system Application Support domain in a root-owned, non-group-writable directory.
Writes use descriptor-relative temporary files, `O_NOFOLLOW`, `fsync`, and
atomic rename. The host cannot write this store.

The stored policy set is not authoritative until the extension validates and loads
it. The authorization path reads only the in-memory snapshot, never the
database or filesystem.

Audit storage is append-oriented JSONL, limited to 10 MiB with one rotated file,
and contains metadata rather than file contents. The host reads recent entries
through authenticated XPC. The separately readable status file is diagnostic
only and can never establish the UI's `Protecting` state.

## 4. High-level data flow

```text
User changes one policy draft
        |
        v
Pasu FS host merges it into the latest active policy set
        |
        v
Mutually code-constrained XPC sends a complete set revision
        |
        v
System extension validates identities, paths, and schema
        |
        v
Atomic replacement of all prepared in-memory policies


Endpoint Security AUTH event
        |
        v
Fast scope check: which policies contain the target?
        | no                         | yes
        v                            v
      ALLOW                  identify requester once
                                      |
                         evaluate each matching rule set
                                      |
                     every Protection policy allows?
                              | yes          | no
                              v              v
                            ALLOW           DENY
                              \              /
                               v            v
                  one asynchronous audit record with
                       all per-policy evaluations
```

## 5. Policy model

The serialization format is strict JSON schema version 2. A policy set has a
stable UUID, monotonic `UInt64` revision, and up to 64 ordered directory policies.
Each policy has its own stable UUID, display name, Protection or Audit mode,
Whitelist or Blacklist type, one protected root, and exact program rules. The set
contains at most 1,024 rules and remains below 1 MiB.

### 5.1 Protected directory

```text
DirectoryPolicy
  id
  display name
  Protection or Audit mode
  Whitelist or Blacklist type
  user-visible path
  rules
```

A root is standardized, symbolic links are resolved, and comparisons are
case-insensitive. The same normalized root+mode pair is rejected, while the same
root with different modes and parent/child overlaps are allowed. Truncated or
ambiguous event paths are handled conservatively.

### 5.2 Program rule

```text
ProcessRule
  id
  team identifier, when available
  signing identifier, when available
  code-signing requirements or flags
  inherit effect to observed descendants
  enabled
```

The default identity strategy combines Team ID and Signing ID for non-platform
programs. Apple platform programs use the kernel-supplied platform-binary flag
plus an exact Signing ID, so a copied program cannot match merely by reusing an
identifier string. Disabled rules remain editable but are omitted from the
matcher and immediately lose retained lineage. Unsigned or ad-hoc-signed
programs are not silently trusted by path or filename.

For a Whitelist, a direct or inherited match allows and no match denies. For a
Blacklist, a direct or inherited match denies and no match allows. Audit mode
stores `wouldAllow`/`wouldDeny`; Protection stores `allow`/`deny` and participates
in the all-matching-policies decision.

### 5.3 Runtime lineage record

```text
LineageRecord
  process PID + PID version extracted from its audit token
  parent PID + PID version extracted from its audit token
  current full audit-token metadata
  originating policy UUID + rule ID
  policy-set generation/revision
  inherited match state
  lifecycle state
```

Runtime lineage records are not long-lived user configuration. They are removed
on observed process exit and invalidated when the relevant policy is revoked.

## 6. Process identity and descendant inheritance

### 6.1 Rule roots

A process becomes a rule root when its current Endpoint Security process facts
match an enabled rule whose descendants option is checked. The extension uses
its audit token and kernel code-signing facts; UI names and paths do not establish
the match.

PID values alone are used only as display metadata because macOS reuses them.
Runtime lineage uses the PID and PID-version pair extracted with libbsm's
supported audit-token functions. Full audit-token metadata remains available
for validation and auditing, but mutable credential fields are not part of the
lineage-map key.

### 6.2 Descendant propagation

For a rule with descendants enabled:

1. an observed `fork` from a matched process creates a matched child record;
2. an `exec` by that child preserves the inherited match while updating the
   child's executable and signing facts for auditing;
3. further observed forks inherit the same originating rule;
4. an observed exit removes the runtime record; and
5. disabling or deleting the originating rule revokes its runtime lineage
   records for future authorization decisions.

This intentionally carries the rule effect across a different executed binary:
Whitelist descendants remain allowed and Blacklist descendants remain blocked.
That behavior must be presented clearly before the option is enabled.

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
Until roots and descendants are observed again, they produce no inherited match.
Each policy then applies its normal no-match semantics: deny for a Whitelist and
allow for a Blacklist.

## 7. Planned Endpoint Security subscriptions

The following table distinguishes the current implementation from later targets.

| Purpose | Planned events | Intended use |
| --- | --- | --- |
| New file opens | `AUTH_OPEN` | **Implemented.** Inspect requested flags and allow or deny the supported open operation |
| Namespace and content mutation | `AUTH_CREATE`, `AUTH_RENAME`, `AUTH_UNLINK`, `AUTH_LINK`, `AUTH_CLONE`, `AUTH_TRUNCATE` | Protect the source, destination, or both, as applicable |
| New file mapping | `AUTH_MMAP` | Authorize supported new mappings; does not monitor later memory accesses |
| Copy operation | `AUTH_COPYFILE`, where available | Protect source and destination for the corresponding supported operation |
| Directory enumeration | `AUTH_READDIR`, where available and required | Restrict supported directory enumeration within protected scope |
| Process lineage | `NOTIFY_FORK`, `NOTIFY_EXEC`, `NOTIFY_EXIT` | **Implemented.** Maintain per-policy rule roots and descendant state |
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
2. collect every policy scope containing the target;
3. allow immediately if the operation is entirely out of scope;
4. identify the requesting process from the message's kernel-provided facts;
5. look for a direct process rule or valid runtime lineage record in each policy;
6. interpret Whitelist/Blacklist matches and require every Protection policy to allow;
7. respond before the message deadline; and
8. enqueue audit metadata without waiting for persistence or UI work.

No network request, disk lookup, synchronous database transaction, code-signing
network validation, or UI prompt is permitted on this path.

For an event matching at least one Protection policy, ambiguity about the
requesting process or a truncated in-scope path produces a fail-closed denial.
Audit-only matches never deny. Unsupported operations are reported as uncovered
rather than silently claimed as protected.

## 10. IPC and policy integrity

The extension authenticates every control connection with Foundation's XPC code
signing requirement checks. A process does not gain policy control merely
because it runs as the same user or knows the Mach service name. The host also
constrains replies to the embedded extension's designated requirement and
completes a nonce handshake before sending policy.

Policy-set updates are complete, versioned replacements rather than a stream of
partially applied edits. A versioned handshake rejects mixed v1/v2 host and
extension control protocols. The extension validates:

- schema version and size limits;
- set/policy UUIDs, unique names, revision, policy/rule count and size limits;
- protected-directory validity and duplicate mode+directory pairs;
- process-rule identity fields;
- duplicate and conflicting rule identifiers;
- the sender's signed identity; and
- monotonic set revision and stable set UUID.

After validation, the extension atomically swaps the immutable in-memory
snapshot. An invalid update leaves the previous valid snapshot active.

## 11. Audit model

An audit entry is expected to contain only the metadata required to explain a
decision, such as:

- timestamp and policy-set UUID/revision;
- final kernel result and aggregate reason;
- event type and requested access flags;
- target path as supplied by the supported event, with truncation status;
- process audit-token-derived identifiers;
- executable path and available code-signing facts;
- every matching policy's UUID, recorded name, mode, type, direct/inherited
  rule match, and actual or hypothetical decision; and
- sequence-gap or health warnings.

File contents, command output, environment values, and unrelated filesystem
activity are not part of the planned log.

Endpoint Security can drop events under pressure, and not every file-content
access has a corresponding event. Audit logs therefore describe observed
events and detected gaps; they are not represented as complete forensic proof.

## 12. Lifecycle and user-visible health

The host app exposes at least these states:

```text
Not installed
Waiting for system-extension approval
Waiting for Full Disk Access
Starting
No policies configured (revision)
Enforcing Protection policies (revision and counts)
Monitoring Audit policies (revision and counts)
Degraded
Stopped
```

`Enforcing Protection policies` is shown only after the extension has connected,
loaded a valid nonempty set containing Protection, subscribed successfully, and
reported ready over authenticated XPC. An Audit-only set is shown as Monitoring,
and an accepted empty set as Idle. A diagnostic file without authenticated XPC produces
`Degraded`, even if the file claims enforcement.

## 13. Verification strategy

### 13.1 Policy-engine tests

- all Whitelist/Blacklist match and no-match combinations;
- overlapping Protection deny-wins and Audit non-interference;
- read-only and write-intent open decisions;
- protected and unprotected paths;
- source/destination boundary decisions;
- rule disable/delete/type-change revision and lineage revocation;
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
- invalid set updates, mixed handshake versions, and schema v1 retirement;
- audit-storage failure;
- host app termination; and
- extension update and removal.

## 14. Unresolved design decisions

The following items remain intentionally undecided:

- production Team ID signing and provisioning configuration;
- audit retention beyond the current 10 MiB plus one-file rotation;
- whether any authorization results may be cached for protected paths (the current
  implementation always responds with `cache: false`);
- the exact identity options exposed for unsigned programs;
- adoption strategy for version-specific deadline-miss behavior; and
- the final installation, update, and uninstallation user experience.

They must be resolved through implementation evidence and platform testing, not
by changing this document to imply completed protection.
