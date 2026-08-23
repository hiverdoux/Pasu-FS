# Pasu FS Threat Model

> **Document status:** Design-stage threat model; not an implementation or
> security guarantee.

## 1. Security objective

Pasu FS has one primary security objective:

> While its Endpoint Security enforcement component is active and healthy,
> prevent unapproved applications running under the same macOS user identity
> from completing supported new file operations within directories selected by
> the user.

An approved process may optionally become an allow root. When the user enables
descendant inheritance, processes in the allow root's observed operating-system
descendant tree receive the same directory access.

The objective is not to reproduce TCC or to protect against every actor capable
of controlling the Mac.

## 2. Protected assets

Depending on the selected directory and enabled policy, protected assets may
include:

- file contents;
- filenames and directory structure;
- integrity of existing files;
- ability to create, remove, rename, link, clone, truncate, or map files; and
- local policy and audit metadata maintained by Pasu FS.

Availability is secondary to confidentiality and integrity. A conservative
deny decision may temporarily prevent legitimate access rather than allow an
unidentified same-user process into a protected directory.

## 3. Adversary model

The in-scope adversary is a process that:

- runs as the logged-in user, including a nonsandboxed third-party application;
- is not directly allowed by the relevant Pasu FS rule;
- is not an observed descendant of an allow root whose rule enables descendant
  inheritance;
- can make ordinary filesystem calls available to that user; and
- may know the protected path, the Pasu FS bundle identifiers, and the general
  policy design.

The process may be correctly Developer ID-signed, ad-hoc signed, unsigned, or a
script executed by an interpreter. Signing is an identity input, not proof that
the process is harmless.

## 4. Trust assumptions

The design trusts:

- the macOS kernel, Endpoint Security subsystem, code-signing enforcement, and
  other platform security mechanisms;
- the currently running Pasu FS Endpoint Security extension and its validated
  in-memory policy;
- the user who installs the extension, grants required approvals, and chooses
  process rules;
- a process explicitly allowed by the user; and
- all actual descendants of that process when descendant inheritance is enabled
  for its rule.

Trusting descendants is intentional. An allowed root that launches arbitrary
code grants that code the inherited access described by the rule.

## 5. Preconditions for a protection claim

Pasu FS may describe a directory as protected only when all of the following are
true:

1. the system extension is installed and active;
2. Endpoint Security client creation and event subscription succeeded;
3. required macOS approvals, including Full Disk Access, are effective;
4. a valid policy revision containing the directory is loaded;
5. the relevant operation has a supported authorization event on the deployed
   macOS version; and
6. the extension can respond within the event deadline.

If these conditions are not met, the UI must report `Stopped`, `Waiting`, or
`Degraded`, not `Protecting`.

## 6. Threats and planned mitigations

| ID | Threat | Planned mitigation | Residual risk |
| --- | --- | --- | --- |
| T1 | An unrelated same-user app opens a protected file for reading | Inspect `AUTH_OPEN` and deny requested read access unless a direct or inherited rule applies | Already-open descriptors and operations without an applicable authorization event are outside this protection |
| T2 | An unrelated app opens or creates a file for modification | Deny disallowed requested flags in `AUTH_OPEN`; handle supported create and mutation authorization events | Individual later `write(2)` calls are not independently reauthorized |
| T3 | A process impersonates an allowed app by copying its name or path | Match kernel-provided audit token and available code-signing facts; never trust display name or PID alone | Weak rules for unsigned tools remain visibly weaker; an allowed signed process may itself be compromised |
| T4 | PID reuse causes a new process to inherit stale trust | Key runtime lineage by the PID and PID-version pair extracted from the audit token; follow exec version changes and remove records on exit | Event loss or an extension restart may make lineage incomplete, requiring conservative revalidation |
| T5 | A descendant executes a different binary | Preserve inherited access only because the user explicitly enabled descendant inheritance; record the new executable for audit | The new binary remains trusted even if it would not qualify for a direct rule |
| T6 | An unrelated instance of the same shell or interpreter seeks access | Inherited access requires an observed fork chain from an allow root, not merely the same executable identity | Brokered process creation may not form a literal descendant relationship |
| T7 | `launchd` or XPC launches a helper on behalf of an allowed app | Do not infer inherited trust without supported lineage evidence; require a direct rule when necessary | Some legitimate workflows may require additional user configuration |
| T8 | A process escapes a protected path through rename, link, clone, copy, or symlink behavior | Inspect all available source and destination information and subscribe to relevant authorization events | Preexisting aliases, unsupported operations, ambiguous paths, and filesystem-specific behavior require empirical validation |
| T9 | A same-user process tampers with policy or impersonates the host app | Store shared state in an access-controlled signed container; authenticate local IPC peers by kernel and code-signing identity; atomically load validated revisions | A compromised trusted host or platform component remains trusted |
| T10 | Logging blocks authorization and causes missed deadlines | Use an in-memory decision path and a bounded asynchronous audit queue | Audit entries may be dropped; authorization behavior on platform-level deadline failure is version-dependent |
| T11 | Audit records expose sensitive path information | Keep logs local, exclude file contents and unrelated activity, restrict storage, and provide retention controls | Filenames and process metadata can themselves be sensitive |
| T12 | The extension stops while the UI still claims protection | Require extension health and ready-state confirmation before displaying `Protecting`; surface degraded and stopped states immediately | There may be a short unavoidable observation gap during failure detection |
| T13 | A process floods the extension with events | Minimize subscriptions, use bounded constant-time lookups, monitor sequence gaps and latency, and shed nonessential audit work | Endpoint Security may still drop events or terminate an unhealthy client |
| T14 | A malicious process sends policy commands directly to the extension | Authenticate the IPC peer and accept versioned complete policy revisions only from the signed Pasu FS host | Exploitation of a vulnerability in the trusted host or extension is out of scope for the rule engine |

## 7. Descendant-inheritance semantics

The phrase **allow descendants** has a precise security meaning:

- the root process matches an explicit allow rule;
- a child is inherited only after a kernel-observed process relationship;
- inheritance continues through multiple observed generations;
- `exec` does not remove inherited trust;
- an independent process with the same executable is not inherited;
- a broker-launched helper is not inherited merely because it serves the same
  application; and
- disabling the root rule prevents future authorization through that lineage.

The user interface must disclose that enabling this option allows arbitrary
programs launched by the root process. This is expected policy behavior, not a
bypass of Pasu FS.

## 8. Explicit non-goals

The following cases are outside the Pasu FS security objective:

- an administrator or device owner intentionally disabling or uninstalling
  Pasu FS;
- root-level platform modification, kernel compromise, SIP bypass, Recovery
  access, alternate-OS boot, or offline disk access;
- protection while the Endpoint Security client is not active and healthy;
- retroactive revocation of file descriptors, duplicated descriptors, passed
  descriptors, or memory mappings established before enforcement;
- recovery of data already read or copied before a policy became active;
- preventing an allowed process or an allowed descendant from copying,
  transmitting, displaying, or otherwise disclosing data it can read;
- code injection or exploitation inside a process that the user chose to trust;
- creation of a new TCC privacy class or replacement of App Sandbox, POSIX
  permissions, ACLs, SIP, FileVault, or other macOS controls;
- observation of every individual `read(2)` or `write(2)` call;
- guaranteed delivery of every audit event; and
- protection of file operations for which the deployed operating system does
  not provide a suitable Endpoint Security authorization event.

These exclusions do not make the in-scope protection ineffective. They define
the boundary within which Pasu FS can make testable claims.

## 9. Security invariants

An implementation must preserve these invariants:

1. A target entirely outside configured protected scopes is not denied by Pasu
   FS policy.
2. A supported in-scope operation is not allowed solely because the requester
   has the same UID as the directory owner.
3. PID or process name alone never establishes an allow decision.
4. Descendant access requires an enabled root rule and an observed lineage
   record.
5. An invalid policy update never partially replaces the last valid policy.
6. Disk, network, database, and interactive UI work never occurs synchronously
   on the Endpoint Security authorization path.
7. A truncated or ambiguous protected target never receives an optimistic allow
   from a path-only rule.
8. The UI never reports `Protecting` without extension readiness and an active
   policy.
9. Audit failure does not silently change the allow or deny result.
10. Documentation never labels a planned or merely compiled protection as
    validated.

## 10. Validation requirements

No release may claim the primary security objective without demonstrating at
least the following on each supported macOS version.

### 10.1 Expected allows

- direct access by an explicitly allowed signed process;
- access by observed children and deeper descendants when inheritance is
  enabled;
- descendant access after `exec` into another program;
- unrelated operations outside protected directories; and
- normal policy update and revocation behavior.

### 10.2 Expected denials

- access by an unrelated same-user application;
- access by a separate instance of the same shell or interpreter;
- access after the direct rule is disabled;
- source or destination boundary escapes for each supported namespace event;
- control requests from an unauthorized local process; and
- ambiguous protected targets for which identity cannot be established safely.

### 10.3 Degraded-state behavior

- missing Full Disk Access;
- system extension not approved or not running;
- failed Endpoint Security client creation or subscription;
- event sequence gaps and queue pressure;
- authorization processing close to a deadline;
- extension crash, restart, update, and removal;
- audit-storage failure; and
- policy persistence corruption.

Test evidence must record the OS build, Pasu FS build, signed component
identities, policy revision, operation performed, expected result, and observed
result.

## 11. Privacy considerations

The product necessarily observes some file and process metadata to make and
explain decisions. The planned minimization rules are:

- do not read file contents for policy evaluation;
- do not collect unrelated system activity merely because Endpoint Security can
  expose it;
- filter to configured scope as early as the supported API permits;
- keep policy and audit data on-device;
- do not add telemetry by default;
- bound audit storage and provide deletion controls; and
- document every stored field and its retention purpose before release.

## 12. Review and maintenance

This threat model must be reviewed when any of the following changes:

- a new Endpoint Security event is subscribed;
- process identity or descendant semantics change;
- protected-path resolution changes;
- IPC, persistence, update, or installation architecture changes;
- a supported macOS version changes relevant API behavior;
- remote services or telemetry are proposed; or
- testing reveals a new bypass or undocumented coverage gap.

The project owner owns threat analysis, review decisions, tests, and release
claims. Pasu FS is a personal project and does not accept external
contributions.
