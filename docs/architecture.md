# How Pasu FS works

Pasu FS separates the configuration interface from the process that makes file
access decisions. All communication and storage are local to the Mac.

## Components

| Component | Purpose |
| --- | --- |
| App | Edits policies, shows protection state and logs, and requests installation or removal of the system extension. |
| System extension | Receives Endpoint Security events and decides supported new file opens. Runs independently of the app. |
| Maintenance service | Performs the narrowly defined privileged installation checks and removal operations. Installed by the PKG. |
| Command-line launcher | Starts the containing app in a terminal mode for status, activation and deactivation. |

Components authenticate their local connections using code-signing requirements.
A process name or a path alone does not authorize a control connection. Protected
configuration is stored in the system Application Support directory with ownership
and permission checks. Status from an unauthenticated diagnostic file is not
presented as proof of active protection.

## Policies and process identity

A policy contains one folder, Protection or Audit mode, Whitelist or Blacklist
behavior, and signed-program rules. Program identity combines Endpoint Security's
kernel-provided process facts with the program's signing identity. Process IDs
alone are insufficient because macOS reuses them.

A rule can optionally extend to observed descendants. The extension tracks process
creation, executable replacement and exit. This authority follows the observed
process relationship, even if a descendant later executes another program.
A separate service launched by macOS does not automatically inherit the rule.

Every matching Protection policy must allow an open. Audit policies record the
same decision without changing the response sent to macOS. The optional system
compatibility catalog is currently empty: no system service receives an automatic
exception. A future compatibility entry must remain separate from user rules and
must not override a Blacklist denial.

## Path matching and event handling

When a policy is prepared, its selected folder is resolved, its existence and
volume comparison rules are checked, and broad system or home directories are
rejected. The directory owner's home location comes from macOS account information,
not a fixed home-folder layout. Case-sensitive volumes keep differently cased
paths distinct.

For each file-open event, the extension compares the path supplied by Endpoint
Security with the prepared policy roots. That comparison only processes strings;
it does not resolve symbolic links or query the filesystem during authorization.
A symbolic link used to select a folder is resolved when the policy is prepared.
Other aliases and preexisting hard links are not a complete protection boundary.

The response is sent without waiting for a user prompt, network request, signing
lookup or log write. Logging is asynchronous and bounded. This avoids putting
persistent storage on the decision path, but does not guarantee that macOS event
deadlines can never be missed. Only implemented and observed events can be covered.

Folder moves, replacement and unmounting are not automatically tracked as durable
object identity. Recheck and save the policy after its folder changes. See the
[security limitations](threat-model.md).

## Storage and logs

Policies use a versioned JSON format. The current format stores multiple policies.
An installation upgrading directly from the original single-policy format deletes
that old policy file rather than migrating it; recreate those rules explicitly.
Newer multi-policy configurations and logs are preserved by normal package updates.

The global log and each policy log retain a current file up to 10 MiB and one
previous file. Each record can include the requesting program, target path,
decision, signing facts and observed process history, and each record notes the
macOS build. Records of process starts, forks and exits also carry the raw audit
token of each process involved: eight numbers holding its audit user ID, its
effective and real user and group IDs, its process ID, its audit session ID and
its process ID version. File contents, command arguments and environment
variables are not collected. Deleting a policy removes its separate policy log;
the global log keeps its own retention cycle.

The in-memory history has a 128 MiB estimated-data limit. When space is needed,
old records no longer needed by observed live executions are reclaimed in batches,
aiming for at most 112 MiB after admitting the new observation.
A pass that cannot create sufficient headroom is retried at a bounded rate. A
later directly observed execution can identify an older execution as superseded;
this observation is recorded separately from an observed exit time.

Pending history and audit work share a maximum of 1,024 entries and 32 MiB of
estimated payloads, with dedicated capacity for lifecycle facts and minimal file
access records. Under load, an access record may omit its process history and
state the reason. If the reserved capacity is also exhausted, the record can be
dropped. Admission drops, storage failures and successfully stored minimal records
are reported separately. A storage failure count represents an event that failed
in at least one intended log destination. These limits do not describe total
resident memory.

Process history is an observation, not a complete reconstruction. Ancestors that
predate observation, lost events and storage limits remain explicit. macOS's
responsible-process attribution does not prove which application sent a request.

## Lifecycle

An active system extension can keep protecting files after the app quits.
The login option starts the app only; it is not the protection service itself.
An update uses the complete PKG so both the app and maintenance service change
together. On launch, the app requests an extension replacement only when its
embedded build is newer than an active installed build and removal or approval
state permits it. macOS may require approval or a restart.

Uninstall requests a fresh administrator authorization, removes the extension,
verifies its state, unregisters the current user's login item and then authorizes
file cleanup. If macOS requires a restart, the app remains available to finish
removal afterward. The maintenance service never takes arbitrary deletion paths
from policy rules or clients.

Each privileged operation (activating the extension, deactivating it and
uninstalling) has its own entry in the macOS authorization database. Every entry
requires a fresh, non-shared administrator authentication that is never cached.
The installer registers the entries as root after each installation, so their
rules and the prompt text macOS shows in each app language match the installed
app. The app and the command-line tool add an entry only when it is missing and
refuse one whose rule was changed. Uninstall removes the entries.
