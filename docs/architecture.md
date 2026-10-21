# How Pasu FS works

Pasu FS separates the configuration interface from the process that makes file
access decisions. All communication and storage are local to the Mac.

## Components

| Component | Purpose |
| --- | --- |
| App | Edits policies, shows protection state and logs, and requests installation or removal of the system extension. |
| System extension | Receives Endpoint Security events and decides supported new file requests. Runs independently of the app. |
| Maintenance service | Performs the narrowly defined privileged installation checks and removal operations. Installed by the PKG. |
| Command-line launcher | Starts the containing app in a terminal mode for status, activation and deactivation. |

Components authenticate their local connections using code-signing requirements.
A process name or a path alone does not authorize a control connection. Protected
configuration is stored in the system Application Support directory with ownership
and permission checks. Status from an unauthenticated diagnostic file is not
presented as proof of active protection.

## Policies and process identity

A policy contains one folder, Protection or Audit mode, independent allow and
deny lists, and an explicit setting that turns the allow list on or off. The
setting is stored as the `isBlacklistEnabled` Boolean, which is `true` when the
allow list is off, so that only the deny list applies, and `false` when it is
on; the name comes from the Whitelist and Blacklist policy kinds of earlier
policy schemas (see [Policy storage states](using.md#policy-storage-states)).
With the allow list on, the first ordinary program in the observed execution
history must directly match it. The program making the request must directly
match or have an observed ancestor matching an enabled allow rule with
`allowsDescendants`. With the list off, both allow checks are disabled without
deleting that list. The setting is never derived from the number of rules. An
ordinary denied program anywhere in the history denies the path in either mode.

The extension records forks, executable replacement and exit synchronously for
authorization. A boot identity plus PID and process version identifies an
execution. macOS's responsible-process attribution never restores a missing
history, and the current parent restores one only in the single case described
in the next paragraph: an Apple platform binary that launchd forked before the
extension began observing. The first ordinary program remains fixed after
parent exit or executable replacement. Only specifically authenticated launchd
and xpcproxy roles skip their own list checks; later occurrences do not reset
origin or denial. Programs themselves are free to launch. No AUTH_EXEC blocking
is performed.

A process the extension sees for the first time has no history
(`beforeObservation`), with one exception. The extension records when it began
observing, just before its first subscription. A process whose fork came
before that moment (the start time Endpoint Security reports, `start_time`,
message version 3 and later), whose original parent (`original_ppid`) and
current parent (from the parent's audit token, version 4 and later) are both
launchd (PID 1), and which the kernel reports as an Apple platform binary with
a valid signature gets the history an observed fork and executable replacement
by launchd would have produced: its current program is the first program
unless it is a system intermediary, no ancestor is recorded, and a program in a
block list denies as usual. This covers the macOS services that start before
the extension, the Apple apps already open when it starts, and, under
`NSEndpointSecurityEarlyBoot`, xpcproxy waiting to start a launch daemon of
another developer, whose start the extension then observes. A process forked
later whose start was not delivered stays without a history. The decision
evidence records how a complete history began (`historyEvidence`: `observed`
or `kernelLaunchdStart`), and the status counts the histories that began with
such a launch (`kernelLaunchdStartHistoryCount`).

Every matching Protection policy must allow a request. Audit policies record
the same rule result without denying the kernel request. An allow list that is
on and has no enabled rule grants no access through the list; active
system-compatibility profiles can still admit matching requests. Descendant
grants cannot bypass origin, denial, observation or overlapping-policy checks.
For requests decided by program identity, a system-compatibility profile turned
on for a policy can allow a request without an observed history or an allow
rule, and only for the specific Apple system processes it names; see
[System-compatibility profiles](#system-compatibility-profiles).

An observed fork or executable replacement records the preceding executable
image as a delegation source. The source survives exit and further
replacement. Each request reevaluates it against that policy's current enabled
allow rules, so disabling or removing a grant revokes future requests
immediately. Observed ancestor identities are retained independently of the
allow rules, so a grant enabled later also applies to already running
descendants whose fork or executable replacement was observed; it cannot create
a relationship that was not observed. System intermediaries never become
delegation sources. Direct actor matches take priority in the decision
evidence; inherited decisions record the granting rule and the observed source
program separately.

### System-compatibility profiles

Some Apple system processes must work inside folders that a policy can protect,
such as the services that prepare an app's container, the XProtect malware
scanner and the service that carries out Finder's copies. launchd starts most
of them on their own, before or after the extension, so their first program is
themselves; the others are started by such a service, which is then their
first program, and those that a service started before the extension did have
no history at all. Either way they are not in the policy's lists, and listing
them would let them in for any request. A policy can therefore turn on profiles from a catalog built
into Pasu FS. A profile names Apple programs by signing identifier and, for
each, the request types it may make in the policy's folder, the open flags it
may ask for and the effective users it may run as. A process acts under a
profile turned on for the policy when all of the following hold:

- The kernel reports it as an Apple platform binary with one of the profile's
  signing identifiers, with the code-signing flags valid, signed, platform
  binary and kill-on-invalid, and without the ad hoc, debuggable,
  invalid-allowed and development-code flags.
- The request is one of the types the profile allows that program, and an open
  asks for no flag outside the program's open flags.
- Its effective user ID, read from its audit token, is 0 (root), or, for a
  program that the profile allows to run as the logged-in user, the user ID
  that owned the policy's folder when the policy was prepared.
- Every path of the request has the profile's path form. The App Container
  Management profile accepts only paths inside
  `<home>/Library/Containers/<name>` or `<home>/Library/Group Containers/<name>`
  of the folder's owner.
- launchd started it, without a program of the user's session in between. With
  a complete history, observed or begun with a launch by launchd before the
  extension started (see [Policies and process identity](#policies-and-process-identity)),
  the first program after launchd and xpcproxy must itself be a program of the
  same profile, so the process is that service or a plug-in it started; a
  command run with `sudo` from Terminal has Terminal as its first program and
  does not qualify. Without a complete history, such as for a plug-in that was
  already running when the extension started or after process events were
  lost, the kernel must report launchd (PID 1) as the process that forked it,
  or the process that forked it must still be its parent and be a program or
  launcher of the same profile that launchd forked, running as a user that
  program allows. This admits the plug-ins of such a service, but not a longer
  chain.
- The running macOS version is inside the program's tested range.

A profile can also name a launcher: a program that gets no access itself but
counts as the first program of the plug-ins it starts.

The request is then allowed without the history and allow-list checks. A
program in the policy's block list anywhere in the observed history still
denies it, and a request the lists already allow keeps that decision. A
profile adds allowed requests to its own policy only: when several Protection
policies cover a path, each of them must allow, and mounts are never part of a
profile. Audit policies record the same result as **Would allow**. The record of
such a decision has the match `systemCompatibilityProfile`, the profile's
identifier and authorization digest, and the execution-origin evidence that
the lists alone would have used.

A policy stores each profile it turns on (`systemCompatibilityProfiles`) with
the profile's authorization digest. The digest covers everything that decides
what the profile allows: its programs, launchers, request types, open flags,
code-signing requirements, effective users, path form and macOS range, but not
its names, descriptions or evidence. If a later version changes what a profile
allows, the stored digest no longer matches and the profile stays inactive
until it is turned on again. Turning a profile on in a Protection policy
reduces protection, so the save needs administrator authorization, and the
extension refuses a save that turns on a profile that would be inactive on
this Mac. The status reports how many profiles are active and warns about
profiles that are turned on but inactive.

A catalog entry is accepted only when each of its programs requires an Apple
platform signature, has a closed tested macOS range and observed evidence, and
is not one of a fixed list of programs that run commands or open paths chosen
by whoever calls them, such as shells, interpreters, general file tools,
`tmutil`, Finder and Finder's scripting helper. Its evidence must also record
that no third-party program chooses what the programs do: each profile names
services that work on their own or brokers that carry out what an Apple program
asks, as the Finder copy service and the XProtect analysis service do. Each
program may make only the requests that were observed for it. The built-in
profiles are:

| Profile | Program | Runs as | Requests |
| --- | --- | --- | --- |
| App Container Management | `containermanagerd` | root or the folder's owner | opens for reading, inside app containers |
| | `secinitd` | root or the folder's owner | opens for reading, inside app containers |
| | `containermanagerd_system`, `apfsd` | root | opens for reading, inside app containers |
| XProtect Malware Scanning | XProtect plug-in service | (launcher) | none |
| | each remediator plug-in | root or the folder's owner | opens for reading |
| | XProtect analysis service (`XprotectService`) | root | opens for reading |
| Finder Copy | `DesktopServicesHelper` | root or the folder's owner | creates, truncates, clones, sets attribute lists, writes and removes extended attributes, opens for reading (with `O_EVTONLY`, `O_NONBLOCK`, `O_DIRECTORY` or `O_CLOEXEC`) or for writing without `O_CREAT`, `O_TRUNC`, `O_APPEND` or `O_EXCL` |

All three are trusted on macOS 26 and 27. The XProtect analysis service is an
XPC service of which launchd starts one instance for each client, running as
that client's user. The profile admits the instance that syspolicyd, the
Gatekeeper daemon, uses, which runs as root, and not the one that Gatekeeper's
agent in the user's session uses. A Gatekeeper check in which the root instance
reads a protected folder has not been verified end to end; its admission rules
are covered by automated tests. See the
[verified configurations](building.md#verified-configurations) for runtime
coverage of the profiles. A Time Machine backup reads a protected
folder through a snapshot and never reaches its path. A restore is
decided like any other write: `tmutil restore` writes the restored files
itself, as a descendant of the program that started it, so the program lists
decide; a restore from the Time Machine screen, like an ordinary Finder copy
or duplicate, is written by `DesktopServicesHelper`, which launchd starts as
root for each operation and which writes as root or, after joining the session
of the user who asked, as that user. Only the Finder Copy profile admits it,
whichever paths Finder chose, including a destination outside the folder when
the source is inside.

## Path matching and event handling

When a policy is prepared, its selected folder is resolved, its existence and
volume comparison rules are checked, and broad system or home directories are
rejected. The directory owner's home location comes from macOS account information,
not a fixed home-folder layout. Case-sensitive volumes keep differently cased
paths distinct.

The extension subscribes to eighteen authorization events while at least one
policy is active: `AUTH_OPEN`, `AUTH_CREATE`, `AUTH_RENAME`, `AUTH_UNLINK`,
`AUTH_LINK`, `AUTH_CLONE`, `AUTH_COPYFILE`, `AUTH_TRUNCATE`,
`AUTH_EXCHANGEDATA`, the metadata changes `AUTH_SETMODE`, `AUTH_SETOWNER`,
`AUTH_SETFLAGS`, `AUTH_SETACL`, `AUTH_SETEXTATTR`, `AUTH_DELETEEXTATTR`,
`AUTH_SETATTRLIST` and `AUTH_UTIMES`, and `AUTH_MOUNT`, together with the
`NOTIFY_UNMOUNT` and `NOTIFY_RENAME` notifications. For each
request it compares every path Endpoint Security supplies with the prepared
policy roots: the opened file; the new entry and its directory for a creation;
the source and the destination of a rename, hard link, clone or `copyfile` copy,
plus the file a copy overwrites; the removed object; the truncated file; both
files of a data exchange; the object whose metadata changes (the event's
`target`); and the mount point of a mount. A policy takes part
when any of these paths is inside its folder, or when the request touches one of
its retired paths (see [Retired paths](#retired-paths)). macOS delivers only
the requests that can concern a policy (see [Request delivery](#request-delivery));
a delivered request outside every policy folder and retired path is allowed at
once.
Every matching Protection policy must allow, each with the same program lists
and execution history as for an open, and Audit policies record the same
result without denying.

A deletion, data exchange, clone or `copyfile` copy whose source is a policy's
folder itself, or a folder that contains it, is treated as a request on that
folder, because deleting or copying the parent deletes or copies the protected
folder with it; so is a rename of the policy's folder itself. Such a request is
decided by the policy's lists instead of being denied unconditionally. An
unconditional denial would also stop the allowed programs and the Mac owner from
reorganizing their folders, Audit mode must never deny, and the lists already
state which programs may change the folder; a program outside the allow list, or
one without observed history, is denied by the same rule as inside the folder.
When a policy takes part only because the request acts on a folder that contains
its folder, its decision is recorded with the match kind `enclosingFolder`,
together with the evidence of the lists.

A metadata change acts on its object only. It is checked when the object is a
policy's folder or lies inside it, and not when the object is a folder that
contains the policy's folder: a parent folder's permissions, flags or
attributes change nothing below it, while every item below keeps its own
metadata, which is checked. Endpoint Security names the object itself,
whichever path, symbolic link or file descriptor the program used to reach it.
`AUTH_SETTIME`, which sets the system clock, names no file and is
not subscribed. Reading metadata is not subscribed either: `stat` has no
authorization event, and attribute reads, extended attribute reads and lists,
directory reads, link reads and catalog searches (`AUTH_GETATTRLIST`,
`AUTH_GETEXTATTR`, `AUTH_LISTEXTATTR`, `AUTH_READDIR`, `AUTH_READLINK`,
`AUTH_SEARCHFS`) are among the most frequent requests on a Mac, while listing a
folder already needs a checked open.

A rename of a folder that contains a policy's folder, with no path of the request
inside any policy folder, is allowed for every program and recorded with the
match kind `enclosingFolder` without program evidence. The files stay where they
are on the volume and the policy follows its folder, so the rename exposes
nothing; denying it would stop Finder and Terminal from renaming a parent folder
or moving it to the Trash. The destination is still compared with policy
folders: renaming a parent into another policy's folder is decided by that
policy's lists. Opening, creating or truncating an entry of a parent folder does
not touch the protected folder and is not checked. The comparison only processes strings; it does not resolve
symbolic links or query the filesystem during authorization. A symbolic link
used to select a folder is resolved when the policy is prepared. Other aliases
and preexisting hard links are not a complete protection boundary.

A mount is decided by its mount point alone. macOS performs every mount through
its own system processes (for a disk image, `mount_apfs` started by
`diskarbitrationd`), so the process Endpoint Security reports is not the
program that asked for the mount, and the program lists cannot describe it. The
mount point is matched like the source of a rename: a policy takes part when
the mount point is its folder, lies inside it or contains it, because the
mounted volume would hide the folder and receive what allowed programs write at
that path. Every such Protection policy denies and every such Audit policy
records **Would deny**. The record names the mount point as the target and the
device or share the volume comes from (`f_mntfromname`) as the destination;
that value is not a path on this Mac and is not compared with policies. An
unmount notification whose mount point is a policy's folder, lies inside it or
contains it sets a status warning naming the mount point and the policies; the
next policy save clears it.

### Request delivery

Endpoint Security can select the requests it delivers to a client by their
target paths, the files a request names, when the client inverts target path
muting: requests are then delivered only when a target path matches a
registered path. When the extension connects, before it subscribes to any
event, it removes the target paths that macOS mutes by default for a new
client (`es_unmute_all_target_paths`), inverts target path muting
(`es_invert_muting`) and registers `/` as a prefix for process starts
(`NOTIFY_EXEC`), which the execution histories need from every program. It
then registers the paths of the stored policies and only after them makes its
first subscription, which names the process events and the policies' events
together (see [Startup](#startup)); paths that later policies need are
registered before those policies take effect. The processes that macOS mutes
by default stay muted (see the
[security limitations](threat-model.md#known-limitations)). Forks, exits,
unmount notifications and mounts name no target path and are always delivered.

For each policy folder, retired path and pending location the extension
registers:

- the path as a prefix, for the seventeen authorization events other than
  `AUTH_MOUNT` and for `NOTIFY_RENAME`;
- each folder on the way to it, except `/`, as a literal path, for
  `AUTH_CREATE`, `AUTH_RENAME`, `AUTH_UNLINK`, `AUTH_LINK`, `AUTH_CLONE`,
  `AUTH_COPYFILE`, `AUTH_EXCHANGEDATA` and `NOTIFY_RENAME`: the requests that
  act on a folder containing it as a whole or place an object at its path.

A request with two target paths (a rename, hard link, clone, `copyfile` copy or
data exchange) is delivered when either one matches. Endpoint Security
compares bytes, without the volume's case rule or Unicode normalization: an
existing object is reported in the spelling stored on disk, and a new name in
the spelling the requesting program used. A prefix matches by bytes, so
`/a/b` also selects `/a/bc`; such requests are compared with the policies and
allowed when they are outside them. Three more registrations keep everything
the policies compare delivered:

- A path that exists in another spelling of the same name, after a rename that
  changed only its letter case or Unicode composition or that of a folder on
  the way to it, is registered in its stored spelling as well. The folder check
  follows a policy folder to its stored spelling as a new revision.
- A path that does not exist, such as a retired path or a missing policy
  folder, also registers the deepest existing folder on the way to it as a
  prefix, for the same requests as a folder on the way, so that creating its
  name in another letter case is delivered and checked.
- When the extension allows a rename that moves a policy folder, it registers
  the folder's new location and the retired paths that moved with it, computed
  from the request's paths, before it answers. No file system call is made
  then, so a relocated retired path that does not exist yet cannot register
  the deepest existing folder on the way to it; when any retired path moved,
  the rename's destination is registered as a prefix for the same requests as
  a folder on the way instead. If the kernel reported the destination as an
  existing file, which is how a rename that changes only the spelling of a
  name is reported, the folder that contains the destination is registered as
  a prefix for every request until a check has read the new spelling.

The set is computed again when policies are applied (saved, deleted or
updated after following a folder) and after each folder check, which runs
after rename notifications and every five seconds. New entries are registered
before the policies that rely on them take effect, and entries that only the
previous policies needed are removed afterwards. The entries of a pending
location are removed when it is withdrawn.

If the default target paths cannot be removed, muting cannot be inverted, or
`/` cannot be registered for process starts, the client keeps ordinary muting
and every request is delivered. If another path cannot be registered, `/` is
registered as a prefix for every request instead, so every request is
delivered as without registration; each later check tries the full set again
and removes that entry once it is complete. If that fails as well, applying
the policies fails and the policies already in effect stay, and an allowed
rename whose new location cannot be registered is denied. Each check compares
the registered set with the list Endpoint Security reports
(`es_muted_paths_events`) and registers missing entries again. The status
reports whether muting is inverted, whether every request is delivered, the
numbers of registered prefixes and literal paths in that list, and the latest
error. Requests that are not delivered because no registered path matches
them do not consume message numbers, so they are not counted as dropped
messages (see [Dropped messages](#dropped-messages)).

### Following a moved folder

When the extension stores a policy set, it records with each policy's scope the
identity of the folder at that path: both words of the volume's `f_fsid`, the
volume UUID when the file system reports one, and the folder's file ID, read
with `getattrlist` without following a symbolic link. Scopes committed without
an identity gain one the next time the extension loads them.

When the extension allows a rename whose source is a policy folder or a folder
that contains it, it computes the folder's new path from the request's paths,
keeping the part below the renamed folder, and adds it to the policy as a
pending location before it answers, registered for delivery as described in
[Request delivery](#request-delivery). A pending location takes part in every
comparison, including mount checks, exactly like the folder itself. At most 32
locations per policy can be pending; a rename that would need another is denied
until a check has confirmed the earlier ones. The calculation only compares
strings, so authorization still makes no file system calls.

A rename notification whose source is a pending rename, a policy folder or a
folder that contains one, or whose source or destination is a retired path or a
folder on the way to one, starts a check of the policy folders on the
extension's configuration queue. The same check runs when the extension starts and every
five seconds when it writes its status. For each policy it compares the folder
at the stored path with the stored identity. If they differ, `fsgetpath` returns
the path of the stored file ID on the volume with the stored UUID, and the
location found is validated with the same rules as a newly selected folder. If
they match but `realpath` spells the path differently, byte for byte, because
a rename changed only the letter case or Unicode composition of a name on the
way, the stored spelling is the location found. The
extension then stores the policy set with the new path as the next revision
and applies it; the app reads the new revision on its next status query. Because Endpoint
Security also reports renames that were denied or failed, the notification
itself never changes a policy. A check withdraws a pending location once the
policies in effect name the folder, once its rename notification has arrived, or
when the rename was allowed ten or more seconds earlier. A pending location
whose destination was reported as an existing file names the folder's previous
spelling and is withdrawn only by the last two.

A folder that can't be found keeps its stored path: the policy is prepared from
its committed scope, so that path stays denied, and the status reports
`Protected folder missing: <path> (<policy>)` until the folder is found again. If
no folder with the stored identity exists anywhere and another folder is at the
stored path, the policy takes that folder's identity. A rename to another volume
fails with `EXDEV`; programs that move across volumes copy and delete instead,
and the policy does not follow the copy.

### Retired paths

When a check follows a folder, the scope committed with the new revision adds
the folder's previous path, with its volume's case rule, to the policy's
retired paths, oldest first. A path the new folder contains is dropped, because
the folder protects it again, and a path named again moves to the end. At most
eight are kept; the oldest is dropped first. Scopes without retired paths are
encoded exactly as before, so commits written by earlier versions keep their
digests.

A request touches a retired path when, comparing strings only:

- a checked path is the retired path or lies below it;
- a path that the request acts on as a whole (the source of a rename, deletion,
  clone or `copyfile` copy, either file of a data exchange, or a mount point)
  is the retired path or contains it; or
- the path where the request makes an object appear (the new entry of a create,
  hard link, clone or `copyfile` copy, or the destination of a rename) is the
  retired path or a folder on the way to it. Such a request could recreate the
  path, fill it with a prepared folder, or point it elsewhere with a symbolic
  link; Endpoint Security reports opens with symbolic links resolved, so a
  redirected save would not be recognized afterward.

A retired path inside the policy's folder or one of its pending locations does
not count. A rename that moves the policy's folder, because its source is the
folder or contains it, does not count its source against the retired paths
inside that source: they are relocated with the same calculation as the folder,
and each relocated path is kept with the pending location until the check
confirms the move. Its destination does not count against a retired path that
the relocated folder contains, so renaming a parent folder back to its old name
lands the folder on its retired path. When the check follows a folder, it
replays the chain of allowed renames that leads from the stored path to the
folder's new path and moves each retired path through the same renames. A move
the extension did not observe has no such chain and leaves retired paths where
they were.

A policy that takes part only through a retired path decides the request like a
request inside its folder: with its lists, execution history and compatibility
profiles, or by the mount point for a mount. The allowance for renaming a folder
that contains the policy's folder does not apply when the rename touches a
retired path. Each policy decision records the retired path in
`retiredFolderPath`, so an allowed request there is logged as a warning, and an
allowed record with a retired path is combined only with identical repeats.

An apply request names the policy whose Save the user chose
(`savedPolicyIdentifier`). When the extension stores that set, the saved policy's
scope is committed without retired paths and the other policies keep theirs. A
revision the extension stores itself after following a folder, a set sent to
delete a policy and the stored set sent again at its own revision release
nothing. The status reports each
stored policy's retired paths, which the app shows on the policy and the
Overview, and emergency recovery keeps denying at them.

See the [security limitations](threat-model.md) for what following a folder does
not cover.

### Responses

An open is answered with the permitted open flags; every other request is
answered allow or deny. The response is sent without waiting for a user prompt,
network request, signing lookup or log write. Logging is asynchronous and bounded. This avoids putting
persistent storage on the decision path, but does not guarantee that macOS event
deadlines can never be missed. Only implemented and observed events can be covered.

### Missed deadlines

macOS holds each authorization request until the extension answers it or the
request's deadline passes. What happens at the deadline is the client's
deadline miss mode:

- On macOS 27 and later, the extension sets the fail-closed mode
  (`es_set_deadline_miss_mode` with `ES_DEADLINE_MISS_MODE_FAIL_CLOSED`) right
  after it creates its Endpoint Security client, before it subscribes to any
  event, and reads the mode back with `es_get_deadline_miss_mode` to confirm it.
  macOS then denies a request whose deadline passes and keeps the extension
  running. It also denies a request whose message it drops because the
  extension's queue is full, instead of allowing it (see
  [Dropped messages](#dropped-messages)).
- Before macOS 27 the default kill mode applies: macOS stops an extension that
  misses a deadline, allows the request it was holding, and starts the
  extension again. It also allows a request whose message it drops. The new
  extension starts with an empty execution history, so Protection policies
  deny requests with incomplete history unless a compatibility profile admits
  them. Affected programs need a new observed launch; Apple platform binaries
  that launchd started directly can regain a history as described under
  [Policies and process identity](#policies-and-process-identity).

The extension looks both functions up by name when it starts (`dlsym`) instead
of linking to them, so one build runs on every supported macOS version and the
package still builds with SDKs that don't declare them. It does so only on
macOS 27 and later, the first version the SDK declares them for: macOS 26
already has both functions, but there they return an error and the mode stays
kill. If either function is missing, the extension keeps the kill mode. If
setting or confirming the mode fails, the extension asks for the kill mode
again unless Endpoint Security already reports it. The extension never sets the
fail-open mode, in which macOS would allow a request whose deadline passes.

Once the fail-closed mode is confirmed, the extension also shortens the
deadline to limit how long an unresponsive extension holds a request. Instead
of keeping macOS's default deadlines, it sets a maximum of 3,000 ms for each of
the eighteen authorization events it answers (`es_set_deadline_max_milliseconds`)
and reads each one back with `es_get_deadline_max_milliseconds`. It looks these
two functions up in the same way and only in the fail-closed mode: in the kill
mode a shorter deadline would only stop the extension sooner and allow the
request. If setting or
confirming the maximum fails, the extension sets each event that changed back
to the deadline it read before, keeps the fail-closed mode and reports the
error.

The status reports the outcome as `deadlineMissMode`: `setting` is
`failClosed`, `killUnavailable` (no setting before macOS 27) or
`killAfterFailure`, and `error` says what failed;
`maximumDeadlineMilliseconds` is the confirmed maximum deadline and
`maximumDeadlineError` what failed while shortening it. Both are absent while
the default deadlines apply.

An extension that stops answering without exiting is not restarted in the
fail-closed mode. Every request delivered to it is denied once its deadline
passes, until the extension exits or the Mac restarts. Requests for the same
file can wait behind each other, so a sequence of requests can take longer than
one deadline. Requests outside the policy folders are not delivered and are
not delayed. When the extension resumes, it answers the requests it was
holding; macOS has already decided
them, so the answer fails (`ES_RESPOND_RESULT_NOT_FOUND`) and the log record is
written with the response `response-error` and the extension's own decision.
The app shows such a record as a missed deadline with what macOS did (see
[Using Pasu FS](using.md#policy-log)). The extension's status file stops
changing while it is stopped; the app reports the extension as not responding
when it can't get a status from the extension and the file is at least 30
seconds old. When macOS reports no enabled extension, only a status request
that waited out its 5-second timeout counts, which happens only while a process
holds the extension's service without answering, so a status file left by an
extension that has stopped is not reported. This covers an earlier extension
that keeps running while an update or a deactivation waits for a restart:
macOS then reports no version as enabled, and reports the same whether the
earlier one still runs or has stopped.
When the extension exits while requests are waiting, macOS allows the waiting
requests even in the fail-closed mode. For this reason the extension does not
stop itself when it detects a stall; restarting the Mac is the recovery.

These deadline behaviors were checked on macOS 26.6.2 and 27.0.1 with the
packaged executable running as a launch daemon and System Integrity Protection
disabled. They have not been verified under normal SIP-enabled system
extension installation; see [verified configurations](building.md#verified-configurations).

### Dropped messages

When the extension's queue of undelivered messages is full, macOS drops
messages instead of delivering them. Endpoint Security numbers every message it
sends to a client (`global_seq_num`, message version 4 and later) and,
separately, every message of each event type (`seq_num`, version 2 and later),
so a skipped number shows a drop. The first message, and the first message of
each type, only sets where the numbering starts.

- A skip in the numbering of process starts, forks or exits (`NOTIFY_EXEC`,
  `NOTIFY_FORK` and `NOTIFY_EXIT`) invalidates every execution history,
  because these notifications are the only source of the histories. Programs
  that were running then have incomplete history until they are started again
  from an observed launch. Protection policies deny requests that depend on
  those histories unless a compatibility profile admits them. Messages without
  these numbers (versions before 2) invalidate the
  histories on every message, since a loss could not be noticed. A skip in any
  other numbering leaves the histories intact.
- macOS answers an authorization request whose message it dropped without the
  extension, which never sees it: in the kill mode macOS allows the request, and
  in the fail-closed mode it denies it (see [Missed deadlines](#missed-deadlines)).
  The extension counts these as unchecked requests.
  The overall numbering shows how many messages were dropped but not which
  kinds, so the count is an estimate. Skips within one second of the first one
  form a stretch, the same window that combines log records. From the messages
  a stretch dropped, the extension subtracts the process notifications whose own
  numbering shows them missing during the stretch, and counts the rest. The
  result is an upper bound: the rest can include notifications of renames and
  unmounts, and process notifications whose loss shows only after the stretch,
  when the next notification of that kind arrives. Before message version 4
  only the per-type numbering exists, and the drops of every type other than
  process notifications are counted.

The status reports the total of unchecked requests since the extension
connected to Endpoint Security, the count of the latest stretch that had any and
the time of its last skip, and the drops of all messages and of process
notifications. A stretch is added to the total, and logged once in the global
log, after its second has passed: when the next message arrives, when the
extension next reports its status or when it stops. The record has event type
`DELIVERY_GAP`, policy decision `unchecked` and response `not-delivered`. Its
`timestamp` is the first skip and `lastTimestamp` the last one when the stretch
has more than one; `eventSequence` is the overall number of the message that
showed the first skip, and `detail` reads
`missedMessages=… missedProcessEvents=… estimatedUncheckedRequests=… gaps=…`.
The record names no process or policy, so policy logs don't receive it.

## Storage and logs

Policy schema 5 stores both lists, the explicit allow-list setting, effective
descendant options and the compatibility profiles turned on in each policy. The
stored formats and the app's contract with the extension carry these versions:

| Item | Version | Earlier versions |
| --- | --- | --- |
| Policy set (`schemaVersion`) | 5 | Schema 4 is read unchanged, descendant options and compatibility profiles included, and the extension stores the same revision again in schema 5 when it starts; the storage state is not `migrated`. Schemas 2 and 3 are migrated while preserving IDs, revision and log identity, with descendant options reset to off (`migrated`). The retired single-policy schema 1 is removed, not migrated. A later schema is rejected. |
| Policy commit record (`schemaVersion`) | 1 | Folder identities and retired paths are optional fields of its scopes, so commits without them keep their digests. |
| Log record (`schemaVersion`) | 9 | Records of every earlier schema are read; the fields they lack are absent. |
| Status (`schemaVersion`) | 7 | Read whatever the schema; what an earlier extension doesn't report is absent. |
| Configuration protocol | 8 | Not accepted: the app and the extension work together only with the same version. |
| Execution-origin capabilities (`version`) | 3 | The app edits policies only when the extension reports this version and policy schema 5. |
| Compatibility catalog (`schemaVersion`) | 3 | Built into the app and the extension. The authorization digests that policies store don't include it, so approvals survive a catalog change that leaves a profile's permissions as they were. An extension whose catalog lacks a profile refuses a save that turns it on. |

Schema 5 has the same fields as schema 4. Its number marks the sets this
version writes, so an earlier extension rejects such a set instead of applying
rules it may decide differently. If storing a schema 4 set again fails, the set
read from schema 4 stays in effect and the next start tries again. Log records
of schema 8 can name a mount point, an enclosing folder or a retired path,
stand for repeated requests (`requestCount`) and report dropped messages
(`DELIVERY_GAP`); schema 9 adds how a complete execution history began
(`historyEvidence`) and the current parent and start time of each recorded
program (`parentProcessID`, `startTime`). The status of schema 4 adds retired paths, request delivery,
the missed-deadline setting and the unchecked-request count, schema 5 adds
the confirmed maximum deadline and the error from shortening it to the
missed-deadline setting, schema 6 adds the version and build of the
extension that reports the status (see [Lifecycle](#lifecycle)), and schema 7
adds when the extension connected to Endpoint Security (`endpointConnection`,
see [Startup](#startup)), when tracking began and how many histories began
with a launch by launchd before it (`observationStartedAt`,
`kernelLaunchdStartHistoryCount`). Protocol 8 carries policy schema 5 and the policy whose
Save released its retired paths. Adding a profile, such as Finder Copy, or a
kind of evidence to the catalog keeps the catalog schema and leaves the digests
of the other profiles unchanged.

The root-owned repository writes two copies into an inactive slot, then commits
a digest and verified scope metadata, including each folder's identity and
retired paths, atomically. Only the latest committed copy
can recover its damaged primary. If both current copies are invalid, known
Protection scopes use deny-all recovery. If the scope/commit evidence is also
unavailable, the runtime reports failure instead of inferring an empty policy.
Before the extension answers a save, each copy and the commit record is
synchronized with `fsync` and then `fcntl(F_FULLFSYNC)`, which asks the storage
device to write out its own cache, and so is the folder after each file is
renamed into place. On storage that supports this flush, a successful response
confirms that the new commit is durable. The commit is written before the
response: if power is lost before a response arrives, either the previous or
the new revision can be stored, depending on whether the commit was completed.
Read the policies and their revision after restarting before retrying a save.
If the volume doesn't support `F_FULLFSYNC` (`ENOTSUP` or `EINVAL`), the save
keeps the `fsync` result and the extension logs the weaker durability; a flush
of the device's own cache is then not confirmed. The status file, written every
five seconds, uses `fsync` alone, and the logs are synchronized only when a file
is closed or rotated, so what they recorded last before a loss of power can be
missing.

The extension, which runs as root, keeps these files in
`/Library/Application Support/PasuFS`:

| File | Contents |
| --- | --- |
| `policy-slot-a.json`, `policy-slot-b.json` | The policy set, one revision per slot. A save writes the slot that is not committed. |
| `policy-slot-a.backup.json`, `policy-slot-b.backup.json` | The second copy of each slot, written before the commit record. When the committed slot's primary file is damaged, this copy restores it. |
| `policy-commit.json` | The commit record (schema 1): the committed slot, the digest of its contents, a copy of the set without program lists for deny-all recovery, each policy's scope with its folder identity and retired paths, and a digest over the record. |
| `status.json` | The extension's status, written every five seconds and when its state changes. |
| `logs/endpoint-events.jsonl` | The global log; `logs/endpoint-events.jsonl.1` is the previous file after a rotation. |
| `logs/policy-<set ID>_<policy ID>.jsonl` | One log per policy, named by the UUIDs of the policy set and the policy; its previous file after a rotation ends in `.1`. |

Files of earlier versions are removed: `policy.json` (schema 1) and
`system-compatibility-settings.json` when the extension starts, and
`policy-set.json`, the policy set of versions before the slots, once a commit
has replaced it. A policy set holds at most 64 policies and 1,024 rules across
all of them, each policy turns on at most 16 compatibility profiles, and the
stored document is at most 1 MiB; a set beyond these limits is rejected.

The execution histories that authorization reads synchronously are kept as one
compact origin summary per live process (its first ordinary program, the denied
programs and the observed ancestors in its lineage), separate from the detailed
logs and from the in-memory history described below. The summaries have a
16 MiB estimated-data budget and a 16,384 live-process limit; these do not
bound total resident memory. Exited parents are not kept as an unlimited graph.
Reaching a limit discards every summary; a lost process start, fork or exit
(see [Dropped messages](#dropped-messages)) marks every history incomplete but
keeps its recorded origin, denial and ancestor facts. Protection policies deny
requests with incomplete history unless a compatibility profile admits them.
Affected programs need a new observed launch. After a limit discards a history,
an eligible Apple program can regain one from its launchd start as described
under [Policies and process identity](#policies-and-process-identity); a retained
history marked incomplete is not repaired that way. After a lost message the
recorded denials keep applying; after
a limit the discarded summaries take their recorded denials with them, and a
block rule denies a program again only when the program's own identity matches
it.
Ancestor identities are retained independently of allow rules, with at most
one observed image per identity in each summary. They share the same data
budget. Each check applies the current descendant options to these facts,
including for processes that were already running when an option or allow rule
was added. An option cannot repair invalidated or missing history. New deny
identities invalidate older histories that could contain an unrecorded
historical match; allow edits and mode changes reevaluate the origin, denial
and ancestor facts already recorded.

The global log and each policy log retain a current file up to 10 MiB and one
previous file. Each record can include the access process, the request type,
the target path and, for a request that names two locations, the destination
path, the decision, signing facts and observed process lineage, and each record
notes the macOS build. Records of process starts, forks and exits also carry the raw audit
token of each process involved: eight numbers holding its audit user ID, its
effective and real user and group IDs, its process ID, its audit session ID and
its process ID version. File contents, command arguments and environment
variables are not collected. Deleting a policy removes its separate policy log;
the global log keeps its own retention cycle.

The in-memory history that feeds the logs, the process lineage graph, is not
used for authorization and has a 128 MiB estimated-data limit. When space is
needed, old records no longer needed by observed live executions are reclaimed
in batches, aiming for at most 112 MiB after admitting the new observation. A
pass that cannot create sufficient headroom is retried at a bounded rate. A
later directly observed execution can identify an older execution as
superseded; this observation is recorded separately from an observed exit time.

Pending history and audit work share a maximum of 1,024 entries and 32 MiB of
estimated payloads, with dedicated capacity for lifecycle facts and minimal file
access records. Records of denied requests wait in a separate lane of 512 entries
and 4 MiB: they never use the shared capacity, and no other record uses theirs.
Under load, an access record may omit its process lineage and state the reason.
If its lane is also exhausted, the record is dropped unless it repeats a record
waiting to be saved, which then counts it. Drops of denial records and of other
records, storage failures, combined requests and successfully stored minimal
records are reported separately; drops and failures are counted in requests. A
storage failure count represents an event that failed in at least one intended
log destination. These limits do not describe total resident memory.

The log store combines records of answered file requests inside policy folders.
Each process instance (process ID and execution number) has at most one record
waiting, for up to one second after its first request. Later allowed requests
with the same per-policy decisions under the same policy revision are counted in
it whatever their target; any other request only when it repeats the request
exactly. A different record from that process saves the waiting one first, so
each process's records keep their order. The saved record keeps every field of
the first request, including its process lineage, and adds the optional
`requestCount` and `lastTimestamp` fields. At most 256 records and 8 MiB wait at
a time, outside the queue budget; beyond that the oldest is saved early. Reading
a log, changing the policy set and a normal stop of the extension (`SIGINT` or
`SIGTERM`), which closes the store, save waiting records; records still waiting
when the extension ends without that stop, such as in a crash, a forced kill or
a loss of power, are lost without being counted. A repeat is matched after the
extension has answered macOS, before its history snapshot is built.

Process lineage is an observation, not a complete reconstruction. Ancestors that
predate observation, lost events and storage limits remain explicit. macOS's
responsible-process attribution does not prove which application sent a request.

## Lifecycle

An active system extension can keep protecting files after the app quits.
The login option starts the app only; it is not the protection service itself.
An update uses the complete PKG so both the app and maintenance service change
together. The PKG doesn't replace the extension itself; its last script opens the
installed app for the user logged in at the screen, with that user's identity, so
the replacement happens during the installation. Installations with the
`installer` command or with nobody at the screen leave this to the next launch.
On launch, the app requests an extension replacement only when its
embedded build is newer than an active installed build and removal or approval
state permits it. macOS may require approval. The extension's Info.plist sets
`NSEndpointSecurityRebootRequired`, and Endpoint Security refuses to stop a
running extension that has the key, so macOS starts the new version only at the
next restart; deactivation and removal likewise finish at the restart. Until
then the earlier extension keeps running with its execution histories and
checks requests, so no program loses its history and requests stay checked
without a gap. macOS reports neither version as enabled meanwhile: the earlier
one as being removed and the new one as neither enabled, being removed nor
waiting for approval. It reports a removed version that has already stopped in
the same way, so the app takes the protection state from the status that the
running extension answers over the authenticated connection, which names the
extension's version, and shows that a restart finishes the update. It derives
the waiting update from the installation states each time it reads them, so the
notice survives quitting and reopening the app. While nothing is enabled the app
requests no further replacement, so a package installed during the wait is
requested only after the restart and needs a second one. The build check
refuses an extension Info.plist without the key.

The app reads two sources at different rates. Every 2 seconds it asks the
running extension for its status over the authenticated connection. It asks
macOS for the installation states with an `OSSystemExtensionRequest` properties
request only at launch, before and after its own activation and deactivation
requests, as soon as macOS reports that an activation request waits for the
user's approval, on a Refresh command, every 5 seconds while the setup
assistant waits for approval, every 15 seconds while Settings → Extension is
open, within seconds after the extension starts or stops answering or restarts,
and otherwise once a minute; in between it uses the states macOS reported last.
These intervals are measured from the start of the previous query and checked
every 2 seconds, so they can run a second or two longer. The
SystemExtensions framework tears a properties request down only when it fails.
On macOS 27.2 an answered request stays registered with
`OSSystemExtensionManager` and keeps its connection to `sysextd` open until the
process that sent it exits, and `sysextd` holds a transaction for each such
connection, so frequent requests from a long-running process accumulate in
both processes.

The app therefore never sends a properties request itself. For each query it
starts its own executable directly, without a shell, as a child process with the
internal command `--pasu-fs-host --installation-states --json`. The child sets
up no user interface, sends one properties request, writes the answer to its
standard output as one JSON object and exits, which closes its connection to
`sysextd`. The object holds a format version and an outcome: `reported` with
each installation's bundle identifier, version, build and whether it is enabled,
waits for approval or is being removed (`isEnabled`,
`isAwaitingUserApproval`, `isUninstalling`); `failed` with the kind of failure
and, for an error from macOS, its domain, code and description; or `timedOut`
when the child itself waited 30 seconds. The exit status is 0, 2 or 3
respectively. A child whose app has quit exits at once. The app reads only
this output; output in another format, or one whose outcome doesn't match the
exit status, counts as a failed query, as does a child that can't start or ends
without an answer. Activation, update and
deactivation requests stay in the app, because the framework tears them down
when they complete. The app gives them a queue of their own rather than the
main queue: when a deactivation needs administrator approval, the framework
waits on the request's queue until the password dialog is answered, and the
app's status checks run on the main queue.

One query manager in the app runs every query, for the schedule, the Refresh
commands, the checks before and after lifecycle requests and the checks that
the extension stopped or that its removal waits for a restart. It runs at most
one child at a time. Queries while a child runs share its answer, except the
checks after the app's own activation, update or deactivation request, which
wait for a child that starts after the request, so that they never take an
answer from before the change. A child that hasn't exited 20 seconds after it
started is ended with SIGKILL, and once it has ended the query counts as
unanswered: the app reports that macOS isn't reporting the states. While macOS
doesn't answer, a new child starts at most once a minute, measured from the
start of the unanswered one, whatever asks for it, Refresh commands included;
scheduled checks wait twice as long after each further unanswered query, up to
10 minutes. Any answer from macOS, even an error, ends these limits.

Reported installation states describe the Mac for 90 seconds, and only while no
later query failed or went unanswered. Outside that window they are unknown,
never a missing or removed extension: the protection state comes from the
status that the extension answers over the authenticated connection alone,
which shows that the extension runs, and the installation rows show that the
state can't be confirmed. Before macOS has reported any states, the app does the
same. The command-line `--status` runs in its own short-lived process, sends
the properties request there, and stops waiting for it after 20 seconds.

Whether the running extension's Info.plist has
`NSEndpointSecurityRebootRequired` decides when a replacement takes effect: an
update to a version without the key would also wait for a restart, and the
update from a version that lacks it, 0.10.3 or earlier, replaces the extension
at once. That replacement extension starts with an empty execution history.
Protection policies deny requests with incomplete history unless a compatibility
profile admits them. Affected programs need a new observed launch; Apple platform
binaries that launchd started directly can regain a history (see [Policies
and process identity](#policies-and-process-identity)). The app records the boot
session of the replacement in its preferences and recommends a restart until the
Mac has been restarted. It shows the recommendation only while a saved
Protection policy's list decisions depend on a complete history, that is, one
whose allow list is off or has a rule in use. Audit policies block nothing; an
empty allow list already denies requests through the lists, and active
compatibility profiles remain exceptions.

Uninstall requests a fresh administrator authorization, removes the extension,
verifies its state, unregisters the current user's login item and then authorizes
file cleanup. macOS removes a running extension only at the next restart, so the
app records that the removal waits for a restart and remains available to finish
it afterward. It skips the deactivation request only when macOS already reports
every version as being removed. While an update waits for a restart, the waiting
version is not, and a deactivation request makes macOS remove it at once;
without the request macOS would start it at the restart, and the removal would
need a second restart. The maintenance service never takes arbitrary deletion
paths from policy rules or clients.

Each privileged operation (activating the extension, deactivating it,
uninstalling, and saving a policy change that reduces protection) has its own
entry in the macOS authorization database. Every entry
requires a fresh, non-shared administrator authentication that is never cached.
The installer registers the entries as root after each installation, so their
rules and the prompt text macOS shows in each app language match the installed
app. The app and the command-line tool add an entry only when it is missing and
refuse one whose rule was changed. Uninstall removes the entries.

For a policy save, the app decides locally whether the change reduces protection
and, if so, transfers a fresh authorization session with the policy set. The
extension makes the same decision against the stored set and verifies the
session as root before storing a weakening change; macOS shows the password
dialog meanwhile. A canceled or failed authentication is reported as a distinct
error and leaves the stored policies and the app's draft unchanged.

### Startup

The extension's Info.plist sets `NSEndpointSecurityEarlyBoot`, and the build
check refuses an extension Info.plist without it. At startup macOS then starts
the approved extension early and holds every mount and the start of every
program that is not an Apple platform binary until the extension's first
subscription; Apple platform binaries keep starting. If no subscription comes,
macOS ends the hold after a timeout of its own, whose length Apple doesn't
document.

Before its first subscription the extension works only with what the startup
volume holds. It removes a retired policy file, loads the stored policies,
checks the policy folders, prepares the authenticated XPC listener, which reads
the installed app's code signature, and starts the five-second folder check.
The listener accepts a connection whose code signature meets the designated
requirement of the app bundle at the path named by the extension's Info.plist
key `PasuFSExpectedHostApplicationPath`, `/Applications/Pasu FS.app`, or that
of the `pasu-fs-host` executable inside it; the extension reads both
requirements from the installed files, which must be owned by root and not
writable by the group or others. Without the key, or without a signed app at
that path, the extension keeps running and checking requests but creates no
authenticated listener, so the app cannot connect, and its status warns
`Authenticated XPC unavailable`. The app must therefore stay at that path.
It then creates the Endpoint Security client, sets the missed-deadline mode,
inverts target path muting, prepares the stored policies, registers their
paths, creates its decision state with those policies and with the moment
observation starts, and subscribes once to the process events (`NOTIFY_EXEC`,
`NOTIFY_FORK` and `NOTIFY_EXIT`) together with the eighteen authorization
events and the two notifications that the policies need. None of these steps
waits for the network, a user session, the app or a volume mounted later;
preparing a policy reads its folder and the folder's volume and looks up the
account that owns the folder, which for a local account also stays on the
startup volume. The first request of a held program therefore finds the
policies in effect, and no event a policy needs is subscribed later. See
[verified configurations](building.md#verified-configurations) for the tested
startup conditions. Without stored policies, or when they can't be prepared,
the first subscription names the process events alone,
and the policies' events follow when policies are applied.

Mounts are held too, so a policy folder on a volume other than the startup
volume can be missing while the policies are prepared. A stored policy whose
folder is missing keeps its path protected and is reported as missing (see
[Following a moved folder](#following-a-moved-folder)). Once such a volume is
mounted at the same place, its requests at the policy's path are checked, and
the next folder check, within five seconds, finds the folder. A Protection
policy denies a mount at its folder or at a folder that contains it, so a
volume holding a Protection policy's folder is not mounted at all.

The extension logs (category `endpoint-client`) and reports in its status
(`endpointConnection`) when it created its client and made its first
subscription, each also in seconds after the Mac started, as `kern.boottime`
gives it, how many event types the first subscription named, whether it
included the policies' events, and its latest failure to connect. If creating
the client fails with an error that can pass, such as missing Full Disk
Access, the extension tries again every 10 seconds; if the subscription fails,
it deletes the client and does the same. Until a subscription succeeds, each
failure's log entry notes that macOS keeps holding mounts and programs until
its own timeout.
