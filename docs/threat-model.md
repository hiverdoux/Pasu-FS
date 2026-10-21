# Security boundaries

Pasu FS provides an additional application-based check on supported file
requests.
It is intended to reduce access by unapproved applications running under the same
macOS user account. It does not replace macOS permissions, privacy controls,
App Sandbox, System Integrity Protection or disk encryption.

## Conditions for protection

A protection claim requires all of the following:

- A correctly signed, entitled and approved system extension is active.
- Full Disk Access is granted and the Endpoint Security client is healthy.
- A valid Protection policy covers the target path.
- The operation is a supported new request: an open, creation, rename, deletion,
  hard link, clone, `copyfile` copy, truncation, data exchange, metadata change
  or mount (the Endpoint Security `AUTH_OPEN`, `AUTH_CREATE`, `AUTH_RENAME`,
  `AUTH_UNLINK`, `AUTH_LINK`, `AUTH_CLONE`, `AUTH_COPYFILE`, `AUTH_TRUNCATE`,
  `AUTH_EXCHANGEDATA`, `AUTH_SETMODE`, `AUTH_SETOWNER`, `AUTH_SETFLAGS`,
  `AUTH_SETACL`, `AUTH_SETEXTATTR`, `AUTH_DELETEEXTATTR`, `AUTH_SETATTRLIST`,
  `AUTH_UTIMES` and `AUTH_MOUNT` events).
- macOS delivers the request to the extension, and the extension can evaluate
  and answer it within macOS's event deadline. macOS delivers only requests at
  the paths the extension registered for the policies; see
  [Request delivery](architecture.md#request-delivery). Under heavy load macOS
  can drop requests. Before macOS 27 it allows them; on macOS 27 and later,
  where the extension sets the fail-closed mode, it denies them. See
  [Known limitations](#known-limitations).

The app's authenticated live state is the source for its protection display.
A successful installer, signature verification or unit test alone proves none of
these runtime conditions. Audit mode never blocks access.

## Identity and rules

Rules match exact signing identities. A signed non-platform program must match
both its developer team and signing identifier. An Apple platform rule also
requires the kernel's platform-binary fact. Paths and display names in a log are
informational; they are not sufficient authorization.

While a policy's allow list is on, the observed first ordinary program must
directly match it. The program making the request must match directly or inherit
access from an observed ancestor whose allow rule enables descendant access.
The original origin check is required in either case. An ordinary
program matching the deny list anywhere in the observed history denies the path,
even after exit or executable replacement. Specifically authenticated system
intermediary roles skip only their own matching; Apple signing alone is not an
exemption. Missing history cannot be repaired by a later direct allow match.

A process the extension has not seen start begins a complete history in one
case: the kernel reports it as an Apple platform binary with a valid signature
whose original parent and current parent are both launchd (PID 1), created by a
fork before observation began. Its history then begins as an observed launch by
launchd would: its current program is the first program, unless it is a system
intermediary, and the lists decide. This restores a history; it allows
nothing by itself. Programs from other developers, processes forked after
observation began, processes reparented to launchd and processes whose parent
is a debugger never qualify.

Descendant access delegates a folder's access to tools selected by the allowed
program, including unsigned tools. It does not restrict their command arguments
or script contents. Grant it only to programs whose downstream work should have
that access. The grant is confined to observed creation and executable replacement
within that policy; an unrelated process with the same tool identity receives
no inherited permission. Disabling a grant revokes future checked requests, not
existing file descriptors or data already read. Enabling a grant also applies
to already running descendants with complete retained history, while preserving
the first-program and deny-list checks. A service accepting external
requests may hide the requester from this history, as described below.

A system-compatibility profile turned on for a policy is the exception to the
history requirement for program-based decisions. It lets specific Apple system
processes make specific request types in that policy's folder without an observed history or an allow
rule. The kernel must report them as Apple platform binaries with the
profile's signing identifiers; they must run as root or, where the profile
allows it, as the user who owns the folder; and launchd must have started them
without a user-session program in between: with a complete history the first
program must itself belong to the profile, and without one the kernel must
report launchd as the original parent, or as the original parent of the
profile program that forked the process and is still its parent. A program in
the block list anywhere in the observed history still denies. Turning a profile
on in a Protection policy needs administrator authorization, and so does
turning it on again after an update changed what it allows.

Overlapping Protection policies combine restrictively: every matching policy
must allow. An allow list that is on but has no enabled rule grants no access
through the list; an active compatibility profile can still admit matching
requests. Turning the allow list off disables both allow checks
while retaining the list; an empty deny list adds no program restriction but still requires valid
history. Pasu FS allowing a request does not override macOS or another security
component. Program launch itself is not blocked.

## Known limitations

- The extension handles the eighteen request types listed above. Opening a
  folder to list its contents is such an open and is checked. A deletion, data
  exchange, clone or `copyfile` copy whose source is a policy's folder or a
  folder that contains it, and a rename of the policy's folder itself, is
  checked like a request inside the folder, by the same lists. A rename of a
  folder that contains a policy's folder is allowed for every program; see the
  item on following a moved folder below. Memory mapping and other operation
  types are not checked. Each check applies only to the request macOS reports;
  a copy made with ordinary reads and writes is checked by its opens and its
  creation.
- Metadata changes (permissions, owner, file flags, access control list,
  extended attributes, attributes set with `setattrlist`, and times) are
  checked on the policy's folder itself and on every item inside it, including
  changes made through an open file descriptor. They stop a program outside
  the lists from granting other accounts access by changing permissions or
  access control lists, from locking a file so that allowed programs can't save
  it, from removing or forging extended attributes such as the quarantine
  attribute, and from forging modification times. The cost is that such
  programs can't change metadata there either: Finder, while it is not
  allowed, can't add tags (it asks for an administrator password instead), and
  commands such as `touch`, `chmod`, `xattr` and `tmutil addexclusion` fail
  inside the folder. A metadata change to a folder that contains the policy's
  folder is not checked: removing that folder's permissions can make the
  protected folder unreachable for allowed programs, but does not expose its
  contents, because the protected folder's own permissions are checked. The record names the changed item and the type of
  change, not the new value or the extended attribute's name.
- macOS services also change metadata on behalf of programs, and a profile
  admits only the requests it lists. When an app whose container is protected
  starts, the container manager tries to set an extended attribute on the
  container; the App Container Management profile allows only opens for
  reading, so the request is denied and recorded, and the app still starts.
  When an allowed app opens a document in a protected folder, the Spotlight
  service `mdwrite`, which writes metadata such as the date a document was
  last opened, is denied when it opens the document, so the document does not
  get that date. The log does not record which extended attribute a denied
  request would have written.
- Reading metadata is not checked: a program outside the lists can read the
  size, times, permissions, flags, access control list and extended attributes
  of an item in a protected folder whose path it knows, for example with
  `stat`, `ls -l@` or the `getxattr` system call, without opening the item.
  (The `xattr` command opens the item first, so that open is checked and
  denied.) It can't list the folder's contents that way, because listing needs
  an open, which is checked. Store confidential information in file contents,
  not in names or extended attributes.
- A mount whose mount point is a policy's folder, a folder inside it or a
  folder that contains it is denied for every program while the policy is in
  Protection mode, and recorded without denial by an Audit policy. The same
  holds for the policy's retired paths, described below. The program
  lists do not apply: macOS performs every mount through its own system
  processes, so the program that asked for it cannot be identified. While such
  a volume is mounted, the original folder and everything below it cannot be
  reached by path, and files written at that path land on the mounted volume
  instead. Mounting a disk image needs no administrator privileges, so this
  check stops an ordinary program from hiding or redirecting a protected
  folder. An administrator who needs such a mount can switch the policy to
  Audit mode or remove it; both changes require administrator authorization.
  The check applies to any volume, including one that macOS mounts at login,
  so a protected folder must not lie on a volume that is mounted below the
  startup volume's root after the extension starts, such as a home folder kept
  on its own volume. Remounting with other options, and the device or server a
  volume is mounted from, are not checked. When a volume that held a policy's
  folder is unmounted, the extension reports the mount point in its status
  until the policies are saved again, and reports the folder as missing while
  it can't be found; the policy keeps naming the old path.
- APFS snapshots and Time Machine backups contain copies of protected folders,
  and those copies are not protected. Time Machine reads the folder through a
  snapshot path, so the backup is made without a check or a log entry, and the
  copy on the backup disk can be read by the same user account without a check.
  A mounted snapshot is not protected either: any user account can create a
  local snapshot, and on a Mac with System Integrity Protection disabled any
  user account can mount it and read the copy. With System Integrity Protection
  enabled, macOS refused the snapshot mount for an ordinary user account in
  testing. Exclude a protected folder from Time Machine by its path (`sudo
  tmutil addexclusion -p`), or treat the backup disk as sensitive, when its
  contents must stay private. An exclusion made without `-p` is an extended
  attribute of the folder, so it is denied while the folder is protected.
- Restoring into a protected folder is checked like any other write.
  `tmutil restore` writes the files itself and is decided by
  the lists of its own history; a restore from the Time Machine screen and an
  ordinary Finder copy are both written by `DesktopServicesHelper`, a macOS
  service that launchd starts as root, and not by Finder. A Finder allow rule
  therefore does not allow Finder copies or Time Machine screen restores on its
  own; the Finder Copy compatibility profile admits the service (see below).
  See [System compatibility](using.md#system-compatibility) for verified and
  unverified copy and restore operations. Restoring with Migration Assistant
  has not been tested.
- macOS excludes a fixed set of its own system processes from Endpoint Security
  monitoring, so their requests never reach the extension. One of them,
  `cfprefsd`, reads and writes property list files on behalf of any program:
  the `defaults` command or the preferences API can read or create a `.plist`
  file inside a protected folder without a check or a log entry. Keep property
  list files that must stay private out of protected folders, or store them in
  another format.
- A policy save requests a storage-device flush (`F_FULLFSYNC`) before the
  extension answers it. On storage that supports this flush, a successful
  response confirms the new commit is durable. If power is lost before the
  response arrives, either the previous or new revision may be stored: the
  commit can finish before its response reaches the app. After restarting,
  check the policies and their revision before retrying. Unsupported flushes
  fall back to filesystem synchronization without confirming that the device's
  own cache was flushed; see [Storage and logs](architecture.md#storage-and-logs).
  The status file and logs are not flushed to the device this way, so their
  latest records can be missing after a loss of power.
- Existing file descriptors or mappings are not revoked. Protection is not a
  record of every individual read or write.
- An allowed program can copy, transmit or reveal information it reads. Attacks
  inside a trusted program and services accepting commands from other programs
  may not preserve the requesting program in their generation history. Same-process
  script contents and universal IPC delegation are not checked.
- A policy follows its folder by identity, the volume and the file number,
  when the folder or a folder that contains it is renamed or moved within its
  volume, including a move made while the extension was not running. Renaming
  or moving a folder that contains a policy's folder is therefore allowed for
  every program: the files stay protected at the new path, which the extension
  protects together with the old path from the moment it allows the rename
  until it has confirmed where the folder is. Moving a folder to another volume
  copies and deletes it and is not followed. A folder that can't be found keeps
  its last path protected and is reported in the status; if another folder
  later appears at that path, the policy protects it. A rename performed by a
  process that macOS excludes from Endpoint Security monitoring, or a folder
  exchanged with another in a single atomic rename, is followed at the latest by
  the periodic check every five seconds, and its new path is not protected in
  between. Preexisting hard links and other aliases can expose the same data
  through another path.
- Once a policy follows its folder, the former path becomes a retired path of
  the policy until the policy is saved from the app. This keeps a program that
  still uses the former path, for example because it stored that path in its
  settings, from being redirected: a program the policy would deny inside its
  folder is denied every checked request at the retired path and below it;
  creating an item, or renaming, moving, cloning, hard linking or copying one,
  at the retired path or at a folder on the way to it, which would recreate the
  path or point it elsewhere through a symbolic link; and renaming, moving,
  deleting, cloning or copying a folder that contains the retired path but not
  the policy's folder. A mount over it is refused. Allowed programs keep
  working there, and each of their requests is logged with the retired path as
  a warning. A rename of a folder that contains both the policy's folder and a
  retired path is still allowed for every program and moves the retired path
  with it. Retired paths are not protected after the policy is saved, which
  needs no administrator password, or after the policy is deleted. A policy
  keeps eight retired paths; when its folder moves again, the oldest is
  released. A move to another volume is not followed and leaves no retired
  path. A rename the extension did not observe, such as one made while it was
  not running, does not move the retired paths inside the renamed folder, so
  what allowed programs saved there is no longer protected at its new location.
  Retired paths are compared as strings, like policy folders, so preexisting
  hard links and other aliases are not covered.
- Path comparison uses the selected volume's reported case rules. Unsupported or
  unavailable volume/account metadata prevents preparing a policy. Network and
  unusual filesystem behavior needs separate runtime validation.
- Requests outside the policies' folders, retired paths and the folders on the
  way to them never reach the extension: macOS delivers only requests whose
  target path matches a path the extension registered, and allows the others
  without asking. macOS compares these paths byte for byte, while policies
  compare names with the volume's case rule. The extension registers each
  path in the spelling stored on disk, follows a folder whose name, or the name
  of a folder containing it, changes only in letter case or Unicode
  composition, and has requests that place an object near a missing path
  delivered, so that a differently cased name created there is checked. One
  gap remains: when an allowed program recreates a retired path or a missing
  policy folder in another spelling, or renames a folder on the way to a
  retired path changing only its spelling, opens, truncations and metadata
  changes at the new spelling are not delivered until the next folder check
  registers it, at most five seconds later and usually at once after a rename.
  A file opened through a hard link outside every registered path is not
  delivered either, which matches the existing limit for hard links. The
  processes that macOS excludes by default, described above, stay excluded.
- Use with iCloud Drive has not been tested, including the Desktop & Documents
  Folders option, which relocates those folders, and the sync processes that
  create, rename and delete files on the user's behalf. Keep protected folders
  outside iCloud-synced locations until this is verified.
- Truncated or undecodable in-scope requests are denied by Protection policies,
  but incomplete paths can limit the ability to identify the matching scope.
- Pre-observation processes, lost lifecycle events and exhausted security-state
  limits cannot acquire authority merely through a direct signature match.
  Relaunch from an observed system origin is required to establish a new history.
  The exceptions are a system-compatibility profile, described above, and an
  Apple platform binary that launchd forked before observation began and that
  is still its child, whose history begins with its current program (see
  [Identity and rules](#identity-and-rules)). Such a history is only as
  complete as the kernel's facts: if the process replaced an earlier program
  with its current one before observation began, the earlier program is
  unknown, and a block rule for it does not deny. At startup, programs that are
  not Apple platform binaries can't run before the extension subscribes (see the
  next item), so such an earlier program can only be another Apple platform
  binary; after the extension restarts while the Mac keeps running, or after
  macOS's early-boot timeout, it can be any program that launchd started. The
  comparison with the start of observation uses the wall clock, as the kernel
  records a process's start: a clock set back after observation began could
  make a process forked later look older, which matters only for a process
  whose fork and start the extension did not receive. An extension update no
  longer causes a pre-observation gap, except the update from 0.10.3 or earlier,
  described below.
- The extension's Info.plist sets `NSEndpointSecurityEarlyBoot`. At startup
  macOS holds every mount and the start of every program that is not an Apple
  platform binary until the extension's first subscription. The extension
  prepares the stored policies, registers their paths and sets up its decision
  state before that subscription, which names the process events and every
  event the policies need at once, so no request of a held program meets an
  unprepared extension. Apple platform binaries are not held: macOS services
  start and make requests before the subscription, and those requests are not
  checked. If the extension can't subscribe, macOS holds mounts and programs
  only until a timeout of its own, whose length Apple doesn't document, and then
  lets them start unchecked; the extension tries again every 10 seconds and
  logs each failure. Volumes other than the startup volume are mounted after
  the subscription, so a Protection policy whose folder is on such a volume
  denies that volume's mount at startup, as described in the mount item above.
  Early startup has been checked only on macOS 27.0.1 with an approved system
  extension and System Integrity Protection disabled. Earlier macOS versions
  and normal SIP-enabled installation remain unverified; see
  [verified configurations](building.md#verified-configurations).
- An extension update, a deactivation and a removal take effect only at the
  next restart. The extension's Info.plist sets
  `NSEndpointSecurityRebootRequired`, and macOS then doesn't stop the running
  extension: it keeps checking requests with its execution histories until the
  restart, so the programs that were open keep their histories and no requests
  go unchecked during the update. In exchange, a fix in the new version,
  including a security fix, has no effect until the Mac restarts, however long
  that takes, and the updated app works with the earlier extension meanwhile
  (see [Update](installation.md#update)). macOS follows the setting of the
  running extension, so the update from 0.10.3 or earlier, which lacks it,
  still replaces the extension at once: the new extension starts with empty
  execution histories, and Protection policies deny the programs that were
  already open until they start again, apart from the Apple platform binaries
  that launchd started directly and requests admitted by compatibility profiles.
  Update behavior also remains unverified with System Integrity Protection
  enabled or on earlier macOS versions; see
  [verified configurations](building.md#verified-configurations).
- Under heavy load macOS drops messages to the extension instead of delivering
  them. A lost process start, fork or exit marks the retained execution histories
  incomplete. Protection policies deny requests that depend on those histories
  unless a compatibility profile admits them; affected programs need a new
  observed launch. A lost message of any other kind leaves the histories intact.
  macOS answers a lost authorization request without the
  extension seeing it, and nothing tells afterwards which file it named. Before
  macOS 27 macOS allows it. On macOS 27 and later the extension sets the
  fail-closed mode, and macOS denies it instead, whichever program made it. The
  extension counts these as unchecked requests, shows them under **Needs
  attention** and in Diagnostics, and logs when they happened. The count is an
  upper-bound estimate: macOS numbers the messages overall and per event type,
  which tells how many messages were lost but not which kinds. The extension
  subtracts the process notifications found missing at the same time and counts
  the rest, which can still include other notifications (see
  [Dropped messages](architecture.md#dropped-messages)). Before macOS 27 a
  program that floods the Mac with file requests can therefore get some
  requests allowed, but not without the count rising; on macOS 27 and later the
  flood gets requests denied instead, including those of allowed programs.
  File requests outside the registered paths never reach the extension's
  queue; a flood of requests at a protected folder, and the process starts,
  forks and exits of every program, still do.
- When the extension misses a request's deadline, macOS 27 and later deny the
  request and keep the extension running; the extension shortens that deadline
  to 3 seconds. Before macOS 27 macOS waits until its default deadline, then
  stops the extension, allows the request and starts the extension again: requests are
  not checked while it is stopped,
  and the new extension starts with an empty execution history, so Protection
  policies deny programs that were already running until they start again,
  apart from the Apple platform binaries that launchd started directly and
  requests admitted by compatibility profiles. On
  macOS 27 and later an extension that stops answering without exiting is not
  restarted: every request delivered to it is denied 3 seconds after it is
  made, requests for the same file wait behind each other so that each
  further one takes another 3 seconds, and this continues until the extension
  exits or the Mac restarts. Programs that use a policy folder, the allowed
  ones included, then fail, and so does every mount. The app shows the extension
  as not responding under **Needs attention**; restart the Mac to recover.
  When the extension exits, by a crash or a restart, macOS allows the requests
  that were waiting for it, even on macOS 27, so the extension doesn't end
  itself when it stalls. A request macOS decided at its deadline has a log
  record only if the extension handled it afterwards; the record keeps the
  extension's decision, and the app shows what macOS did according to the
  current setting. If the fail-closed mode can't be set or confirmed, the
  extension keeps the kill mode of earlier macOS versions, and Diagnostics
  shows the error. Deadline behavior has not been verified under normal
  SIP-enabled system extension installation; see
  [verified configurations](building.md#verified-configurations) and
  [Missed deadlines](architecture.md#missed-deadlines).
- A system-compatibility profile widens the folder's trust to the Apple
  services it names, and those services act for other programs too: any
  program can ask the container service to prepare the container of an app it
  controls. Pasu FS sees only the service's request, not the program that
  caused it. App Container Management and XProtect Malware Scanning allow only
  opens for reading.
- XProtect Malware Scanning admits XProtect's analysis service running as root,
  which reads whatever item `syspolicyd`, the Gatekeeper daemon, asks it to
  check, such as software being installed or run. A program that installs or
  runs software in a protected folder can thus cause the service to read it.
  The service returns a verdict to Gatekeeper, not the file contents. Pasu FS
  does not authenticate that service's clients, and direct use by other client
  types has not been exhaustively evaluated. The copy of the service that runs
  as the user for Gatekeeper's agent is not admitted.
- The Finder Copy profile admits `DesktopServicesHelper`, which copies whatever
  source and destination Finder chooses. While it is on, a Finder copy,
  duplicate or restore from the Time Machine screen that writes into the folder
  is allowed, and so is a Finder copy of items out of the folder, or of the
  whole folder, to any location the user can write to. The helper may also
  write and remove extended attributes of the items it copies. Finder's own
  requests are still decided by the lists, but the profile does not depend on
  them: with Finder not in the allow list, Finder's listing of the folder is
  denied and the folder looks empty, yet a paste into it is written and the
  folder can be copied as a whole. The profile does not admit requests outside
  its enumerated types and open flags; the ordinary program rules can still
  allow them. See [System compatibility](using.md#system-compatibility) for
  runtime coverage. Pasu FS can't tell who started a copy in Finder: the person
  at the Mac, or a program that controls Finder's
  interface, for example through Accessibility permission. No profile covers
  `DesktopServicesScriptingHelper`, which handles scripted Finder operations,
  and the catalog refuses to include it: the policy's lists decide those
  requests, which have not been verified end to end. Pasu FS does not
  authenticate the copy helper's clients. Other client types have not been
  exhaustively evaluated; if another client uses this helper, its matching
  requests receive the same profile allowance.
- Some services a profile admits run as the logged-in user: the container
  manager, `secinitd`, the XProtect plug-in service and its remediators, and
  `DesktopServicesHelper` once it has joined the user's session.
  A program running under the same user account can start one of these Apple
  programs as its own launchd job, and that process meets the profile's
  conditions. The effect is limited: the programs are hardened platform
  binaries, so no code can be injected into them; on a Mac with System
  Integrity Protection enabled, such a job can't take over the name of the
  system's own service, so other programs keep talking to the real one; and
  the remediators exit at once when they are not started by the plug-in
  service. These services also act on requests that programs of the same
  account send them over XPC, so the same exposure exists whatever their
  lineage. Root processes started by a launch daemon that an administrator
  installed meet the conditions as well; installing one is an administrator
  action.
- For a process whose history is incomplete, only its original parent, and at
  most that parent's original parent, is checked, not the programs either of
  them ran before its current one. A profile's programs are listed by exact
  signing identifier, so a helper that a later macOS or XProtect update adds is
  not covered until Pasu FS updates the profile. Turn a profile on only for a
  folder that needs it.
- Protection is absent when the extension is inactive. Startup gaps, crashes,
  event loss and deadline failures are not a guarantee of continued denial,
  except where macOS 27 and later deny lost requests and missed deadlines as
  described above.
- Administrator actions, the Mac owner intentionally disabling protection,
  Recovery access, kernel compromise and offline disk access are outside scope.

## Privileged operations

Installation and removal require administrator authorization. State-changing
command-line operations request a new authorization for that operation; status
queries are read-only. Each operation's authorization entry requires a fresh,
non-shared administrator authentication. The installer defines the entries as
root, and clients refuse an entry whose rule no longer matches. Local component connections verify code signatures.
The maintenance service has no arbitrary shell command or arbitrary path-removal
interface. Removal checks ownership, avoids following symbolic links and refuses
to cross mounted filesystems.

Policy changes that reduce protection require the same authorization. The app
sends a fresh authorization session together with the policy set, and the
extension, running as root, checks the `policy.weaken` entry with one
administrator authentication before it stores the set. For a policy in
Protection mode this covers switching it to Audit, changing its folder, turning
the allow list off, allowing an additional program or letting an allowed program
pass its permission to descendant processes, turning on a compatibility profile,
and removing a block rule; deleting a policy is covered in either mode. Changes that only add restrictions, new
policies and changes to Audit policies are accepted from the authenticated app
without a password. A process that borrows the app's identity can therefore make
policies stricter but cannot weaken them without an administrator. The policy
request states its configuration protocol version, and the app and the extension
accept only their own version: an app and an extension from different versions
refuse to exchange policies instead of reading rules they don't understand, and
an older app that sends a bare policy set receives an error instead of a silent
downgrade.

Application files are installed at a fixed system location. The app and extension
must retain their configured signing identity during updates. Changing the team
or bundle identifiers requires separate installation planning.

## Privacy and retention

Policies and logs remain local. Logs contain sensitive metadata such as program
identities and file paths. Do not publish unredacted logs or development signing
profiles. No telemetry service is used by the policy engine.

Log queues and storage are bounded; dropped records and incomplete history are
possible. Denial records have reserved queue space and repeats of one request
are counted in a single record, but a program that sends denied requests for many
different files faster than they can be saved can still cause denial records to
be lost; the loss is counted. Logs are diagnostic evidence, not a complete
forensic audit trail.
The [removal guide](installation.md) explains which settings and logs are retained
or deleted. macOS may retain its own permissions and diagnostic history.

Report a concern using [the security policy](../SECURITY.md).
