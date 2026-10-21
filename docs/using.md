# Using Pasu FS

This guide explains each screen of the app. The app keeps its own text short;
the details are here. It uses the English names; with Korean as the preferred
language, the app shows the same items in Korean. For installation and removal,
see [install, verify, update and uninstall](installation.md). For what Pasu FS
can and cannot protect, see the [security boundaries](threat-model.md).

Each policy has two independent lists, **Programs to Allow** and **Programs to
Block**. The extension checks both the first program in the observed execution
history and the program opening the file; see [Behavior](#behavior).

## Setup assistant

The app shows a four-step checklist while the system extension (the component
that checks file requests) is not installed, waits for approval or Full Disk
Access, or runs without a saved policy for the first time. Nothing is protected
until every step is done. The app checks the extension's status every 2
seconds and, while the checklist waits for your approval, asks macOS for the
extension's installation state every 5 seconds, so it moves to the next step by
itself. The checklist closes as soon as you start creating
the first policy. When the extension is stopped or being uninstalled, the
Overview shows that state instead of the checklist.

When macOS doesn't answer a request for the installation state within 20
seconds, the checklist shows the same notice as the Overview, with **Show
Extension Settings…** (see [Troubleshooting](installation.md#troubleshooting)).
Until macOS answers again, an extension that answers over the authenticated
connection decides the step: it is installed and approved, so the checklist
shows the step that its own status calls for, such as Full Disk Access. Without
that answer, the app can't tell which step applies and shows the Overview
instead.

1. **Activate the system extension.** **Activate Extension** only sends the
   request to macOS; it does not approve anything. macOS then shows a notice
   that a new Endpoint Security extension wants to run, with a button that
   opens System Settings. As soon as macOS reports that the request waits for
   your approval, the checklist moves to the next step.
2. **Approve in System Settings.** macOS requires you to approve security
   extensions yourself. **Open System Settings…** opens the location shown in
   the step: General → Login Items & Extensions → Endpoint Security Extensions
   on macOS 15 and later, or Privacy & Security on macOS 14. Menu names can
   differ slightly between macOS versions. macOS may ask you to restart.
3. **Allow Full Disk Access.** Turn on **Pasu FS Endpoint Security** in
   Privacy & Security → Full Disk Access. The extension cannot start without it.
   When access is allowed, the extension starts on its own.
4. **Create your first policy.** **Create Policy** opens a new policy; see
   [Creating a policy](#creating-a-policy).

**Uninstall Pasu FS…** at the bottom of the checklist starts the same removal as
the Settings window.

## Overview

- **Status.** The title and the line below it describe the current state:
  - **Protecting**: at least one Protection policy is checking file requests. The
    line below counts the Protection and Audit policies in use.
  - **Auditing**: only Audit policies are active; nothing is blocked.
  - **No Active Policies**, **Starting**, **Waiting for Approval**,
    **Full Disk Access Needed**, **Stopped**, **Uninstalling** and
    **Not Installed** mean that files are not protected, or that protection
    is not confirmed yet. **Stopped** appears only when macOS reports no
    enabled extension and no extension answers over the authenticated
    connection.
  - **Uninstalling** with **macOS removes the extension when the Mac restarts.
    Until then, the extension keeps checking requests.** on the line below
    means that macOS removes the extension at the next restart and the
    extension still answers; its policies stay in effect until then.
  - **Needs Attention** shows the reason on the second line.
- While an extension update waits for a restart, the status is that of the
  extension that was running before the update. It keeps running and checking
  requests until the Mac restarts, although macOS reports no version as enabled
  meanwhile. See [Update](installation.md#update).
- The row below the status shows how the status was obtained. **Verified over
  an authenticated connection** with a recent age means the running extension
  answered the app directly. A status read only from the diagnostic file, or one
  more than 15 seconds old, cannot confirm protection. **Policy revision** is
  the number of the policy set the extension is using; each save creates a new
  revision.
- The app asks the running extension for its status every 2 seconds. It asks
  macOS for the extension's installation state (which versions are installed,
  enabled, waiting for approval or being removed) less often: when the app
  opens, before and after it asks macOS to activate, update or deactivate the
  extension, every 5 seconds while the setup assistant waits for approval,
  every 15 seconds while **Settings… → Extension** is open, a few seconds after
  the extension starts or stops answering, and otherwise once a minute. Between
  these requests the app uses the installation state macOS reported last, for
  at most 90 seconds. Each request comes from a short-lived process of the app
  that exits once macOS answers: on macOS 27.2 an answered request keeps a
  connection to the system extension daemon `sysextd` open until the process
  that sent it exits (see [Lifecycle](architecture.md#lifecycle)). **Refresh**
  in the toolbar, **View → Refresh** (⌘R) and **Refresh Status** in the menu bar
  ask macOS and the extension at once; a progress indicator appears next to the
  status until both have answered or 20 seconds have passed without an answer
  from macOS, and the command is unavailable meanwhile. While macOS doesn't
  answer, the app asks it at most once a minute, also on **Refresh**, and the
  automatic checks wait longer after each unanswered request, up to 10 minutes.
- The Overview does not list which requests are checked. The extension checks
  new requests to open, create, rename or move, delete, hard link, clone, copy
  with the `copyfile` system call, truncate and exchange files and folders in a
  policy's folder (the Endpoint Security `AUTH_OPEN`, `AUTH_CREATE`,
  `AUTH_RENAME`, `AUTH_UNLINK`, `AUTH_LINK`, `AUTH_CLONE`, `AUTH_COPYFILE`,
  `AUTH_TRUNCATE` and `AUTH_EXCHANGEDATA` events); requests to change the
  metadata of the policy's folder itself or of a file or folder in it: its
  permissions, owner, file flags such as **Locked**, access control list,
  extended attributes (which hold, for example, Finder tags), other attributes
  set with `setattrlist`, and access or modification times (`AUTH_SETMODE`,
  `AUTH_SETOWNER`, `AUTH_SETFLAGS`, `AUTH_SETACL`, `AUTH_SETEXTATTR`,
  `AUTH_DELETEEXTATTR`, `AUTH_SETATTRLIST` and `AUTH_UTIMES`); and mounting a
  volume at the policy's folder, inside it or at a folder that contains it
  (`AUTH_MOUNT`). Opening a folder to list its contents is also a file open.
  Renaming or moving the policy's folder itself, and deleting, cloning or
  copying it or a folder that contains it, is checked in the same way. Renaming or moving a
  folder that contains the policy's folder is allowed for every program, and
  the policy follows its folder (see
  [Moving a protected folder](#moving-a-protected-folder)); the folder's
  previous path is then checked as a [retired path](#retired-paths) until the
  policy is saved. A mount at those
  locations is
  refused for every program, including the programs in **Programs to Allow**,
  because the mounted volume would hide the folder; to allow one, switch the
  policy to **Audit** or delete it. Memory mapping and reading metadata, such
  as a file's size, times or extended attributes, are not checked, and neither
  is a metadata change to a folder that contains the policy's folder. Nor are
  the copies of a protected folder in APFS snapshots and Time Machine backups,
  and neither are
  requests from the system processes macOS excludes from Endpoint Security
  monitoring, such as `cfprefsd`, which reads and writes property list files
  for other programs (see the [threat model](threat-model.md#known-limitations)).
  Use with iCloud Drive, including the Desktop & Documents Folders option, has
  not been tested; keep protected folders outside iCloud-synced locations.
  **Settings… → Diagnostics → Checked requests** shows the request types the
  running extension reports.
- **Needs attention** lists policy, policy storage, approval, restart, version,
  logging, [unchecked request](#unchecked-requests) and uninstall problems, and
  an extension that has stopped responding. Items that have a related screen
  show a button that opens it. **The extension isn’t responding (last status N
  ago). Restart this Mac.** appears when the app can't get a status from the
  running extension and the extension hasn't updated its status for 30
  seconds; it disappears once the extension answers again
  (see [Missed deadlines](#missed-deadlines)). While macOS reports no enabled
  extension, for example while an update or a deactivation waits for a restart
  and the earlier extension keeps running, it appears only after a status
  request has also gone unanswered for its 5-second timeout: a stopped extension
  refuses the connection at once, and only a running one leaves it unanswered.
  **macOS isn’t reporting the system extension state (for N). In Terminal, run
  “sudo killall sysextd”, or restart this Mac.** appears when macOS has not
  answered a request for the installation state within 20 seconds; N counts
  from the first unanswered request. Until macOS answers again, the version line
  reads **Version check unavailable** and the app keeps showing the status the
  extension reports over the authenticated connection. While the extension
  answers, the line below the item reads **The extension still answers, so
  protection continues.** (or **The extension still answers.** when no
  Protection policy is checking requests); without an answer, the status reads
  **Needs Attention** with **macOS isn’t reporting the system extension state.**
  The item disappears when macOS answers a later request; **Refresh** sends one
  at once, except within a minute of the start of the previous unanswered
  request. See [Troubleshooting](installation.md#troubleshooting).
  A notice that
  a volume holding a policy's folder was unmounted stays until the policies are
  saved again. A notice that a
  protected folder can't be found stays while the folder is missing; see
  [Moving a protected folder](#moving-a-protected-folder). A notice that a
  policy protects a retired path stays until that policy is saved; **Show
  Policy** opens it (see [Retired paths](#retired-paths)). See [Saved and in effect](#saved-and-in-effect) and
  [Policy storage states](#policy-storage-states). **The extension update
  finishes when you restart this Mac.** appears while macOS waits for a restart
  to start a newer extension; it stays when the app is reopened and disappears
  after the restart. **Show Extension Settings…** opens **Settings… → Extension**.
  After the app replaces a running extension with a newer one at once, which
  happens only on the update from 0.10.3 or earlier, **The extension was
  updated. Restarting this Mac is recommended.** appears here until the Mac
  restarts, while a saved
  Protection policy could deny the programs opened before the update: one with
  **Allow Only Programs in This List** off, or with at least one rule in use in
  **Programs to Allow**. Audit policies, and Protection policies whose allow list
  is in use but empty, don't show it: missing history does not change their list
  decisions, and active compatibility profiles remain exceptions. The item
  follows policy changes, so saving such a policy later in the same boot session
  shows it. See [Update](installation.md#update).
- **Policies** lists the saved policies with their mode and the number of
  rules in use in each list, for example **Allow 3 · Block 1**. A policy with
  **Allow Only Programs in This List** turned off counts only its block rules.
  **New Policy** at the right of the heading adds a policy (see
  [Creating a policy](#creating-a-policy)); while no policy is saved, the
  section shows **No active policies** with the same button.
- **Recent denials** shows the three newest requests that Pasu FS actually
  denied, taken from the newest 500 records of each policy's log. Audit results
  (**Would deny**) are not included. Select one to open it in its policy's log.
- The last line compares the app and extension versions; select it to open
  **Settings… → Extension**.

## Policies

A policy applies to one folder and everything inside it. Select a policy in the
sidebar to edit it on the **Settings** tab, or view its records on the **Log**
tab. A dot after a policy's name means it has unsaved changes. Changes apply only
when you choose **Save**; **Revert** discards them. Saving applies all policies
together as a new revision. The File menu offers the same actions as **Save
Policy** (⌘S) and **Revert to Saved**, plus **Duplicate Policy** (⌘D, see
[Creating a policy](#creating-a-policy)) and **Show Protected Folder in
Finder**. In the View menu, **Refresh** (⌘R) reloads the current screen (see
[Overview](#overview) for what it reads there) and
**Sort Programs By** chooses the order of the program lists (see
[Programs in the lists](#programs-in-the-lists)).

### Creating a policy

Choose **New Policy** (⌘N) in the File menu, the + button in the sidebar, or
**New Policy** in the **Policies** section of the Overview. An unsaved policy
named **Policy 1** (or the next free number) opens with its **Protected Folder**
field ready for typing. **Name** can be changed at any time; it must be unique
(ignoring case and accents), at most 80 characters, without leading or trailing
spaces. Every new policy starts in **Audit** mode with **Allow Only Programs in
This List** turned on: it blocks nothing and records which programs open the
files, so you can add the programs to allow before switching to **Protection**.
Change either setting at any time; see [Behavior](#behavior).

Enter a folder and choose **Save**. A policy can't be saved without a valid
folder, and nothing is applied until you save.

**Duplicate Policy** (⌘D) in the File menu adds an unsaved copy of the selected
policy and places it after that policy in the sidebar. The copy is named after
the policy with **copy**, or **copy 2** and so on when that name is taken,
shortened if needed to fit the name length. It has the same mode, both lists
with each rule's settings, the state of **Allow Only Programs in This List**
and the same compatibility profiles, taken from the policy as currently shown,
including unsaved changes, but no folder. Enter a folder and choose **Save**;
a new policy is saved without a password in either mode.

Up to 64 policies can exist at a time, unsaved ones included. At that limit,
**New Policy**, the + button in the sidebar and **Duplicate Policy** are
unavailable until a policy is deleted.

### Saved and in effect

Saving stores all policies in the extension as a new revision. The app then
checks that the extension reports that revision, with the same contents, as the
policies it is using. Until it does, the policy shows **Saved as revision N. The
extension has not confirmed that it is in effect.** and the Overview lists the
same message. This can last while the extension starts or when it could not
apply the stored policies; the status on the Overview shows the reason.

Before confirming a save, the extension asks the storage device to flush it.
If power is lost before you receive confirmation, either the previous or the
new revision may be stored. After restarting, check **Policy revision** on the
Overview and the policy's contents before saving again. See
[Storage and logs](architecture.md#storage-and-logs) for durability limits on
storage that does not support this flush.

If another change was saved after this app loaded the policies, the save is
refused. The app loads the saved policies again and keeps your unsaved changes;
save again. If the extension does not reply to a save, the app first reads what
was stored. A change that was stored is treated as saved, a change that was not
is reported, and while neither can be read the app does not save again, so a
second revision is never created for the same change. Saving also needs an
extension that reports support for the two lists; otherwise the app asks you to
update the extension.

### Changes that need an administrator password

A save that reduces protection is applied only after macOS has asked for an
administrator name and password. **Save** and **Save Policy** then end with an
ellipsis (**Save…**). Compared with the saved policy, these changes count when
the saved policy is in **Protection** mode:

- switching it to **Audit**;
- changing its protected folder;
- turning **Allow Only Programs in This List** off;
- adding a program to **Programs to Allow**, or turning a rule there back on;
- turning on **Include descendant processes** for an allow rule;
- removing a program from **Programs to Block**, or turning its rule off;
- turning on a [system compatibility profile](#system-compatibility), including
  turning one off and on again after it became inactive.

Deleting a saved policy asks as well, in either mode. A new policy, a change
to an Audit policy, switching to **Protection**, renaming, and every other
change that only adds restrictions are saved without a password. Saving a
policy without changes to release its [retired paths](#retired-paths) needs no
password either.

macOS shows the dialog while the extension checks the authorization. Every such
save asks again; the password is not kept. If you cancel the dialog or the
authentication fails, nothing changes: the policy keeps its unsaved changes and
the message **Administrator authentication was canceled. The policies were not
changed.** appears. Choose **Save…** again to retry, or **Revert** to discard
the changes.

### Protected folder

Use **Choose…**, drop a folder on the row, or select the path and type one.
A typed path is applied when you press Return or move to another field; Escape
restores the current path. `~` stands for your home folder. A path is stored
with symbolic links resolved, as when you choose the folder.

The folder must exist. Very broad folders are refused: `/`, `/Applications`,
`/Library`, `/System`, `/Users`, `/Volumes`, `/bin`, `/private`, `/sbin`, `/usr`
and your home folder itself. Two policies of the same mode can't use the same
folder. The folder button in the toolbar shows the folder in Finder.

### Moving a protected folder

A policy follows its folder when the folder, or a folder that contains it, is
renamed or moved within the same volume. When a policy is saved, the extension
records the folder's identity: the volume it is on and its file number on that
volume. After a move, the extension finds the folder by this identity, stores
the new path as the next policy revision and applies it. No administrator
password is needed, because the folder and its protection stay the same. The
app shows the new path within a few seconds. A policy with unsaved changes keeps
them; if those changes did not include another folder, the draft takes the new
path.

- **Who can move it.** Renaming or moving a folder that contains the protected
  folder, including moving it to the Trash, is allowed for every program, such
  as Finder or Terminal when they are not in **Programs to Allow**. The files
  stay protected at their new location. Renaming or moving the protected folder
  itself is decided by the policy's lists, like any other request inside it. A
  folder that contains one of the policy's retired paths, but not its folder,
  is reserved instead; see [Retired paths](#retired-paths).
- **During the move.** When the extension allows such a rename, it protects the
  folder's new path together with the old one before macOS carries out the
  rename, and keeps both until it has confirmed where the folder is. It checks
  as soon as macOS reports the rename, and again every five seconds.
- **Changing only the letter case.** Renaming the folder, or a folder that
  contains it, so that only the letter case or the composition of accented
  letters changes, such as `Documents` to `documents`, is followed like any
  other rename.
- **While the extension was not running.** A move made while the extension was
  stopped, for example during an update, is followed when the extension starts.
- **Other volumes.** Moving a folder to another volume copies it and deletes
  the original, so it is not a rename. The copy needs a program that is allowed
  to read the folder, the deletion is checked like any other, and the policy
  does not move to the copy.
- **A missing folder.** When the folder can't be found anywhere, for example
  because it was deleted or its volume is not mounted, the policy keeps
  protecting its last path and the Overview shows that the protected folder
  can't be found. When the volume is mounted again, the policy finds the folder
  and the notice goes away. If the original folder is gone and a new folder is
  created at the same path, the policy protects the new folder.
- **The Trash.** A protected folder moved to the Trash stays protected there.
  Emptying the Trash deletes its files, which is denied for programs that are
  not allowed. Delete the policy first to discard the folder.
- **The former path.** Once the policy follows its folder, the old path becomes
  a retired path of the policy. It stays reserved for the programs the policy
  allows until you save the policy; see [Retired paths](#retired-paths).
- **Locations that can't be followed.** If the folder is moved to a place that
  can't be a policy folder, such as a home folder itself, the policy keeps its
  old path and the Overview reports that its policy could not be updated.

### Retired paths

When a policy follows its folder, the folder's previous path becomes a
*retired path* of the policy. A program that remembers the old path, such as an
editor reopening a recent document, could otherwise save there after another
program had created a folder with the same name, or had sent the path
elsewhere with a symbolic link (a file that points to another location).
Until you save the policy, its retired paths are reserved for the programs the
policy allows:

- **Other programs are denied.** A program that the policy would deny inside
  its folder, such as Finder or Terminal when they are not in **Programs to
  Allow**, is denied:
  - every checked request at the retired path or inside it: opening, creating,
    renaming or moving, deleting, hard linking, cloning, copying, truncating,
    exchanging and changing metadata;
  - creating an item at the retired path or at a folder on the way to it, or
    renaming, moving, cloning, hard linking or copying an item there. For
    example, after a parent folder was renamed, a folder with its old name, or
    a symbolic link with that name, can't be created, and another folder can't
    be renamed to it;
  - renaming, moving (including to the Trash), deleting, cloning or copying a
    folder that contains the retired path but not the policy's folder.

  An Audit policy records these requests as **Would deny** and blocks nothing.
- **Allowed programs are allowed** and warned about: they can create the
  retired path and the folders leading to it and save inside it. Each such
  request is recorded in the policy's log with **Retired path**; see
  [Policy log](#policy-log). Point those programs at the new location.
- **A mount** at the retired path, inside it or at a folder that contains it is
  refused for every program, as a mount over the policy's folder is.

Two kinds of rename are allowed for every program, because the policy's folder
moves with them:

- Renaming or moving a folder that contains both the policy's folder and a
  retired path. The retired paths inside it move along and stay retired at their
  new location, so what allowed programs saved there stays out of reach of
  other programs. Deleting, cloning or copying such a folder is decided by the
  lists, as for any folder that contains the policy's folder.
- A rename that brings the policy's folder back onto a retired path, such as
  renaming its parent folder back to the old name or choosing **Undo** in
  Finder. The policy follows the folder back, that path is no longer retired,
  and the path the folder just left becomes retired instead.

The policy's **Settings** tab shows **Retired Path** below the protected folder,
and the Overview lists the policy under **Needs attention**. While a policy has
retired paths, **Save** is available without other changes. Saving the policy
releases all of its retired paths, without an administrator password; saving
another policy does not, and the policy's own updates when it follows a folder
do not either. Deleting the policy removes them with it.

Retired paths are kept when the extension or the Mac restarts. A policy keeps up
to eight; when its folder moves again with eight already kept, the oldest is
released. A rename the extension did not see, for example one made while it was
not running, does not move the retired paths inside the renamed folder: they
stay reserved at their old location, and what allowed programs had saved there
is no longer protected at its new location.

### Behavior

- **Mode.** **Protection** denies checked requests according to the rules.
  **Audit** blocks nothing and records what Protection would have decided:
  **Would deny** or **Would allow**.

Every policy has both lists. The rules below describe a file open; every other
checked request (create, rename or move, delete, hard link, clone, copy,
truncate, data exchange and the metadata changes listed under
[Overview](#overview)) is decided the same way, with the program that makes
the request as the access process. There are two exceptions. A mount is
performed by macOS through its own system processes, so the lists do not apply
and the mount point alone decides (see [Overview](#overview)). Renaming or
moving a folder that contains the policy's folder is allowed for every program,
because the policy follows its folder (see
[Moving a protected folder](#moving-a-protected-folder)). Requests at the
policy's [retired paths](#retired-paths) are decided by the same lists. Each
list is checked as follows:

- **Programs to Block** always applies. A program in it anywhere in the observed
  execution history denies the open: as the first program, in between, or as
  the access process. This holds after that program has exited or replaced
  itself with another program, and a block rule wins over an allow rule for
  the same program.
- **Programs to Allow** applies while its switch **Allow Only Programs in This
  List** is on, which is the default. An open is then allowed only when two
  conditions are met: the first program is in the list, and the access process
  is either in the list or inherits permission through **Include descendant
  processes**. The
  first program is the first one in the observed execution history after the
  system launch services `launchd` and `xpcproxy`, for example the app you
  opened or the Terminal a command was typed in. The access process is the one
  that opens the file. Programs in between need no rule unless they open a
  protected file themselves or delegate access to their descendants. Starting
  a program delegates access only when the corresponding allow rule has
  **Include descendant processes** on and the execution relationship was observed.
- With the switch off, the two allow checks are not made, so any program that
  passes **Programs to Block** is allowed. The rules in **Programs to Allow** are
  kept, dimmed, and can't be changed until the switch is on again.
- In every case, an open is denied when the history it needs could not be
  established, for example for a program that was already running before the
  extension started tracking processes, unless a
  [system compatibility profile](#system-compatibility) turned on for the
  policy allows it. Starting that program again from the
  Dock or Finder, or logging in again, lets its history be observed; for a
  command, restart the app it is run from, such as Terminal. An updated
  extension starts tracking anew when the app replaces the running one, so
  programs that were already open may need to start again; the Apple-program
  exception below still applies. After the Mac
  restarts, every program that isn't part of macOS starts only once the
  extension is tracking processes (see
  [At startup](installation.md#at-startup)); restart after the app has replaced
  the extension, not before (see [Update](installation.md#update)).
- A program that was already running has a history in one case: it is an Apple
  platform binary (a program that is part of macOS) that `launchd`, the macOS
  process that starts services and apps, started directly and that is still
  its child, such as a macOS service or an Apple app opened from the Dock or
  Finder. macOS reports these facts and when the process started, so its
  history begins with that program as the first program, as if the extension
  had seen it start, and the lists decide as usual: with **Allow Only Programs
  in This List** on, it is denied unless it is in the list, and a block rule for
  it denies. Programs started by it later have it as their first program. A
  program that such a process ran before tracking began, and then replaced with
  its current one, is unknown, so a block rule for that earlier program doesn't
  apply. Programs from other developers never get a history this way.

Metadata changes are checked on the policy's folder itself and on everything
inside it, but not on the folders that contain it. A program that is not
allowed therefore can't change these items' metadata either:

- While Finder is not in **Programs to Allow**, it can't show the folder's
  contents, and adding a tag to the folder makes Finder ask for an
  administrator password. Cancelling leaves the folder unchanged; entering the
  password has not been tested with Pasu FS.
- Commands such as `chmod`, `chown`, `chflags`, `xattr -w`, `xattr -d` and
  `touch` fail with "Operation not permitted", and `tmutil addexclusion` fails
  with error -20, unless the lists allow them.

With Finder in **Programs to Allow**, Finder writes tags itself and they are
saved. To change other metadata in a protected folder, use a program in
**Programs to Allow**, or a command from a Terminal session whose first
program and access process the lists allow.

Turning the switch on or off never moves or removes a rule in either list, and
the switch does not depend on how many rules a list has. Pasu FS does not block
programs from starting; it only decides file requests. When several Protection
policies cover the same file, every one must allow the request.

### Programs in the lists

Rules identify programs by their code signature, not by name or path:

- **Developer signed** programs match both their Team ID (the developer's team)
  and their Signing ID (the program's identifier).
- **Apple platform binaries** are programs that are part of macOS. They match
  their Signing ID only.

The same command can have a different Signing ID on different macOS versions:
for example, `ln` is `com.apple.link` on macOS 27 and `com.apple.ln` on macOS 26.

Unsigned and ad hoc signed programs (signed without a developer identity, so
they have no Team ID) can't be added. A rule allows only the
requests its program makes itself or, with descendant access, the programs it
starts. Copies you make in Finder are written by a separate macOS service, so a
rule for Finder alone does not allow them; the **Finder Copy**
[compatibility profile](#system-compatibility) lets that service in. The switch
on each row turns a rule off without removing it; a rule that is off is not
used in decisions.
The ⋯ menu edits or removes the rule. The same program can be in both lists, but
only once in each. All policies together can hold up to 1,024 rules, counting
both lists and rules that are off; the number of policies is limited as well
(see [Creating a policy](#creating-a-policy)).

Both lists of every policy are shown in the order chosen in **Sort Programs
By** in the View menu: **Name** (the default), **Signing ID**, **Signature Kind
and Team ID** (developer-signed programs grouped by Team ID, then Apple
platform binaries) or **Order Added**. Names and identifiers are compared as
Finder compares file names, ignoring case and treating numbers by their value;
rules that compare the same keep their order. The choice is kept by the app for
all policies and changes only how the lists are shown, not the saved policies,
so it needs no save and no password. A rule's name can change when the app
learns the program's name from the log, which can move the rule in **Name**
order.

A Protection policy with **Allow Only Programs in This List** on and no rule in
use in **Programs to Allow** grants no access through that list. Active
[system compatibility profiles](#system-compatibility) can still admit matching
requests. Removing or turning off the last allow rule does not turn the switch
off. **Programs to Allow** then shows a warning about the empty list and active
profiles, which mentions saving while the change is not yet saved. With the
switch off and no rule in use in **Programs to Block**, the lists deny no
program, but still need an established
execution history unless a compatibility profile admits the request.

### Allowing a program's descendants

In **Programs to Allow**, add or edit a program and turn on **Include descendant
processes** to let tools it starts access this policy's folder. It is off by
default. A branch symbol marks a rule with this option on. The option is absent
from **Programs to Block** because a block anywhere in the execution history
already applies to all later executions in that path.

For example, an allowed automation app can start a shell, which starts another
tool. With descendant access on for that app, neither tool needs its own allow
rule. Children, later generations and observed executable replacement are
included, even after the original app exits. This delegates the folder's access
to the tools the app chooses, including tools that cannot be added as signed
rules themselves. The app warns about this broader access when the option is on.

The first program must still be allowed. If the automation app runs inside a
terminal, that terminal may be the first program and need its own allow rule.
Turning on descendant access for the automation app does not turn it on for
the terminal's other children. A block anywhere in the observed path wins, and
missing execution history never becomes trusted through this option. Every
overlapping Protection policy must independently allow the access.

Save the policy to apply the option to subsequent file opens, including those
from already running tools whose execution relationships Pasu FS has fully
observed. This also applies when adding a new allow rule for an observed ancestor;
the tools do not need to restart just because the setting changed. Turning the
option off, disabling the rule or removing it prevents further opens through
that rule, including for existing descendants. Files already opened remain
outside this revocation. The log identifies inherited access and its
**Permission Source**.

The option cannot recover relationships from before observation began, a lost
event or discarded tracking state. After such a gap, start the affected app and
its tools again so Pasu FS can observe a complete execution history.

On upgrade from policy schema 2 or 3, previous descendant settings are reset to
off so inactive saved values cannot silently grant access. Review each allowed
program and turn the option on where needed. Other lists, policy IDs and log
identity are preserved. Policies saved in schema 4 or later keep their
descendant settings.

### Adding a program

Each list has its own **Add Program…** button, which offers four sources.
**Add** adds every chosen program at once. In **Programs to Allow**, the
**Include descendant processes** switch at the bottom applies to all programs
added from the first three sources.

- **Recent Access** lists signed programs from the newest 500 records of this
  policy's log: the programs that opened files and the first programs recorded
  for those opens. Select one or more programs: ⇧-click or ⌘-click extends the
  selection, and **Select All** (⌘A) in the Edit menu selects every program in
  the list. The selection is kept while you search, so a program chosen before
  a search is added even while the search hides it; a plain click replaces the
  whole selection, as in any list. Programs already in the list are dimmed and
  are not added again.
  Records without a complete signing identity can't be used. Paths and names
  are shown only to help you choose; the rule stores the code signature.
- **App or Executable** checks the code signature of an app or a command-line
  program you drop or choose, which can take a moment for a large app. In the
  file dialog, press ⇧⌘G to type a path such as `/usr/bin/ssh`. Programs that
  are part of macOS are added as Apple platform binaries; others are added as
  developer-signed programs. A program whose signature is invalid, missing or
  ad hoc can't be added.
- **Manual Entry** takes the signature kind, Team ID and Signing ID. To look them
  up, run `codesign -dv` with the program's path in Terminal:

  ```sh
  codesign -dv /Applications/Example.app
  ```

  In the output, `Identifier` is the Signing ID and `TeamIdentifier` is the
  Team ID. The command only reads the signature and changes nothing.
- **Other Policy** copies programs from the same list of another policy. Choose
  the policy among the others as they are currently shown, unsaved ones
  included; its **Programs to Allow** or **Programs to Block** appears in the
  chosen sort order, and the selection works as in **Recent Access**. Each copy
  keeps the settings of the rule it is made from: a rule that is off is copied
  off, and in **Programs to Allow** its **Include descendant processes** setting
  stays as it was, which the sheet points out when a selected rule has it on;
  the sheet's own descendant switch is not shown for this source. The copies
  are rules of this policy, so later changes to either policy don't affect the
  other.

### System compatibility

Some macOS services have to work inside folders that a policy can protect. They
are Apple system processes that macOS starts by itself, some of them before
Pasu FS, so a policy denies them: they are not in your lists, and no program in
your lists started them. A service that `launchd` started directly before
Pasu FS has a history that begins with itself (see [Behavior](#behavior)); one
that a service started before Pasu FS has no history at all.
**System Compatibility**, the last section of a policy's **Settings** tab
before **Delete Policy…**, lists profiles that let such services in. Each
profile has a switch, which is off in a new policy. The section appears once
the running extension reports that it supports profiles, and also while the
policy has a profile turned on, so that it can be turned off.

| Profile | Turn it on when the folder | What it lets in |
| --- | --- | --- |
| **App Container Management** | is an app's container, such as `~/Library/Containers/com.example.App`, or a group container in `~/Library/Group Containers`, or lies inside one | `containermanagerd`, `containermanagerd_system`, `secinitd` and `apfsd` may open files in the container for reading |
| **XProtect Malware Scanning** | holds files that the built-in malware scanner XProtect checks, such as `~/Library/LaunchAgents` or an app's container, or software that Gatekeeper checks before it is installed or run | XProtect's remediator plug-ins and its analysis service `XprotectService` may open files for reading |
| **Finder Copy** | should accept files and folders that you copy or duplicate in Finder or restore from the Time Machine screen, or should let you copy them out of it with Finder | `DesktopServicesHelper`, which carries out these copies for Finder, may create files and folders, open them for reading or writing, truncate files, clone files, set attributes and write or remove extended attributes |

Some of these services run as your user account rather than as root, the
system's administrator account: the container manager and `secinitd`, which
prepares an app's sandbox, run once for each logged-in user, XProtect runs its
plug-ins both as root and as the user, and `DesktopServicesHelper` starts as
root and, for a Finder copy, writes as the user who asked for it. A profile
lets them in as the user only when the folder belongs to that user.

Without **App Container Management**, protecting a container stops its app
from starting: macOS can't read the container, and the app quits right away.
With the profile on, add the app itself to **Programs to Allow**. An app that
shows an Open or Save dialog uses the macOS service
`com.apple.appkit.xpc.openAndSavePanelService` for it; add that service as an
Apple platform binary as well, or the dialog can't list the container's files.
Without **XProtect Malware Scanning**, XProtect can't scan the folder. Neither of
these two profiles lets a service change or delete files, so XProtect can't
remove malware from a protected folder. Neither lets a service change metadata
either: when an app with a protected container starts, the container manager's
requests to set an extended attribute on the container folder are denied and
recorded, and the app still starts.

XProtect's analysis service, `XprotectService`, scans software for Gatekeeper,
the macOS feature that checks apps and installer packages before they are
installed or run. macOS starts a separate copy of the service for each program
that uses it, running as that program's user. **XProtect Malware Scanning**
lets in only the copy that runs as root, which the Gatekeeper daemon
`syspolicyd` uses. The copy that Gatekeeper starts as your user account when
you first open a downloaded app is still denied. An app stored in a protected
folder can't be opened with Finder or the `open` command anyway, because the
macOS services that open apps, such as `lsd`, are denied there too.

Finder hands each copy (**Copy** and **Paste Item**), each duplicate
(**Duplicate**, ⌘D) and each restore from the Time Machine screen to
`DesktopServicesHelper`, a macOS service that launchd starts for the operation
and that writes the copies; Finder itself only reads. To copy files and folders
into a protected folder or out of it with Finder, or to restore into it from
the Time Machine screen:

1. Add Finder (Signing ID `com.apple.finder`, an Apple platform binary) to
   **Programs to Allow**.
2. Turn on **Finder Copy** and save. For a saved Protection policy, macOS asks
   for an administrator password.

The Finder rule allows the requests Finder makes itself, such as listing the
folder and reading its files, and the profile allows the service's copies.
Moving files, moving them to the Trash, renaming them and creating folders are
done by Finder itself and need only the rule. With the profile on but Finder
not in **Programs to Allow**, the service's copies are still allowed while
Finder's own requests are denied: the folder looks empty in Finder, yet an item
pasted into it is written, and the folder as a whole can be copied elsewhere.
When a policy denies a Finder copy, Finder asks for an administrator name and
password to try again; cancelling leaves nothing behind, and entering the
password has not been tested with Pasu FS.

The profile lets the service create files and folders, read and write files,
truncate and clone them, set their attributes and write or remove their
extended attributes, for example the mark Finder shows on an item while it is
being copied. It can't rename or delete anything, or change permissions,
owners, flags, access control lists or dates on their own. It copies whatever
Finder asks it to, in either direction: with the profile on, Finder can also
copy items out of the protected folder, or the protected folder as a whole, to
any folder you can write to. Copies that a script asks Finder to make, for
example with AppleScript, go through a different service,
`DesktopServicesScriptingHelper`. No profile covers that service, so **Finder
Copy** doesn't allow such copies and the policy's lists decide them, as for
any other program.

Finder copies and Time Machine screen restores of files and folders were
checked on macOS 27.0.1 with the profile enabled. These operations remain
unverified on macOS 26.6.2. Copies to another volume, copies that replace an
item of the same name and scripted Finder copies also remain unverified with
Pasu FS. See [verified configurations](building.md#verified-configurations)
for the test conditions and [Restoring from Time Machine](#restoring-from-time-machine)
for restore procedures.

While a profile is on, its row says what the services can do in the folder.
Turning a profile on reduces protection, so saving asks for an administrator
password (see
[Changes that need an administrator password](#changes-that-need-an-administrator-password));
turning it off does not. A profile lets in only the programs it names, and only
when all of these hold:

- The program is part of macOS, identified by its code signature.
- It runs as root or, for the services named above, as the user who owns the
  folder.
- macOS's launch service `launchd` started it, directly or through another
  program of the same profile. Running the same program yourself, for example
  with `sudo` in Terminal, does not qualify.
- The request is one the profile allows that program; for **App Container
  Management**, its path must be inside an app container of the folder's
  owner.
- The Mac runs macOS 26 or 27. On another version the switch is unavailable
  and shows **Not supported on this macOS**.

A program in **Programs to Block** still denies, and when several Protection
policies cover a file, each of them must allow the request. In the log, a
request that a profile allowed shows **Allowed by the compatibility profile**
with the profile's name (see [Policy log](#policy-log)).

These services also act for other programs. Any app can ask the container
service to prepare its own container, XProtect reads whatever Gatekeeper asks
it to check, and
`DesktopServicesHelper` copies whatever Finder chooses: Pasu FS can't tell
whether you started a copy or a program that controls Finder did, for example
one with Accessibility permission. Turn a profile on only for a folder that
needs it.

A profile that is on can become inactive. Its row then says why, and the
Overview lists it under **Needs attention**:

- **Inactive because the profile changed. Turn it off and on again.** An
  update of Pasu FS changed what the profile allows. Turn the switch off and
  on and save; macOS asks for an administrator password.
- **Inactive on this version of macOS.** The profile is not trusted on the
  macOS version now running, for example after a major macOS update.
- **Inactive because this version doesn’t offer it.** This version of Pasu FS
  no longer has the profile. Turn it off.

**Settings… → Diagnostics** shows the number of active profiles.

A service that was already running when the extension started, for example
after an extension update, is admitted when launchd started it directly: its
history begins with itself. A plug-in it starts later, like an XProtect
remediator, is admitted as well, because the extension sees the plug-in start
and the service is its first program. A plug-in that was already running too is
admitted when the service that started it is still its parent.

### Restoring from Time Machine

Time Machine backs up a protected folder without a check, because it reads the
folder through a snapshot; the copy on the backup disk is not protected (see
[Security boundaries](threat-model.md#known-limitations)). Restoring into a
protected folder is a file request like any other, decided by who writes the
files:

- **The Time Machine screen.** When you restore from the Time Machine browser,
  the files are written not by Finder but by `DesktopServicesHelper`, the
  macOS service that also writes the copies you make in Finder. launchd starts
  it, so its first program is the service itself, and a rule for Finder in
  **Programs to Allow** allows only the requests Finder makes itself, such as
  listing the folder. With Finder in **Programs to Allow** and the
  **Finder Copy** profile on (see [System compatibility](#system-compatibility)),
  the restore is allowed; that section lists what has been verified.
- **`tmutil restore`.** The command writes the files itself, as a process
  started from the Terminal window you type it in, so Terminal is the first
  program and `tmutil` the access process. With both in **Programs to Allow**,
  the restore is allowed.

If you don't want to keep **Finder Copy** on, restore with `tmutil restore`,
or follow [Pausing protection for system tasks](#pausing-protection-for-system-tasks)
and restore from the Time Machine screen while the policy is in **Audit**.
Restoring with Migration Assistant has not been tested with Pasu FS.

To keep a protected folder out of Time Machine backups, exclude it by its path:

```sh
sudo tmutil addexclusion -p ~/Example
```

The command asks for your password and stores the path in the Time Machine
settings. Without `-p`, `tmutil addexclusion` marks the folder with an
extended attribute instead, which is a metadata change in the protected folder
and fails with error -20 unless the lists allow it.

### Policy storage states

The extension keeps two copies of the saved policies. **Settings… → Diagnostics
→ Policy storage** shows their state, and the Overview lists every state other
than **Normal**:

- **Converted from an earlier format**: policies saved in policy schema 2 or 3
  were converted. Rules of a Whitelist policy are now in **Programs to Allow**
  with **Allow Only Programs in This List** on, and rules of a Blacklist policy
  are in **Programs to Block** with the switch off. Review the former Whitelist
  policies, because programs started by an allowed program are no longer
  allowed automatically. Policies saved in schema 4 mean the same in the
  current schema: the extension stores them again in the current schema when
  it starts, and the state stays **Normal** (see
  [Update](installation.md#update)).
- **Restored from the verified copy**: one copy was unreadable and the other,
  identical copy is in use. Nothing was lost.
- **Damaged; denying every request**: both copies are unreadable. The
  extension still knows the folders of the Protection policies and denies every
  checked request in them; Audit policies only record. The app shows the policies without their
  programs, which can't be restored. Add the programs to each policy again and
  save each one; **Save** is available without other changes.
- **Unavailable**: neither the policies nor their folders could be recovered,
  and the Overview shows **Needs Attention** because those folders are not
  protected.

### Deleting a policy

**Delete Policy…** stops the policy right away and removes its log files.
Deleting a saved policy first asks for an administrator password, as described
in [Changes that need an administrator password](#changes-that-need-an-administrator-password);
if you cancel, nothing is deleted. An unsaved new policy is simply discarded.

### Pausing protection for system tasks

Some macOS tasks move whole folders or read every file, and a Protection
policy stops them part way: Migration Assistant, moving a home folder to
another location, reinstalling macOS, restoring a folder from Time Machine
(see [Restoring from Time Machine](#restoring-from-time-machine)), and turning
iCloud Drive's Desktop & Documents Folders option on or off or changing the
folders of another sync tool. Pasu FS does not detect these tasks. Before you
start one that involves a protected folder or a folder that contains it:

1. Open each such policy's **Settings** tab, choose **Audit** and choose
   **Save…**. macOS asks for an administrator password. The policy now records
   requests without denying them, and its folder is not protected.
2. Run the task.
3. Check each policy's **Protected Folder**. If the task copied the folder to
   another volume or replaced it, choose the folder at its new location.
4. Choose **Protection** and **Save**. Restoring protection needs no password.

The policy's log shows what the task did while the policy was in Audit mode.

## Program and process terminology

| Concept | English | Korean |
| --- | --- | --- |
| Persistent software identity matched by a policy, even after restarting | Program | 프로그램 |
| Records grouped by that software identity | By Program | 프로그램별 |
| Running instance that makes a file access request (`message.process` in Endpoint Security) | Access process | 접근 프로세스 |
| First program in the observed execution history after the system launch services | First program | 첫 프로그램 |
| Process identified by Apple's `responsible_audit_token` | Responsible process | 책임 프로세스 |
| The immediate parent in an actual parent relationship | Parent process | 부모 프로세스 |
| Processes further up an actual parent chain | Ancestor processes | 조상 프로세스 |
| Connected process relationships | Process chain / process lineage | 프로세스 사슬 / 프로세스 계보 |
| The binary stored on disk | Executable | 실행 파일 |

A process ID (PID) identifies a running instance, not a persistent program.
Responsibility alone does not establish a parent or ancestor relationship.
Descendant processes include children and later generations linked by observed
parent relationships. An executable path names a file, not a process chain.

## Policy log

The **Log** tab shows the newest 500 records of the policy's log. Its bottom bar
shows the folder, the number of records loaded and the 500-record limit. This
bar appears only on the Log tab. Hover over a shortened folder path to read it
in full. **Refresh** loads the records again,
the search field filters the loaded records, and the details button or **Show
Inspector** (⌃⌘I) in the View menu shows the selected item in a side panel.

- **By Program** groups the requests by program with their denied and allowed
  counts, adding up the requests each record stands for. **Add Rule** adds the program to **Programs to Allow** or **Programs
  to Block** (save to apply); for a program already in one list, the button
  names that list (**In Programs to Allow** or **In Programs to Block**), with
  **· Off** after the name while that rule is off. A program in both lists
  shows **In Both Lists** instead of a button. While **Allow Only Programs in
  This List** is off, a program can't be added to **Programs to Allow**.
  **Can’t Add** means the records have no signing information.
  The decision above the counts is the program's latest one. When it was made
  under an earlier [policy revision](#saved-and-in-effect) than the one in use,
  it appears in gray with **Earlier revision**; hold the pointer over it to see
  both revision numbers. Every save creates a revision, including saving
  another policy and the update the extension stores when a policy follows its
  moved folder, so the mark doesn't mean that this policy changed: it means
  the loaded records have no decision on the program from the policies in use.
  Its next request is decided by the policies in use and may get the same or a
  different decision. The counts include the records of every revision. The
  program's details show the revision as **Latest decision revision**, with the
  revision in use in parentheses.
- **All Events** lists each record with its time, access process, target,
  decision, response and **Requests**, the number of requests the record stands
  for. When that is more than one, the time of the last request appears below
  it (see [Requests and records](#requests-and-records)). The line under the
  decision is the recorded reason, or **Allowed by the compatibility profile**
  with the profile's name for a request a
  [system compatibility profile](#system-compatibility) allowed; a request at
  one of the policy's [retired paths](#retired-paths) shows **Retired path**
  above it. The response is **Deny** or **Allow** with **Missed deadline** below
  it for a request macOS decided because Pasu FS's answer came too late (see
  the details below).
  The target is the opened, created, deleted or truncated path, the source
  of a rename, link, clone, copy or data exchange, the file or folder whose
  metadata a metadata change modifies, or the mount point of a mount.

Errors and warnings appear to the right of the view selector. The summary shows
the first error, or the first warning if there is no error, and the total number
of issues when there is more than one. Select it to read all current messages in
a scrollable panel. Errors appear before warnings; refreshing successfully clears
the previous load error. Storage warnings, unreadable records and failed refreshes
remain separate messages. Historical alerts do not accumulate here.
If refreshing fails after records have loaded, the previous records stay visible
and the error explains that they are from the previous successful load. If the
first load fails, the table shows **Log Unavailable**.

Right-click a cell to copy its value:

| View | Column | Menu items |
| --- | --- | --- |
| By Program | Program | Copy Program Name |
| By Program | Code Signature | Copy Signing Identifier |
| All Events | Access Process | Copy Responsible Process Name, Copy Access Process Name, Copy Signing Identifier |
| All Events | Target | Copy Path |

Copying uses the record under the pointer, including when another row is
selected. Names, identifiers and paths are copied in full, even when shortened
on screen; paths retain their full form instead of the `~` home-folder shorthand.
In All Events, the responsible process is the process macOS reports as
responsible for the request; the access process is the running instance that
opened the target. Their names can be copied separately, even when they are the
same. The signing identifier belongs to the access process. A signing identifier is the
program identifier recorded in its code signature; it is not necessarily an app
bundle identifier. Copy actions are disabled when their value is missing.

The details show the request (its type, its target and, for a rename, link,
clone, copy or data exchange, the **Destination**; for a mount, the **Mount
point** and **Mounted from**, the device or share the volume comes from; a
metadata change shows its type, such as **Permissions change** or **Extended
attribute change**, but not the new value or the attribute's name), the
decision of each policy that covered the file, the access process's identity
and its process chain. A record that stands for more than one request also
shows **Requests** and **Last request**; when it combines allowed requests for
different files, its paths are labeled **First target** and **First
destination**.

- **Would deny** and **Would allow** are Audit predictions and have no effect.
- Each decision shows what the extension recorded when it decided, not a new
  calculation from the current rules: the policy's mode at that time,
  the reason, the **First Program**, the **Access Process** and, when a block
  rule matched, the **Blocked Program**. Open a row to see that program's PID,
  execution number, executable and signature. A PID alone does not identify a
  program; it is shown with the execution number macOS assigned. The reasons are:

  | Reason | Meaning |
  | --- | --- |
  | First program and access process are allowed | Both are in Programs to Allow. A system launch service that opens a file itself is shown as **System intermediary** and needs no rule. |
  | No blocked program in the execution history | Programs to Allow was not used, and no rule in Programs to Block matched. |
  | No program is allowed | Programs to Allow was used but had no rule in use. |
  | First program is not allowed | The first program is not in Programs to Allow. |
  | Access process is not allowed | The process that opened the file is not in Programs to Allow. |
  | Blocked program in the execution history | A rule in Programs to Block matched the program shown as Blocked Program. |
  | The mount point covers this policy’s folder | A mount at the policy's folder, inside it or at a folder that contains it. No program is shown: the access process is the system process that performed the mount, not the program that asked for it. |
  | Execution history is incomplete | Needed history is missing; the warning below the rows says why. |
  | First program is unknown | Only system launch services were observed before the access process. |

- A decision whose history began with a program that `launchd` started before
  the extension started tracking processes (see [Behavior](#behavior)) also
  shows **This history begins with a process that launchd started before the
  extension started tracking processes.** The rest of that history was
  observed.
- A request that a [system compatibility profile](#system-compatibility)
  allowed shows **Allowed by the compatibility profile** with the profile's
  name instead of a reason. The **First Program** and **Access Process** rows
  still show what the extension recorded, which is often an incomplete history.
- A decision on a request that acts on a folder containing the policy's folder,
  such as renaming or deleting a parent folder, also shows **The request acts
  on a folder that contains this policy’s folder**. Renaming such a folder is
  allowed for every program, so that decision shows no program; the other
  requests show the reason and programs of the lists.
- A decision on a request at one of the policy's retired paths, or at a folder
  on the way to it, shows a warning with **Retired path:** and that path. For an
  allowed request this is how you can tell that a program still uses the
  folder's previous location; see [Retired paths](#retired-paths).
- An unknown first program is shown as **Unknown**. Pasu FS does not substitute
  the responsible process or the current parent for it.
- Records made by an earlier version show **This record has no first-program
  evidence.** Their history is unknown, not clean.
- The **response** is Pasu FS's answer to macOS. Other macOS permission checks
  can still deny access that Pasu FS allowed.
- When Pasu FS's answer didn't reach macOS before the request's deadline,
  macOS decided the request itself, and the record shows what macOS did rather
  than Pasu FS's decision: the details read **Denied (missed deadline)** when
  **On a missed deadline** in Diagnostics reads **Deny the request**, and
  **Allowed (missed deadline)** when it reads **Stop the extension** (see
  [Missed deadlines](#missed-deadlines)). The decision of each policy still
  shows what Pasu FS decided when it got to the request. The app uses the
  current setting, so a record made on an earlier macOS version can show the
  wrong outcome. While Diagnostics shows no **On a missed deadline**, for
  example while the app has no status from the extension, the record shows
  **Missed deadline** alone.
- The process chain is built only from process events the extension observed.
  Relationships from before observation started, and changes that were not
  delivered, are unknown. The responsible process is the process macOS reports
  as responsible for the request, such as the app that launched a helper. macOS
  can report a process as responsible for itself, including when no responsible
  process exists or it has already exited. Processes listed under
  **Responsible processes outside the ancestor chain** are linked only by such a
  responsibility relationship, not as parents.
- Counts in a program's details add up the requests of the loaded records only.
- **Create Rule From This Program…** opens **Add Program…** for the policy you
  choose with this program preselected. The program goes to **Programs to
  Allow**, or to **Programs to Block** while that policy's **Allow Only
  Programs in This List** is off; the rule is added when you save that policy.

Logs contain metadata only, never file contents. Each policy keeps up to 10 MiB
of records plus one previous file; older records are removed. A log belongs to
its policy: after you change the protected folder, or the policy follows a moved
folder, records made under the previous folder stay in the same log.

### Requests and records

Pasu FS logs requests, not user actions. macOS asks once for each request, so
one action can produce several requests: creating a file usually appears as a
create followed by an open, and saving a document can add renames and deletes.

To keep busy programs from filling the log, the extension combines requests
into one record before saving it:

- Allowed requests from one running process are combined for up to one second
  when every policy that took part made the same decision under the same policy
  revision, even when they name different files. The record shows the first
  request's type, target and time. An allowed request at a
  [retired path](#retired-paths) is combined only with identical repeats, like
  a denied one, so each file written there keeps a record of its own.
- A denied request, or one an Audit policy would deny, is combined only with
  identical repeats from the same process within one second: the same request
  type, target, destination, access and decisions. A denied request for another
  file gets its own record.
- A running process is one execution of a program. The same program started
  again, or a process that replaced its program, gets new records.
- Any other record from the same process ends the combined record, so each
  process's records stay in order. Records of different processes can be saved
  up to a second out of order; sort by **Time** to read them in sequence.
- A record waits up to one second for repeats before it is saved. Loading the
  log saves waiting records first, and later repeats start a new record.

Records of denied requests have their own space in the queue of records waiting
to be saved: 512 records and 4 MiB that no other record can use. A repeat of a
waiting denied record is counted even when that space is full. A burst of
allowed requests or process events therefore can't crowd denial records out of
the queue, and a program that keeps repeating one denied request is logged with its full
count. If a program sends denied requests for many different files faster than
they can be saved, the records that don't fit are lost.

Lost records and save failures are counted per request; a lost record of a
process start, fork or exit counts as one. Every file request the extension
answered inside a policy folder is therefore either counted by a saved record
or counted as lost, except for records still waiting when the extension stops
unexpectedly. Saved records still leave the log once it reaches its size limit.
Losses appear as a warning in the log, under **Needs attention** on the
Overview and in [Diagnostics](#diagnostics).

### Switching an Audit policy to Protection

The sidebar icon shows the policy's mode, including an unsaved change to it.
The subtitle under the policy name in the window title shows the mode of a
saved policy without unsaved changes: **Protection**, or **Audit · Nothing is
blocked**. A policy that has never been saved reads **Not saved yet** there,
and one with unsaved changes reads **Unsaved changes**. Review the programs in
the log and add them to **Programs to Allow** or **Programs to Block**. While
**Allow Only Programs in This List** is on, allow both the program you start
and any separate program that opens the files for it. Then open the policy's
**Settings** tab, choose **Protection** and **Save**.

## Settings

Open the Settings window with **Settings…** (⌘,) in the Pasu FS menu.

### General

- **Open at Login** opens the menu bar app when you log in. It does not control
  protection: an activated system extension runs whether or not the app is open.
  macOS may require approval in Login Items.
- **Registration with macOS** shows the login item state that macOS reports:
  Off, On, Approval required or No registration found. When approval is
  required, **Open Login Items…** opens that System Settings pane.
- **Uninstall Pasu FS** removes the app and the system extension and stops
  protection. See [Uninstall](installation.md#uninstall).

### Extension

- **Versions** compares the app, the extension included with it and the running
  extension. **Running extension** is the version that the running extension
  reports over the authenticated connection; an extension from 0.10.3 or earlier
  doesn't report it, and the version macOS reports as enabled is shown instead.
  macOS reports versions and installation states. The app asks for them every
  15 seconds while this tab is open, and once a minute otherwise (see
  [Overview](#overview)); results more than 90 seconds old, and results from
  before a failed or unanswered request, are shown as unconfirmed. While an
  update waits for a restart, **Comparison** reads **Restart to finish the
  extension update**.
  When macOS hasn't answered a request within 20 seconds, the section shows the
  same notice as the Overview, and **The extension still answers, so protection
  continues.** while the extension answers.
- **Installed on This Mac** lists every Pasu FS extension version macOS knows
  about, each with one or more states separated by ·: **In use** (macOS
  reports it as enabled), **Waiting for approval** (it waits for your approval
  in System Settings), **Removal pending** (macOS still reports it as enabled
  and removes it at the next restart), **Running until restart** (macOS no
  longer reports it as enabled and removes it at the next restart, but it still
  runs and checks requests), **Cleanup after restart** (a stopped older version
  that macOS removes at the next restart; this does not affect protection),
  **Starts after restart** (the version that macOS starts at the next restart)
  and **Not active** (installed, in none of these states). **Last checked**
  shows when macOS last reported the installation state. **Refresh** next to
  the section title, or ⌘R, asks macOS and the extension again at once.
  **Checking with macOS…** appears only until macOS answers the first request
  or doesn't answer within 20 seconds; **Can’t confirm** appears while the
  reported versions are out of date, the latest request failed or macOS
  doesn't answer.
- **Deactivate Extension** offers **Deactivate…**, which first asks
  **Deactivate the system extension?**; **Deactivate** then asks macOS to
  remove the extension, after administrator approval; **Cancel** changes
  nothing. macOS stops the extension only at the next restart:
  until then it keeps protecting, the Overview shows **Uninstalling**, and the
  request ends with **The request will finish after the Mac restarts.**
  While an extension update waits for a restart, deactivating also withdraws
  the update: macOS removes the waiting version at once, and the earlier version
  keeps protecting until the restart that removes it.
  **Deactivate…** stays unavailable while macOS reports every installed
  version as being removed: macOS answers another deactivation request then
  with an error, and the extension stops at the restart anyway. It is also
  unavailable while macOS reports that no Pasu FS extension is installed. While
  the installation state can't be confirmed (**Can’t confirm** under
  **Connection**), it stays available, and macOS answers the request.
- **Connection** shows how the status was obtained as **Status check** (the same
  text as the row below the status on the Overview), the installation state
  macOS reports and the extension's bundle identifier. Before macOS has
  reported an installation state, **Installation** reads **Checking…**.
  **Can’t confirm** appears once macOS hasn't answered within 20 seconds, the
  latest request failed, or the state macOS reported is more than 90 seconds
  old; the app then doesn't treat the extension as not installed or removed.

### Diagnostics

Diagnostics shows the extension's runtime report, updated every 2 seconds.
Lost records, records that could not be queued or saved, failed or late
authorization responses and unchecked requests also appear under **Needs
attention** on the Overview.

- **Runtime** shows how the status was obtained, when it was last updated (in
  orange, with the date and time of the extension's last status, while the
  extension doesn't respond), the
  policy revision in use, which request types the extension checks (the
  eighteen events listed under [Overview](#overview)), which requests macOS
  delivers to the extension (see [Request delivery](#request-delivery)), the
  number of [system compatibility profiles](#system-compatibility) active in
  the policies in effect, the [policy storage state](#policy-storage-states),
  the number of [retired paths](#retired-paths) of all policies and the digest
  (a checksum) of the policies in effect.
- **Execution History** shows the data behind first-program decisions: the
  processes being tracked and the data they use, each with its limit (16,384
  processes and 16 MiB). **Tracking started** shows when the extension began
  tracking processes and, when the extension reports it, how long after the Mac
  started (see [At startup](installation.md#at-startup)). **Started by launchd
  before tracking** counts the histories that began with an Apple platform
  binary that `launchd` started before then (see [Behavior](#behavior)).
  **History resets** counts the times earlier history became unusable, with
  the latest cause below it: a lost process start, fork or exit, a process
  event that could not be read, a macOS event version that does not number its
  process events, the limit being reached, or a program newly added to a block
  list. **Discarded process entries** counts the tracked processes that were
  dropped when the history reached its limit and was reset. After a reset,
  Protection policies deny requests with incomplete history unless a
  compatibility profile admits them. Restart affected programs to establish a new history; for a
  command, restart the app it is run from, such as Terminal. An Apple program
  whose discarded history can be established from launchd's start may recover
  as described in [Behavior](#behavior); a retained history marked incomplete
  after event loss is not repaired that way.
- **Process Lineage** observes process starts and ends even without policies,
  using only the events the extension received. **Status** reads **Tracking**
  while the extension collects these events and **Stopped** after its Endpoint
  Security client has stopped, for example when the extension stops. **Observed process events** counts the process starts, forks
  and exits received during this run. **Dropped messages (all kinds)**
  counts every message macOS dropped instead of delivering it during this run,
  whatever its kind, from the numbers macOS puts on every message: process
  starts, forks and exits, file requests and other notifications alike. Only
  the process events among them reset the execution history (**History
  resets**), and the file requests among them are estimated under
  **Unchecked requests (upper estimate)** (see
  [Unchecked requests](#unchecked-requests)). Other listed issues explain gaps
  in the observed process chains.
- **Log Storage** counts records saved without process lineage, records that
  couldn't enter the save queue and the denial records among them, save
  failures and lost records. All but the first count requests (see
  [Requests and records](#requests-and-records)).
- **Authorization Responses** counts answers to macOS that failed or finished
  after macOS's deadline, shows what macOS does when an answer is late (**On a
  missed deadline**) and how long macOS waits for an answer when Pasu FS
  shortened the wait (**Maximum deadline**; see
  [Missed deadlines](#missed-deadlines)), and counts the
  requests macOS answered without asking the extension (**Unchecked requests
  (upper estimate)**, see [Unchecked requests](#unchecked-requests)). **Latest
  unchecked requests** shows the count of the most recent one-second stretch
  that had any and the time of its last drop. The section also shows the shortest time that was
  left before a deadline, the number of requests the extension evaluated
  (**Requests evaluated**, including the few delivered requests outside every
  policy folder, which only need a lookup), and the average and longest time one evaluation
  took.

#### Request delivery

macOS sends the extension only the file requests that can concern a policy:
those in a policy's folder, a retired path or a location a folder is moving
to, and those that rename, delete, copy or create something at a folder on the
way to one of them. Requests anywhere else on the Mac never reach the
extension, and it doesn't spend time on them. Mounts, and the process starts,
forks and exits that the execution history is built from, always reach it.
The extension registers these paths with macOS and updates them when policies
are saved or deleted, when a folder is followed, and after each folder check.

- **Request delivery** reads **Registered paths only** in normal operation. It
  reads **All requests**, in orange, when macOS couldn't take a path: the
  extension then has every request delivered, as without registration, so
  protection is unchanged and only the extension's work grows. It tries again
  with each check.
- **Registered path prefixes** counts the registered paths that select
  everything below them, and **Registered exact paths** those that select
  requests on that path only (the folders on the way to a policy folder). Both
  are counted as macOS reports them.
- **Path registration error** shows the latest error, if any, until the
  extension restarts.

#### Missed deadlines

macOS holds each file request until Pasu FS answers it, up to a deadline set
by macOS. **On a missed deadline** shows what happens when Pasu FS doesn't
answer in time:

- **Deny the request**: macOS denies the request and Pasu FS keeps running.
  macOS also denies the requests it drops under heavy load (see
  [Unchecked requests](#unchecked-requests)). Pasu FS sets this on macOS 27 and
  later.
- **Stop the extension**: macOS stops the extension, allows the request and
  starts the extension again. It also allows the requests it drops. This is
  the only behavior before macOS 27, where macOS's default deadlines apply.
  After the extension restarts, Protection policies deny requests with incomplete
  history unless a compatibility profile admits them. Restart affected programs
  to establish a new history. Apple programs that launchd started directly can
  regain a history as described in [Behavior](#behavior). On macOS 27 and later it appears in
  orange, with **Deadline setting error** below it, if Pasu FS couldn't set or
  confirm **Deny the request**.

With **Deny the request**, Pasu FS also shortens macOS's default deadlines:
**Maximum deadline** shows the new deadline, 3,000 ms. This limits how long an
unresponsive extension holds each request; it does not guarantee that every
request can be evaluated in time. If the deadline can't be shortened, **Deadline
shortening error** says why; macOS's default deadline then applies and
**Deny the request** stays in effect.

A request that macOS denies at its deadline is denied without Pasu FS's
answer. Its log record, if Pasu FS writes one when it gets to the request
later, keeps Pasu FS's own decision, and the log shows what macOS did (see
[Policy log](#policy-log)).

If the extension stops answering while it keeps running, macOS doesn't restart
it on macOS 27 and later. Until the extension exits or the Mac restarts, every
request it would have checked is denied 3 seconds after it is made, including
those of allowed programs and every mount, and requests for the same file wait
behind each other, so a program that opens a file several times, or lists a
folder, can wait much longer. After 30 seconds without a status from the
extension, the Overview shows **The extension isn’t responding (last status N
ago). Restart this Mac.** under **Needs attention**, and **Last update** in
Diagnostics turns orange with the time of the last status. The same applies to
an earlier extension that keeps running while an update or a deactivation
waits for a restart, once a status request to it has timed out (see
[Overview](#overview)). Restart the Mac to start the extension again;
installing the same package again doesn't replace a running extension with the
same version and build number, the numbers **Settings… → Extension** shows
(see [Update](installation.md#update)). If the extension exits on its own, for
example after a crash, requests that were waiting for it are allowed, even on
macOS 27, and macOS starts it again. Before macOS 27 macOS stops an extension
that misses its deadline, allows the request and starts it again.

Deadline behavior has not been verified under normal SIP-enabled system
extension installation. See [verified configurations](building.md#verified-configurations)
for the macOS versions and test conditions.

#### Unchecked requests

When the Mac produces requests and process events faster than the extension
can take them, macOS drops some of them instead of delivering them. macOS
answers a dropped file request without Pasu FS checking it, and Pasu FS can't
tell afterwards which file it named. Before macOS 27 macOS allows the request;
on macOS 27 and later, where Pasu FS sets **Deny the request** (see
[Missed deadlines](#missed-deadlines)), macOS denies it, even when the program
is allowed. Pasu FS counts these requests from the numbers macOS puts on every
message it sends. The numbers show how many messages were
dropped but not what they were, so the count is the most there could have
been: Pasu FS leaves out the process starts, forks and exits it can tell were
dropped at the same time, but the count can still include other kinds of
messages. Drops within one second of the first one are counted together, and
appear about a second later. The count starts again when the extension
restarts. When it is above zero, the Overview shows **macOS allowed up to N
requests without asking Pasu FS during this run.** under **Needs attention**,
or **macOS denied up to N requests without asking Pasu FS during this run.**
when **On a missed deadline** reads **Deny the request**.

A dropped process start, fork or exit is handled differently: it marks the
retained execution histories incomplete (**History resets** under **Execution
History**). Protection policies deny requests that depend on those histories
unless a compatibility profile admits them. Restart affected programs to
establish new histories. Other dropped messages don't reset them.

## Menu bar

The shield in the menu bar shows the status. Its menu lists the status, the
number of policies in use and the first item that needs attention, and it opens
the app and Settings. **Refresh Status** asks macOS for the installation state
and the extension for its status at once, as **Refresh** on the Overview does;
it is unavailable while a refresh runs.

The two quit commands below are also in the app's Pasu FS menu, where **Quit
Pasu FS** is ⌘Q, and each first asks for confirmation.

- **Quit Pasu FS** asks **Quit Pasu FS?**; **Quit** quits only the app. The
  system extension keeps protecting.
- **Stop Protection and Quit…** asks **Stop Protection and Quit?**; **Stop
  Protection and Quit** asks macOS to deactivate the system extension and
  quits once macOS confirms that the extension stopped. macOS stops the
  extension only at the next restart, so Pasu FS shows **Restart Required** and
  stays open; protection continues until the restart. The same applies while an
  extension update waits for a restart: macOS then removes the waiting version
  at once, and the earlier version stops at the restart. If the stop cannot be
  confirmed, Pasu FS also shows a message and stays open. The request needs
  administrator approval. While macOS already removes the extension at the next
  restart, Pasu FS sends no new request: it quits if the extension no longer
  answers, and otherwise shows **Restart Required**.

Unsaved policy changes are discarded when the app quits; while such changes
exist, both confirmations say so.
