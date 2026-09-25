# Using Pasu FS

This guide explains each screen of the app. The app keeps its own text short;
the details are here. It uses the English names; with Korean as the preferred
language, the app shows the same items in Korean. For installation and removal,
see [install, verify, update and uninstall](installation.md). For what Pasu FS
can and cannot protect, see the [security boundaries](threat-model.md).

## Setup assistant

The app shows a four-step checklist while the system extension (the component
that checks file opens) is not installed, waits for approval or Full Disk
Access, or runs without a saved policy for the first time. Nothing is protected
until every step is done. The app checks the status every 2 seconds and moves
to the next step by itself. The checklist closes as soon as you start creating
the first policy. When the extension is stopped or being uninstalled, the
Overview shows that state instead of the checklist.

1. **Activate the system extension.** **Activate Extension** only sends the
   request to macOS; it does not approve anything. macOS then shows a notice
   that a new Endpoint Security extension wants to run, with a button that
   opens System Settings.
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
  - **Protecting**: at least one Protection policy is checking file opens. The
    line below counts the Protection and Audit policies in use.
  - **Auditing**: only Audit policies are active; nothing is blocked.
  - **No Active Policies**, **Starting**, **Waiting for Approval**,
    **Full Disk Access Needed**, **Stopped**, **Uninstalling** and
    **Not Installed** mean that files are not protected, or that protection
    is not confirmed yet.
  - **Needs Attention** shows the reason on the second line.
- The row below the status shows how the status was obtained. **Verified over
  an authenticated connection** with a recent age means the running extension
  answered the app directly. A status read only from the diagnostic file, or one
  more than 15 seconds old, cannot confirm protection. **Policy revision** is
  the number of the policy set the extension is using; each save creates a new
  revision.
- The Overview does not list which requests are checked. The extension checks
  new file-open requests only (the Endpoint Security `AUTH_OPEN` event); opening
  a folder to list its contents is also a file open. Creating, renaming,
  deleting, hard linking, cloning, truncating, memory mapping and copying are
  not blocked. **Settings… → Diagnostics → Checked requests** shows the request
  types the running extension reports.
- **Needs attention** lists policy, compatibility, approval, restart, version,
  logging and uninstall problems. Items that have a related screen show a
  button that opens it.
- **Policies** lists the saved policies with their mode, list type and number of
  rules in use.
- **Recent denials** shows the three newest opens that Pasu FS actually denied,
  taken from the newest 500 records of each policy's log. Audit results
  (**Would deny**) are not included. Select one to open it in its policy's log.
- The last line compares the app and extension versions; select it to open
  **Settings… → Extension**.

## Policies

A policy applies to one folder and everything inside it. Select a policy in the
sidebar to edit it on the **Settings** tab, or view its records on the **Log**
tab. A dot after a policy's name means it has unsaved changes. Changes apply only
when you choose **Save**; **Revert** discards them. Saving applies all policies
together as a new revision. The File menu offers the same actions as **Save
Policy** (⌘S) and **Revert to Saved**, plus **Show Protected Folder in Finder**;
**Refresh** (⌘R) in the View menu reloads the current screen.

### Creating a policy

Choose **New Policy** (⌘N) or the + button in the sidebar. An unsaved policy
named **Policy 1** (or the next free number) opens with its **Protected Folder**
field ready for typing. **Name** can be changed at any time; it must be unique
(ignoring case and accents), at most 80 characters, without leading or trailing
spaces. Every new policy starts in **Audit** mode with a
**Whitelist**: it blocks nothing and records which programs open the files, so
you can add the programs to allow before switching to **Protection**. Change the
mode or type at any time; see [Behavior](#behavior).

Enter a folder and choose **Save**. A policy can't be saved without a valid
folder, and nothing is applied until you save.

### Protected folder

Use **Choose…**, drop a folder on the row, or select the path and type one.
A typed path is applied when you press Return or move to another field; Escape
restores the current path. `~` stands for your home folder. A path is stored
with symbolic links resolved, as when you choose the folder.

The folder must exist. Very broad folders are refused: `/`, `/Applications`,
`/Library`, `/System`, `/Users`, `/Volumes`, `/bin`, `/private`, `/sbin`, `/usr`
and your home folder itself. Two policies of the same mode can't use the same
folder. The folder button in the toolbar shows the folder in Finder.

### Behavior

- **Mode.** **Protection** denies file opens according to the rules. **Audit**
  blocks nothing and records what Protection would have decided: **Would deny**
  or **Would allow**.
- **Type.** A **Whitelist** allows only the programs in its list. A **Blacklist**
  denies only the programs in its list.

When several Protection policies cover the same file, every one of them must
allow the open.

Changing the type of a policy that has rules asks what to do with them.
**Keep Rules and Change** reverses their meaning: allowed programs become denied,
or the other way around, and the child-process setting of each rule has the
opposite effect too. **Delete All Rules and Change** starts with an empty list.
Either way, the change applies when you save.

### Programs in the list

Rules identify programs by their code signature, not by name or path:

- **Developer signed** programs match both their Team ID (the developer's team)
  and their Signing ID (the program's identifier).
- **Apple platform binaries** are programs that are part of macOS. They match
  their Signing ID only.

Unsigned and ad-hoc signed programs can't be added. The switch on each row turns
a rule off without removing it; a rule that is off is not used in decisions.
The ⋯ menu edits or removes the rule.

A Protection Whitelist with no rules in use denies every open in its folder. The
list shows a warning in that case. An empty Blacklist denies nothing.

**Include child processes** applies a rule to the processes the program was
observed starting, even after they run a different program:

- In a Whitelist, everything the program starts can open the files. If the
  program is a shell or a script runner, that includes every command started
  through it. Turn it on only when needed.
- In a Blacklist, everything the program starts is denied too, including
  helper programs that other apps share.

### Adding a program

**Add Program…** offers three sources:

- **Recent Access** lists signed programs from the newest 500 records of this
  policy's log. Programs already in the list are dimmed. Records without a
  complete signing identity can't be used. Paths and names are shown only to
  help you choose; the rule stores the code signature.
- **Application** reads the code signature of an app you drop or choose. Apps
  that are part of macOS are added as Apple platform binaries; other apps are
  added as developer-signed programs and need a Team ID, otherwise they can't
  be added.
- **Manual Entry** takes the signature kind, Team ID and Signing ID. To look them
  up, run `codesign -dv` with the program's path in Terminal:

  ```sh
  codesign -dv /Applications/Example.app
  ```

  In the output, `Identifier` is the Signing ID and `TeamIdentifier` is the
  Team ID. The command only reads the signature and changes nothing.

### System compatibility

This section appears for Whitelist policies. A compatibility profile allows one
built-in macOS service, such as a backup service, to open the folder's files
without adding it to the list. A profile allows only the listed service itself,
not the programs it starts. No service is allowed automatically, and a profile
is added to Pasu FS only after that service's behavior has been verified; the
current release includes none. A Blacklist does not need profiles, because it
already allows every program that is not in its list.

Profiles are turned on and off separately from **Save** and take effect right
away. The policy must be saved first, and the app and extension must use the same
built-in definitions.

### Deleting a policy

**Delete Policy…** stops the policy right away and removes its log files.
An unsaved new policy is simply discarded.

## Policy log

The **Log** tab shows the newest 500 records of the policy's log. The header
shows the folder and the number of records loaded. **Refresh** loads them again,
the search field filters the loaded records, and the details button shows the
selected item in a side panel.

- **By Program** groups the opens by program with their denied and allowed
  counts. **Add to Whitelist** or **Add to Blacklist** adds the program as a rule
  (save to apply). **Can't Add** means the records have no signing information.
- **All Events** lists each open with its time, program, target, decision and
  response.

The details show the request, the program's identity, its execution path and the
decision of each policy that covered the file:

- **Would deny** and **Would allow** are Audit predictions and have no effect.
- The **response** is Pasu FS's answer to macOS. Other macOS permission checks
  can still deny access that Pasu FS allowed.
- The execution path is built only from process events the extension observed.
  Relationships from before observation started, and changes that were not
  delivered, are unknown. The responsible process is the process macOS reports
  as responsible for the request, such as the app that launched a helper. macOS
  can report a process as responsible for itself, including when no responsible
  process exists or it has already exited. Processes listed under
  **Responsibility outside the process's ancestors** are linked only by such a
  responsibility relationship, not as parents.
- Counts in a program's details cover only the loaded records.
- **Create Rule From This Program…** opens **Add Program…** for the policy you
  choose with this program preselected; the rule is added when you save that
  policy.

Logs contain metadata only, never file contents. Each policy keeps up to 10 MiB
of records plus one previous file; older records are removed. A log belongs to
its policy: after you change the protected folder, records made under the
previous folder stay in the same log.

### Switching an Audit policy to Protection

An Audit policy's log shows **This Audit policy blocks nothing** with
**Switch to Protection…**. Review the programs that opened files in the folder,
add the ones to allow (Whitelist) or to block (Blacklist), then switch. The
confirmation lists the programs in the loaded records that would be denied.
Programs that have not opened files in the folder yet are not included. The
switch is saved and applied right away, together with any other unsaved changes
to the policy.

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
  extension. macOS reports versions and installation states; results more than
  15 seconds old are shown as unconfirmed.
- **Installed on This Mac** lists every Pasu FS extension version macOS knows
  about. macOS removes stopped older versions at the next restart; this does not
  affect protection.
- **Deactivate Extension** asks macOS to remove the extension. Protection stops
  only after macOS finishes, which may need administrator approval or a restart.
- **Connection** shows how the status was obtained as **Status check** (the same
  text as the row below the status on the Overview), the installation state
  macOS reports and the extension's bundle identifier.

### Diagnostics

Diagnostics shows the extension's runtime report, updated every 2 seconds.
Lost records, records that could not be queued or saved, and failed or late
authorization responses also appear under **Needs attention** on the Overview.

- **Runtime** shows how the status was obtained, when it was last updated, the
  policy revision in use and which request types the extension checks
  (currently `AUTH_OPEN` only).
- **Process History** observes process starts and ends even without policies,
  using only the events the extension received. Listed issues explain gaps.
- **Log Storage** counts records saved without process history, records that
  couldn't enter the save queue, save failures and lost records.
- **Authorization Responses** counts answers to macOS that failed or finished
  after macOS's deadline.

## Menu bar

The shield in the menu bar shows the status. Its menu lists the status, the
number of policies in use and the first item that needs attention, and it opens
the app, Settings and a status refresh.

- **Quit Pasu FS** quits only the app. The system extension keeps protecting.
- **Stop Protection and Quit…** asks macOS to deactivate the system extension
  and quits once macOS confirms that the extension stopped. If macOS needs a
  restart or the stop cannot be confirmed, Pasu FS shows a message and stays
  open. Protection stops only after macOS completes the request, which may need
  administrator approval or a restart.

Unsaved policy changes are discarded when the app quits.
