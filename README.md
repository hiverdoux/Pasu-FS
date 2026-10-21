# Pasu FS

Pasu FS controls which applications can open and change files in selected
folders on macOS.
It adds application-based rules to normal file permissions: two applications
running under the same user account can receive different access decisions.

The app uses Apple's **Endpoint Security** framework, which lets an authorized
system extension approve or deny supported operations before they proceed.
This source release is for developers with Apple's Endpoint Security capability
and development signing profiles for their test Macs. It is not a notarized
installer for unrestricted distribution. The app and its installer follow the
macOS language setting and are available in English and Korean.

## What it protects

Each policy selects one folder and has independent allow and deny lists. The
deny list always applies: a denied ordinary program anywhere in the observed
history blocks that path. The allow list has its own switch, on by default.
While it is on, the first ordinary program in the observed execution history
must match it. The program opening the file must either match it directly or
inherit permission from an allowed program with **Include descendant processes**
on. This option follows observed process creation and executable replacement;
it never bypasses a denied origin, a block rule or missing history. An allow list
without an enabled rule grants no access through the list. Active
system-compatibility profiles can still allow matching requests. Turning the
list off keeps its rules but turns both allow checks off.

A policy can also turn on system-compatibility profiles, which let specific Apple
system services work in its folder although no program in the lists started
them: the services that prepare an app's container and the XProtect malware
scanner, which may only read, and the service that carries out Finder's
copies and restores from the Time Machine screen, which lets Finder copy files
and folders into the folder and out of it, including the whole folder. A
profile admits only the named Apple programs that launchd started, running as
root or, for some services, as the folder's owner. Turning one on in a saved
Protection policy needs an administrator password.

**Protection** enforces these decisions. **Audit** records predictions without
blocking access. Every overlapping Protection policy must allow. Exact signature
identity and observed history determine access; a filename or current responsible
process alone cannot establish origin. Program launch itself is not blocked.

The app edits both lists and the allow-list switch of each policy. Its policy
log shows the decision the extension recorded for each request: the first
program, the program that made the request, the program that delegated access,
a blocked program found in the history, or the reason the history could not be
established.

New requests to open, create, rename or move, delete, hard link, clone, copy
with the `copyfile` system call, truncate and exchange files are covered (the
Endpoint Security `AUTH_OPEN`, `AUTH_CREATE`, `AUTH_RENAME`, `AUTH_UNLINK`,
`AUTH_LINK`, `AUTH_CLONE`, `AUTH_COPYFILE`, `AUTH_TRUNCATE` and
`AUTH_EXCHANGEDATA` events), and so are changes to the metadata of a policy's
folder and of the items in it: permissions, owner, file flags, access control
lists, extended attributes, other attributes and times (`AUTH_SETMODE`,
`AUTH_SETOWNER`, `AUTH_SETFLAGS`, `AUTH_SETACL`, `AUTH_SETEXTATTR`,
`AUTH_DELETEEXTATTR`, `AUTH_SETATTRLIST` and `AUTH_UTIMES`). Mounting a volume
at a policy's folder, inside it or at a folder that contains it (`AUTH_MOUNT`)
is refused for every program, because the mounted volume would hide the folder.
Renaming or moving a folder that contains a policy's folder is allowed for every
program: the policy follows its folder by the folder's identity when it moves
within its volume, and the files stay protected at the new path. The previous
path stays reserved for the policy's allowed programs until the policy is saved
again, so other programs can't recreate it or redirect saves made to it. Memory
mapping, reading metadata such as sizes, times and extended attributes, metadata
changes to the folders that contain a protected folder, and existing open files
are not covered, and neither are the copies of a protected folder in APFS
snapshots and Time Machine backups. An allowed program can disclose information
it reads. Protection stops when the system extension is inactive. See the
[security boundaries](docs/threat-model.md).

## Build and install

You need a test Mac running macOS 14 or later, a build Mac with the
[documented Xcode toolchain](docs/building.md#toolchain-and-compatibility), and the
Apple signing permissions described in the [build guide](docs/building.md).
The build targets the Mac's current processor architecture.

1. Clone this repository and open its folder in Terminal.
2. Follow [signing setup and product builds](docs/building.md) to supply your own
   identifiers, certificate and provisioning profiles.
3. Run `./scripts/build_installer.sh` to produce `.local/dist/Pasu-FS.pkg` and its checksum.
4. Follow [installation, updates and removal](docs/installation.md), including
   macOS approval and a check of the running extension.

Building source code alone does not install or activate the system extension.
A valid signature alone does not establish that file protection is active.

## Check the source

From the repository root:

```sh
./scripts/check_source.sh
```

This checks public source content, formatting, property lists, shell syntax,
compilation, the Korean translations of the app and installer, and automated
tests. Temporary build files are removed afterward.
It does not install the app or validate macOS permission prompts, file enforcement,
updates or removal on a real Mac.

The optional `es-capability-probe` executable reports whether its current process
can create an Endpoint Security client. A privilege or entitlement error from an
unsigned command-line build is expected; it is not evidence that the signed
product will fail. It does not subscribe to file events or enforce policies.

## Learn more

- [Build and signing setup](docs/building.md)
- [Install, verify, update and uninstall](docs/installation.md)
- [Using the app's screens and settings](docs/using.md)
- [How the components work](docs/architecture.md)
- [Security boundaries and limitations](docs/threat-model.md)
- [Report a security problem](SECURITY.md)

Policies and logs stay on the Mac. Logs contain process identities and file paths,
not file contents or command arguments. Repeated requests from one process within
a second are counted in one record. Each log is limited to a current 10 MiB
file and one previous file. The app displays a limited recent portion of those
records, not a complete history of every filesystem operation.

## Licensing and contributions

No open-source license is granted. This repository makes the source available
for inspection; it does not grant permission to redistribute the code or binaries.
External contributions and pull requests are not accepted.
