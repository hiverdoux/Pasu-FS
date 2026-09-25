# Pasu FS

Pasu FS controls which applications can open files in selected folders on macOS.
It adds application-based rules to normal file permissions: two applications
running under the same user account can receive different access decisions.

The app uses Apple's **Endpoint Security** framework, which lets an authorized
system extension approve or deny supported operations before they proceed.
This source release is for developers with Apple's Endpoint Security capability
and development signing profiles for their test Macs. It is not a notarized
installer for unrestricted distribution. The app and its installer follow the
macOS language setting and are available in English and Korean.

## What it protects

Each policy selects one folder and one of these rule types:

- **Whitelist:** allow matching programs and deny other programs. An empty list
  denies all supported opens in that folder.
- **Blacklist:** deny matching programs and allow other programs.

**Protection** applies these decisions. **Audit** records the predicted decisions
without blocking access. When folders overlap, every matching Protection policy
must allow the operation. Rules identify signed programs, rather than trusting a
program's filename alone. An optional descendant rule extends its effect to
processes that the matched program launches.

Only new file opens represented by Endpoint Security's `AUTH_OPEN` event are
covered. Creating, moving, deleting, linking, copying and memory-mapping files
are not comprehensively protected. Existing open files are not revoked. An
allowed program can disclose information it reads. Protection stops when the
system extension is inactive. See the [security boundaries](docs/threat-model.md).

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
not file contents or command arguments. Each log is limited to a current 10 MiB
file and one previous file. The app displays a limited recent portion of those
records, not a complete history of every filesystem operation.

## Licensing and contributions

No open-source license is granted. This repository makes the source available
for inspection; it does not grant permission to redistribute the code or binaries.
External contributions and pull requests are not accepted.
