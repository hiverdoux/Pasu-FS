# Building Pasu FS

This guide produces a development-signed application and an unsigned PKG
installer for registered test Macs. The app requires Apple's restricted
Endpoint Security capability. It does not provide a general-distribution signing
or notarization workflow.

## Requirements

- A build Mac that can run the selected Xcode, with its macOS SDK and Swift
  toolchain. Swift is the compiler; the SDK contains Apple's system interfaces.
- A test Mac running macOS 14 or later. This is the configured deployment target,
  not a claim that every newer OS has passed installation and protection tests.
- An Apple Development signing certificate whose private key is in Keychain.
- Apple's Endpoint Security capability for your extension identifier.
- Development provisioning profiles for the app and extension, both covering
  the same certificate, developer team and test devices. A provisioning profile
  is Apple's authorization for the identifier, capabilities and test devices.
- An administrator account on the test Mac for installation and removal.

### Toolchain and compatibility

Use Xcode 27.1 with Swift 6.4 to reproduce the checked build. The package declares
Swift tools version 6.0; that declaration alone does not establish compatibility
with every Swift 6 compiler or SDK. The build Mac must meet Xcode's own requirements,
which are separate from the app's macOS 14 deployment target.

Select Xcode for the current Terminal session without changing the global setting:

```sh
export DEVELOPER_DIR=/path/to/Xcode.app/Contents/Developer
xcrun swift --version
```

Replace `/path/to/Xcode.app` with your installed Xcode. Complete Xcode's first-launch
setup if it reports missing components or a license that must be accepted.
The build produces the architecture of the build Mac; use a compatible test Mac.

The GitHub Actions workflow selects Xcode 27.0 on the `xcode-27` image and retains
an Xcode 16.4 / `macos-15` compatibility job. The former image is a
[public preview](https://github.com/actions/runner-images/issues/14404); its exact
Xcode build may differ from the checked configuration. Each job prints its actual
compiler version. The workflow configuration is not evidence that a job has passed:
check the results for the source revision you use. Neither job installs the product
or establishes runtime compatibility, and Xcode 16.4 has not been verified locally.

The extension uses two Endpoint Security interfaces that macOS 27 added, the
deadline miss mode and the maximum deadline (see
[Missed deadlines](architecture.md#missed-deadlines)). It looks their four
functions up by name at run time, on macOS 27 and later only, instead of
referring to them in the source, so the package also builds with SDKs that don't
declare them, such as the one in Xcode 16.4, and the same build runs on earlier
macOS versions.

| Scope | Configuration and limit |
| --- | --- |
| Source compilation and automated checks | Xcode 27.1 (27A9275), Swift 6.4, macOS 27.2, Apple silicon. |
| Installation and runtime checks | macOS 26.6.2 and macOS 27.0.1 on Apple silicon with development signing. [Verified configurations](#verified-configurations) lists what was checked in each configuration and what has not been. |
| macOS 14 deployment target | Configured in the package and installer; runtime compatibility has not been verified on macOS 14. |

### Verified configurations

The table separates normal installation checks from checks with System
Integrity Protection (SIP), a macOS system safeguard, disabled. "Launch daemon"
means that the packaged executable ran as a background service rather than as
an approved system extension. Those results do not establish behavior under
normal SIP-enabled installation.

| Configuration | Checked scope |
| --- | --- |
| macOS 26, SIP enabled, approved system extension; an earlier Pasu FS release | System Settings approval, file-open decisions, case-sensitive APFS, symbolic links, updates and removal. This does not validate the current release's startup or update behavior. |
| macOS 26.6.2, SIP disabled, launch daemon | File requests, folder following, retired paths, request delivery, policy schema 4 migration, App Container Management, XProtect remediator plug-ins and default deadline behavior. |
| macOS 27.0.1, SIP disabled, launch daemon | File requests and mounts, folder following, retired paths, App Container Management, XProtect remediator plug-ins and profile invalidation after a permission change, rejection of the user-session XProtect analysis service, Finder file/folder copies and Time Machine screen restores, schema 5 policy preservation, completed-save durability, shortened fail-closed deadlines and stalled-extension reporting. |
| macOS 27.0.1, SIP disabled, approved system extension | Immediate and restart-dependent extension updates, pending updates, deactivation and removal; early startup, execution histories for preexisting Apple processes and policy behavior on volumes mounted at startup. |

The current update and early-startup behavior has not been verified on macOS 26
or earlier or with SIP enabled. A root XProtect analysis-service scan of a
protected folder has not been verified end to end; its admission rules are
covered by automated tests. Finder copies and Time Machine screen restores
with the compatibility profile enabled remain unverified on macOS 26.6.2.
See [system compatibility](using.md#system-compatibility) for other unverified
operations and [security boundaries](threat-model.md) for protection limits.

## Configure your identifiers and signing

Choose an app identifier you control, for example `com.example.pasu.fs`. In your
Apple developer account, configure these two identifiers and download matching
macOS development profiles:

| Component | Identifier | Required capability |
| --- | --- | --- |
| App | Your chosen app identifier | System Extension installation |
| Extension | App identifier plus `.endpointsecurity` | Endpoint Security client |

The app's requested entitlement is
`com.apple.developer.system-extension.install`. The extension's is
`com.apple.developer.endpoint-security.client`. Register each test device in both
profiles. Keep the same app identifier and signing team when updating an existing
installation; changing them is a different product identity, not an update.

From the repository root:

```sh
mkdir -p .local/signing
cp Product/development-signing.example.json .local/development-signing.json
```

Put your profiles in `.local/signing/` and edit `.local/development-signing.json`:

```json
{
  "appBundleIdentifier": "com.example.pasu.fs",
  "hostProfile": ".local/signing/sample-host.provisionprofile",
  "extensionProfile": ".local/signing/sample-extension.provisionprofile"
}
```

Replace the sample identifier and filenames. Relative profile paths are resolved
from the repository root. Absolute paths are also accepted in this local file.
`PASU_FS_SIGNING_CONFIG` can select a different local JSON configuration; a
relative value is also resolved from the repository root.

A linked worktree is an additional checkout of the same repository made with
`git worktree add`; the original checkout is the main worktree. When you build in
a linked worktree, a relative configuration or profile path that does not exist in
that worktree is resolved from the main worktree instead, so the linked worktree
needs no copy of the signing files.

The builder substitutes the app identifier consistently into a temporary copy of
the product sources, property lists, services, authorization rights and installer.
It does not put your identifier into the checked-in source. The compiler and tests
can use the synthetic source identifier without your signing configuration.

The signing step requires one valid Apple Development certificate shared by both
profiles and available with its private key. If several match, add `identitySHA1`
with the chosen 40-character certificate fingerprint shown by:

```sh
security find-identity -v -p codesigning
```

Do not export your private key. Profiles, local configuration and generated
products are ignored by Git. The generated app embeds the development profiles,
which contain registered-device information; keep these test products private.

## Build a complete installer

```sh
./scripts/build_installer.sh
./scripts/check_dist.sh
```

Successful output consists of:

- `.local/dist/Pasu-FS.zip` and `.local/dist/Pasu-FS.zip.sha256`;
- `.local/dist/Pasu-FS.pkg` and `.local/dist/Pasu-FS.pkg.sha256`.

The product step compiles the app, command-line launcher, system extension and
maintenance service, embeds the profiles, signs each component and verifies the
signatures. It also compiles the String Catalogs in `Product/Localization/` into
the English and Korean resources of the app and extension with Xcode's
`xcstringstool`. Each executable records the macOS SDK version of the build Mac;
macOS uses that record to draw the app with the current system design, and the
build stops if an executable records a different SDK. The installer includes the
app and system maintenance service. Every component must be signed with the hardened
runtime (`codesign --options runtime`) because without it another program running under
the same user account can take control of the running app or extension and act with its
identity; the build also requests a secure timestamp so the signatures stay valid after
the certificate expires. The PKG itself is unsigned. Keychain may ask you to authorize
use of the private key.

The numeric build number increases automatically using `.local/build-sequence.json`.
It is never lower than the `CFBundleVersion` in the product Info.plist templates
under `Product/`, so the first build on a new Mac starts from that value. The same
number is used in the app, extension and package. Failed builds consume an issued
number so a later build cannot accidentally reuse it. Its issue timestamp uses the
build process's current system time zone, including the UTC offset. Keep this local
record when changing branches or restoring older source. To start on a new build
Mac when an installed product has a higher number, choose a greater number explicitly:

```sh
./scripts/build_installer.sh --build-number NUMBER
```

`NUMBER` must be greater than every build number recorded as issued in your
checkout and at least the `CFBundleVersion` of the templates under `Product/`;
otherwise the build stops with `The requested build number must exceed every
previously issued number and meet the product template minimum.` Also choose
it above the installed build, which the record doesn't know, because the
installer rejects a lower build.
The displayed version comes from the product Info.plist templates; keep the app
and extension display versions equal when preparing a new version.

In a linked worktree, the builder reads and advances the record and its lock in
`.local/` of the main worktree, so all worktrees of one repository draw from one
sequence and never issue the same number. A record that an earlier build left in
the linked worktree is also read, so numbers do not go back. The ZIP and PKG are
still written to `.local/dist/` of the worktree you build in. The builder finds
the main worktree with `git rev-parse`, which needs Git 2.31 or later and a
repository whose Git directory is the `.git` folder of the main worktree; if Git
cannot determine it, the worktree's own `.local/` is used. To choose the folder
yourself, set `PASU_FS_LOCAL_ROOT` to the checkout whose `.local/` holds the
record and signing files.

Do not run product builds concurrently in the same checkout. A failed build may
leave the previous successful ZIP or PKG. Check the command's exit status and
both outputs before installing. Temporary files stay under `.local/build/` and are removed
when a builder exits. `check_dist.sh` checks output names and checksums; it does
not establish runtime protection.

For only the application ZIP, run `./scripts/build_product.sh`. Installing an
app from that ZIP alone does not install the maintenance service. Use the PKG for
normal installation and updates.

## Translations

The app follows the macOS language setting and supports English and Korean.
Source code contains the English text. Translations are kept in these files:

- `Product/Localization/App/Localizable.xcstrings` for the app's text. Some
  English entries also define plural forms.
- `Product/Localization/*/InfoPlist.xcstrings` for text macOS shows from the app
  and extension property lists.
- `Product/Installer/Resources/<language>.lproj/` for the installer pages and
  messages. Each `Welcome.html` keeps the `@PASU_VERSION@` and `@PASU_BUILD@`
  placeholders, which the installer build replaces with the version and build
  number of the package.

A String Catalog (`.xcstrings`) is a JSON file that Xcode can edit. After changing
user-facing text, run `./scripts/check_source.sh`. Its localization check lists
text without a Korean translation, catalog entries the app no longer uses,
installer files or messages missing in a language, and Korean text in
`Localizable.xcstrings` that offers both forms of a particle, as in `을(를)`.
A Korean particle's form depends on the sound before it, so write such a
sentence so that no particle follows the inserted value. The four
administrator password prompts that macOS shows for Pasu FS operations
(activating the extension, deactivating it, uninstalling, and saving a policy
change that reduces protection) are catalog entries with a manual extraction
state: macOS reads them from the installed app when the installer registers the
operations, so the check does not expect them in the app's source code.
Messages from the system extension and the command-line tools are in English;
the app shows known extension messages in the selected language.

## Troubleshooting

| Error | Action |
| --- | --- |
| Missing signing configuration or profile | Check your JSON filename and the profile paths. A linked worktree uses the files of the main worktree when it has none of its own. |
| Profile App ID mismatch | Use profiles for the exact app identifier and its `.endpointsecurity` extension. |
| Expired profile or missing entitlement | Renew the profile with the required capability and registered test devices. |
| No matching signing identity | Import the certificate into Keychain with its private key, or select the right certificate fingerprint. |
| Build number rejected | Use a number greater than the locally recorded number and installed build, and at least the template's `CFBundleVersion`. |
| Compilation or SDK error | Confirm the selected Xcode includes a Swift 6 toolchain and macOS SDK. |
| `records SDK … instead of …` | Select a full Xcode with `DEVELOPER_DIR` so the compiler, linker and SDK come from the same toolchain. |
| `Missing compiled localization` | The catalogs compiled to no Korean file or no English plural file at all: `Localizable.xcstrings` needs at least one Korean translation and one English plural variation, and each `InfoPlist.xcstrings` at least one Korean translation. Individual missing entries are reported by `./scripts/check_source.sh` instead. |
| `Invalid app version` | Keep `CFBundleShortVersionString` in the Info.plist templates numeric, with dots only. |
| `Unfilled placeholder` | Keep `@PASU_VERSION@` and `@PASU_BUILD@` in every installer `Welcome.html`. |
| `xcstringstool` not found | Select a full Xcode installation with `DEVELOPER_DIR`; the Command Line Tools alone do not include it. |
| Signature succeeds but app cannot run | Confirm the device is registered, profiles are valid, and macOS allows development-signed software on that device. |

See [installation and verification](installation.md) for system-extension and
Full Disk Access approvals. Never interpret a successful build as proof that
those runtime requirements are satisfied.

To check the packaged command-line launcher's help, invalid arguments and path
handling without activating the extension, run:

```sh
./scripts/check_product_cli.sh "/Applications/Pasu FS.app"
```

This check requires an already installed or extracted app. It does not replace the
installation, permission and file-access checks in the installation guide.

The optional capability probe described in the README runs from the repository
root with `swift run es-capability-probe`. It prints the result of creating an
Endpoint Security client and exits with status 0 for the expected outcomes of an
unsigned build, such as a missing entitlement or permission.
