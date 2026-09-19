# Install, verify, update and uninstall

Use a registered test Mac and the development-signed PKG from the
[build guide](building.md). The PKG itself is unsigned and is not a notarized
public distribution. Keep your protected test files separate from important data
until you have verified the behavior needed for your use.

## Verify the files

In the repository folder:

```sh
cd .local/dist
shasum -a 256 -c Pasu-FS.pkg.sha256
shasum -a 256 -c Pasu-FS.zip.sha256
```

Both commands must report `OK`. If you transfer a package to another Mac, transfer
its checksum too and repeat the check there. A checksum detects an unexpected
file change; it does not grant permission to run or prove protection is active.

## Install and approve

1. Quit any running Pasu FS app normally. For an update, do not choose
   **Stop Protection and Quit** and do not deactivate the system extension.
2. Open `Pasu-FS.pkg` and follow macOS Installer's administrator authorization.
   The destination is `/Applications/Pasu FS.app`; do not relocate it afterward.
3. Open Pasu FS from Applications and select **Activate Extension** on the setup
   screen. Approve the separate administrator request when it appears.
4. When the app asks for system-extension approval, choose **Open System Settings**
   and approve Pasu FS there. Depending on macOS, this appears under Privacy &
   Security or General → Login Items & Extensions. Follow any required restart.
5. When the app asks for **Full Disk Access**, open that settings page and enable
   the Pasu FS protection component shown by macOS. Close and reopen the app or
   restart if macOS requires it. A waiting or failed state is not active protection.
6. Create a policy for a dedicated test folder. Choose **Protection** or **Audit**,
   a Whitelist or Blacklist, and save the policy.

The first policy can block programs you have not allowed, including applications
you normally use to open the test folder. Start with synthetic files you can
recreate. Do not select a whole home directory or a system directory.

The PKG installs the app and its maintenance service. Copying only the ZIP's app
omits the service and is not the supported installation or update procedure.
Installer success means files were installed; continue with the checks below.

## Confirm the active state

Open **Overview**. Confirm that:

- The extension is active and its authenticated live status is current.
- The app, included extension and active extension versions match.
- A saved Protection policy is present if blocking is intended. Audit or an idle
  state alone is not blocking protection.
- No extension approval, restart, unavailable-status or version-mismatch warning
  remains for the active installation.

For a second read-only check:

```sh
"/Applications/Pasu FS.app/Contents/MacOS/pasu-fs-host" --status
systemextensionsctl list
```

The first command reports the app's authenticated runtime status. It should not
request administrator authorization. In the second output, locate your configured
app identifier plus `.endpointsecurity` and verify the active version. An obsolete
disabled entry waiting for cleanup is different from the active protection entry.
Do not treat a command returning successfully as proof that its reported state is
healthy; read its status and warnings.

To test a Whitelist, create a new text file in the selected folder, allow a signed
editor through **Add Rule**, and save. Open the file in that editor, then attempt a
new open from a different application that is not allowed. The allowed open should
succeed and the unapproved open should be denied. Close existing file handles
before retesting, because already-open files are not revoked. Check the policy's
**Log** tab for the matching path, program, policy decision and final response.
Switching the policy to Audit should record a predicted denial without Pasu FS
blocking the open. Other macOS permissions may still reject access.

This checks one supported new-open scenario. It does not prove protection for
create, delete, rename, hard links or other uncovered operations. See the
[security boundaries](threat-model.md).

## Update

1. Keep the same app identifier, developer team and signing configuration.
2. Build with `./scripts/build_installer.sh`. The builder assigns a new, higher
   build number. On a new build Mac, use `--build-number NUMBER` greater than the
   installed build if the local number record is missing.
3. Verify both output checksums. Quit Pasu FS normally and install the new PKG.
   Replace the whole product through the installer, including its maintenance service.
4. Open Pasu FS and complete any new approval or restart requested by macOS.
5. Repeat the active-state checks above. Confirm the running extension now has
   the new build number and the saved policies and logs you expect are present.

The app requests an automatic extension replacement only when the embedded build
is newer than an active installed build. It does not reactivate an extension you
previously disabled or removed, and it does not automatically downgrade.
A pending approval or current removal can postpone replacement.

The installer preserves multi-policy configuration, compatibility settings and
logs. **An upgrade from the original single-policy format deletes its old
`policy.json`; it does not migrate or back it up.** Record those old rules before
upgrading and recreate them afterward. This does not apply to ordinary updates
between versions using the current multi-policy format.

A lower build is rejected. Reinstalling the same existing PKG is permitted for
repair. If installation fails, retain the error and retry the same package or a
newer package; there is no automatic downgrade or complete rollback.
A running copy in another login session must also be quit before installation.

## Uninstall

1. In **Overview → Application**, select **Uninstall Pasu FS…**. The same action
   is available on the setup screen.
2. Decide whether to select **Also delete Pasu FS settings and audit records**.
   Without it, product configuration and logs are retained for a later reinstall.
   Protected folders and their files are never deleted by this operation.
3. Confirm removal and complete the fresh administrator authorization.
4. If macOS requires a restart, restart manually, reopen Pasu FS and repeat the
   removal confirmation. The app remains installed until it can finish safely.
5. After final cleanup, verify that the app is gone and the configured extension
   no longer has an active entry in `systemextensionsctl list`.

For additional read-only checks, replace the sample identifier below with the
`appBundleIdentifier` in your build configuration:

```sh
APP_ID=com.example.pasu.fs
test ! -e "/Applications/Pasu FS.app" && echo "Application removed"
test ! -e "/Library/PrivilegedHelperTools/$APP_ID.maintenance" && echo "Helper removed"
test ! -e "/Library/LaunchDaemons/$APP_ID.maintenance.plist" && echo "Service file removed"
launchctl print "system/$APP_ID.maintenance"
pkgutil --pkg-info "$APP_ID.pkg"
```

The final two commands should report that the service and package receipt cannot
be found. If you selected data deletion, the product's system Application Support
folder (`/Library/Application Support/PasuFS`) should also be absent. If you kept
settings, that directory may remain. Do not remove protected folders as cleanup.
macOS can retain its own privacy permissions, extension history and diagnostics;
these are not deleted directly by Pasu FS.

App termination by itself does not prove cleanup completed. If removal fails,
retain the message. If the app has already disappeared, reinstall the same or a
newer PKG to restore the removal interface, then retry. Other users should close
their app instances; the remover does not traverse their home directories.
