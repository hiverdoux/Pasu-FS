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

Pasu FS follows the macOS language setting. The app and the installer pages
appear in Korean when Korean is your preferred language and in English otherwise.
This guide uses the English names. Command-line output is always in English, and
detailed messages reported by the system extension or by macOS can also appear in
English inside the app.

1. Quit any running Pasu FS app normally. For an update, do not choose
   **Stop Protection and Quit…** and do not deactivate the system extension.
2. Open `Pasu-FS.pkg` and follow macOS Installer's administrator authorization.
   The first page shows the version and build number the package installs.
   The destination is `/Applications/Pasu FS.app`; do not relocate it afterward.
3. Open Pasu FS from Applications. The setup screen lists four steps. Select
   **Activate Extension**. The app only sends the request to macOS, which then
   shows a notice that a new Endpoint Security extension wants to run, with a
   button that opens System Settings.
4. At **Approve in System Settings**, choose **Open System Settings…** and turn on
   Pasu FS at the location the screen shows: General → Login Items & Extensions →
   Endpoint Security Extensions on macOS 15 and later, or Privacy & Security on
   macOS 14. macOS may ask for an administrator password to turn it on. Follow
   any required restart.
5. At **Allow Full Disk Access**, choose **Open System Settings…** and turn on
   **Pasu FS Endpoint Security**. Close and reopen the app or restart if macOS
   requires it. The checklist moves on by itself; a waiting or failed state is not
   active protection.
6. At **Create your first policy**, choose **Create Policy**. A new policy opens
   in Audit mode with a Whitelist, which blocks nothing. Type the path of a
   dedicated test folder in **Protected Folder**, or use **Choose…**, and choose
   **Save**. Nothing is applied until you save. To block programs, add the ones
   to allow with **Add Program…** and switch **Mode** to **Protection**.
   [Using Pasu FS](using.md) explains each option and screen.

The first policy can block programs you have not allowed, including applications
you normally use to open the test folder. Start with synthetic files you can
recreate. Do not select a whole home directory or a system directory.

The PKG installs the app and its maintenance service. Copying only the ZIP's app
omits the service and is not the supported installation or update procedure.
Installer success means files were installed; continue with the checks below.

## Confirm the active state

Open **Overview**. Confirm that:

- The status at the top reads **Protecting**, with the number of Protection
  and Audit policies on the line below it. The next row reads **Verified over
  an authenticated connection** with an age of a few seconds.
  **Auditing** or **No Active Policies** means nothing is blocked.
- The version line at the bottom reads **Versions match**. **Settings… →
  Extension** lists the app, included extension and running extension versions.
- A saved Protection policy is listed if blocking is intended.
- If a **Needs attention** section appears, resolve its approval, restart, status
  or version items for the active installation first.

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
editor with **Add Program…**, and save. Open the file in that editor, then attempt a
new open from a different application that is not allowed. The allowed open should
succeed and the unapproved open should be denied. Close existing file handles
before retesting, because already-open files are not revoked. In the policy's
**Log**, **All Events** lists each open with its path, program, policy decision and
final response, and **By Program** groups the opens by program. Switching the
policy to Audit should record **Would deny** without Pasu FS blocking the open.
Other macOS permissions may still reject access.

This checks one supported new-open scenario. It does not prove protection for
create, delete, rename, hard links or other uncovered operations. See the
[security boundaries](threat-model.md).

## Update

1. Keep the same app identifier, developer team and signing configuration.
2. Build with `./scripts/build_installer.sh`. The builder assigns a new, higher
   build number. On a new build Mac, use `--build-number NUMBER` greater than the
   installed build if the local number record is missing.
3. Verify both output checksums. Quit Pasu FS normally and install the new PKG,
   checking the build number on the installer's first page.
   Replace the whole product through the installer, including its maintenance service.
4. Open Pasu FS and complete any new approval or restart requested by macOS.
5. Repeat the active-state checks above. In **Settings… → Extension**, confirm
   the running extension has the new build number. Confirm the saved policies and
   logs you expect are present.

The app requests an automatic extension replacement only when the embedded build
is newer than an active installed build. It does not reactivate an extension you
previously disabled or removed, and it does not automatically downgrade.
A pending approval or current removal can postpone replacement.

The installer preserves multi-policy configuration, compatibility settings and
logs. **An upgrade from the original single-policy format deletes its old
`policy.json`; it does not migrate or back it up.** Record those old rules before
upgrading and recreate them afterward. This does not apply to ordinary updates
between versions using the current multi-policy format. A saved policy set that
the running extension cannot read is not deleted either: it stays inactive and
the Overview reports it under **Needs attention**.

A lower build is rejected. Reinstalling the same existing PKG is permitted for
repair. If installation fails, retain the error and retry the same package or a
newer package; there is no automatic downgrade or complete rollback.
A running copy in another login session must also be quit before installation.

## Uninstall

1. Choose **Settings…** from the Pasu FS menu, select **General** and choose
   **Uninstall…**. The setup screen also offers **Uninstall Pasu FS…**.
2. Decide whether to select **Also delete Pasu FS settings and logs**.
   Without it, product configuration and logs are retained for a later reinstall.
   Protected folders and their files are never deleted by this operation.
3. Confirm removal and complete the administrator authentication that Pasu FS
   requests. macOS then asks for the password a second time to let Pasu FS
   deactivate the system extension.
4. If macOS requires a restart, restart manually, reopen Pasu FS and repeat the
   removal confirmation. The app remains installed until it can finish safely.
5. After final cleanup, verify that the app is gone and the configured extension
   no longer has an active entry in `systemextensionsctl list`. The removal also
   cancels the **Open at Login** registration, so System Settings → General →
   Login Items & Extensions should no longer list Pasu FS. If that registration
   cannot be removed, the app stops before deleting any files and shows the error.

For additional read-only checks, replace the sample identifier below with the
`appBundleIdentifier` in your build configuration:

```sh
APP_ID=com.example.pasu.fs
test ! -e "/Applications/Pasu FS.app" && echo "Application removed"
test ! -e "/Library/PrivilegedHelperTools/$APP_ID.maintenance" && echo "Helper removed"
test ! -e "/Library/LaunchDaemons/$APP_ID.maintenance.plist" && echo "Service file removed"
launchctl print "system/$APP_ID.maintenance"
pkgutil --pkg-info "$APP_ID.pkg"
security authorizationdb read "$APP_ID.uninstall"
```

The final three commands should report that the service, the package receipt and
the administrator-authentication entry cannot be found. If you selected data deletion, the product's system Application Support
folder (`/Library/Application Support/PasuFS`) should also be absent. If you kept
settings, that directory may remain. Do not remove protected folders as cleanup.
macOS can retain its own privacy permissions, extension history and diagnostics;
these are not deleted directly by Pasu FS.

macOS also keeps window sizes, sidebar widths and the last folder used in the
file chooser for each user in `~/Library/Preferences/<app identifier>.plist`
(for example `~/Library/Preferences/com.example.pasu.fs.plist`) and may keep a
`~/Library/Saved Application State/<app identifier>.savedState` folder. The
removal never touches home directories, so these files remain. To delete them,
run the following in each user account after the app is gone, replacing the
sample identifier with your `appBundleIdentifier`:

```sh
defaults delete com.example.pasu.fs
rm -rf ~/Library/Saved\ Application\ State/com.example.pasu.fs.savedState
```

The first command reports that the domain does not exist if nothing was saved.

App termination by itself does not prove cleanup completed. If removal fails,
retain the message. If the app has already disappeared, reinstall the same or a
newer PKG to restore the removal interface, then retry. Other users should close
their app instances; the remover does not traverse their home directories.
