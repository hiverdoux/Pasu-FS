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
3. When the installation finishes, Pasu FS opens by itself for the user logged in
   at the screen (see [Opening the app after installation](#opening-the-app-after-installation));
   otherwise open it from Applications. The setup screen lists four steps. Select
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
   in Audit mode, which blocks nothing. Type the path of a
   dedicated test folder in **Protected Folder**, or use **Choose…**, and choose
   **Save**. Nothing is applied until you save. To block programs, add the ones
   to allow with **Add Program…** under **Programs to Allow** and switch **Mode**
   to **Protection**.
   [Using Pasu FS](using.md) explains each option and screen.

The first policy can block programs you have not allowed, including applications
you normally use to open the test folder. Start with synthetic files you can
recreate. Do not select a whole home directory or a system directory.

The PKG installs the app and its maintenance service. Copying only the ZIP's app
omits the service and is not the supported installation or update procedure.
Installer success means files were installed; continue with the checks below.

### Opening the app after installation

At the end of the installation, the package opens `/Applications/Pasu FS.app`
for the user logged in at the screen, with that user's account rather than as
root. On an update this lets the app ask macOS to update the running extension
right away, so a restart after the installation completes the update. When several users
are logged in with fast user switching, only the user at the screen gets the
app. Nothing opens when nobody is logged in at the screen, or when the package
is installed with the `installer` command (`sudo installer -pkg Pasu-FS.pkg
-target /`); open Pasu FS yourself before restarting. If the app can't be
opened, the installation still succeeds and the installer log says to open it
from Applications.

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

The first command reports the installation state macOS reports and the app's
authenticated runtime status. It should not request administrator authorization.
When macOS doesn't report the installation state within 20 seconds, it prints
`System extension properties: unanswered within 20 seconds` and reports the
status from the running extension alone. In the second output, locate your
configured app identifier plus `.endpointsecurity` and verify the active
version. An obsolete disabled entry waiting for cleanup is different from the
active protection entry.
Do not treat a command returning successfully as proof that its reported state is
healthy; read its status and warnings.

To test **Programs to Allow**, create a new text file in the selected folder, allow a signed
editor with **Add Program…** under **Programs to Allow**, and save. Relaunch the editor after observation
has started to test a newly observed launch. Both that first program and
any separate helper that opens the file must be directly allowed. Open the file
in the editor, then attempt a new open from a different application that is not
allowed. The allowed open should
succeed and the unapproved open should be denied. Close existing file handles
before retesting, because already-open files are not revoked. In the policy's
**Log**, **All Events** lists each open with its path, program, policy decision and
final response, and **By Program** groups the opens by program. Switching the
policy to Audit should record **Would deny** without Pasu FS blocking the open.
Other macOS permissions may still reject access.

Select a record and open its details to see why it was decided that way: the
first program, the access process and, for a denial, the reason. The test above
checks one file open. Creating, renaming, deleting, hard linking, cloning,
copying and truncating files in the folder, and changing the permissions,
owner, flags, extended attributes, attributes or times of the folder and the
items in it, are decided by the same rules and appear in the log with their own
request type; memory mapping and other uncovered operations are not checked.
See the [security boundaries](threat-model.md).

## At startup

An approved extension asks macOS to start it early when the Mac starts up (its
Info.plist sets `NSEndpointSecurityEarlyBoot`). From then until the extension
has subscribed to its events, macOS holds every mount and the start of every
program that isn't an Apple platform binary, one of the programs that are part
of macOS. Programs from other developers, including launch daemons, login
items and apps that open at login, therefore start only once the extension
checks requests, so the policies apply to them from their first request. The
extension subscribes once it has read the saved policies, registered their
folders and prepared its decisions, so its first subscription covers every
checked request type at once. macOS services keep starting in the meantime;
their requests before the subscription aren't checked, and those that
`launchd` started directly get an execution history afterwards (see
[Behavior](using.md#behavior)).

**Settings… → Diagnostics → Execution History → Tracking started** shows when the
subscription happened and how long after the Mac started, and
`"/Applications/Pasu FS.app/Contents/MacOS/pasu-fs-host" --status` prints the
same with `firstSubscriptionAfterStartup`. If the extension can't subscribe,
for example before Full Disk Access is granted, it tries again every 10
seconds, and macOS holds mounts and programs only until a timeout of its own,
whose length Apple doesn't document; after it, they start without being
checked until the extension subscribes. A Mac that starts up noticeably more
slowly after installing Pasu FS may be waiting for that timeout; check
**Needs attention** and the extension's log (subsystem
`com.example.pasu.fs.endpointsecurity`, category `endpoint-client`, with your
own identifier in place of `com.example.pasu.fs`).

Volumes other than the startup volume are mounted only after the subscription.
A Protection policy denies a mount at its folder or at a folder that contains
it, so a Protection policy whose folder is on such a volume keeps that volume
from being mounted at startup (see the
[security boundaries](threat-model.md#known-limitations)). Keep protected
folders on the startup volume, or use Audit mode for a folder on another
volume.

## Update

1. Keep the same app identifier, developer team and signing configuration.
2. Build with `./scripts/build_installer.sh`. The builder assigns a new, higher
   build number. On a new build Mac, use `--build-number NUMBER` greater than the
   installed build if the local number record is missing.
3. Verify both output checksums. Quit Pasu FS normally and install the new PKG,
   checking the build number on the installer's first page.
   Replace the whole product through the installer, including its maintenance service.
4. Pasu FS opens by itself when the installation finishes (see
   [Opening the app after installation](#opening-the-app-after-installation));
   if it doesn't, open it from Applications before restarting. The app, not the
   installer, asks macOS to update the running extension. Complete any new
   approval requested by macOS.
5. Restart the Mac after the app has opened. The extension asks macOS to replace
   it only at a restart, so macOS doesn't stop the running extension: until the
   restart the earlier version keeps checking requests with its policies, and
   programs that were already open keep their access. Meanwhile **Needs
   attention** on the Overview and the menu bar show **The extension update
   finishes when you restart this Mac.**, and **Settings… → Extension** shows
   the earlier build as the running extension, **Running until restart**, and
   the new build as **Starts after restart**. The notice stays when you quit and
   reopen the app. After the restart the new extension starts while every
   program starts again, and the notice disappears. Until then the update,
   including any security fix it contains, has not taken effect. A restart
   before the app has opened doesn't help: the update is requested only when the
   app opens afterwards, including at login, and another restart is needed. The
   installer's last page gives the same order.

   The update from 0.10.3 or earlier is different, because macOS follows the
   setting of the running extension and those versions don't have it: macOS
   replaces the extension at once when the app opens. **Settings… → Extension**
   then shows the new build number running, and while a Protection policy could
   deny programs, **Needs attention** shows **The extension was updated.
   Restarting this Mac is recommended.** The new extension has not observed the
   programs that were already open. Protection policies deny requests with
   incomplete history, even when a rule allows the program, unless a
   compatibility profile admits them. Apple programs that `launchd` started
   directly, such as Apple apps opened from the Dock, can regain a history
   (see [Behavior](using.md#behavior)). Restarting gives affected programs a
   newly observed launch and clears the recommendation. Without a restart,
   quit and reopen affected programs; for a command, restart the app it is run
   from, such as Terminal.
6. After the restart, repeat the active-state checks above. In **Settings… →
   Extension**, confirm the running extension has the new build number. Confirm
   the saved policies and logs you expect are present.

The app requests an automatic extension replacement only when the embedded build
is newer than an active installed build. It does not reactivate an extension you
previously disabled or removed, and it does not automatically downgrade.
A pending approval or current removal can postpone replacement. While an update
waits for a restart, macOS reports no version as enabled, and the app requests
no further update. A newer package installed meanwhile therefore takes two
restarts: macOS starts the version that was waiting at the first one, the app
then asks for its own extension when it opens, and that update finishes at the
second restart. **Settings… → Extension** says so while the first update waits. Until the new extension replaces the running one, including
while the replacement waits for an approval or a restart, the app works with the
running extension. What
happens then depends on the configuration protocol version (see
[Storage and logs](architecture.md#storage-and-logs)):

- When the update keeps the protocol version, the app reads and saves the
  policies through the running extension as before. What the new version adds
  to the extension takes effect only after the replacement: the earlier
  extension refuses a save that turns on a compatibility profile its own
  catalog doesn't have, and its status lacks the fields that the new version
  added.
- When the update changes the protocol version, for example from a version that
  stores policy schema 4 or earlier, the app can't read or save the policies.
  Meanwhile it shows only the state the running extension writes to its
  diagnostic file, which can't confirm protection, and lists no policies, while
  the policies in effect keep protecting. The extension refuses the app's
  connection check when the versions differ, so the app reports no version
  difference in this case. Its message **The app and extension use different
  configuration versions (app N, extension M). Install a matching package.**
  appears only if an extension accepts the check and then reports another
  version.

The installer preserves the policies, including the compatibility profiles
turned on in them, and logs. Policies saved in the current policy schema (5)
are used as they are, with their lists, descendant options, compatibility
profile approvals, each folder's identity and retired paths. Policies saved in
policy schema 4 keep everything they hold as well; the new extension stores
them again in the current schema when it starts, and **Policy storage** stays
**Normal**. Policies saved in schema 2 or 3 are converted as described in
[Policy storage states](using.md#policy-storage-states). A compatibility
profile stays active unless the update changed what it allows; it then becomes
inactive until it is turned on again (see
[System compatibility](using.md#system-compatibility)). Earlier log records
stay readable next to new ones, and the new extension writes its status in the
current status schema. An earlier version can't read policies saved in a later
policy schema, so its extension would apply none of them; see the format
versions in [Storage and logs](architecture.md#storage-and-logs). **An upgrade from the original single-policy
format deletes its old `policy.json`; it does not migrate or back it up.** Record those old rules before
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
   deactivate the system extension, unless it was already deactivated in
   **Settings… → Extension**.
4. macOS removes the extension only at the next restart, and it keeps
   protecting until then. Pasu FS shows **Finish Uninstalling Pasu FS** and
   removes no files yet. Restart the Mac, open Pasu FS, choose **Continue
   Uninstalling** and complete the administrator authentication again. The app
   remains installed until it can finish safely; **Continue Uninstalling**
   before the restart only repeats that a restart is needed. If an extension
   update waits for a restart, the deactivation also makes macOS remove the
   waiting version at once, so the same single restart finishes the removal.
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
security authorizationdb read "$APP_ID.extension.activate"
security authorizationdb read "$APP_ID.extension.deactivate"
security authorizationdb read "$APP_ID.uninstall"
security authorizationdb read "$APP_ID.policy.weaken"
```

The final six commands should report that the service, the package receipt and
the four administrator-authentication entries cannot be found. If you selected
data deletion, the product's system Application Support folder
(`/Library/Application Support/PasuFS`) should also be absent. If you kept
settings, that directory may remain (see [Storage and
logs](architecture.md#storage-and-logs) for the files it holds). Do not remove
protected folders as cleanup. macOS can retain its own privacy permissions,
extension history and diagnostics; these are not deleted directly by Pasu FS.

macOS also keeps window sizes, sidebar widths, the last folder used in the
file chooser and the app's note of the last extension update for each user in
`~/Library/Preferences/<app identifier>.plist`
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

## Troubleshooting

### macOS isn't reporting the system extension state

Pasu FS asks macOS for the extension's installation state (which versions are
installed, enabled, waiting for approval or being removed) through the system
extension daemon `sysextd`. When `sysextd` doesn't answer a request within 20
seconds, the Overview lists **macOS isn’t reporting the system extension state
(for N). In Terminal, run “sudo killall sysextd”, or restart this Mac.** under
**Needs attention**, the menu bar and the setup assistant show the same line,
and **Settings… → Extension** shows **Version check unavailable** with the same
notice. N counts from the first unanswered request.

While `sysextd` doesn't answer, the app asks it at most once a minute, measured
from the previous unanswered request, also when you choose **Refresh**; its own
checks wait longer after each unanswered request, up to 10 minutes. Meanwhile
the app keeps asking the running extension for its status over the
authenticated connection. **The extension still answers, so protection
continues.** below the notice means that the extension still checks requests
with the policies in effect. Without that line, the status at the top of the
Overview shows whether the extension answers. Activation, updates and
deactivation also go through `sysextd`, so they may not finish until it answers
again.

To recover:

1. In Terminal, run the following command and enter an administrator password:

   ```sh
   sudo killall sysextd
   ```

   macOS starts `sysextd` again when it is next needed. The Pasu FS extension
   runs as a separate process and keeps running.
2. Choose **Refresh** on the Overview, or **Refresh Status** in the menu bar.
   The notice disappears once macOS answers. Within a minute of the previous
   unanswered request, **Refresh** doesn't ask macOS again; choose it again
   after that minute.
3. If the notice stays, restart the Mac.

Pasu FS sends each installation-state request from a short-lived process that
exits once macOS answers and stops waiting after 20 seconds. This closes the
request's connection to `sysextd` and prevents connections accumulating while
the app stays open. An earlier app version can leave `sysextd` busy releasing
connections after it quits; the recovery steps above also apply after an
update. See [Overview](using.md#overview) for the current request schedule.
