# Security boundaries

Pasu FS provides an additional application-based check on supported file opens.
It is intended to reduce access by unapproved applications running under the same
macOS user account. It does not replace macOS permissions, privacy controls,
App Sandbox, System Integrity Protection or disk encryption.

## Conditions for protection

A protection claim requires all of the following:

- A correctly signed, entitled and approved system extension is active.
- Full Disk Access is granted and the Endpoint Security client is healthy.
- A valid Protection policy covers the target path.
- The operation is a supported new `AUTH_OPEN` request.
- The request can be evaluated and answered within macOS's event deadline.

The app's authenticated live state is the source for its protection display.
A successful installer, signature verification or unit test alone proves none of
these runtime conditions. Audit mode never blocks access.

## Identity and rules

Rules match exact signing identities. A signed non-platform program must match
both its developer team and signing identifier. An Apple platform rule also
requires the kernel's platform-binary fact. Paths and display names in a log are
informational; they are not sufficient authorization.

Descendant inheritance deliberately trusts or blocks programs launched by the
matched process, including later executable replacements. Enable it only if that
broader effect is wanted. An independent service is not a descendant merely
because it serves the application.

Overlapping Protection policies combine restrictively: every matching policy
must allow. An empty Whitelist denies all supported matching opens. An empty
Blacklist adds no denials. Pasu FS allowing a request does not override a denial
by macOS or another security component.

## Known limitations

- The current extension handles `AUTH_OPEN`. Opening a folder to list its
  contents is such an open and is checked. Other operation types do not have
  complete enforcement, including create, rename, delete, link, clone, truncate,
  copy and memory mapping. Reading the metadata of a path by name, such as
  `stat`, does not open the file and is not checked.
- Existing file descriptors or mappings are not revoked. Protection is not a
  record of every individual read or write.
- An allowed program can copy, transmit or reveal information it reads. Attacks
  inside a trusted program and services accepting commands from other programs
  are outside the simple signing-identity boundary.
- Path matching does not follow a folder's persistent object identity after
  moves, replacement or unmounting. Preexisting hard links and other aliases can
  expose the same data through another path. Review policies after folder changes.
- Path comparison uses the selected volume's reported case rules. Unsupported or
  unavailable volume/account metadata prevents preparing a policy. Network and
  unusual filesystem behavior needs separate runtime validation.
- Truncated or undecodable in-scope requests are denied by Protection policies,
  but incomplete paths can limit the ability to identify the matching scope.
- Protection is absent when the extension is inactive. Startup gaps, crashes,
  event loss and deadline failures are not a guarantee of continued denial.
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

Application files are installed at a fixed system location. The app and extension
must retain their configured signing identity during updates. Changing the team
or bundle identifiers requires separate installation planning.

## Privacy and retention

Policies and logs remain local. Logs contain sensitive metadata such as program
identities and file paths. Do not publish unredacted logs or development signing
profiles. No telemetry service is used by the policy engine.

Log queues and storage are bounded; dropped records and incomplete history are
possible. Logs are diagnostic evidence, not a complete forensic audit trail.
The [removal guide](installation.md) explains which settings and logs are retained
or deleted. macOS may retain its own permissions and diagnostic history.

Report a concern using [the security policy](../SECURITY.md).
