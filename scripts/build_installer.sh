#!/bin/sh
set -eu
usage() { echo "Usage: $0 [--build-number NUMBER]" >&2; exit 64; }
case "$#" in
  0) ;;
  2) [ "$1" = --build-number ] || usage ;;
  *) usage ;;
esac
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_dir="$repo_root/.local/dist"
"$script_dir/build_product.sh" "$@"
mkdir -p "$repo_root/.local/build"
stage=$(/usr/bin/mktemp -d "$repo_root/.local/build/installer.XXXXXX")
trap '/bin/rm -rf "$stage"' EXIT HUP INT TERM
mkdir -p "$stage/root/Applications" "$stage/root/Library/PrivilegedHelperTools" "$stage/root/Library/LaunchDaemons" "$stage/scripts" "$stage/resources"
(
  cd "$output_dir"
  /usr/bin/shasum -a 256 -c Pasu-FS.zip.sha256
)
/usr/bin/ditto -x -k "$output_dir/Pasu-FS.zip" "$stage/root/Applications"
app="$stage/root/Applications/Pasu FS.app"
app_id=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleIdentifier' "$app/Contents/Info.plist")
extension="$app/Contents/Library/SystemExtensions/$app_id.endpointsecurity.systemextension"
helper="$app/Contents/Library/LaunchServices/$app_id.maintenance"
/usr/bin/codesign --verify --deep --strict "$app"
version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$app/Contents/Info.plist")
extension_version=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$extension/Contents/Info.plist")
[ "$version" = "$extension_version" ] || { echo 'App and extension build versions differ.' >&2; exit 1; }
case "$version" in ''|*[!0-9.]*|.*|*..*|*.) echo 'Invalid build version.' >&2; exit 1;; esac
/usr/bin/ditto "$helper" "$stage/root/Library/PrivilegedHelperTools/$app_id.maintenance"
/usr/bin/ditto "$helper" "$stage/scripts/pasu-fs-maintenance"
/usr/bin/sed "s/com[.]example[.]pasu[.]fs/$app_id/g" "$repo_root/Product/Installer/maintenance.plist" > "$stage/root/Library/LaunchDaemons/$app_id.maintenance.plist"
/usr/bin/sed "s/com[.]example[.]pasu[.]fs/$app_id/g" "$repo_root/Product/Installer/preinstall" > "$stage/scripts/preinstall"
/usr/bin/sed "s/com[.]example[.]pasu[.]fs/$app_id/g" "$repo_root/Product/Installer/postinstall" > "$stage/scripts/postinstall"
/bin/chmod 755 "$stage/scripts/preinstall" "$stage/scripts/postinstall" "$stage/scripts/pasu-fs-maintenance"
/bin/chmod -R go-w "$stage/root"
/bin/chmod 644 "$stage/root/Library/LaunchDaemons/$app_id.maintenance.plist"
printf '%s\n' "$version" > "$stage/scripts/build-version"
/usr/bin/ditto "$repo_root/Product/Installer/Welcome.html" "$stage/resources/Welcome.html"
/usr/bin/ditto "$repo_root/Product/Installer/Conclusion.html" "$stage/resources/Conclusion.html"
/usr/bin/pkgbuild --root "$stage/root" --identifier "$app_id.pkg" --version "$version" \
  --install-location / --ownership recommended --component-plist "$repo_root/Product/Installer/components.plist" \
  --scripts "$stage/scripts" "$stage/Pasu-FS-component.pkg"
architectures=$(/usr/bin/lipo -archs "$app/Contents/MacOS/pasu-fs-app" | /usr/bin/tr ' ' ',')
case "$architectures" in arm64|x86_64|arm64,x86_64|x86_64,arm64) ;; *) echo 'Unsupported product architectures.' >&2; exit 1;; esac
cat > "$stage/Distribution.xml" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>Pasu FS</title>
  <welcome file="Welcome.html" mime-type="text/html"/>
  <conclusion file="Conclusion.html" mime-type="text/html"/>
  <options customize="never" require-scripts="false" rootVolumeOnly="true" hostArchitectures="$architectures"/>
  <domains enable_anywhere="false" enable_currentUserHome="false" enable_localSystem="true"/>
  <allowed-os-versions><os-version min="14.0"/></allowed-os-versions>
  <installation-check script="checkAppIsClosed()"/>
  <script><![CDATA[
    function checkAppIsClosed() {
      try {
        var running = system.applications.fromIdentifier("$app_id");
        if (running.length === 0) return true;
        my.result.title = "Quit Pasu FS before installing";
        my.result.message = "Pasu FS is running. Quit it normally, then close and reopen this installer. Protection continues when the app quits; do not use Stop Protection and Quit for an update.";
      } catch (error) {
        my.result.title = "Unable to check running applications";
        my.result.message = "Close Pasu FS and reopen this installer. No application files have been changed.";
      }
      my.result.type = "Fatal";
      return false;
    }
  ]]></script>
  <choices-outline><line choice="default"/></choices-outline>
  <choice id="default" visible="false"><pkg-ref id="$app_id.pkg"/></choice>
  <pkg-ref id="$app_id.pkg" version="$version" onConclusion="None">Pasu-FS-component.pkg</pkg-ref>
</installer-gui-script>
EOF
/usr/bin/productbuild --distribution "$stage/Distribution.xml" --package-path "$stage" --resources "$stage/resources" "$stage/Pasu-FS.pkg"
(
  cd "$stage"
  /usr/bin/shasum -a 256 Pasu-FS.pkg > Pasu-FS.pkg.sha256
)
/bin/mv -f "$stage/Pasu-FS.pkg" "$output_dir/Pasu-FS.pkg"
/bin/mv -f "$stage/Pasu-FS.pkg.sha256" "$output_dir/Pasu-FS.pkg.sha256"
echo "Built local test installer: $output_dir/Pasu-FS.pkg"
echo 'The PKG is unsigned; its application and helper use Apple Development signing.'
