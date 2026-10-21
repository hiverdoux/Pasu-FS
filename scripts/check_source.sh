#!/bin/sh
set -eu
[ "$#" -eq 0 ] || { echo "Usage: $0" >&2; exit 64; }
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
cd "$repo_root"
mkdir -p .local/build
scratch=$(mktemp -d .local/build/check.XXXXXX)
trap 'rm -rf "$scratch"' EXIT HUP INT TERM
export TMPDIR="$repo_root/$scratch/tmp"
mkdir -p "$TMPDIR"
swift -module-cache-path "$scratch/module-cache" scripts/check_public_content.swift
swift format lint --recursive --strict Package.swift Sources Tests scripts/*.swift
find Product -type f \( -name '*.plist' -o -name '*.entitlements' -o -name '*.strings' \) -exec plutil -lint {} +
# The app's display of an extension update that waits for a restart depends on this key.
[ "$(/usr/libexec/PlistBuddy -c 'Print :NSEndpointSecurityRebootRequired' Product/PasuFSSystemExtension-Info.plist 2>/dev/null || true)" = true ] ||
  { echo 'Product/PasuFSSystemExtension-Info.plist must set NSEndpointSecurityRebootRequired to true.' >&2; exit 1; }
# Protection from early in startup, before programs other than Apple platform binaries run,
# depends on this key.
[ "$(/usr/libexec/PlistBuddy -c 'Print :NSEndpointSecurityEarlyBoot' Product/PasuFSSystemExtension-Info.plist 2>/dev/null || true)" = true ] ||
  { echo 'Product/PasuFSSystemExtension-Info.plist must set NSEndpointSecurityEarlyBoot to true.' >&2; exit 1; }
for file in scripts/*.sh Product/Installer/preinstall Product/Installer/postinstall; do
  sh -n "$file"
done
# The compiler lists the app's user-facing strings so the catalog check can compare them.
strings="$repo_root/$scratch/strings"
swift build --scratch-path "$scratch/package" --cache-path "$scratch/cache" --config-path "$scratch/config" --security-path "$scratch/security" \
  -Xswiftc -emit-localized-strings -Xswiftc -emit-localized-strings-path -Xswiftc "$strings"
swift -module-cache-path "$scratch/module-cache" scripts/check_localization.swift "$strings"
swift test --scratch-path "$scratch/package" --cache-path "$scratch/cache" --config-path "$scratch/config" --security-path "$scratch/security" \
  -Xswiftc -emit-localized-strings -Xswiftc -emit-localized-strings-path -Xswiftc "$strings"
echo 'Source checks passed. Installation and runtime behavior require separate verification.'
