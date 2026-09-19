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
find Product -type f \( -name '*.plist' -o -name '*.entitlements' \) -exec plutil -lint {} +
for file in scripts/*.sh Product/Installer/preinstall Product/Installer/postinstall; do
  sh -n "$file"
done
swift build --scratch-path "$scratch/package" --cache-path "$scratch/cache" --config-path "$scratch/config" --security-path "$scratch/security"
swift test --scratch-path "$scratch/package" --cache-path "$scratch/cache" --config-path "$scratch/config" --security-path "$scratch/security"
echo 'Source checks passed. Installation and runtime behavior require separate verification.'
