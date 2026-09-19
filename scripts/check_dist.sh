#!/bin/sh
set -eu
[ "$#" -eq 0 ] || { echo "Usage: $0" >&2; exit 64; }
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_dir="$repo_root/.local/dist"
[ ! -L "$output_dir" ] || { echo 'Artifact directory must not be a symbolic link.' >&2; exit 1; }
[ -d "$output_dir" ] || { echo 'Artifact directory is absent; no outputs to check.'; exit 0; }
status=0
for entry in "$output_dir"/* "$output_dir"/.[!.]* "$output_dir"/..?*; do
  [ -e "$entry" ] || [ -L "$entry" ] || continue
  name=${entry##*/}
  case "$name" in
    Pasu-FS.zip|Pasu-FS.zip.sha256|Pasu-FS.pkg|Pasu-FS.pkg.sha256)
      if [ ! -f "$entry" ] || [ -L "$entry" ]; then
        echo "Expected a regular deliverable file: $name" >&2
        status=1
      fi
      ;;
    *) echo "Unexpected artifact entry: $name" >&2; status=1 ;;
  esac
done
[ "$status" -eq 0 ] || exit "$status"
cd "$output_dir"
for name in Pasu-FS.zip Pasu-FS.pkg; do
  if [ -f "$name" ] || [ -f "$name.sha256" ]; then
    if [ ! -f "$name" ] || [ ! -f "$name.sha256" ]; then
      echo "Missing deliverable or checksum partner: $name" >&2
      status=1
      continue
    fi
    expected=$(/usr/bin/shasum -a 256 "$name")
    recorded=$(/bin/cat "$name.sha256")
    if [ "$recorded" != "$expected" ]; then
      echo "Checksum mismatch: $name" >&2
      status=1
    else
      echo "$name: OK"
    fi
  fi
done
[ "$status" -eq 0 ] || exit "$status"
echo 'Artifact directory contains only final deliverables and matching checksums.'
