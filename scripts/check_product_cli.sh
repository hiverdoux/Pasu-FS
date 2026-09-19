#!/bin/sh
set -eu

[ "$#" -eq 1 ] || { echo "Usage: $0 APP_BUNDLE" >&2; exit 64; }
app=$(CDPATH= cd -- "$1" && pwd)
cli="$app/Contents/MacOS/pasu-fs-host"
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
mkdir -p "$repo_root/.local/build"
scratch=$(mktemp -d "$repo_root/.local/build/cli-check.XXXXXX")
trap 'rm -rf "$scratch"' EXIT HUP INT TERM

check_help() {
  "$@" > "$scratch/stdout" 2> "$scratch/stderr"
  test ! -s "$scratch/stderr"
  grep -q '^Usage: pasu-fs-host --activate | --deactivate | --status$' "$scratch/stdout"
}

check_invalid() {
  result=0
  "$@" > "$scratch/stdout" 2> "$scratch/stderr" || result=$?
  test "$result" -eq 1
  test ! -s "$scratch/stdout"
  grep -q '^Usage: pasu-fs-host ' "$scratch/stderr"
}

check_help "$cli" --help
check_help "$cli" -h
check_invalid "$cli"
check_invalid "$cli" --invalid
check_invalid "$cli" --status extra
check_invalid "$cli" '--help --activate'
check_invalid "$cli" --help --activate

# Resolve the executable independently of argv[0] and the working directory.
ln -s "$cli" "$scratch/sample-cli"
check_help "$scratch/sample-cli" --help
(
  cd "$app/Contents/MacOS"
  check_help ./pasu-fs-host --help
)
echo "CLI help, invalid arguments, exit codes, streams and path resolution: passed."
