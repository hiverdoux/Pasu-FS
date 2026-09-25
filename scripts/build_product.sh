#!/bin/sh

set -eu

build_number=
case "$#" in
  0) ;;
  2) [ "$1" = --build-number ] || { echo "Usage: $0 [--build-number NUMBER]" >&2; exit 64; }; build_number=$2; case "$build_number" in ''|*[!0-9]*) echo "Build number must be a positive integer." >&2; exit 64 ;; esac ;;
  *) echo "Usage: $0 [--build-number NUMBER]" >&2; exit 64 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_root=$(CDPATH= cd -- "$script_dir/.." && pwd)
output_dir="$repo_root/.local/dist"
mkdir -p "$output_dir"
mkdir -p "$repo_root/.local/build"
stage_dir=$(mktemp -d "$repo_root/.local/build/product.XXXXXX")
trap 'rm -rf "$stage_dir"' EXIT HUP INT TERM

if [ -n "$build_number" ]; then
  swift -module-cache-path "$stage_dir/module-cache" "$script_dir/prepare_build.swift" \
    "$repo_root" "${PASU_FS_SIGNING_CONFIG:-$repo_root/.local/development-signing.json}" "$stage_dir" "$build_number"
else
  swift -module-cache-path "$stage_dir/module-cache" "$script_dir/prepare_build.swift" \
    "$repo_root" "${PASU_FS_SIGNING_CONFIG:-$repo_root/.local/development-signing.json}" "$stage_dir"
fi
source_root="$stage_dir/source"
app_id=$(cat "$stage_dir/app-identifier")
swift -module-cache-path "$stage_dir/module-cache" \
  "$script_dir/prepare_development_signing.swift" "$source_root" "$stage_dir/signing.json" "$stage_dir/signing"
signing_identity=$(cat "$stage_dir/signing/identity")
host_entitlements="$stage_dir/signing/host.entitlements"
extension_entitlements="$stage_dir/signing/extension.entitlements"

scratch_path="$stage_dir/swift-build"
# macOS draws an app with the current system design only when its executables record a
# current SDK. The default Swift Build engine records the deployment target instead, so pass
# the minimum macOS version from the package manifest and the SDK version to the linker.
minimum_macos=$(swift package \
  --package-path "$source_root" \
  --scratch-path "$scratch_path" \
  --cache-path "$stage_dir/cache" \
  --config-path "$stage_dir/config" \
  --security-path "$stage_dir/security" \
  dump-package | plutil -extract platforms.0.version raw -o - -)
sdk_version=$(xcrun --sdk macosx --show-sdk-version)
platform_version="-Xlinker -platform_version -Xlinker macos -Xlinker $minimum_macos -Xlinker $sdk_version"
swift build \
  --package-path "$source_root" \
  --scratch-path "$scratch_path" \
  --cache-path "$stage_dir/cache" \
  --config-path "$stage_dir/config" \
  --security-path "$stage_dir/security" \
  --configuration release \
  $platform_version \
  --product pasu-fs-app
swift build \
  --package-path "$source_root" \
  --scratch-path "$scratch_path" \
  --cache-path "$stage_dir/cache" \
  --config-path "$stage_dir/config" \
  --security-path "$stage_dir/security" \
  --configuration release \
  $platform_version \
  --product pasu-fs-host
swift build \
  --package-path "$source_root" \
  --scratch-path "$scratch_path" \
  --cache-path "$stage_dir/cache" \
  --config-path "$stage_dir/config" \
  --security-path "$stage_dir/security" \
  --configuration release \
  $platform_version \
  --product pasu-fs-system-extension
swift build \
  --package-path "$source_root" \
  --scratch-path "$scratch_path" \
  --cache-path "$stage_dir/cache" \
  --config-path "$stage_dir/config" \
  --security-path "$stage_dir/security" \
  --configuration release \
  $platform_version \
  --product pasu-fs-maintenance

bin_path=$(swift build \
  --package-path "$source_root" \
  --scratch-path "$scratch_path" \
  --cache-path "$stage_dir/cache" \
  --config-path "$stage_dir/config" \
  --security-path "$stage_dir/security" \
  --configuration release \
  $platform_version \
  --show-bin-path)
for executable in pasu-fs-app pasu-fs-host pasu-fs-system-extension pasu-fs-maintenance; do
  recorded=$(otool -l "$bin_path/$executable" |
    awk '$1 == "cmd" && $2 == "LC_BUILD_VERSION" { found = 1 } found && $1 == "sdk" { print $2; exit }')
  [ "$recorded" = "$sdk_version" ] ||
    { echo "$executable records SDK ${recorded:-none} instead of $sdk_version." >&2; exit 1; }
done

app="$stage_dir/Pasu FS.app"
system_extension="$app/Contents/Library/SystemExtensions/$app_id.endpointsecurity.systemextension"

mkdir -p "$app/Contents/MacOS" "$system_extension/Contents/MacOS"
mkdir -p "$app/Contents/Library/LaunchServices"
maintenance="$app/Contents/Library/LaunchServices/$app_id.maintenance"
ditto "$bin_path/pasu-fs-maintenance" "$maintenance"
ditto "$source_root/Product/PasuFSHost-Info.plist" "$app/Contents/Info.plist"
ditto "$bin_path/pasu-fs-app" "$app/Contents/MacOS/pasu-fs-app"
ditto "$bin_path/pasu-fs-host" "$app/Contents/MacOS/pasu-fs-host"
ditto \
  "$source_root/Product/PasuFSSystemExtension-Info.plist" \
  "$system_extension/Contents/Info.plist"
ditto \
  "$bin_path/pasu-fs-system-extension" \
  "$system_extension/Contents/MacOS/pasu-fs-system-extension"

# Each language folder lets macOS show the app in the user's preferred language.
localization="$source_root/Product/Localization"
app_resources="$app/Contents/Resources"
extension_resources="$system_extension/Contents/Resources"
mkdir -p "$app_resources" "$extension_resources"
xcrun xcstringstool compile "$localization/App/Localizable.xcstrings" \
  --output-directory "$app_resources"
xcrun xcstringstool compile "$localization/App/InfoPlist.xcstrings" \
  --output-directory "$app_resources"
xcrun xcstringstool compile "$localization/SystemExtension/InfoPlist.xcstrings" \
  --output-directory "$extension_resources"
for resource in \
  "$app_resources/ko.lproj/Localizable.strings" \
  "$app_resources/en.lproj/Localizable.stringsdict" \
  "$app_resources/ko.lproj/InfoPlist.strings" \
  "$extension_resources/ko.lproj/InfoPlist.strings"
do
  [ -f "$resource" ] || { echo "Missing compiled localization: $resource" >&2; exit 1; }
done

ditto "$stage_dir/signing/host.provisionprofile" "$app/Contents/embedded.provisionprofile"
ditto "$stage_dir/signing/extension.provisionprofile" \
    "$system_extension/Contents/embedded.provisionprofile"

# The launcher claims no restricted entitlement. The app runs the CLI operations.
codesign \
  --force \
  --sign "$signing_identity" \
  --identifier "$app_id.maintenance" \
  "$maintenance"
codesign \
  --force \
  --sign "$signing_identity" \
  --identifier "$app_id.cli" \
  "$app/Contents/MacOS/pasu-fs-host"

codesign \
  --force \
  --sign "$signing_identity" \
  --identifier "$app_id.endpointsecurity" \
  --entitlements "$extension_entitlements" \
  "$system_extension"

codesign \
  --force \
  --sign "$signing_identity" \
  --identifier "$app_id" \
  --entitlements "$host_entitlements" \
  "$app"

codesign --verify --deep --strict --verbose=2 "$app"
codesign --verify --strict --verbose=2 "$app/Contents/MacOS/pasu-fs-host"
codesign --verify --strict --verbose=2 "$system_extension"
codesign --verify --strict --verbose=2 "$maintenance"
plutil -lint "$app/Contents/Info.plist" "$system_extension/Contents/Info.plist"

archive="$output_dir/Pasu-FS.zip"
archive_name=$(basename "$archive")
ditto -c -k --keepParent "$app" "$stage_dir/$archive_name"
(
  cd "$stage_dir"
  shasum -a 256 "$archive_name" > "$archive_name.sha256"
)
mv -f "$stage_dir/$archive_name" "$archive"
mv -f "$stage_dir/$archive_name.sha256" "$archive.sha256"

echo "Built: $archive"
echo "Signing: Apple Development"
echo "Checksum: $archive.sha256"
