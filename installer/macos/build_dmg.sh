#!/usr/bin/env bash
set -euo pipefail

warn() {
    printf '[WARN] %s\n' "$*" >&2
}

fail() {
    printf '[ERROR] %s\n' "$*" >&2
    exit 1
}

VERSION="${1:-}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    fail "Usage: $0 MAJOR.MINOR.PATCH"
fi

if [[ "$(uname -s)" != "Darwin" ]]; then
    warn "DMG packaging is only available on macOS; skipping."
    exit 0
fi

if ! command -v hdiutil >/dev/null 2>&1; then
    warn "hdiutil was not found; skipping DMG build."
    exit 0
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$ROOT/builds/macos"
SOURCE_APP="$BUILD_DIR/Paracci.app"
SOURCE_BINARY="$BUILD_DIR/Paracci"
STAGE="$BUILD_DIR/Paracci-${VERSION}-dmg"
MOUNT_POINT="$BUILD_DIR/Paracci-${VERSION}-mount"
OUTPUT="$BUILD_DIR/Paracci-${VERSION}-macOS.dmg"
NOTE="$ROOT/installer/macos/GatekeeperNote.txt"

[[ -f "$NOTE" ]] || fail "Gatekeeper note not found: $NOTE"
rm -rf "$STAGE" "$MOUNT_POINT"
rm -f "$OUTPUT"
mkdir -p "$STAGE"

if [[ -d "$SOURCE_APP" ]]; then
    ditto "$SOURCE_APP" "$STAGE/Paracci.app"
elif [[ -f "$SOURCE_BINARY" ]]; then
    mkdir -p "$STAGE/Paracci.app/Contents/MacOS"
    install -m 0755 "$SOURCE_BINARY" "$STAGE/Paracci.app/Contents/MacOS/Paracci"
    cat > "$STAGE/Paracci.app/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleDisplayName</key><string>Paracci</string>
  <key>CFBundleExecutable</key><string>Paracci</string>
  <key>CFBundleIdentifier</key><string>com.paracci.desktop</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>CFBundleDocumentTypes</key>
  <array><dict>
    <key>CFBundleTypeName</key><string>Paracci Encrypted Message</string>
    <key>CFBundleTypeRole</key><string>Viewer</string>
    <key>LSItemContentTypes</key><array><string>com.paracci.message</string></array>
    <key>CFBundleTypeExtensions</key><array><string>paracci</string></array>
  </dict></array>
  <key>UTExportedTypeDeclarations</key>
  <array><dict>
    <key>UTTypeIdentifier</key><string>com.paracci.message</string>
    <key>UTTypeConformsTo</key><array><string>public.data</string></array>
    <key>UTTypeTagSpecification</key><dict>
      <key>public.filename-extension</key><array><string>paracci</string></array>
      <key>public.mime-type</key><array><string>application/x-paracci</string></array>
    </dict>
  </dict></array>
</dict>
</plist>
EOF
else
    fail "macOS payload not found in $BUILD_DIR"
fi

ln -s /Applications "$STAGE/Applications"
install -m 0644 "$NOTE" "$STAGE/GatekeeperNote.txt"

PLIST="$STAGE/Paracci.app/Contents/Info.plist"
[[ -f "$PLIST" ]] || fail "Application Info.plist not found in staged bundle."
plutil -lint "$PLIST" >/dev/null
plutil -extract CFBundleDocumentTypes xml1 -o - "$PLIST" | grep -q "com.paracci.message"
plutil -extract UTExportedTypeDeclarations xml1 -o - "$PLIST" | grep -q "com.paracci.message"

hdiutil create \
    -volname "Paracci $VERSION" \
    -srcfolder "$STAGE" \
    -ov \
    -format UDZO \
    "$OUTPUT"
hdiutil verify "$OUTPUT"

mkdir -p "$MOUNT_POINT"
mounted=false
cleanup() {
    if [[ "$mounted" == true ]]; then
        hdiutil detach "$MOUNT_POINT" -quiet || true
    fi
    rm -rf "$MOUNT_POINT"
}
trap cleanup EXIT
hdiutil attach -readonly -nobrowse -mountpoint "$MOUNT_POINT" "$OUTPUT" >/dev/null
mounted=true
[[ -d "$MOUNT_POINT/Paracci.app" ]] || fail "DMG does not contain Paracci.app."
[[ -L "$MOUNT_POINT/Applications" ]] || fail "DMG does not contain the Applications symlink."
[[ -f "$MOUNT_POINT/GatekeeperNote.txt" ]] || fail "DMG does not contain GatekeeperNote.txt."
plutil -extract CFBundleDocumentTypes xml1 -o - "$MOUNT_POINT/Paracci.app/Contents/Info.plist" | grep -q "com.paracci.message"
plutil -extract UTExportedTypeDeclarations xml1 -o - "$MOUNT_POINT/Paracci.app/Contents/Info.plist" | grep -q "com.paracci.message"
hdiutil detach "$MOUNT_POINT" -quiet
mounted=false
trap - EXIT
rm -rf "$MOUNT_POINT"
rm -rf "$STAGE"
printf '[OK] DMG created: %s\n' "$OUTPUT"
