#!/usr/bin/env bash
set -euo pipefail

if ! command -v convert &> /dev/null; then
    sudo apt-get install -y imagemagick
fi

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

if [[ "$(uname -s)" != "Linux" ]]; then
    warn "AppImage packaging is only available on Linux; skipping."
    exit 0
fi

APPIMAGETOOL="${APPIMAGETOOL:-}"
APPIMAGE_RUNTIME_FILE="${APPIMAGE_RUNTIME_FILE:-}"

if [[ -z "$APPIMAGETOOL" ]]; then
    warn "APPIMAGETOOL is required; skipping AppImage build."
    exit 0
fi
if [[ -z "$APPIMAGE_RUNTIME_FILE" || ! -f "$APPIMAGE_RUNTIME_FILE" ]]; then
    warn "APPIMAGE_RUNTIME_FILE is unavailable; skipping AppImage build."
    exit 0
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$ROOT/builds/linux"
PAYLOAD="$BUILD_DIR/Paracci"
APPDIR="$BUILD_DIR/Paracci.AppDir"
OUTPUT="$BUILD_DIR/Paracci-${VERSION}-x86_64.AppImage"
DESKTOP_FILE="$ROOT/installer/linux/paracci.desktop"
MIME_FILE="$ROOT/installer/linux/application-x-paracci.xml"
ICON_FILE="$ROOT/paracci_icon.png"

[[ -d "$PAYLOAD" ]] || fail "Linux payload not found: $PAYLOAD"
[[ -x "$PAYLOAD/Paracci" ]] || fail "Linux executable not found: $PAYLOAD/Paracci"
[[ -f "$DESKTOP_FILE" ]] || fail "Desktop entry not found: $DESKTOP_FILE"
[[ -f "$MIME_FILE" ]] || fail "MIME definition not found: $MIME_FILE"
[[ -f "$ICON_FILE" ]] || fail "Application icon not found: $ICON_FILE"

rm -rf "$APPDIR"
rm -f "$OUTPUT"

# 1. Build the AppDir manually:
mkdir -p \
    "$APPDIR/usr/lib/paracci" \
    "$APPDIR/usr/share/applications" \
    "$APPDIR/usr/share/icons/hicolor/512x512/apps" \
    "$APPDIR/usr/share/mime/packages"

# 2. Write the AppRun script:
cat > "$APPDIR/AppRun" <<'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "${0}")")"
exec "$HERE/usr/lib/paracci/Paracci" "$@"
EOF
chmod 0755 "$APPDIR/AppRun"

# 3. Copy the onedir payload:
cp -r "$PAYLOAD/." "$APPDIR/usr/lib/paracci/"
chmod 0755 "$APPDIR/usr/lib/paracci/Paracci"

# 4. Resize and place the icon:
convert "$ROOT/paracci_icon.png" -resize 512x512 "$APPDIR/usr/share/icons/hicolor/512x512/apps/paracci.png"
cp "$APPDIR/usr/share/icons/hicolor/512x512/apps/paracci.png" "$APPDIR/paracci.png"

# 5. Place desktop and MIME files:
cp "$DESKTOP_FILE" "$APPDIR/usr/share/applications/paracci.desktop"
cp "$DESKTOP_FILE" "$APPDIR/paracci.desktop"
cp "$MIME_FILE" "$APPDIR/usr/share/mime/packages/application-x-paracci.xml"

# 6. Package with appimagetool:
ARCH=x86_64 "$APPIMAGETOOL" \
  --runtime-file "$APPIMAGE_RUNTIME_FILE" \
  "$APPDIR" \
  "$OUTPUT"

chmod 0755 "$OUTPUT"
rm -rf "$APPDIR"
printf '[OK] AppImage created: %s\n' "$OUTPUT"
