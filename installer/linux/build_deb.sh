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

if [[ "$(uname -s)" != "Linux" ]]; then
    warn "Debian packaging is only available on Linux; skipping."
    exit 0
fi

if ! command -v dpkg-deb >/dev/null 2>&1; then
    warn "dpkg-deb was not found; skipping Debian package build."
    exit 0
fi

ROOT="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="$ROOT/builds/linux"
PAYLOAD="$BUILD_DIR/Paracci"
STAGE="$BUILD_DIR/paracci_${VERSION}_amd64"
OUTPUT="$BUILD_DIR/paracci_${VERSION}_amd64.deb"
DESKTOP_FILE="$ROOT/installer/linux/paracci.desktop"
MIME_FILE="$ROOT/installer/linux/application-x-paracci.xml"
ICON_FILE="$ROOT/paracci_icon.png"

if [[ -d "$PAYLOAD" ]]; then
    [[ -x "$PAYLOAD/Paracci" ]] || fail "Linux executable not found: $PAYLOAD/Paracci"
else
    [[ -f "$PAYLOAD" ]] || fail "Linux payload not found: $PAYLOAD"
fi
[[ -f "$DESKTOP_FILE" ]] || fail "Desktop entry not found: $DESKTOP_FILE"
[[ -f "$MIME_FILE" ]] || fail "MIME definition not found: $MIME_FILE"
[[ -f "$ICON_FILE" ]] || fail "Application icon not found: $ICON_FILE"

rm -rf "$STAGE"
rm -f "$OUTPUT"
mkdir -p \
    "$STAGE/DEBIAN" \
    "$STAGE/opt/paracci" \
    "$STAGE/usr/local/bin" \
    "$STAGE/usr/share/applications" \
    "$STAGE/usr/share/icons/hicolor/256x256/apps" \
    "$STAGE/usr/share/mime/packages"

if [[ -d "$PAYLOAD" ]]; then
    cp -r "$PAYLOAD/." "$STAGE/opt/paracci/"
    chmod 0755 "$STAGE/opt/paracci/Paracci"
else
    install -m 0755 "$PAYLOAD" "$STAGE/opt/paracci/Paracci"
fi
ln -s /opt/paracci/Paracci "$STAGE/usr/local/bin/paracci"
install -m 0644 "$DESKTOP_FILE" "$STAGE/usr/share/applications/paracci.desktop"
install -m 0644 "$ICON_FILE" "$STAGE/usr/share/icons/hicolor/256x256/apps/paracci.png"
install -m 0644 "$MIME_FILE" "$STAGE/usr/share/mime/packages/application-x-paracci.xml"

cat > "$STAGE/DEBIAN/control" <<EOF
Package: paracci
Version: $VERSION
Architecture: amd64
Section: utils
Priority: optional
Maintainer: Paracci
Depends: gir1.2-webkit2-4.1 | gir1.2-webkit2-4.0, desktop-file-utils, shared-mime-info
Description: Offline secure messaging for encrypted message exchange
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e

if command -v update-mime-database >/dev/null 2>&1; then
    update-mime-database /usr/share/mime
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications
fi
EOF

cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e

if command -v update-mime-database >/dev/null 2>&1; then
    update-mime-database /usr/share/mime
fi
if command -v update-desktop-database >/dev/null 2>&1; then
    update-desktop-database -q /usr/share/applications
fi
EOF

chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/postrm"
dpkg-deb --root-owner-group --build "$STAGE" "$OUTPUT"
rm -rf "$STAGE"
printf '[OK] Debian package created: %s\n' "$OUTPUT"
