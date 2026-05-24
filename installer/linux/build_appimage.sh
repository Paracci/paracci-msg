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

resolve_tool() {
    local configured="$1"
    shift
    if [[ -n "$configured" ]]; then
        [[ -x "$configured" ]] && printf '%s\n' "$configured" && return 0
        return 1
    fi
    local candidate
    for candidate in "$@"; do
        if command -v "$candidate" >/dev/null 2>&1; then
            command -v "$candidate"
            return 0
        fi
    done
    return 1
}

run_tool() {
    local tool="$1"
    shift
    if [[ "$tool" == *.AppImage ]]; then
        "$tool" --appimage-extract-and-run "$@"
    else
        "$tool" "$@"
    fi
}

VERSION="${1:-}"
if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    fail "Usage: $0 MAJOR.MINOR.PATCH"
fi

if [[ "$(uname -s)" != "Linux" ]]; then
    warn "AppImage packaging is only available on Linux; skipping."
    exit 0
fi

LINUXDEPLOY_TOOL="$(resolve_tool "${LINUXDEPLOY:-}" linuxdeploy linuxdeploy-x86_64.AppImage || true)"
APPIMAGETOOL_TOOL="$(resolve_tool "${APPIMAGETOOL:-}" appimagetool appimagetool-x86_64.AppImage || true)"
RUNTIME_FILE="${APPIMAGE_RUNTIME_FILE:-}"
if [[ -z "$LINUXDEPLOY_TOOL" || -z "$APPIMAGETOOL_TOOL" ]]; then
    warn "linuxdeploy and appimagetool are required; skipping AppImage build."
    exit 0
fi
if [[ -z "$RUNTIME_FILE" || ! -f "$RUNTIME_FILE" ]]; then
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

[[ -f "$PAYLOAD" ]] || fail "Linux payload not found: $PAYLOAD"
[[ -f "$DESKTOP_FILE" ]] || fail "Desktop entry not found: $DESKTOP_FILE"
[[ -f "$MIME_FILE" ]] || fail "MIME definition not found: $MIME_FILE"
[[ -f "$ICON_FILE" ]] || fail "Application icon not found: $ICON_FILE"

rm -rf "$APPDIR"
rm -f "$OUTPUT"
mkdir -p \
    "$APPDIR/usr/lib/paracci" \
    "$APPDIR/usr/share/applications" \
    "$APPDIR/usr/share/icons/hicolor/256x256/apps" \
    "$APPDIR/usr/share/mime/packages"

install -m 0755 "$PAYLOAD" "$APPDIR/usr/lib/paracci/Paracci"
install -m 0644 "$DESKTOP_FILE" "$APPDIR/usr/share/applications/paracci.desktop"
install -m 0644 "$MIME_FILE" "$APPDIR/usr/share/mime/packages/application-x-paracci.xml"

# Resize icon to a linuxdeploy-compatible resolution
ICON_512="/tmp/paracci.png"
convert "$ROOT/paracci_icon.png" -resize 512x512 "$ICON_512"

install -m 0644 "$ICON_512" "$APPDIR/usr/share/icons/hicolor/256x256/apps/paracci.png"

deploy_args=(
    --appdir "$APPDIR"
    --executable "$APPDIR/usr/lib/paracci/Paracci"
    --desktop-file "$DESKTOP_FILE"
    --icon-file "$ICON_512"
)

# GTK, WebKit and GStreamer load parts of their runtime dynamically rather
# than exposing every dependency through the frozen executable's ELF imports.
while IFS= read -r library; do
    deploy_args+=(--library "$library")
done < <(
    find /usr/lib -type f \
        \( -name 'libgtk-3.so.*' -o -name 'libwebkit2gtk-*.so.*' -o \
           -name 'libjavascriptcoregtk-*.so.*' -o -path '*/gstreamer-1.0/*.so' \) \
        2>/dev/null | sort -u
)

run_tool "$LINUXDEPLOY_TOOL" "${deploy_args[@]}"

mkdir -p "$APPDIR/usr/lib/girepository-1.0"
while IFS= read -r typelib; do
    install -m 0644 "$typelib" "$APPDIR/usr/lib/girepository-1.0/$(basename "$typelib")"
done < <(find /usr/lib -type f -path '*/girepository-1.0/*.typelib' 2>/dev/null | sort -u)

for runtime_dir in /usr/lib/*/webkit2gtk-* /usr/lib/*/gstreamer-1.0; do
    [[ -d "$runtime_dir" ]] || continue
    mkdir -p "$APPDIR$(dirname "$runtime_dir")"
    cp -a "$runtime_dir" "$APPDIR$runtime_dir"
done

if [[ -d /usr/share/glib-2.0/schemas ]]; then
    mkdir -p "$APPDIR/usr/share/glib-2.0/schemas"
    cp -a /usr/share/glib-2.0/schemas/. "$APPDIR/usr/share/glib-2.0/schemas/"
    if command -v glib-compile-schemas >/dev/null 2>&1; then
        glib-compile-schemas "$APPDIR/usr/share/glib-2.0/schemas"
    fi
fi

mkdir -p "$APPDIR/usr/bin"
cat > "$APPDIR/usr/bin/paracci" <<'EOF'
#!/usr/bin/env bash
set -e
APPDIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
export LD_LIBRARY_PATH="$APPDIR/usr/lib:$APPDIR/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export GI_TYPELIB_PATH="$APPDIR/usr/lib/girepository-1.0:$APPDIR/usr/lib/x86_64-linux-gnu/girepository-1.0${GI_TYPELIB_PATH:+:$GI_TYPELIB_PATH}"
export GSETTINGS_SCHEMA_DIR="$APPDIR/usr/share/glib-2.0/schemas"
export GST_PLUGIN_PATH="$APPDIR/usr/lib/gstreamer-1.0:$APPDIR/usr/lib/x86_64-linux-gnu/gstreamer-1.0${GST_PLUGIN_PATH:+:$GST_PLUGIN_PATH}"
exec "$APPDIR/usr/lib/paracci/Paracci" "$@"
EOF
chmod 0755 "$APPDIR/usr/bin/paracci"
ln -sfn usr/bin/paracci "$APPDIR/AppRun"
ln -sfn usr/share/applications/paracci.desktop "$APPDIR/paracci.desktop"
ln -sfn usr/share/icons/hicolor/256x256/apps/paracci.png "$APPDIR/paracci.png"

ARCH=x86_64 run_tool "$APPIMAGETOOL_TOOL" --no-appstream --runtime-file "$RUNTIME_FILE" "$APPDIR" "$OUTPUT"
chmod 0755 "$OUTPUT"
rm -rf "$APPDIR"
printf '[OK] AppImage created: %s\n' "$OUTPUT"
