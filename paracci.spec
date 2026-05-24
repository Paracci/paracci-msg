# -*- mode: python ; coding: utf-8 -*-
"""
Paracci — PyInstaller Spec File
Supports: Windows (.exe), macOS (.app), Linux (binary)

Usage (local):
    pyinstaller paracci.spec

This file is also used by the automated build pipeline (build.py).
"""

import sys
import os
import re
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules, collect_data_files

# ── Determine icon path ────────────────────────────────────────────────────────
ROOT = Path(SPECPATH)
VERSION_FILE = ROOT / "VERSION"
VERSION_INFO_FILE = ROOT / "build_metadata" / "file_version_info.txt"


def _read_app_version():
    try:
        version = VERSION_FILE.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise SystemExit(f"Canonical version file is unavailable: {VERSION_FILE}") from exc
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise SystemExit(f"VERSION must contain MAJOR.MINOR.PATCH, got {version!r}.")
    return version


APP_VERSION = _read_app_version()
if not VERSION_INFO_FILE.is_file():
    raise SystemExit("Generated version resource is missing. Build with: python build.py")


def _dedupe_paths(paths):
    seen = set()
    unique = []
    for path in paths:
        path = Path(path).expanduser()
        key = os.path.normcase(str(path))
        if key in seen:
            continue
        seen.add(key)
        unique.append(path)
    return unique


def _liboqs_names():
    if sys.platform == "win32":
        return ("oqs.dll", "liboqs.dll")
    if sys.platform == "darwin":
        return ("liboqs.dylib",)
    return ("liboqs.so",)


def _liboqs_dest_dir():
    return "bin" if sys.platform == "win32" else "lib"


def _candidate_liboqs_dirs():
    dirs = []
    for env_name in ("LIBOQS_LIB_DIR", "OQS_INSTALL_PATH"):
        env_value = os.environ.get(env_name)
        if not env_value:
            continue
        base = Path(env_value)
        dirs.extend([base, base / "bin", base / "lib", base / "lib64"])

    if sys.platform == "win32":
        dirs.extend(
            [
                Path("C:/liboqs/bin"),
                Path("C:/liboqs/lib"),
                Path("C:/Program Files/liboqs/bin"),
                Path("C:/Program Files/liboqs/lib"),
                ROOT / "_oqs" / "bin",
                ROOT / "_oqs" / "lib",
            ]
        )
    elif sys.platform == "darwin":
        dirs.extend(
            [
                Path("/opt/homebrew/lib"),
                Path("/usr/local/lib"),
                Path("/usr/lib"),
                ROOT / "_oqs" / "lib",
                ROOT / "_oqs" / "lib64",
            ]
        )
    else:
        dirs.extend(
            [
                Path("/usr/local/lib"),
                Path("/usr/local/lib64"),
                Path("/usr/lib"),
                Path("/usr/lib64"),
                ROOT / "_oqs" / "lib",
                ROOT / "_oqs" / "lib64",
            ]
        )

    return _dedupe_paths(dirs)


def _find_liboqs():
    for directory in _candidate_liboqs_dirs():
        for name in _liboqs_names():
            candidate = directory / name
            if candidate.exists():
                return candidate
    return None


def _write_liboqs_runtime_hook():
    hook_dir = ROOT / "build_cache" / "runtime_hooks"
    hook_dir.mkdir(parents=True, exist_ok=True)
    hook_path = hook_dir / "pyi_rth_paracci_liboqs.py"
    hook_path.write_text(
        """\
import os
import sys
from pathlib import Path

bundle_root = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
os.environ["OQS_INSTALL_PATH"] = str(bundle_root)
""",
        encoding="utf-8",
    )
    return str(hook_path)


liboqs_runtime_hook = _write_liboqs_runtime_hook()

if sys.platform == "win32":
    app_icon = str(ROOT / "paracci_icon.ico")
elif sys.platform == "darwin":
    app_icon = str(ROOT / "paracci_icon.icns") if (ROOT / "paracci_icon.icns").exists() else None
else:
    app_icon = str(ROOT / "paracci_icon.ico")

# ── Data files to bundle ───────────────────────────────────────────────────────
datas = [
    (str(VERSION_FILE),                              "."),
    (str(ROOT / "paracci" / "app" / "templates"), "paracci/app/templates"),
    (str(ROOT / "paracci" / "app" / "static"),    "paracci/app/static"),
    (str(ROOT / "paracci" / "app" / "i18n"),      "paracci/app/i18n"),
    (str(ROOT / "paracci" / "app" / "reports"),   "paracci/app/reports"),
    (str(ROOT / "paracci_icon.ico"),             "."),
]

binaries = []
hiddenimports = []

# ── liboqs-python / native liboqs (lazy ctypes import) ─────────────────────────
hiddenimports += ["oqs", "oqs.oqs", "oqs.rand", "oqs.serialize"]
liboqs_path = _find_liboqs()
if liboqs_path:
    liboqs_dest = _liboqs_dest_dir()
    binaries.append((str(liboqs_path), liboqs_dest))
    print(f"[INFO] Bundling liboqs shared library: {liboqs_path} -> {liboqs_dest}")
else:
    print(
        "[WARN] liboqs shared library was not found; ML-KEM will fail in the packaged app.",
        file=sys.stderr,
    )

# ── Collect all submodules for pywebview ──────────────────────────────────────
tmp_ret = collect_all("webview")
datas    += tmp_ret[0]
binaries += tmp_ret[1]
hiddenimports += tmp_ret[2]

# ── argon2 (cffi extension — must be explicitly collected) ────────────────────
tmp_ret = collect_all("argon2")
datas    += tmp_ret[0]
binaries += tmp_ret[1]
hiddenimports += tmp_ret[2]

# ── Flask and Jinja2 (template engine) ────────────────────────────────────────
hiddenimports += collect_submodules("flask")
hiddenimports += collect_submodules("jinja2")
hiddenimports += collect_submodules("werkzeug")
hiddenimports += collect_submodules("click")
hiddenimports += [
    "flask",
    "jinja2",
    "jinja2.ext",
    "werkzeug.serving",
    "werkzeug.debug",
    "itsdangerous",
]

# ── Cryptography (native extension) ───────────────────────────────────────────
tmp_ret = collect_all("cryptography")
datas    += tmp_ret[0]
binaries += tmp_ret[1]
hiddenimports += tmp_ret[2]

# ── Pillow (image processing) ─────────────────────────────────────────────────
tmp_ret = collect_all("PIL")
datas    += tmp_ret[0]
binaries += tmp_ret[1]
hiddenimports += tmp_ret[2]

# ── QRCode ────────────────────────────────────────────────────────────────────
hiddenimports += collect_submodules("qrcode")

# ── PyOTP ─────────────────────────────────────────────────────────────────────
hiddenimports += ["pyotp"]

# ── Paracci internal modules ───────────────────────────────────────────────────
hiddenimports += [
    "core.shields",
    "core.config",
    "core.burn",
    "core.crypto",
    "core.envelope",
    "core.evolution",
    "core.identity",
    "core.integrity",
    "core.logger",
    "core.package",
    "core.sanitizer",
    "core.security_utils",
    "core.session",
    "app",
    "app.routes",
    "app.i18n_manager",
]

# ── Platform-specific webview backends ────────────────────────────────────────
if sys.platform == "win32":
    # pywebview on Windows uses EdgeChromium (WebView2) or MSHTML — no pythonnet dependency
    hiddenimports += ["webview.platforms.winforms", "webview.platforms.edgechromium", "webview.platforms.mshtml"]
elif sys.platform == "darwin":
    hiddenimports += ["webview.platforms.cocoa"]
else:
    hiddenimports += ["webview.platforms.gtk", "gi", "gi.repository.Gtk", "gi.repository.WebKit2"]

# ── Analysis ──────────────────────────────────────────────────────────────────
a = Analysis(
    ["run.py"],
    pathex=[str(ROOT / "paracci")],   # makes "core" and "app" importable
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[liboqs_runtime_hook],
    excludes=["paracci.audits", "paracci.scratch", "tkinter", "_tkinter", "matplotlib"],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

# ── Windows Onedir / Other Platforms Onefile Setup ────────────────────────────
if sys.platform == "win32":
    exe = EXE(
        pyz,
        a.scripts,
        exclude_binaries=True,
        name="Paracci",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,          # No console window (GUI app)
        disable_windowed_traceback=False,
        argv_emulation=False,   # macOS only — keep False for pywebview
        target_arch='x86_64',
        codesign_identity=None,
        entitlements_file=None,
        version=str(VERSION_INFO_FILE),
        icon=app_icon,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name="Paracci",
    )
elif sys.platform == "darwin":
    exe = EXE(
        pyz,
        a.scripts,
        a.binaries,
        a.datas,
        [],
        name="Paracci",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        upx_exclude=[],
        runtime_tmpdir=None,
        console=False,          # No console window (GUI app)
        disable_windowed_traceback=False,
        argv_emulation=False,   # macOS only — keep False for pywebview
        target_arch=None,       # None = current machine arch
        codesign_identity=None,
        entitlements_file=None,
        version=str(VERSION_INFO_FILE),
        icon=app_icon,
    )
else:
    exe = EXE(
        pyz,
        a.scripts,
        exclude_binaries=True,
        name="Paracci",
        debug=False,
        bootloader_ignore_signals=False,
        strip=False,
        upx=False,
        console=False,          # No console window (GUI app)
        disable_windowed_traceback=False,
        argv_emulation=False,   # macOS only — keep False for pywebview
        target_arch=None,       # None = current machine arch
        codesign_identity=None,
        entitlements_file=None,
        version=str(VERSION_INFO_FILE),
        icon=app_icon,
    )
    coll = COLLECT(
        exe,
        a.binaries,
        a.zipfiles,
        a.datas,
        strip=False,
        upx=False,
        upx_exclude=[],
        name="Paracci",
    )



# ── macOS .app Bundle ─────────────────────────────────────────────────────────
# Only generated when building on macOS.
if sys.platform == "darwin":
    app = BUNDLE(
        exe,
        name="Paracci.app",
        icon=app_icon,
        bundle_identifier="com.paracci.desktop",
        info_plist={
            "CFBundleDisplayName": "Paracci",
            "CFBundleVersion": APP_VERSION,
            "CFBundleShortVersionString": APP_VERSION,
            "NSHighResolutionCapable": True,
            "NSRequiresAquaSystemAppearance": False,  # Dark mode support
            "LSMinimumSystemVersion": "11.0",
            "CFBundleDocumentTypes": [
                {
                    "CFBundleTypeName": "Paracci Encrypted Message",
                    "CFBundleTypeRole": "Viewer",
                    "LSHandlerRank": "Owner",
                    "LSItemContentTypes": ["com.paracci.message"],
                    "CFBundleTypeExtensions": ["paracci"],
                }
            ],
            "UTExportedTypeDeclarations": [
                {
                    "UTTypeIdentifier": "com.paracci.message",
                    "UTTypeDescription": "Paracci Encrypted Message",
                    "UTTypeConformsTo": ["public.data"],
                    "UTTypeTagSpecification": {
                        "public.filename-extension": ["paracci"],
                        "public.mime-type": ["application/x-paracci"],
                    },
                }
            ],
        },
    )
