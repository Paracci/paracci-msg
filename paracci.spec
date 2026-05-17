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
from pathlib import Path
from PyInstaller.utils.hooks import collect_all, collect_submodules, collect_data_files

# ── Determine icon path ────────────────────────────────────────────────────────
ROOT = Path(SPECPATH)

if sys.platform == "win32":
    app_icon = str(ROOT / "paracci_icon.ico")
elif sys.platform == "darwin":
    app_icon = str(ROOT / "paracci_icon.icns") if (ROOT / "paracci_icon.icns").exists() else None
else:
    app_icon = str(ROOT / "paracci_icon.ico")

# ── Data files to bundle ───────────────────────────────────────────────────────
datas = [
    (str(ROOT / "paracci" / "app" / "templates"), "paracci/app/templates"),
    (str(ROOT / "paracci" / "app" / "static"),    "paracci/app/static"),
    (str(ROOT / "paracci" / "app" / "i18n"),      "paracci/app/i18n"),
]

binaries = []
hiddenimports = []

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
    runtime_hooks=[],
    excludes=["paracci.audits", "paracci.scratch", "tkinter", "_tkinter", "matplotlib"],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

# ── Single-file executable ─────────────────────────────────────────────────────
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
    version=str(ROOT / "file_version_info.txt"),
    icon=app_icon,
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
            "CFBundleVersion": "1.0.0",
            "CFBundleShortVersionString": "1.0.0",
            "NSHighResolutionCapable": True,
            "NSRequiresAquaSystemAppearance": False,  # Dark mode support
            "LSMinimumSystemVersion": "11.0",
        },
    )
