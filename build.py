"""
Paracci — build.py
Automated cross-platform build script using PyInstaller.

Usage:
    python build.py              # Build for the current OS
    python build.py --clean      # Clean previous build artifacts first
    python build.py --install    # Install/upgrade build dependencies first
    python build.py --installer  # Build the Windows Inno Setup installer
    python build.py --appimage   # Build the Linux AppImage package
    python build.py --deb        # Build the Linux Debian package
    python build.py --dmg        # Build the macOS disk image
    python build.py --clean --install  # Full fresh build

Output structure:
    builds/
    ├── windows/   → Paracci/ (folder containing Paracci.exe)
    ├── macos/     → Paracci.app  (or Paracci binary)
    └── linux/     → Paracci/ (folder containing Paracci and _internal/)

GitHub Actions uses this script on 3 separate runners (win/mac/linux)
and uploads each platform's builds/ subfolder as a release asset.
"""

from __future__ import annotations

import argparse
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

# ── Constants ─────────────────────────────────────────────────────────────────
ROOT        = Path(__file__).resolve().parent
SPEC_FILE   = ROOT / "paracci.spec"
BUILD_DIR   = ROOT / "builds"
DIST_DIR    = ROOT / "dist"          # PyInstaller temp output
WORK_DIR    = ROOT / "build_cache"   # PyInstaller work/ temp
METADATA_DIR = ROOT / "build_metadata"  # Generated inputs consumed during packaging

APP_NAME    = "Paracci"

DEV_LOCK    = ROOT / "requirements-dev.lock"
VERSION_FILE = ROOT / "VERSION"
VERSION_INFO_FILE = METADATA_DIR / "file_version_info.txt"
INSTALLER_SCRIPT = ROOT / "installer" / "windows" / "paracci.iss"
LINUX_APPIMAGE_SCRIPT = ROOT / "installer" / "linux" / "build_appimage.sh"
LINUX_DEB_SCRIPT = ROOT / "installer" / "linux" / "build_deb.sh"
MACOS_DMG_SCRIPT = ROOT / "installer" / "macos" / "build_dmg.sh"
WINDOWS_PAYLOAD_DIR = BUILD_DIR / "windows" / APP_NAME
VERSION_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


# ── Helpers ───────────────────────────────────────────────────────────────────
def run(cmd: list[str], **kwargs) -> int:
    """Run a subprocess command, print it, and return exit code."""
    print(f"\n  [CMD] {' '.join(str(c) for c in cmd)}")
    return subprocess.call(cmd, **kwargs)


def detect_platform() -> str:
    """Return a short platform identifier: 'windows', 'macos', or 'linux'."""
    s = sys.platform
    if s == "win32":
        return "windows"
    if s == "darwin":
        return "macos"
    return "linux"


def get_output_dir(platform_id: str) -> Path:
    """Return the target output directory for the given platform."""
    return BUILD_DIR / platform_id


def clean_artifacts() -> None:
    """Remove previous PyInstaller temp directories."""
    print("\n  [CLEAN] Removing previous build artifacts...")
    for d in [DIST_DIR, WORK_DIR, METADATA_DIR]:
        if d.exists():
            shutil.rmtree(d)
            print(f"    Removed: {d}")


def install_build_deps() -> int:
    """Upgrade pip and install locked build-time dependencies."""
    if not DEV_LOCK.exists():
        print(f"\n  [ERROR] Dev dependency lock not found: {DEV_LOCK}")
        return 1
    print("\n  [INSTALL] Installing build dependencies...")
    rc = run([sys.executable, "-m", "pip", "install", "--upgrade", "pip"])
    if rc != 0:
        return rc
    return run([sys.executable, "-m", "pip", "install", "--require-hashes", "-r", str(DEV_LOCK)])


def build_frontend() -> int:
    """Install Node dependencies and build frontend assets."""
    print("\n  [FRONTEND] Building frontend dependencies...")
    npm_exe = shutil.which("npm")
    if not npm_exe:
        print("\n  [ERROR] npm is not found in PATH. Please install Node.js.")
        return 1
    
    lock_file = ROOT / "package-lock.json"
    npm_cmd = "ci" if lock_file.exists() else "install"
    
    rc = subprocess.call([npm_exe, npm_cmd], cwd=str(ROOT), shell=(sys.platform == "win32"))
    if rc != 0:
        print(f"\n  [ERROR] npm {npm_cmd} failed with exit code {rc}.")
        return rc
        
    rc = subprocess.call([npm_exe, "run", "build"], cwd=str(ROOT), shell=(sys.platform == "win32"))
    if rc != 0:
        print(f"\n  [ERROR] npm run build failed with exit code {rc}.")
        return rc
        
    return 0


def find_pyinstaller() -> str:
    """Return the path to the pyinstaller executable."""
    exe = shutil.which("pyinstaller")
    if exe:
        return exe
    # Fallback: use python -m PyInstaller
    return None


def run_pyinstaller() -> int:
    """Run PyInstaller against the spec file and return the exit code."""
    pyi = find_pyinstaller()

    base_cmd = [pyi] if pyi else [sys.executable, "-m", "PyInstaller"]
    cmd = base_cmd + [
        str(SPEC_FILE),
        "--distpath", str(DIST_DIR),
        "--workpath", str(WORK_DIR),
        "--noconfirm",          # Overwrite without asking
        "--clean",              # Clean PyInstaller cache before build
        "--log-level", "WARN",  # Less noise, warnings still shown
    ]
    return run(cmd, cwd=str(ROOT))


def move_outputs(platform_id: str) -> None:
    """
    Move the compiled binary from PyInstaller's dist/ into builds/<platform>/.
    """
    out_dir = get_output_dir(platform_id)
    out_dir.mkdir(parents=True, exist_ok=True)

    # Remove stale files in the target dir
    for f in out_dir.iterdir():
        if f.is_file():
            f.unlink()
        elif f.is_dir():
            shutil.rmtree(f)

    moved = False

    if platform_id == "windows":
        src = DIST_DIR / APP_NAME
        if src.exists() and src.is_dir():
            python_dll = src / "_internal" / f"python{sys.version_info.major}{sys.version_info.minor}.dll"
            if not python_dll.is_file():
                print(f"\n  [ERROR] Windows onedir payload is missing Python runtime DLL: {python_dll}")
                sys.exit(1)
            dst = out_dir / APP_NAME
            shutil.move(str(src), str(dst))
            print(f"\n  [OK] Windows build ready: {dst / f'{APP_NAME}.exe'}")
            moved = True

    elif platform_id == "macos":
        # PyInstaller produces either Paracci.app bundle or bare binary
        bundle = DIST_DIR / f"{APP_NAME}.app"
        bare   = DIST_DIR / APP_NAME
        if bundle.exists():
            dst = out_dir / f"{APP_NAME}.app"
            shutil.move(str(bundle), str(dst))
            print(f"\n  [OK] macOS build ready: {dst}")
            moved = True
        elif bare.exists():
            dst = out_dir / APP_NAME
            shutil.move(str(bare), str(dst))
            print(f"\n  [OK] macOS build ready: {dst}")
            moved = True

    else:  # linux
        src = DIST_DIR / APP_NAME
        if src.exists():
            dst = out_dir / APP_NAME
            shutil.move(str(src), str(dst))
            # Make executable
            if dst.is_dir():
                (dst / APP_NAME).chmod(0o755)
            else:
                dst.chmod(0o755)
            print(f"\n  [OK] Linux build ready: {dst}")
            moved = True

    if not moved:
        print(f"\n  [ERROR] No output found in {DIST_DIR}. Build may have failed.")
        sys.exit(1)


def print_summary(platform_id: str) -> None:
    out_dir = get_output_dir(platform_id)
    print("\n" + "=" * 60)
    print(f"  BUILD COMPLETE — {platform_id.upper()}")
    print("=" * 60)
    print(f"  Output directory : {out_dir}")

    for f in sorted(out_dir.rglob("*")):
        if f.is_file():
            size_mb = f.stat().st_size / (1024 * 1024)
            print(f"    {f.relative_to(out_dir)}  ({size_mb:.1f} MB)")
    print("=" * 60)
    print()


def print_liboqs_env() -> None:
    """Print liboqs discovery hints passed into the PyInstaller spec."""
    print("  liboqs env:")
    for name in ("LIBOQS_LIB_DIR", "OQS_INSTALL_PATH"):
        print(f"    {name}: {os.environ.get(name) or '(not set)'}")


def read_app_version() -> tuple[str, tuple[int, int, int]]:
    """Read the canonical release version from VERSION."""
    if not VERSION_FILE.exists():
        raise ValueError(f"Canonical version file not found: {VERSION_FILE}")
    version = VERSION_FILE.read_text(encoding="ascii").strip()
    match = VERSION_RE.fullmatch(version)
    if not match:
        raise ValueError(f"VERSION must contain MAJOR.MINOR.PATCH, got {version!r}.")
    return version, tuple(map(int, match.groups()))


def write_version_info(version: str, parts: tuple[int, int, int]) -> None:
    """Generate the Windows executable version resource from VERSION."""
    major, minor, patch = parts
    VERSION_INFO_FILE.parent.mkdir(parents=True, exist_ok=True)
    VERSION_INFO_FILE.write_text(
        f"""# UTF-8
# Generated by build.py from VERSION. Do not edit.

VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=({major}, {minor}, {patch}, 0),
    prodvers=({major}, {minor}, {patch}, 0),
    mask=0x3f,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
  ),
  kids=[
    StringFileInfo(
      [
        StringTable(
          '040904b0',
          [
            StringStruct('CompanyName', 'Paracci'),
            StringStruct('FileDescription', 'Paracci Offline Secure Messenger'),
            StringStruct('FileVersion', '{version}.0'),
            StringStruct('InternalName', 'Paracci'),
            StringStruct('LegalCopyright', 'Copyright (c) 2026 Paracci. All rights reserved.'),
            StringStruct('OriginalFilename', 'Paracci.exe'),
            StringStruct('ProductName', 'Paracci Secure Messaging'),
            StringStruct('ProductVersion', '{version}.0')
          ]
        )
      ]
    ),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""",
        encoding="utf-8",
    )


def find_iscc() -> str | None:
    """Locate the Inno Setup 6 compiler on PATH or in standard locations."""
    for executable in ("ISCC.exe", "iscc.exe"):
        path = shutil.which(executable)
        if path:
            return path

    install_roots = [
        os.environ.get("ProgramFiles(x86)"),
        os.environ.get("ProgramFiles"),
        os.environ.get("LOCALAPPDATA"),
    ]
    candidates = [
        Path(install_roots[0]) / "Inno Setup 6" / "ISCC.exe"
        if install_roots[0]
        else None,
        Path(install_roots[1]) / "Inno Setup 6" / "ISCC.exe"
        if install_roots[1]
        else None,
        Path(install_roots[2]) / "Programs" / "Inno Setup 6" / "ISCC.exe"
        if install_roots[2]
        else None,
    ]
    for candidate in candidates:
        if candidate and candidate.is_file():
            return str(candidate)
    return None


def run_installer_build(platform_id: str, app_version: str) -> int:
    """Compile the Windows installer after the PyInstaller payload is ready."""
    if platform_id != "windows":
        print("\n  [WARN] --installer is only available on Windows; skipping installer build.")
        return 0

    if not INSTALLER_SCRIPT.exists():
        print(f"\n  [ERROR] Inno Setup script not found: {INSTALLER_SCRIPT}")
        return 1

    iscc = find_iscc()
    if not iscc:
        print(
            "\n  [WARN] Inno Setup compiler (ISCC.exe) was not found. "
            "Skipping installer build; the portable payload is still available."
        )
        return 0

    executable = WINDOWS_PAYLOAD_DIR / f"{APP_NAME}.exe"
    if not executable.is_file():
        print(f"\n  [ERROR] Windows installer payload not found: {executable}")
        return 1

    portable_marker = WINDOWS_PAYLOAD_DIR / "data"
    if portable_marker.exists():
        print(
            f"\n  [ERROR] Refusing to build an installer from payload containing {portable_marker}. "
            "Installed builds must use Standard Mode."
        )
        return 1

    print(f"\n  [INSTALLER] Building Paracci Setup v{app_version}...")
    return run(
        [iscc, f"/DAppVersion={app_version}", str(INSTALLER_SCRIPT)],
        cwd=str(ROOT),
    )


def run_native_package_build(
    platform_id: str,
    expected_platform: str,
    script: Path,
    package_name: str,
    app_version: str,
) -> int:
    """Run a platform package script after its PyInstaller payload is ready."""
    if platform_id != expected_platform:
        print(
            f"\n  [WARN] {package_name} packaging is only available on "
            f"{expected_platform}; skipping."
        )
        return 0
    if not script.exists():
        print(f"\n  [ERROR] {package_name} build script not found: {script}")
        return 1
    print(f"\n  [PACKAGE] Building {package_name} v{app_version}...")
    return run(["bash", str(script), app_version], cwd=str(ROOT))


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(
        description="Paracci automated build script (PyInstaller wrapper)"
    )
    parser.add_argument(
        "--clean",
        action="store_true",
        help="Remove previous dist/ and build_cache/ before building.",
    )
    parser.add_argument(
        "--install",
        action="store_true",
        help="Install/upgrade build dependencies (pyinstaller) before building.",
    )
    parser.add_argument(
        "--installer",
        action="store_true",
        help="Compile the Windows Inno Setup installer after the PyInstaller build.",
    )
    parser.add_argument(
        "--appimage",
        action="store_true",
        help="Build a Linux AppImage after the PyInstaller build.",
    )
    parser.add_argument(
        "--deb",
        action="store_true",
        help="Build a Linux Debian package after the PyInstaller build.",
    )
    parser.add_argument(
        "--dmg",
        action="store_true",
        help="Build a macOS disk image after the PyInstaller build.",
    )
    args = parser.parse_args()

    platform_id = detect_platform()
    try:
        app_version, app_version_parts = read_app_version()
    except ValueError as exc:
        print(f"\n  [ERROR] {exc}")
        return 1

    print("\n" + "=" * 60)
    print(f"  Paracci Build Script")
    print(f"  Version   : {app_version}")
    print(f"  Platform  : {platform_id.upper()} ({platform.machine()})")
    print(f"  Python    : {sys.version.split()[0]}")
    print(f"  Spec      : {SPEC_FILE}")
    print_liboqs_env()
    print("=" * 60)

    if not SPEC_FILE.exists():
        print(f"\n  [ERROR] Spec file not found: {SPEC_FILE}")
        return 1

    if args.install:
        rc = install_build_deps()
        if rc != 0:
            return rc

    if args.clean:
        clean_artifacts()

    write_version_info(app_version, app_version_parts)

    # Build frontend dependencies
    rc = build_frontend()
    if rc != 0:
        return rc

    # Run PyInstaller
    rc = run_pyinstaller()
    if rc != 0:
        print(f"\n  [ERROR] PyInstaller exited with code {rc}.")
        return rc

    # Move outputs to builds/<platform>/
    move_outputs(platform_id)

    if args.installer:
        rc = run_installer_build(platform_id, app_version)
        if rc != 0:
            print(f"\n  [ERROR] Installer compilation exited with code {rc}.")
            return rc

    package_requests = [
        (args.appimage, "linux", LINUX_APPIMAGE_SCRIPT, "AppImage"),
        (args.deb, "linux", LINUX_DEB_SCRIPT, "Debian package"),
        (args.dmg, "macos", MACOS_DMG_SCRIPT, "DMG"),
    ]
    for requested, expected_platform, script, package_name in package_requests:
        if not requested:
            continue
        rc = run_native_package_build(platform_id, expected_platform, script, package_name, app_version)
        if rc != 0:
            print(f"\n  [ERROR] {package_name} packaging exited with code {rc}.")
            return rc

    print_summary(platform_id)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
