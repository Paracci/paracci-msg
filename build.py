"""
Paracci — build.py
Automated cross-platform build script using PyInstaller.

Usage:
    python build.py              # Build for the current OS
    python build.py --clean      # Clean previous build artifacts first
    python build.py --install    # Install/upgrade build dependencies first
    python build.py --clean --install  # Full fresh build

Output structure:
    builds/
    ├── windows/   → Paracci/ (folder containing Paracci.exe)
    ├── macos/     → Paracci.app  (or Paracci binary)
    └── linux/     → Paracci

GitHub Actions uses this script on 3 separate runners (win/mac/linux)
and uploads each platform's builds/ subfolder as a release asset.
"""

from __future__ import annotations

import argparse
import os
import platform
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

APP_NAME    = "Paracci"

DEV_LOCK    = ROOT / "requirements-dev.lock"


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
    for d in [DIST_DIR, WORK_DIR]:
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
    args = parser.parse_args()

    platform_id = detect_platform()

    print("\n" + "=" * 60)
    print(f"  Paracci Build Script")
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

    # Run PyInstaller
    rc = run_pyinstaller()
    if rc != 0:
        print(f"\n  [ERROR] PyInstaller exited with code {rc}.")
        return rc

    # Move outputs to builds/<platform>/
    move_outputs(platform_id)
    print_summary(platform_id)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
