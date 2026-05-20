import importlib.metadata
import re
import subprocess
import sys
from pathlib import Path

from packaging import version

# Paracci Dependency Audit Tool
# Checks locked dependency inputs, installed versions, and vendored browser libs.

ROOT = Path(__file__).resolve().parents[2]
RUNTIME_LOCK = ROOT / "requirements.lock"
DEV_LOCK = ROOT / "requirements-dev.lock"
DOMPURIFY_PATH = ROOT / "paracci" / "app" / "static" / "js" / "lib" / "purify.min.js"
DOMPURIFY_MIN_VERSION = "3.1.3"
DOMPURIFY_EXPECTED_VERSION = "3.4.5"

CRITICAL_DEPS = {
    "Flask": "3.1.1",
    "argon2-cffi": "23.1.0",
    "cryptography": "44.0.1",
    "liboqs-python": "0.15.0",
    "Pillow": "10.3.0",
    "pyotp": "2.9.0",
    "pywebview": "5.0.0",
    "qrcode": "7.4.2",
    "packaging": "24.0",
}

OPTIONAL_CRITICAL_DEPS = {
    "PySide6": "6.7.0",
}


def _is_at_least(installed: str, minimum: str) -> bool:
    return version.parse(installed) >= version.parse(minimum)


def _run_pip_audit() -> int:
    print("[*] Auditing locked Python dependencies with pip-audit...")
    missing_locks = [str(path) for path in (RUNTIME_LOCK, DEV_LOCK) if not path.exists()]
    if missing_locks:
        for path in missing_locks:
            print(f"  [X] ERROR: Missing dependency lock file: {path}")
        return len(missing_locks)

    cmd = [
        sys.executable,
        "-m",
        "pip_audit",
        "-r",
        str(RUNTIME_LOCK),
        "-r",
        str(DEV_LOCK),
    ]
    try:
        audit_res = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print("  [X] ERROR: Python executable was not found for pip-audit.")
        return 1

    output = (audit_res.stdout or "").strip()
    error_output = (audit_res.stderr or "").strip()
    if audit_res.returncode != 0:
        if output:
            print(output)
        if error_output:
            print(error_output)
        return 1

    print("  [+] pip-audit: No vulnerabilities found in lock files.")
    return 0


def _check_installed_versions() -> int:
    print("[*] Verifying installed critical library versions...")
    issues = 0

    for pkg, min_ver in CRITICAL_DEPS.items():
        try:
            installed_version = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            print(f"  [X] ERROR: {pkg} is not installed!")
            issues += 1
            continue

        if not _is_at_least(installed_version, min_ver):
            print(f"  [!] WARNING: {pkg} version is low ({installed_version} < {min_ver})")
            issues += 1
        else:
            print(f"  [+] {pkg}: {installed_version} (Secure)")

    for pkg, min_ver in OPTIONAL_CRITICAL_DEPS.items():
        try:
            installed_version = importlib.metadata.version(pkg)
        except importlib.metadata.PackageNotFoundError:
            print(f"  [i] {pkg}: not installed in this environment.")
            continue

        if not _is_at_least(installed_version, min_ver):
            print(f"  [!] WARNING: {pkg} version is low ({installed_version} < {min_ver})")
            issues += 1
        else:
            print(f"  [+] {pkg}: {installed_version} (Secure)")

    return issues


def _check_dompurify() -> int:
    print("[*] Verifying vendored DOMPurify...")
    if not DOMPURIFY_PATH.exists():
        print(f"  [X] ERROR: DOMPurify file is missing: {DOMPURIFY_PATH}")
        return 1

    content = DOMPURIFY_PATH.read_text(encoding="utf-8", errors="replace")
    match = re.search(r"DOMPurify\s+([0-9]+(?:\.[0-9]+){2})", content)
    if not match:
        print("  [X] ERROR: Could not detect DOMPurify version.")
        return 1

    detected = match.group(1)
    issues = 0
    if not _is_at_least(detected, DOMPURIFY_MIN_VERSION):
        print(f"  [!] WARNING: DOMPurify version is vulnerable ({detected} < {DOMPURIFY_MIN_VERSION})")
        issues += 1
    if detected != DOMPURIFY_EXPECTED_VERSION:
        print(f"  [!] WARNING: DOMPurify version is unexpected ({detected} != {DOMPURIFY_EXPECTED_VERSION})")
        issues += 1

    if issues == 0:
        print(f"  [+] DOMPurify: {detected} (Secure)")
    return issues


def run():
    """Runs dependency audit and verifies critical library versions."""
    print("--- Starting Dependency Audit ---\n")

    issues = 0
    issues += _run_pip_audit()
    issues += _check_installed_versions()
    issues += _check_dompurify()

    print(f"\nDependency Audit RESULT: {issues} Issues")
    return issues == 0


if __name__ == "__main__":
    if run():
        sys.exit(0)
    sys.exit(1)
