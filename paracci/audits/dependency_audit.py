import os
import sys
import subprocess
import importlib.metadata
from packaging import version

# Paracci Dependency Audit Tool
# Checks library versions and security vulnerabilities.

CRITICAL_DEPS = {
    "argon2-cffi": "21.1.0",
    "cryptography": "41.0.0",
    "PySide6": "6.7.0",
    "Pillow": "10.0.0",
    "pyotp": "2.9.0"
}

def run():
    """Runs dependency audit and verifies critical library versions."""
    print("--- Starting Dependency Audit ---\n")
    issues = 0
    
    # 1. Pip-audit check (best choice if installed)
    try:
        print("[*] Attempting deep scan with 'pip-audit'...")
        result = subprocess.run(["pip-audit", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            audit_res = subprocess.run(["pip-audit"], capture_output=True, text=True)
            if audit_res.returncode != 0:
                print(audit_res.stdout)
                issues += 1
            else:
                print("  [+] pip-audit: No vulnerabilities found.")
                return True
    except FileNotFoundError:
        print("  [i] 'pip-audit' not found, switching to manual version check.")

    # 2. Manual Version Control
    print("[*] Verifying critical library versions...")
    for pkg, min_ver in CRITICAL_DEPS.items():
        try:
            installed_version = importlib.metadata.version(pkg)
            if version.parse(installed_version) < version.parse(min_ver):
                print(f"  [!] WARNING: {pkg} version is low ({installed_version} < {min_ver})")
                issues += 1
            else:
                print(f"  [+] {pkg}: {installed_version} (Secure)")
        except importlib.metadata.PackageNotFoundError:
            print(f"  [X] ERROR: {pkg} is not installed!")
            issues += 1

    print(f"\nDependency Audit RESULT: {issues} Issues")
    return issues == 0

if __name__ == "__main__":
    if run():
        sys.exit(0)
    else:
        sys.exit(1)
