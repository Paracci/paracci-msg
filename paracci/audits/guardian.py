import sys
import os
import time

# Paracci Guardian - Master Audit Runner
# Paracci Guardian - Master Audit Runner
# Manages all audit systems centrally.

import io

# Unicode support (for Windows console) - Central Management
if sys.platform == 'win32':
    try:
        # Check existing stdout/stderr objects and wrap them only once
        if not isinstance(sys.stdout, io.TextIOWrapper) or sys.stdout.encoding.lower() != 'utf-8':
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', line_buffering=True)
        if not isinstance(sys.stderr, io.TextIOWrapper) or sys.stderr.encoding.lower() != 'utf-8':
            sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8', line_buffering=True)
    except Exception:
        # If an error occurs (might already be wrapped), continue silently
        pass
import security_audit
import leak_audit
import dependency_audit
import integrity_audit
import performance_audit
import a11y_audit
import i18n_audit
import quality_audit
import linter_audit
import sanity_audit

def run_guardian():
    """Main Guardian function that runs all audit systems in sequence."""
    print("\n" + "╔" + "═"*68 + "╗")
    print("║" + " "*23 + "PARACCI GUARDIAN SYSTEM" + " "*22 + "║")
    print("╚" + "═"*68 + "╝")
    
    start_time = time.time()
    
    audits = [
        ("Security & Code", security_audit.run),
        ("Secret Leak Check", leak_audit.run),
        ("Dependencies", dependency_audit.run),
        ("Performance & Assets", performance_audit.run),
        ("Accessibility", a11y_audit.run),
        ("i18n & Localization", i18n_audit.run),
        ("Code Quality & Clean", quality_audit.run),
        ("Static Analysis (Linter)", linter_audit.run),
        ("Sanity & Health", sanity_audit.run),
        ("System Integrity", integrity_audit.run),
    ]
    
    results = []
    
    for name, audit_func in audits:
        print(f"\n[>] Starting Audit: {name}")
        print("-" * 50)
        try:
            success = audit_func()
            results.append((name, "PASSED" if success else "FAILED", success))
        except Exception as e:
            print(f"  [X] Audit error: {e}")
            results.append((name, "ERROR", False))
        print("-" * 50)

    # Summary Report
    duration = time.time() - start_time
    print("\n" + "="*40)
    print(f"{'AUDIT NAME':<25} | {'STATUS':<10}")
    print("-" * 40)
    
    all_passed = True
    for name, status, success in results:
        print(f"{name:<25} | {status:<10}")
        if not success:
            all_passed = False
            
    print("-" * 40)
    print(f"Total Time: {duration:.2f}s")
    print("="*40)
    
    if all_passed:
        print("\n[PERFECT] The system passed all audits successfully! 🛡️")
        return True
    else:
        print("\n[WARNING] Some audits failed. Please review the details above. ⚠️")
        return False

if __name__ == "__main__":
    # Add the current directory to sys.path for imports to work
    sys.path.append(os.path.dirname(os.path.abspath(__file__)))
    
    if run_guardian():
        sys.exit(0)
    else:
        sys.exit(1)
