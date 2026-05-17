import os
import sys
import sqlite3
import json

# Paracci Integrity Audit Tool
# Verifies database and file system integrity.

REQUIRED_DIRS = ['app', 'core', 'data', 'logs', 'keys']

def check_db_integrity(db_path):
    """Checks the physical integrity of the SQLite database file using PRAGMA."""
    if not os.path.exists(db_path):
        return True # It might not have been created yet
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("PRAGMA integrity_check;")
        result = cursor.fetchone()[0]
        conn.close()
        return result == "ok"
    except Exception as e:
        print(f"  [X] Database error: {e}")
        return False

def run():
    """Runs the system integrity audit (folders, database, configuration)."""
    print("--- Starting Integrity Audit ---\n")
    issues = 0
    
    # One level above the audits folder (paracci/)
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # 1. Folder structure check
    print("[*] Verifying folder structure...")
    for d in REQUIRED_DIRS:
        d_path = os.path.join(root_dir, d)
        if not os.path.exists(d_path):
            print(f"  [!] MISSING DIRECTORY: {d} -> Creating...")
            try:
                os.makedirs(d_path, exist_ok=True)
                print(f"  [+] {d}/ created successfully.")
            except Exception as e:
                print(f"  [X] Failed to create {d}/: {e}")
                issues += 1
        else:
            print(f"  [+] {d}/ exists.")

    # 2. Database integrity
    print("[*] Checking SQLite database integrity...")
    db_path = os.path.join(root_dir, 'data', 'paracci.db')
    if not check_db_integrity(db_path):
        print(f"  [X] CRITICAL: Database corrupted! ({db_path})")
        issues += 1
    else:
        print("  [+] Database is healthy.")

    # 3. Config check
    config_path = os.path.join(root_dir, 'config.json')
    if os.path.exists(config_path):
        print("[*] config.json structure verifying...")
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                json.load(f)
            print("  [+] config.json is valid.")
        except Exception as e:
            print(f"  [X] config.json is corrupted: {e}")
            issues += 1

    print(f"\nIntegrity Audit RESULT: {issues} Issues")
    return issues == 0

if __name__ == "__main__":
    if run():
        sys.exit(0)
    else:
        sys.exit(1)
