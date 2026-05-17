import os
import re
import sys

# Paracci Leak Audit Tool
# This script scans for accidentally leaked sensitive data (keys, passwords).

# Sensitive data patterns
PATTERNS = [
    (r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----', "PEM/SSH Private Key"),
    (r'\"seed\":\s*\"[a-f0-9]{64}\"', "Plaintext Seed (JSON)"),
    (r'\"key\":\s*\"[a-f0-9]{64}\"', "Plaintext Key (JSON)"),
    (r'password\s*=\s*[\'\"].{4,}[\'\"]', "Potential Hardcoded Password"),
]

def run():
    """Checks if sensitive data (private keys, plaintext keys, etc.) has leaked into the codebase."""
    print("--- Starting Leak Audit ---\n")
    issues = 0
    
    # One level above the audits folder (paracci/)
    root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    # Folders to be scanned
    target_dirs = ['app', 'core', 'data', 'logs', 'tests']
    
    for t_dir in target_dirs:
        dir_path = os.path.join(root_dir, t_dir)
        if not os.path.exists(dir_path): continue
        
        for root, _, files in os.walk(dir_path):
            if "__pycache__" in root or "node_modules" in root: continue
            
            for file in files:
                if file.endswith(('.py', '.json', '.log', '.txt', '.html')):
                    path = os.path.join(root, file)
                    try:
                        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            for pattern, desc in PATTERNS:
                                if re.search(pattern, content, re.IGNORECASE):
                                    # Exclude legitimate files like security_audit.py
                                    if "leak_audit.py" in path or "security_audit.py" in path:
                                        continue
                                    
                                    rel_path = os.path.relpath(path, root_dir)
                                    print(f"  [!] LEAK FOUND: {rel_path} -> {desc}")
                                    issues += 1
                    except Exception as e:
                        print(f"  [i] Skipped file {file}: {e}")

    print(f"\nLeak Audit RESULT: {issues} Critical Leak(s)")
    return issues == 0

if __name__ == "__main__":
    if run():
        sys.exit(0)
    else:
        sys.exit(1)
