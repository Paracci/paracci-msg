import os
import ast
import sys
import re
import time

class ParacciAuditor:
    """
    Paracci Security and Integrity Auditor.
    Scans project files to report vulnerabilities, errors, and structural defects.
    """
    def __init__(self, root_dir):
        """Initializes the Auditor instance."""
        self.root_dir = root_dir
        self.issues = []
        self.files_scanned = 0
        self.start_time = time.time()

    def audit(self):
        """Starts all security audits and reports the results."""
        print("\n" + "="*70)
        print("[!] PARACCI SECURITY & INTEGRITY AUDIT")
        print("="*70)
        print(f"[*] Target Directory: {self.root_dir}")
        print("[*] Scanning started...\n")

        for root, dirs, files in os.walk(self.root_dir):
            if any(x in root for x in ["venv", ".git", "__pycache__", "data_", "node_modules"]):
                continue

            for file in files:
                path = os.path.join(root, file)
                if file == "security_audit.py": continue 
                
                self.files_scanned += 1
                
                if file.endswith(".py"):
                    self.check_python_file(path)
                elif file.endswith(".html"):
                    self.check_html_file(path)
                elif file.endswith(".css"):
                    self.check_css_file(path)

        self.generate_report()
        return len([i for i in self.issues if i['severity'] in ['CRITICAL', 'HIGH']]) == 0

    def check_python_file(self, path):
        """Audits Python files for dangerous functions and syntax errors."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except UnicodeDecodeError:
            return 

        try:
            compile(content, path, "exec")
        except SyntaxError as e:
            self.add_issue("CRITICAL", path, f"Syntax Error: {e}")
            return

        dangerous_patterns = [
            (r'eval\(', "eval() usage (Code injection risk)"),
            (r'(?<!\.)\bexec\(', "exec() usage (Code injection risk)"),
            (r'os\.system\(', "os.system() usage (Command injection risk)"),
            (r'pickle\.load\(', "Insecure pickle load"),
            (r'yaml\.load\(', "Insecure YAML load (Use SafeLoad)"),
        ]
        
        for pattern, desc in dangerous_patterns:
            if re.search(pattern, content):
                self.add_issue("HIGH", path, desc)

        if re.search(r'[a-f0-9]{64}', content):
            if "crypto.py" not in path and "test" not in path and "security_audit" not in path:
                self.add_issue("MEDIUM", path, "Potential hardcoded key or hash found.")

        if re.search(r'\bprint\(', content) and "run.py" not in path and "audit" not in path:
            if not any(x in path for x in ["security_audit.py", "logger.py", "tests\\", "tools\\", "audits\\"]):
                self.add_issue("LOW", path, "Debug 'print' usage may remain.")

    def check_html_file(self, path):
        """Audits HTML files for XSS risks and security policy compliance."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except: return

        if "| safe" in content:
            if "purify.min.js" not in content and "DOMPurify.sanitize" not in content:
                 self.add_issue("HIGH", path, "Unsanitized HTML render (| safe) detected! XSS risk.")

        if "<script>" in content and "base.html" not in path:
             self.add_issue("MEDIUM", path, "Inline <script> usage detected. May be risky for CSP policy.")

    def check_css_file(self, path):
        """Audits CSS files for privacy risks (external source usage)."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
        except: return
        
        if "@import url(" in content and "http" in content:
            self.add_issue("LOW", path, "External CSS being imported. Privacy risk.")

    def add_issue(self, severity, path, desc):
        """Adds the found security issue to the list."""
        self.issues.append({
            "severity": severity,
            "file": os.path.relpath(path, self.root_dir),
            "description": desc
        })

    def generate_report(self):
        """Creates a security report containing all scan results."""
        duration = time.time() - self.start_time
        print("-" * 70)
        print(f"[*] Report Created: {self.files_scanned} files scanned in {duration:.2f} seconds.\n")
        
        if not self.issues:
            print("[+] [PERFECT] No security vulnerabilities or structural issues found.")
            return

        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.issues.sort(key=lambda x: order.get(x['severity'], 99))

        print(f"[!] {len(self.issues)} Potential Issues Detected:\n")
        
        for issue in self.issues:
            icon = {"CRITICAL": "[X]", "HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[i]"}.get(issue['severity'], "•")
            print(f"{icon} [{issue['severity']}] {issue['file']}")
            print(f"   -> {issue['description']}\n")

def run():
    """Main function called by Guardian."""
    # One level up from audits folder (paracci/)
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    auditor = ParacciAuditor(root)
    return auditor.audit()

if __name__ == "__main__":
    if run():
        sys.exit(0)
    else:
        sys.exit(1)
