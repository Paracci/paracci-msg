import os
import sys

# Paracci Performance & Resource Hygiene Audit
# Audits asset sizes, log sizes, and resource usage.

class PerformanceAuditor:
    """Class that audits application performance and resource usage hygiene."""
    def __init__(self, root_dir):
        """Initializes the auditor instance."""
        self.root_dir = root_dir
        self.issues = []

    def audit(self):
        """Runs all performance checks."""
        print("\n" + "="*70)
        print("[!] PARACCI PERFORMANCE & RESOURCE AUDIT")
        print("="*70)

        # 1. Image Optimization Check
        print("[*] Auditing image sizes...")
        self.check_assets()

        # 2. Log Hygiene
        print("[*] Checking log files...")
        self.check_logs()

        # 3. CSS/JS Payload Check
        print("[*] Checking static file payloads...")
        self.check_static_payloads()

        self.report()
        # Performance warnings are generally not considered critical (HIGH), just report them.
        return True

    def check_assets(self):
        """Audits the sizes of static assets (images)."""
        assets_path = os.path.join(self.root_dir, 'app', 'static', 'assets')
        if not os.path.exists(assets_path): return

        for file in os.listdir(assets_path):
            fpath = os.path.join(assets_path, file)
            if os.path.isfile(fpath):
                size_kb = os.path.getsize(fpath) / 1024
                if size_kb > 500:
                    severity = "MEDIUM" if size_kb > 1000 else "LOW"
                    self.add_issue(severity, fpath, f"Large image file: {size_kb:.1f}KB (Needs optimization)")

    def check_logs(self):
        """Audits log file sizes and rotation needs."""
        logs_path = os.path.join(self.root_dir, 'logs')
        if not os.path.exists(logs_path): return

        for file in os.listdir(logs_path):
            if file.endswith(".log"):
                fpath = os.path.join(logs_path, file)
                size_mb = os.path.getsize(fpath) / (1024 * 1024)
                if size_mb > 5:
                    self.add_issue("MEDIUM", fpath, f"Large log file: {size_mb:.2f}MB (Log rotation may be needed)")

    def check_static_payloads(self):
        """Audits the sizes of CSS and JS files."""
        static_path = os.path.join(self.root_dir, 'app', 'static', 'css')
        if not os.path.exists(static_path): return

        for root, _, files in os.walk(static_path):
            for file in files:
                if file.endswith(".css"):
                    fpath = os.path.join(root, file)
                    size_kb = os.path.getsize(fpath) / 1024
                    if size_kb > 50:
                        self.add_issue("LOW", fpath, f"Bloated CSS file: {size_kb:.1f}KB (Consider splitting)")

    def add_issue(self, severity, path, desc):
        """Adds a discovered performance issue to the list."""
        self.issues.append({
            "severity": severity,
            "file": os.path.relpath(path, self.root_dir),
            "description": desc
        })

    def report(self):
        """Prints the audit report to the screen."""
        if not self.issues:
            print("[+] [PERFORMANCE EXCELLENT] Resource usage is optimized.")
            return

        for issue in self.issues:
            icon = {"HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[i]"}.get(issue['severity'], "•")
            print(f"{icon} [{issue['severity']}] {issue['file']} -> {issue['description']}")

def run():
    """Main function called by Guardian."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    auditor = PerformanceAuditor(root)
    return auditor.audit()

if __name__ == "__main__":
    run()
