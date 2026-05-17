import os
import re
import sys

# Paracci Accessibility (A11y) & W3C Standards Audit
# Paracci Accessibility (A11y) & W3C Standards Audit
# Audits accessibility standards and HTML structure.

class A11yAuditor:
    """Class that audits accessibility and W3C standards."""
    def __init__(self, root_dir):
        """Initializes the auditor instance."""
        self.root_dir = root_dir
        self.issues = []

    def audit(self):
        """Runs all accessibility audits."""
        print("\n" + "="*70)
        print("[!] PARACCI ACCESSIBILITY & STANDARDS AUDIT")
        print("="*70)

        template_path = os.path.join(self.root_dir, 'app', 'templates')
        if os.path.exists(template_path):
            for file in os.listdir(template_path):
                if file.endswith(".html"):
                    self.check_template(os.path.join(template_path, file))

        self.report()
        return True

    def check_template(self, path):
        """Audits the HTML template according to accessibility rules."""
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

            # 1. HTML Lang Attribute
            if "<html" in content and 'lang=' not in content:
                self.add_issue("MEDIUM", path, "Missing <html lang='...'> attribute (critical for screen readers).")

            # 2. Image Alt Tags
            img_tags = re.findall(r"<img[^>]*>", content)
            for img in img_tags:
                if 'alt=' not in img or 'alt=""' in img:
                    self.add_issue("HIGH", path, f"Missing alt tag in image: {img[:50]}...")

            # 3. Icon-only Buttons (Aria Labels)
            # Catch structures like <button><i></i></button>
            interactive_tags = re.findall(r"<(button|a)[^>]*>.*?</\1>", content, re.DOTALL)
            for tag in interactive_tags:
                # If it contains only an icon and aria-label/title is missing
                if "<i " in tag and "aria-label=" not in tag and "title=" not in tag:
                    # Simple check: is there plain text inside the tag?
                    clean_text = re.sub(r"<[^>]*>", "", tag).strip()
                    if not clean_text:
                        self.add_issue("MEDIUM", path, f"Button/link without text: aria-label or title missing.")

            # 4. Heading Hierarchy
            h_tags = re.findall(r"<h([1-6])", content)
            if h_tags:
                h_levels = [int(x) for x in h_tags]
                for i in range(len(h_levels) - 1):
                    if h_levels[i+1] > h_levels[i] + 1:
                        self.add_issue("LOW", path, f"Incorrect heading hierarchy: skipped from h{h_levels[i]} to h{h_levels[i+1]}.")

    def add_issue(self, severity, path, desc):
        """Adds the found issue to the list."""
        self.issues.append({
            "severity": severity,
            "file": os.path.relpath(path, self.root_dir),
            "description": desc
        })

    def report(self):
        """Prints the audit report to the screen."""
        if not self.issues:
            print("[+] [ACCESSIBILITY PERFECT] The application complies with inclusive standards.")
            return

        for issue in self.issues:
            icon = {"HIGH": "[!]", "MEDIUM": "[*]", "LOW": "[i]"}.get(issue['severity'], "•")
            print(f"{icon} [{issue['severity']}] {issue['file']} -> {issue['description']}")

def run():
    """Main function called by Guardian."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    auditor = A11yAuditor(root)
    return auditor.audit()

if __name__ == "__main__":
    run()
