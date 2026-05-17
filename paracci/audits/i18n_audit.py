import os
import re
import json
import sys

# Paracci i18n (Internationalization) Audit Tool - V2
# Audits hardcoded texts, missing translations, and unused keys.

class I18nAuditor:
    """Class that audits internationalization (i18n) and localization standards."""
    def __init__(self, root_dir):
        """Initializes the auditor instance."""
        self.root_dir = root_dir
        self.issues = []
        self.i18n_dir = os.path.join(self.root_dir, 'app', 'i18n')
        self.languages = self.list_languages()
        self.all_keys = {lang: self.load_keys(f"{lang}.json") for lang in self.languages}
        self.used_keys = set()
        self.missing_translations = {} # lang -> set of missing keys

    def list_languages(self):
        """Lists all supported languages based on JSON files."""
        if not os.path.exists(self.i18n_dir): return []
        return [f.replace('.json', '') for f in os.listdir(self.i18n_dir) if f.endswith('.json')]

    def load_keys(self, filename):
        """Loads and flattens the specified translation file."""
        path = os.path.join(self.i18n_dir, filename)
        if not os.path.exists(path): return {}
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                return self.flatten_dict(data)
        except Exception as e:
            print(f"Error loading {filename}: {e}")
            return {}

    def flatten_dict(self, d, parent_key='', sep='.'):
        """Converts nested dictionary structure into a flat dotted key structure."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self.flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def audit(self):
        """Runs all i18n audits."""
        print("\n" + "="*70)
        print("[!] PARACCI i18n & MULTI-LANGUAGE AUDIT V2")
        print("="*70)

        # 1. Parity Check
        print(f"[*] Comparing {len(self.languages)} translation files: {', '.join(self.languages)}...")
        self.check_parity()

        # 2. Template Audit
        print("[*] Scanning templates (HTML) for hardcoded texts and missing keys...")
        template_path = os.path.join(self.root_dir, 'app', 'templates')
        for root, _, files in os.walk(template_path):
            for file in files:
                if file.endswith(".html"):
                    self.check_template(os.path.join(root, file))

        # 3. Python Audit
        print("[*] Scanning Python files for UI texts and missing keys...")
        self.check_files_by_extension(".py", self.check_python_content)

        # 4. Javascript Audit
        print("[*] Scanning Javascript files for hardcoded UI texts...")
        static_js_path = os.path.join(self.root_dir, 'app', 'static', 'js')
        if os.path.exists(static_js_path):
            self.check_files_by_extension(".js", self.check_js_content, search_path=static_js_path)

        self.report()
        return len([i for i in self.issues if i['severity'] in ['HIGH', 'MEDIUM']]) == 0

    def check_parity(self):
        """Checks key consistency across all translation files."""
        all_key_sets = {lang: set(keys.keys()) for lang, keys in self.all_keys.items()}
        union_keys = set().union(*all_key_sets.values())

        for lang, key_set in all_key_sets.items():
            missing = union_keys - key_set
            if missing:
                self.missing_translations[lang] = missing
                for key in missing:
                    self.add_issue("MEDIUM", f"app/i18n/{lang}.json", f"Missing key: {key}")

    def check_files_by_extension(self, ext, check_func, search_path=None):
        """Generic file scanner by extension."""
        path = search_path or os.path.join(self.root_dir, 'app')
        for root, _, files in os.walk(path):
            if "i18n" in root or "static/js/lib" in root: continue
            for file in files:
                if file.endswith(ext):
                    check_func(os.path.join(root, file))

    def check_template(self, path):
        """Scans for hardcoded texts and validates i18n keys in HTML templates."""
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()

            # 1. Check for used keys
            # Patterns like _('key'), _("key"), _('key', ...)
            i18n_calls = re.findall(r"_\([\"'](.*?)[\"']", content)
            for key in i18n_calls:
                self.used_keys.add(key)
                self.validate_key(key, path)

            # 2. Check for hardcoded text
            # Clean Jinja2 blocks
            clean_content = re.sub(r"\{\{.*?\}\}|\{\%.*?\%\}", "", content, flags=re.DOTALL)
            # Clean Script and Style tags
            clean_content = re.sub(r"<(script|style).*?>.*?</\1>", "", clean_content, flags=re.DOTALL | re.IGNORECASE)
            
            # Attributes to check
            for attr in ['placeholder', 'title', 'alt', 'label']:
                matches = re.findall(rf'{attr}=["\']([^"\']+)["\']', clean_content)
                for match in matches:
                    text = match.strip()
                    if text and len(text) > 2 and not text.isnumeric():
                        self.add_issue("LOW", path, f"Hardcoded attribute {attr}: \"{text[:30]}\"")

            # Text nodes
            text_nodes = re.findall(r">([^<>\n\r]+)<", clean_content)
            for node in text_nodes:
                text = node.strip()
                if self.is_suspicious_text(text):
                    self.add_issue("LOW", path, f"Hardcoded text node: \"{text[:30]}\"")

    def check_python_content(self, path):
        """Searches for hardcoded texts and validates i18n keys in Python."""
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            
            # i18n keys
            i18n_calls = re.findall(r"_\([\"'](.*?)[\"']", content)
            for key in i18n_calls:
                self.used_keys.add(key)
                self.validate_key(key, path)

            # Flash messages
            flash_matches = re.findall(r"flash\([\"'](.*?)[\"']", content)
            for match in flash_matches:
                if not match.startswith("i18n.") and self.is_suspicious_text(match):
                    self.add_issue("LOW", path, f"Flash message hardcoded: \"{match[:30]}\"")

    def check_js_content(self, path):
        """Searches for hardcoded strings in JS files."""
        with open(path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            # Look for alert(), console.log (maybe exclude), or innerHTML/textContent assignments with strings
            # This is tricky in JS, let's look for common UI text patterns
            strings = re.findall(r"[\"']([A-Z][^\"']{3,})[\"']", content) # Strings starting with uppercase
            for s in strings:
                if self.is_suspicious_text(s) and not s.isupper(): # Exclude CONSTANTS
                    if "data-" not in s and "id" not in s: # Exclude some technical strings
                         self.add_issue("LOW", path, f"Possible hardcoded JS text: \"{s[:30]}\"")

    def is_suspicious_text(self, text):
        """Heuristic to determine if a string is UI text that should be localized."""
        if not text or text.isnumeric() or len(text) <= 1: return False
        if text.startswith(('_', '.', '#', '/', 'http')): return False
        if any(c in "çğışöüÇĞİŞÖÜ" for c in text): return True # Turkish characters
        if re.search(r'[a-zA-Z]{3,}', text):
            # Check if it contains spaces or lowercase letters (to avoid IDs/Constants)
            if ' ' in text or any(c.islower() for c in text):
                 # Avoid technical strings
                 if not all(c in "0123456789.()[]{} :;-_/\\|*&^%$#@!+='\"" for c in text):
                     return True
        return False

    def validate_key(self, key, path):
        """Checks if an i18n key exists in at least one language, and reports if missing in others."""
        found_any = False
        missing_langs = []
        for lang in self.languages:
            if key in self.all_keys[lang]:
                found_any = True
            else:
                missing_langs.append(lang)
        
        if not found_any:
            self.add_issue("HIGH", path, f"Undefined i18n key used: {key}")
        elif missing_langs:
            for lang in missing_langs:
                self.add_issue("MEDIUM", f"app/i18n/{lang}.json", f"Missing key used in code: {key}")

    def add_issue(self, severity, path, desc):
        """Adds the found i18n issue to the list."""
        self.issues.append({
            "severity": severity,
            "file": os.path.relpath(path, self.root_dir) if os.path.isabs(path) else path,
            "description": desc
        })

    def report(self):
        """Prints the audit report to the screen."""
        if not self.issues:
            print("[+] [i18n PERFECT] All UI texts are localized.")
            return

        # Sort issues by severity
        severity_map = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
        self.issues.sort(key=lambda x: severity_map.get(x['severity'], 3))

        print(f"[!] {len(self.issues)} i18n Issues detected:\n")
        for issue in self.issues:
            icon = {"HIGH": "[!!]", "MEDIUM": "[*]", "LOW": "[i]"}.get(issue['severity'], "•")
            print(f"{icon} [{issue['severity']}] {issue['file']} -> {issue['description']}")

        # Summary of missing translations for easier fixing
        if self.missing_translations or any(i['severity'] == 'MEDIUM' for i in self.issues):
             print("\n" + "-"*30)
             print("MISSING KEYS SUMMARY (For Filling)")
             print("-"*30)
             for lang, keys in self.missing_translations.items():
                 if keys:
                     print(f"[{lang}] : {len(keys)} keys missing")
                     for k in sorted(list(keys))[:10]: # Show first 10
                         print(f"  - {k}")
                     if len(keys) > 10: print(f"  ... and {len(keys)-10} more")

def run():
    """Main function."""
    # Adjusted root calculation to handle different entry points
    script_dir = os.path.dirname(os.path.abspath(__file__))
    root = os.path.dirname(script_dir)
    auditor = I18nAuditor(root)
    return auditor.audit()

if __name__ == "__main__":
    run()
