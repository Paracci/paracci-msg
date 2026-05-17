import os
import ast
import re
import sys
import io

# Paracci Quality & Clean Code Audit
# This module uses AST to audit code quality and adherence to standards.

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_DIRS = ['app', 'core', 'audits']

class QualityChecker(ast.NodeVisitor):
    """Visitor class that analyzes Python files via AST to audit code quality."""
    def __init__(self, filename):
        """Initializes the checker instance."""
        self.filename = filename
        self.issues = []
        self.current_function = None
        self.nesting_level = 0

    def visit_FunctionDef(self, node):
        """Visits function definitions; audits length, naming, and docstrings."""
        self.current_function = node.name
        
        # 1. Function Length Check
        line_count = node.end_lineno - node.lineno
        if line_count > 60:
            self.issues.append({
                'line': node.lineno,
                'type': 'WARNING',
                'msg': f"Function too long ({line_count} lines): '{node.name}' -> Consider splitting it."
            })

        # 2. Naming Standard (snake_case)
        if not re.match(r'^[a-z_][a-z0-9_]*$', node.name):
            # Exceptions for visit_* (AST) and __*__ (Built-in)
            if not (node.name.startswith('visit_') or node.name.startswith('__')):
                self.issues.append({
                    'line': node.lineno,
                    'type': 'WARNING',
                    'msg': f"Naming error: '{node.name}' should be snake_case."
                })

        # 3. Docstring Check
        if not ast.get_docstring(node):
            self.issues.append({
                'line': node.lineno,
                'type': 'INFO',
                'msg': f"Missing docstring: '{node.name}'"
            })

        self.generic_visit(node)
        self.current_function = None

    def visit_Import(self, node):
        """Visits import statements; audits imports inside functions for performance."""
        if self.current_function:
            # EXCEPTION: app/__init__.py -> routes.bp is inside a function to prevent circular dependency.
            if "app\\__init__.py" in self.filename and any(n.name == "bp" for n in node.names):
                return
            self.issues.append({
                'line': node.lineno,
                'type': 'INFO',
                'msg': f"Import inside function detected: '{self.current_function}' -> Consider moving to top for performance."
            })
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Visits From-Import statements; audits imports inside functions for performance."""
        if self.current_function:
            # EXCEPTION: app/__init__.py -> routes.bp is inside a function to prevent circular dependency.
            if "app" in self.filename and "__init__.py" in self.filename and node.module == "routes" and node.level == 1:
                return
            self.issues.append({
                'line': node.lineno,
                'type': 'INFO',
                'msg': f"Import inside function detected: '{self.current_function}'"
            })
        self.generic_visit(node)

    def visit_Call(self, node):
        """Visits function calls; audits print() usage."""
        # 4. Print Usage (Excluding audits folder)
        if isinstance(node.func, ast.Name) and node.func.id == 'print':
            if 'audits' not in self.filename:
                self.issues.append({
                    'line': node.lineno,
                    'type': 'WARNING',
                    'msg': "print() usage detected. Consider using the logging module."
                })
        self.generic_visit(node)

    def visit_If(self, node):
        """Visits If blocks; audits nesting depth."""
        self.nesting_level += 1
        if self.nesting_level > 4:
            self.issues.append({
                'line': node.lineno,
                'type': 'WARNING',
                'msg': "Excessive nesting (If depth > 4). Simplify the code."
            })
        self.generic_visit(node)
        self.nesting_level -= 1

def check_quality():
    """Main function that scans and reports code quality across the entire project."""
    print("--- Quality & Clean Code Audit Starting ---\n")
    all_issues = 0
    warnings = 0
    infos = 0

    for target in TARGET_DIRS:
        target_path = os.path.join(BASE_DIR, target)
        if not os.path.exists(target_path): continue

        for root, _, files in os.walk(target_path):
            for file in files:
                if file.endswith('.py'):
                    path = os.path.join(root, file)
                    rel_path = os.path.relpath(path, BASE_DIR)
                    
                    try:
                        with open(path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                            # 5. Comment Checks (TODO/FIXME)
                            for i, line in enumerate(content.splitlines()):
                                if any(tag in line.upper() for tag in ['TODO', 'FIXME']):
                                    # Exclude the audit engine's own code or comments
                                    if "quality_audit.py" in rel_path:
                                        if "tag in line.upper()" in line or "(TODO/FIXME)" in line:
                                            continue
                                    print(f"  [i] {rel_path}:{i+1} -> Forgotten Note: {line.strip()}")
                                    infos += 1

                            tree = ast.parse(content)
                            visitor = QualityChecker(rel_path)
                            visitor.visit(tree)
                            
                            for issue in visitor.issues:
                                icon = "⚠️" if issue['type'] == 'WARNING' else "ℹ️"
                                print(f"  {icon} {rel_path}:{issue['line']} -> {issue['msg']}")
                                if issue['type'] == 'WARNING': warnings += 1
                                else: infos += 1
                                all_issues += 1
                    except Exception as e:
                        print(f"  [X] {rel_path} could not be analyzed: {e}")

    print(f"\nQuality Audit RESULT: {warnings} Warnings, {infos} Info Notes")
    # Returns True if there are no critical errors (only warnings and info)
    return True 

def run():
    """Main function called by Guardian."""
    return check_quality()

if __name__ == "__main__":
    run()
