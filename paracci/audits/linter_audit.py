import os
import ast
import builtins
import sys

# Paracci Linter Audit (v5 - Professional)
# This module detects undefined names and missing imports within the code.

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET_DIRS = ['app', 'core', 'audits']

# Python's built-in functions and special names
MAGIC_NAMES = {'__name__', '__file__', '__doc__', '__package__', '__loader__', '__spec__', '__annotations__', 'self', 'cls'}
BUILTINS = set(dir(builtins)) | MAGIC_NAMES

class GlobalCollector(ast.NodeVisitor):
    """Collects all module-level definitions (for hoisting) in the file."""
    def __init__(self):
        """Initializes the collector instance."""
        self.globals = set()

    def visit_Import(self, node):
        """Collects global imports."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.globals.add(name.split('.')[0])

    def visit_ImportFrom(self, node):
        """Collects global from-imports."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.globals.add(name)

    def visit_FunctionDef(self, node):
        """Collects global function names."""
        self.globals.add(node.name)

    def visit_ClassDef(self, node):
        """Collects global class names."""
        self.globals.add(node.name)

    def visit_Assign(self, node):
        """Collects global assignments."""
        for target in node.targets:
            self._extract_names(target, self.globals)

    def visit_AnnAssign(self, node):
        """Collects global annotated assignments."""
        self._extract_names(node.target, self.globals)

    def visit_NamedExpr(self, node):
        """Collects global names bound via walrus operator."""
        self._extract_names(node.target, self.globals)


    def _extract_names(self, node, target_set):
        """Extracts names recursively from an AST node."""
        if isinstance(node, ast.Name):
            target_set.add(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                self._extract_names(elt, target_set)

class LinterChecker(ast.NodeVisitor):
    """Static analysis visitor that detects undefined variables."""
    def __init__(self, filename, global_names):
        """Initializes the checker instance."""
        self.filename = filename
        self.issues = []
        self.scopes = [set(BUILTINS) | global_names]

    def _current_scope(self):
        """Returns the active scope set object."""
        return self.scopes[-1]

    def _is_defined(self, name):
        """Checks if the name is defined in the scope stack."""
        for scope in reversed(self.scopes):
            if name in scope:
                return True
        return False

    def visit_Import(self, node):
        """Adds local imports to the active scope."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self._current_scope().add(name.split('.')[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        """Adds local from-imports to the active scope."""
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self._current_scope().add(name)
        self.generic_visit(node)

    def _add_args_to_scope(self, args_node, scope):
        """Helper to collect all kinds of function/lambda arguments into scope."""
        if hasattr(args_node, 'posonlyargs'):
            for arg in args_node.posonlyargs:
                scope.add(arg.arg)
        for arg in args_node.args:
            scope.add(arg.arg)
        if hasattr(args_node, 'kwonlyargs'):
            for arg in args_node.kwonlyargs:
                scope.add(arg.arg)
        if args_node.vararg:
            scope.add(args_node.vararg.arg)
        if args_node.kwarg:
            scope.add(args_node.kwarg.arg)

    def visit_FunctionDef(self, node):
        """Processes function definition and its arguments."""
        # Add function name to the current scope (for recursive calls or nested functions)
        self._current_scope().add(node.name)
        
        new_scope = set()
        self._add_args_to_scope(node.args, new_scope)
        
        self.scopes.append(new_scope)
        self.generic_visit(node)
        self.scopes.pop()

    def visit_Lambda(self, node):
        """Takes lambda arguments into a new scope."""
        new_scope = set()
        self._add_args_to_scope(node.args, new_scope)
        self.scopes.append(new_scope)
        self.generic_visit(node)
        self.scopes.pop()

    def visit_ClassDef(self, node):
        """Processes class definition."""
        self._current_scope().add(node.name)
        self.scopes.append(set())
        self.generic_visit(node)
        self.scopes.pop()

    def _visit_comp(self, node):
        """Manages comprehension scope."""
        new_scope = set()
        for gen in node.generators:
            self._extract_to_scope(gen.target, new_scope)
        self.scopes.append(new_scope)
        for gen in node.generators:
            self.visit(gen)
        if hasattr(node, "elt"):
            self.visit(node.elt)
        if hasattr(node, "key"):
            self.visit(node.key)
        if hasattr(node, "value"):
            self.visit(node.value)
        self.scopes.pop()

    def visit_ListComp(self, node): 
        """Visits list generator."""
        self._visit_comp(node)
    
    def visit_SetComp(self, node): 
        """Visits set generator."""
        self._visit_comp(node)
    
    def visit_DictComp(self, node): 
        """Visits dictionary generator."""
        self._visit_comp(node)
    
    def visit_GeneratorExp(self, node): 
        """Visits generator expression."""
        self._visit_comp(node)

    def visit_For(self, node):
        """Defines target variables in a for loop."""
        self._extract_to_scope(node.target, self._current_scope())
        self.generic_visit(node)

    def visit_With(self, node):
        """Defines variables in a with block."""
        for item in node.items:
            if item.optional_vars:
                self._extract_to_scope(item.optional_vars, self._current_scope())
        self.generic_visit(node)

    def visit_Assign(self, node):
        """Defines target names in an assignment operation."""
        for target in node.targets:
            self._extract_to_scope(target, self._current_scope())
        self.generic_visit(node)

    def visit_AnnAssign(self, node):
        """Defines target name in an annotated assignment."""
        self._extract_to_scope(node.target, self._current_scope())
        self.generic_visit(node)

    def visit_NamedExpr(self, node):
        """Defines name bound via walrus operator in current scope."""
        self._extract_to_scope(node.target, self._current_scope())
        self.generic_visit(node)


    def visit_ExceptHandler(self, node):
        """Defines the error handler name."""
        if node.name:
            self._current_scope().add(node.name)
        self.generic_visit(node)

    def _extract_to_scope(self, node, scope):
        """Extracts names from AST node and adds them to the target scope."""
        if isinstance(node, ast.Name):
            scope.add(node.id)
        elif isinstance(node, (ast.Tuple, ast.List)):
            for elt in node.elts:
                self._extract_to_scope(elt, scope)

    def visit_Name(self, node):
        """Checks if the used name is defined."""
        if isinstance(node.ctx, ast.Load):
            if not self._is_defined(node.id):
                self.issues.append({'line': node.lineno, 'msg': f"Undefined name: '{node.id}'"})
        self.generic_visit(node)

def check_linter():
    """Checks for missing names and imports across the entire project."""
    print("--- Starting Linter Audit ---\n")
    all_errors = 0

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
                            tree = ast.parse(content)
                            
                            # 1. Pass: Global Hoisting
                            collector = GlobalCollector()
                            collector.visit(tree)
                            
                            # 2. Pass: Scope Analysis
                            checker = LinterChecker(rel_path, collector.globals)
                            checker.visit(tree)
                            
                            if checker.issues:
                                for issue in checker.issues:
                                    print(f"  [!] {rel_path}:{issue['line']} -> {issue['msg']}")
                                    all_errors += 1
                                
                    except Exception as e:
                        print(f"  [X] {rel_path} could not be analyzed: {e}")
                        all_errors += 1

    print(f"\nLinter Audit RESULT: {all_errors} Critical Error(s)")
    return all_errors == 0

def run():
    """Main linter function called by Guardian."""
    return check_linter()

if __name__ == "__main__":
    if not run():
        sys.exit(1)
