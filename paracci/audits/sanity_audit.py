import os
import sys
import json
import ast

# Paracci Sanity & Health Audit (v3.1)
# Performs critical file, path, and logic checks to ensure the application does not crash at runtime.

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def check_required_folders():
    """Checks for the existence of folders required for the application to run."""
    required = [
        os.path.join(BASE_DIR, 'app', 'i18n'),
        os.path.join(BASE_DIR, 'desktop'),
        os.path.join(BASE_DIR, 'core'),
    ]
    
    errors = 0
    for folder in required:
        if not os.path.exists(folder):
            print(f"  [!] CRITICAL MISSING: Folder not found -> {os.path.relpath(folder, BASE_DIR)}")
            errors += 1
    return errors

def check_i18n_files():
    """Checks that the JSON files in the i18n folder are valid."""
    i18n_dir = os.path.join(BASE_DIR, 'app', 'i18n')
    errors = 0
    
    if os.path.exists(i18n_dir):
        files = os.listdir(i18n_dir)
        if not files:
            print("  [!] ERROR: i18n folder is empty!")
            errors += 1
            
        for file in files:
            if file.endswith('.json'):
                path = os.path.join(i18n_dir, file)
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        json.load(f)
                except Exception as e:
                    print(f"  [!] ERROR: Invalid JSON file ({file}) -> {e}")
                    errors += 1
    return errors

def has_return_logic(node):
    """Checks if an AST node or its children contains return/raise."""
    if isinstance(node, (ast.Return, ast.Raise)):
        return True
    
    if isinstance(node, ast.If):
        if node.orelse:
            return has_return_logic(node.body[-1]) and has_return_logic(node.orelse[-1])
        return False
        
    if isinstance(node, ast.Try):
        try_returns = has_return_logic(node.body[-1])
        except_returns = all(has_return_logic(handler.body[-1]) for handler in node.handlers)
        return try_returns and except_returns
        
    return False

def check_route_return_statements():
    """Legacy Flask route check kept only when the route file is present."""
    routes_path = os.path.join(BASE_DIR, 'app', 'routes.py')
    errors = 0
    
    if not os.path.exists(routes_path):
        return 0
        
    try:
        with open(routes_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read())
            
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                is_route = False
                for dec in node.decorator_list:
                    if (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr == 'route') or \
                       (isinstance(dec, ast.Attribute) and dec.attr == 'route'):
                        is_route = True
                
                if is_route:
                    if not has_return_logic(node.body[-1]):
                        print(f"  [!] LOGIC ERROR: Route '{node.name}' (L:{node.lineno}) has a risky return structure!")
                        errors += 1
                        
    except Exception as e:
        print(f"  [!] ERROR: routes.py could not be analyzed -> {e}")
        errors += 1
        
    return errors

def check_database_access():
    """Checks if there is write permission to the data directory."""
    data_dir = os.path.join(BASE_DIR, 'data')
    errors = 0
    
    if not os.path.exists(data_dir):
        try:
            os.makedirs(data_dir)
        except Exception as e:
            print(f"  [!] ERROR: 'data' directory cannot be created -> {e}")
            return 1
            
    test_file = os.path.join(data_dir, '.write_test')
    try:
        with open(test_file, 'w') as f:
            f.write('test')
        os.remove(test_file)
    except Exception as e:
        print(f"  [!] ERROR: No write permission to the 'data' directory -> {e}")
        errors += 1
        
    return errors

def check_path_construction():
    """Audits dynamic path creation (path join) errors."""
    errors = 0
    # This check can be improved, currently a placeholder
    return errors

def run():
    """Runs all sanity & health checks."""
    print("--- Sanity & Health Audit Starting ---\n")
    
    errors = 0
    try:
        errors += check_required_folders()
        errors += check_i18n_files()
        errors += check_route_return_statements()
        errors += check_database_access()
        errors += check_path_construction()
    except Exception as e:
        print(f"  [X] Audit error: {e}")
        return False
    
    if errors == 0:
        print("\nSanity Audit RESULT: 0 Issues (System ready to work)")
        return True
    else:
        print(f"\nSanity Audit RESULT: {errors} Critical Issues Detected!")
        return False

if __name__ == "__main__":
    if not run():
        sys.exit(1)
