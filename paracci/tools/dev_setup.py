"""
Paracci — tools/dev_setup.py
Script that automatically connects users X and Y (handshake) 
to speed up development and testing processes.

This script automatically detects if it is being run outside the local 
virtual environment (missing mandatory dependencies like 'yoyo'). If so, 
it attempts to re-execute itself using the local virtual environment's 
Python interpreter.

Usage:
    python tools/dev_setup.py
"""

import os
import sys
import shutil
import io
from pathlib import Path

# Add project root directory
ROOT_DIR = Path(__file__).parent.parent.parent

# Check dependencies and auto-re-execute in virtual environment if available
try:
    import yoyo
except ImportError:
    if os.environ.get("PARACCI_VENV_BOOTSTRAPPED"):
        print("[ERROR] Running inside virtual environment but 'yoyo' dependency is still missing.", file=sys.stderr)
        print("[ERROR] Please install dependencies by running: pip install -r requirements.lock", file=sys.stderr)
        sys.exit(1)

    # Look for local workspace virtual environment (.venv)
    venv_dir = ROOT_DIR / ".venv"
    appdata_local = os.environ.get("LOCALAPPDATA")
    appdata_venv = Path(appdata_local) / "Paracci" / ".venv" if appdata_local else None

    target_python = None
    if venv_dir.exists():
        py_exe = venv_dir / "Scripts" / "python.exe" if sys.platform == "win32" else venv_dir / "bin" / "python"
        if py_exe.exists():
            target_python = py_exe
    elif appdata_venv and appdata_venv.exists():
        py_exe = appdata_venv / "Scripts" / "python.exe" if sys.platform == "win32" else appdata_venv / "bin" / "python"
        if py_exe.exists():
            target_python = py_exe

    # If no virtual environment is found, automatically create one in the workspace
    if not target_python:
        print("[*] Virtual environment (.venv) not found. Creating a new virtual environment...", flush=True)
        import subprocess
        try:
            subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
            
            # Locate python in the new venv
            if sys.platform == "win32":
                py_exe = venv_dir / "Scripts" / "python.exe"
            else:
                py_exe = venv_dir / "bin" / "python"

            if py_exe.exists():
                print("[*] Installing dependencies into the virtual environment...", flush=True)
                
                # Install lock files using python -m pip to prevent lock errors when upgrading pip
                req_args = [str(py_exe), "-m", "pip", "install", "--require-hashes", "-r", str(ROOT_DIR / "requirements.lock")]
                if (ROOT_DIR / "requirements-dev.lock").exists():
                    req_args.extend(["-r", str(ROOT_DIR / "requirements-dev.lock")])
                subprocess.run(req_args, check=True)

                # If on Windows, also install sqlcipher3-wheels to prevent build failures/DatabaseErrors
                if sys.platform == "win32":
                    print("[*] Installing sqlcipher3-wheels for Windows SQLCipher support...", flush=True)
                    subprocess.run([str(py_exe), "-m", "pip", "install", "sqlcipher3-wheels"], check=True)
                
                target_python = py_exe
        except Exception as e:
            print(f"[ERROR] Failed to automatically create virtual environment and install dependencies: {e}", file=sys.stderr)
            print("[ERROR] Please create a virtual environment manually:", file=sys.stderr)
            if sys.platform == "win32":
                print("    python -m venv .venv\n    .\\.venv\\Scripts\\activate\n    pip install -r requirements.lock", file=sys.stderr)
            else:
                print("    python -m venv .venv\n    source .venv/bin/activate\n    pip install -r requirements.lock", file=sys.stderr)
            sys.exit(1)

    if target_python:
        print(f"[*] Re-running script inside virtual environment: {target_python}", flush=True)
        import subprocess
        env = os.environ.copy()
        env["PARACCI_VENV_BOOTSTRAPPED"] = "1"
        try:
            result = subprocess.run([str(target_python), str(Path(__file__).resolve())] + sys.argv[1:], env=env)
            sys.exit(result.returncode)
        except Exception as e:
            print(f"[ERROR] Failed to execute script within virtual environment: {e}", file=sys.stderr)
            sys.exit(1)

sys.path.insert(0, str(ROOT_DIR / "paracci"))

# Unicode support (for Windows console)
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

from core.burn import BurnDB, init_device
from core.identity import get_or_create_device_identity
from core.session import (
    create_initiator_session,
    accept_initiator_and_create_responder,
    finalize_initiator_session,
    apply_bond_nonce_to_y,
    serialize_session_meta,
    confirm_safety_code,
    get_session_safety_code
)

DEFAULT_PIN = "Correct-Horse-95175328"

def setup_user(user_name: str):
    data_dir = ROOT_DIR / f"data_{user_name}"
    if data_dir.exists():
        print(f"  [!] {data_dir} already exists, cleaning up...")
        shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True)
    
    db = BurnDB(data_dir / "sessions.db")
    device_key = init_device(db, DEFAULT_PIN)
    db = db.with_device_key(device_key)
    
    # Create default profile settings
    import json
    config = {
        "username": f"User {user_name.upper()}",
        "avatar_color": "#10b981" if user_name == 'x' else "#3b82f6",
        "downloads_dir": "downloads",
        "anti_screenshot": True,
        "quiet_mode": False,
        "default_ttl": 0
    }
    with open(data_dir / "config.json", "w") as f:
        json.dump(config, f)
    
    (data_dir / "downloads").mkdir(exist_ok=True)
    
    return db, device_key

def main():
    print("--- Paracci Automated Development Setup ---")
    
    # 1. Prepare Users
    db_x, key_x = setup_user("x")
    db_y, key_y = setup_user("y")
    
    print("[+] User X and Y data directories prepared.")
    print(f"[+] Default PIN: {DEFAULT_PIN}")

    # 2. Handshake Simulation
    print("\n[*] Setup starting.")
    # Load device identities
    identity_x = get_or_create_device_identity(db_x, key_x)
    identity_y = get_or_create_device_identity(db_y, key_y)

    # X: Create session
    meta_x_init, init_file = create_initiator_session(
        "Automated Test Channel",
        my_username="User X",
        identity_pub=identity_x.public_key,
        identity_priv=identity_x.private_key
    )
    print("  [1/4] X: Initiator created.")
    
    # Y: Accept Initiator and create Responder
    meta_y, resp_file = accept_initiator_and_create_responder(
        init_file, 
        "Automated Test Channel",
        my_username="User Y",
        identity_pub=identity_y.public_key,
        identity_priv=identity_y.private_key
    )
    print("  [2/4] Y: Initiator accepted, Responder created.")
    
    # X: Accept Responder and finalize
    meta_x_final = finalize_initiator_session(meta_x_init, resp_file)
    print("  [3/4] X: Responder accepted, session activated.")

    # Y: Apply bond nonce from X to finalize bonding
    meta_y_final = apply_bond_nonce_to_y(meta_y, meta_x_final.bond_nonce)
    print("  [4/4] Y: Bond nonce applied, session fully bonded.")

    # Automatically confirm safety codes to activate the sessions
    code_x = get_session_safety_code(meta_x_final)
    meta_x_final = confirm_safety_code(meta_x_final, code_x)
    
    code_y = get_session_safety_code(meta_y_final)
    meta_y_final = confirm_safety_code(meta_y_final, code_y)
    print("  [+] X & Y: Safety codes matched and sessions activated.")

    # 3. Save to Database
    enc_x = serialize_session_meta(meta_x_final, key_x)
    db_x.save_session(
        meta_x_final.session_id, meta_x_final.label, meta_x_final.state, 
        enc_x, meta_x_final.created_at
    )
    
    enc_y = serialize_session_meta(meta_y_final, key_y)
    db_y.save_session(
        meta_y_final.session_id, meta_y_final.label, meta_y_final.state, 
        enc_y, meta_y_final.created_at
    )
    
    print("\n[✔] Setup completed!")
    print("---------------------------------------------")
    print("You can now start the applications with these commands:")
    print("  Terminal 1: python run.py --user x")
    print("  Terminal 2: python run.py --user y")
    print("---------------------------------------------")
    print(f"Note: Use '{DEFAULT_PIN}' on the PIN entry screen.")

if __name__ == "__main__":
    main()
