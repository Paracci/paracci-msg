"""
Paracci — tools/dev_setup.py
Script that automatically connects users X and Y (handshake) 
to speed up development and testing processes.

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

DEFAULT_PIN = "95175328"

def setup_user(user_name: str):
    data_dir = ROOT_DIR / f"data_{user_name}"
    if data_dir.exists():
        print(f"  [!] {data_dir} already exists, cleaning up...")
        shutil.rmtree(data_dir)
    data_dir.mkdir(parents=True)
    
    db = BurnDB(data_dir / "sessions.db")
    device_key = init_device(db, DEFAULT_PIN)
    
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

    # 2. Profile Selection
    print("\n[?] Select Security Profile:")
    print("  1) Standard (Fast)")
    print("  2) Paranoid (Balanced)")
    print("  3) Quantum-Armor (Maximum Armor)")
    print("  4) Custom (Custom Settings)")
    
    if sys.stdin.isatty():
        choice = input("\nSelection (1-4) [Default: 2]: ").strip()
    else:
        choice = "2"
        print("\n[*] Non-interactive mode detected, using default: 2 (Paranoid)")
    profile_map = {"1": "standard", "2": "paranoid", "3": "quantum", "4": "custom"}
    TEST_PROFILE = profile_map.get(choice, "paranoid")
    
    CUSTOM_PARAMS = None
    if TEST_PROFILE == "custom":
        print("\n--- Custom Security Parameters ---")
        try:
            t = int(input("  Time Cost (t) [Default: 32]: ") or "32")
            m = int(input("  Memory Cost (m - KB) [Default: 1048576 (1GB)]: ") or "1048576")
            p = int(input("  Parallelism (p) [Default: 2]: ") or "2")
            CUSTOM_PARAMS = {"t": t, "m": m, "p": p}
        except ValueError:
            print("[!] Invalid input, reverting to Paranoid settings.")
            TEST_PROFILE = "paranoid"

    print(f"\n[*] Setup Starting: {TEST_PROFILE.upper()} profile active.")
    
    # 3. Handshake Simulation
    # Load device identities
    identity_x = get_or_create_device_identity(db_x, key_x)
    identity_y = get_or_create_device_identity(db_y, key_y)

    # X: Create session
    meta_x_init, init_file = create_initiator_session(
        "Automated Test Channel", 
        profile=TEST_PROFILE,
        custom_params=CUSTOM_PARAMS,
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

    # 4. Save to Database
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
