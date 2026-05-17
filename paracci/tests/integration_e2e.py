"""
Paracci — tests/integration_e2e.py
Full End-to-End Handshake and Messaging Flow Validation.

This script simulates User X and User Y interacting to ensure:
1. Handshake consistency (Quantum Seeds exchange)
2. Correct key derivation on both sides
3. Successful message sealing and opening
4. Argon2id (Quantum Shield) integrity
"""

import sys
import os
import time
import traceback

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.session import (
    create_initiator_session,
    accept_initiator_and_create_responder,
    finalize_initiator_session
)
from core.envelope import seal_envelope, open_envelope
from core.package import create_package, extract_package

def run_e2e_test(profile="quantum"):
    print(f"\n[>] Starting E2E Integration Test (Profile: {profile})")
    print("-" * 50)
    
    try:
        # 1. User X: Create Session
        print(f"[X] Step 1: User X creating session...")
        meta_x_init, init_file = create_initiator_session(
            label="Test Session",
            profile=profile
        )
        print(f"[+] User X session created. (ID: {meta_x_init.session_id.hex()[:8]})")

        # 2. User Y: Accept Init & Create Resp
        print(f"[Y] Step 2: User Y accepting initiator file...")
        meta_y, resp_file = accept_initiator_and_create_responder(
            initiator_file_bytes=init_file,
            local_label="X's Session"
        )
        print(f"[+] User Y session active. (Role: {meta_y.role})")
        print(f"[i] User Y sync_key: {meta_y.keys.sync_key.hex()[:16]}...")

        # 3. User X: Finalize with Resp
        print(f"[X] Step 3: User X finalizing with responder file...")
        meta_x = finalize_initiator_session(
            meta=meta_x_init,
            responder_file_bytes=resp_file
        )
        print(f"[+] User X session finalized. (Role: {meta_x.role})")
        print(f"[i] User X sync_key: {meta_x.keys.sync_key.hex()[:16]}...")

        # --- VALIDATION: Sync Keys must match ---
        if meta_x.keys.sync_key != meta_y.keys.sync_key:
            print("[!] ERROR: Sync Keys do not match! Handshake failed.")
            return False
        print("[*] SUCCESS: Handshake completed. Keys are synchronized.")

        # 4. User X: Send First Message (Bond Ceremony)
        print(f"[X] Step 4: User X sealing first message...")
        test_payload = b"Hello User Y! This is a secure quantum message."
        sealed = seal_envelope(
            payload_bytes=test_payload,
            session=meta_x,
            single_use=True
        )
        print(f"[+] Message sealed. (ID: {sealed.msg_id.hex()[:8]})")

        # 5. User Y: Open Message
        print(f"[Y] Step 5: User Y opening message...")
        opened = open_envelope(
            file_bytes=sealed.file_bytes,
            session=meta_y
        )
        
        if opened.payload == test_payload:
            print(f"[*] SUCCESS: Message decrypted correctly!")
            print(f"[i] Content: {opened.payload.decode()}")
        else:
            print(f"[!] ERROR: Payload mismatch!")
            print(f"    Expected: {test_payload}")
            print(f"    Got: {opened.payload}")
            return False

        # 6. Verify Bond Nonce (Ceremony Check)
        if opened.bond_nonce is not None:
            print(f"[+] Bond Nonce received by Y: {opened.bond_nonce.hex()[:16]}...")
        else:
            print(f"[!] ERROR: Bond Nonce missing in first message!")
            return False

        print("-" * 50)
        print("[#] E2E TEST PASSED SUCCESSFULLY!")
        return True

    except Exception as e:
        print(f"\n[!] FATAL ERROR DURING TEST:")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    # Test multiple profiles
    results = []
    for p in ["standard", "paranoid", "quantum"]:
        start = time.time()
        success = run_e2e_test(p)
        elapsed = time.time() - start
        results.append((p, success, elapsed))
        
    print("\n" + "="*50)
    print("FINAL TEST SUMMARY")
    print("="*50)
    for p, s, t in results:
        status = "PASSED" if s else "FAILED"
        print(f"Profile: {p:<10} | Status: {status:<8} | Time: {t:.2f}s")
    print("="*50)
    
    if all(r[1] for r in results):
        sys.exit(0)
    else:
        sys.exit(1)
