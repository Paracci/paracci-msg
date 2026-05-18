import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.crypto import generate_identity_keypair
from core.session import (
    create_initiator_session,
    accept_initiator_and_create_responder,
    finalize_initiator_session,
    confirm_safety_code,
    get_session_safety_code,
)
from core.envelope import seal_envelope, open_envelope

def quick_test():
    try:
        print("Starting Quick Integration Test (Standard Profile)...")
        x_identity_priv, x_identity_pub = generate_identity_keypair()
        y_identity_priv, y_identity_pub = generate_identity_keypair()
        # Step 1: X Init
        meta_x_init, init_file = create_initiator_session(
            "Quick Test",
            profile="standard",
            identity_pub=x_identity_pub,
            identity_priv=x_identity_priv,
        )
        print("User X initialized.")
        
        # Step 2: Y Accept
        meta_y, resp_file = accept_initiator_and_create_responder(
            init_file,
            "Y Label",
            identity_pub=y_identity_pub,
            identity_priv=y_identity_priv,
        )
        print("User Y accepted.")
        
        # Step 3: X Finalize
        meta_x = finalize_initiator_session(meta_x_init, resp_file)
        safety_code = get_session_safety_code(meta_x)
        meta_x = confirm_safety_code(meta_x, safety_code)
        meta_y = confirm_safety_code(meta_y, safety_code)
        print("User X finalized.")
        
        # Step 4: X -> Y Message
        payload = b"Quick test message"
        sealed = seal_envelope(payload, meta_x, single_use=True)
        print("Message sealed by X.")
        
        # Step 5: Y Open
        opened = open_envelope(sealed.file_bytes, meta_y)
        print("Message opened by Y.")
        
        if opened.payload == payload:
            print("SUCCESS: Message matches!")
            return True
        else:
            print("FAIL: Payload mismatch.")
            return False
    except Exception as e:
        print(f"ERROR: {e}")
        import traceback
        traceback.print_exc()
        return False

if __name__ == "__main__":
    if quick_test():
        sys.exit(0)
    else:
        sys.exit(1)
