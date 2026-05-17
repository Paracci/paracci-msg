import sys
import os

# Add project root to path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from core.session import create_initiator_session, accept_initiator_and_create_responder, finalize_initiator_session
from core.envelope import seal_envelope, open_envelope

def quick_test():
    try:
        print("Starting Quick Integration Test (Standard Profile)...")
        # Step 1: X Init
        meta_x_init, init_file = create_initiator_session("Quick Test", profile="standard")
        print("User X initialized.")
        
        # Step 2: Y Accept
        meta_y, resp_file = accept_initiator_and_create_responder(init_file, "Y Label")
        print("User Y accepted.")
        
        # Step 3: X Finalize
        meta_x = finalize_initiator_session(meta_x_init, resp_file)
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
