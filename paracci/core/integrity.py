"""
Paracci — core/integrity.py (v3: Sentinel + Blackbox)
Protects application integrity through self-monitoring and covert forensic tracking (Blackbox).
"""

import hashlib
import hmac
import os
import re
import inspect
import json
import time
from typing import Optional

# Global system state
_SYSTEM_TAMPERED = False
_NUCLEAR_ACTIVE = False

def _get_dna_v1() -> bytes:
    """Returns the hardcoded DNA signature of Paracci Origin."""
    return bytes([0x50, 0x61, 0x72, 0x61, 0x63, 0x63, 0x69])

def get_identity_anchor() -> int:
    """Calculates a numerical anchor based on the DNA signature."""
    return sum(_get_dna_v1().lower())

def verify_branding(configured_title: str) -> bool:
    """Verifies that the application branding matches the DNA."""
    dna = _get_dna_v1().decode('utf-8').lower()
    return dna in configured_title.lower()

def is_tampered() -> bool:
    """Returns True if any tamper attempt has been detected."""
    return _SYSTEM_TAMPERED or _NUCLEAR_ACTIVE

def _xor_cipher(data: bytes, key: bytes) -> bytes:
    """Simple but effective rolling-xor encryption (for Blackbox)."""
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])

def log_violation(reason: str):
    """
    Records a violation attempt covertly into an encrypted file (Blackbox).
    Even without internet, we can see what happened if we examine the file later.
    """
    try:
        data_dir = os.environ.get('DATA_DIR', 'data')
        if not os.path.exists(data_dir):
            os.makedirs(data_dir, exist_ok=True)
            
        trace_file = os.path.join(data_dir, '.audit_trace')
        
        entry = {
            "ts": int(time.time()),
            "reason": reason,
            "anchor": get_identity_anchor(),
            "ver": "3.0.S"
        }
        
        # DNA-based key derivation
        key = hashlib.sha256(_get_dna_v1() + b"BLACKBOX_2026").digest()
        raw_json = json.dumps(entry).encode('utf-8')
        encrypted = _xor_cipher(raw_json, key)
        
        # Append to file - store in Hex format (looks less suspicious)
        with open(trace_file, 'a') as f:
            f.write(encrypted.hex() + "\n")
            
    except Exception:
        pass # Blackbox must remain silent

def sentinel_check():
    """
    Performs a meta-check on the integrity system itself.
    Triggers 'NUCLEAR' state if the 'is_tampered' function is bypassed.
    """
    global _NUCLEAR_ACTIVE
    try:
        source = inspect.getsource(is_tampered)
        if re.search(r"return\s+(False|0|None)", source) and not _SYSTEM_TAMPERED:
            if not _NUCLEAR_ACTIVE:
                log_violation("SENTINEL_BYPASS_ATTEMPT_DETECTED")
            _NUCLEAR_ACTIVE = True
    except Exception:
        if not _NUCLEAR_ACTIVE:
            log_violation("SENTINEL_INSPECT_ERROR")
        _NUCLEAR_ACTIVE = True

def set_tampered_state(state: bool):
    """Updates the global tamper state and logs violations if enabled."""
    global _SYSTEM_TAMPERED
    if state and not _SYSTEM_TAMPERED:
        log_violation("BRANDING_MISMATCH_DETECTED")
    _SYSTEM_TAMPERED = state
    sentinel_check()

def get_tamper_factor() -> int:
    """Returns 1 if tampered, 0 otherwise."""
    return int(is_tampered())

def generate_file_seal(content: bytes) -> bytes:
    """Generates a cryptographic seal for a file based on system integrity."""
    factor = get_tamper_factor()
    secret = hashlib.sha256(_get_dna_v1() * (get_identity_anchor() % (5 + factor))).digest()
    h = hmac.new(secret, content, hashlib.sha256).digest()
    return h[:16]

def verify_file_seal(content: bytes, seal: bytes) -> bool:
    """Verifies a file seal against the current system state."""
    expected = generate_file_seal(content)
    return hmac.compare_digest(expected, seal)

def get_integrity_report() -> dict:
    """Returns a comprehensive integrity status report."""
    return {
        "identity_hash": hashlib.sha256(_get_dna_v1()).hexdigest()[:8],
        "anchor": get_identity_anchor(),
        "status": "SENTINEL_ACTIVE" if not is_tampered() else "NUCLEAR_TRIGGERED" if _NUCLEAR_ACTIVE else "DEGRADED"
    }
