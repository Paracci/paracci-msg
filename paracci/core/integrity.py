"""
Paracci - core/integrity.py
Diagnostic integrity helpers and legacy envelope seal compatibility.

This module must not influence key derivation, AEAD additional data, nonces, or
protocol labels. The file seal key is frozen in core.constants for compatibility.
"""

import hashlib
import hmac
import logging

from .constants import ENVELOPE_FILE_SEAL_HMAC_KEY_V1


logger = logging.getLogger(__name__)

BRAND_IDENTITY = "paracci"
BRAND_IDENTITY_BYTES = BRAND_IDENTITY.encode("utf-8")

_SYSTEM_TAMPERED = False


def get_identity_anchor() -> int:
    """Return a display-only diagnostic value for the configured brand."""
    return sum(BRAND_IDENTITY_BYTES)


def verify_branding(configured_title: str) -> bool:
    """Verify application branding for UI diagnostics only."""
    return BRAND_IDENTITY in str(configured_title or "").lower()


def is_tampered() -> bool:
    """Return the diagnostic branding-tamper state."""
    return _SYSTEM_TAMPERED


def log_violation(reason: str):
    """Log a diagnostic integrity event without covert files or crypto effects."""
    logger.warning("Integrity diagnostic event: %s", reason)


def set_tampered_state(state: bool):
    """Update diagnostic tamper state; this has no cryptographic side effects."""
    global _SYSTEM_TAMPERED
    state = bool(state)
    if state and not _SYSTEM_TAMPERED:
        log_violation("BRANDING_MISMATCH_DETECTED")
    _SYSTEM_TAMPERED = state


def get_tamper_factor() -> int:
    """Return 1 if diagnostics detected tampering, 0 otherwise."""
    return int(is_tampered())


def generate_file_seal(content: bytes) -> bytes:
    """Generate the legacy envelope file seal with a frozen compatibility key."""
    h = hmac.new(ENVELOPE_FILE_SEAL_HMAC_KEY_V1, content, hashlib.sha256).digest()
    return h[:16]


def verify_file_seal(content: bytes, seal: bytes) -> bool:
    """Verify the legacy envelope file seal."""
    expected = generate_file_seal(content)
    return hmac.compare_digest(expected, seal)


def get_integrity_report() -> dict:
    """Return display-only diagnostic status."""
    identity_hash = hashlib.sha256(BRAND_IDENTITY_BYTES).hexdigest()[:8]
    return {
        "identity_hash": identity_hash,
        "anchor": get_identity_anchor(),
        "status": "DIAGNOSTIC_DEGRADED" if is_tampered() else "DIAGNOSTIC_OK",
        "version_signature": "diagnostic-only",
        "dna_status": "not-cryptographic",
    }
