"""
Paracci hybrid KEM handshake helpers.

This module coordinates ML-KEM operations for the future hybrid handshake while
keeping liboqs access behind quantum_kem.py.
"""

from . import constants
from .crypto import wipe
from .quantum_kem import (
    QuantumKEMError,
    kem_decapsulate,
    kem_encapsulate,
    kem_generate_keypair,
)

HYBRID_HANDSHAKE_VERSION = 3
SIGNED_X25519_HANDSHAKE_VERSION = 2
LEGACY_HANDSHAKE_VERSION = 1

OLDER_VERSION_ERROR = (
    "This session was created with an older version of Paracci and does not "
    "have post-quantum protection. Please ask your contact to start a new "
    "session."
)
NO_POST_QUANTUM_ERROR = (
    "This session was created without post-quantum protection. Please start a "
    "new session."
)


class HybridKEMError(Exception):
    """Raised on hybrid KEM setup, response, completion, or validation failure."""

    def __init__(self, message: str, i18n_key: str = "hybrid_kem_respond_failed"):
        super().__init__(message)
        self.i18n_key = i18n_key


def _raise_hybrid_error(message: str, exc: Exception, i18n_key: str) -> None:
    raise HybridKEMError(message, i18n_key) from exc


def initiator_kem_setup() -> dict:
    """
    Generate the initiator's ML-KEM keypair.

    The secret key is returned to the caller for temporary in-memory use in
    Phase 4B. Phase 4C must persist it only in encrypted local session metadata.
    """
    try:
        public_key, secret_key = kem_generate_keypair()
    except QuantumKEMError as exc:
        _raise_hybrid_error(
            f"{constants.KEM_ALGORITHM} keypair generation failed.",
            exc,
            "hybrid_kem_init_failed",
        )
    except Exception as exc:
        _raise_hybrid_error("Hybrid KEM setup failed.", exc, "hybrid_kem_init_failed")
    return {
        "ml_kem_public_key": public_key,
        "ml_kem_secret_key": secret_key,
    }


def responder_kem_respond(ml_kem_public_key: bytes) -> dict:
    """
    Encapsulate to the initiator's ML-KEM public key.

    The ciphertext is public handshake metadata. The shared secret feeds the
    hybrid X25519 + ML-KEM combiner.
    """
    try:
        ciphertext, shared_secret = kem_encapsulate(ml_kem_public_key)
    except QuantumKEMError as exc:
        _raise_hybrid_error(
            f"{constants.KEM_ALGORITHM} encapsulation failed.",
            exc,
            "hybrid_kem_respond_failed",
        )
    except Exception as exc:
        _raise_hybrid_error("Hybrid KEM response failed.", exc, "hybrid_kem_respond_failed")
    return {
        "ml_kem_ciphertext": ciphertext,
        "ml_kem_shared_secret": shared_secret,
    }


def initiator_kem_complete(
    ml_kem_secret_key: bytes,
    ml_kem_ciphertext: bytes,
) -> bytes:
    """
    Decapsulate the responder ciphertext using the initiator's ML-KEM secret key.

    Python cannot guarantee zeroization of immutable bytes already held by the
    caller or runtime, so cleanup is best-effort for a mutable local copy.
    """
    secret_key_copy = None
    try:
        secret_key_copy = bytearray(ml_kem_secret_key)
        return kem_decapsulate(bytes(secret_key_copy), ml_kem_ciphertext)
    except QuantumKEMError as exc:
        _raise_hybrid_error(
            f"{constants.KEM_ALGORITHM} decapsulation failed.",
            exc,
            "hybrid_kem_complete_failed",
        )
    except Exception as exc:
        _raise_hybrid_error("Hybrid KEM completion failed.", exc, "hybrid_kem_complete_failed")
    finally:
        if secret_key_copy is not None:
            wipe(secret_key_copy)
        del ml_kem_secret_key


def validate_hybrid_handshake_payload(payload: dict, *, expected_kind: str) -> None:
    """
    Validate future v3 hybrid handshake metadata and reject legacy setup files.

    expected_kind must be "initiator" or "responder"; the helper stays isolated
    in Phase 4B and is intended to be called from session.py in Phase 4C.
    """
    if expected_kind not in {"initiator", "responder"}:
        raise ValueError("expected_kind must be 'initiator' or 'responder'.")
    if not isinstance(payload, dict):
        raise HybridKEMError("Invalid handshake payload.", "hybrid_kem_respond_failed")

    version = payload.get("handshake_version")
    if version is None or version in {LEGACY_HANDSHAKE_VERSION, SIGNED_X25519_HANDSHAKE_VERSION}:
        raise HybridKEMError(OLDER_VERSION_ERROR, "hybrid_kem_legacy_session")
    if version != HYBRID_HANDSHAKE_VERSION:
        raise HybridKEMError("Unsupported hybrid handshake version.", "hybrid_kem_legacy_session")

    failure_key = "hybrid_kem_respond_failed" if expected_kind == "initiator" else "hybrid_kem_complete_failed"
    if payload.get("ml_kem_algorithm") != constants.KEM_ALGORITHM:
        raise HybridKEMError("Unsupported hybrid KEM algorithm.", failure_key)

    field = "ml_kem_public_key" if expected_kind == "initiator" else "ml_kem_ciphertext"
    if not isinstance(payload.get(field), str) or not payload[field]:
        raise HybridKEMError(NO_POST_QUANTUM_ERROR, failure_key)
