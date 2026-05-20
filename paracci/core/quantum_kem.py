"""
Paracci post-quantum KEM wrapper.

This module is the only core boundary that imports liboqs-python. Keep imports
lazy so the rest of Paracci remains importable before native liboqs is present.
"""

from . import constants as _constants

__all__ = [
    "QuantumKEMError",
    "kem_generate_keypair",
    "kem_encapsulate",
    "kem_decapsulate",
]

_KEM_PUBLIC_KEY_BYTES = 1184
_KEM_SECRET_KEY_BYTES = 2400
_KEM_CIPHERTEXT_BYTES = 1088
_KEM_SHARED_SECRET_BYTES = 32


class QuantumKEMError(Exception):
    """Raised on any KEM operation failure."""


def _load_oqs():
    try:
        import oqs
    except ImportError as exc:
        raise QuantumKEMError(
            "liboqs-python is not installed or could not be imported. "
            "Install requirements.lock and ensure native liboqs can be loaded."
        ) from exc
    except SystemExit as exc:
        raise QuantumKEMError(
            "liboqs could not initialize. Ensure CMake, a C compiler, and the "
            "liboqs shared library are available."
        ) from exc
    except (OSError, RuntimeError) as exc:
        raise QuantumKEMError(
            "liboqs could not be loaded. Ensure native liboqs is installed or "
            "allow liboqs-python to build it."
        ) from exc
    return oqs


def _require_bytes(name: str, value: bytes, expected_length: int) -> None:
    if not isinstance(value, bytes):
        raise QuantumKEMError(f"{name} must be bytes.")
    if len(value) != expected_length:
        raise QuantumKEMError(
            f"{name} must be {expected_length} bytes for "
            f"{_constants.KEM_ALGORITHM}; received {len(value)} bytes."
        )


def _require_output_bytes(name: str, value: bytes, expected_length: int) -> None:
    if not isinstance(value, bytes):
        raise QuantumKEMError(f"liboqs returned non-bytes {name}.")
    if len(value) != expected_length:
        raise QuantumKEMError(
            f"liboqs returned invalid {name} length for "
            f"{_constants.KEM_ALGORITHM}: expected {expected_length} bytes, "
            f"received {len(value)} bytes."
        )


def kem_generate_keypair() -> tuple[bytes, bytes]:
    """
    Generate a ML-KEM-768 keypair.
    Returns (public_key, secret_key).
    Raises QuantumKEMError on failure.
    """
    try:
        oqs = _load_oqs()
        with oqs.KeyEncapsulation(_constants.KEM_ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            secret_key = kem.export_secret_key()
        _require_output_bytes("public key", public_key, _KEM_PUBLIC_KEY_BYTES)
        _require_output_bytes("secret key", secret_key, _KEM_SECRET_KEY_BYTES)
        return public_key, secret_key
    except QuantumKEMError:
        raise
    except SystemExit as exc:
        raise QuantumKEMError(
            f"{_constants.KEM_ALGORITHM} keypair generation failed because "
            "liboqs could not initialize."
        ) from exc
    except Exception as exc:
        raise QuantumKEMError(
            f"{_constants.KEM_ALGORITHM} keypair generation failed."
        ) from exc


def kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulate a shared secret to the given public key.
    Returns (ciphertext, shared_secret).
    Raises QuantumKEMError on failure.
    """
    _require_bytes("public key", public_key, _KEM_PUBLIC_KEY_BYTES)
    try:
        oqs = _load_oqs()
        with oqs.KeyEncapsulation(_constants.KEM_ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        _require_output_bytes("ciphertext", ciphertext, _KEM_CIPHERTEXT_BYTES)
        _require_output_bytes(
            "shared secret",
            shared_secret,
            _KEM_SHARED_SECRET_BYTES,
        )
        return ciphertext, shared_secret
    except QuantumKEMError:
        raise
    except SystemExit as exc:
        raise QuantumKEMError(
            f"{_constants.KEM_ALGORITHM} encapsulation failed because liboqs "
            "could not initialize."
        ) from exc
    except Exception as exc:
        raise QuantumKEMError(
            f"{_constants.KEM_ALGORITHM} encapsulation failed."
        ) from exc


def kem_decapsulate(secret_key: bytes, ciphertext: bytes) -> bytes:
    """
    Decapsulate and recover the shared secret.
    Returns shared_secret.
    Raises QuantumKEMError on failure.
    """
    _require_bytes("secret key", secret_key, _KEM_SECRET_KEY_BYTES)
    _require_bytes("ciphertext", ciphertext, _KEM_CIPHERTEXT_BYTES)
    try:
        oqs = _load_oqs()
        with oqs.KeyEncapsulation(_constants.KEM_ALGORITHM, secret_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        _require_output_bytes(
            "shared secret",
            shared_secret,
            _KEM_SHARED_SECRET_BYTES,
        )
        return shared_secret
    except QuantumKEMError:
        raise
    except SystemExit as exc:
        raise QuantumKEMError(
            f"{_constants.KEM_ALGORITHM} decapsulation failed because liboqs "
            "could not initialize."
        ) from exc
    except Exception as exc:
        raise QuantumKEMError(
            f"{_constants.KEM_ALGORITHM} decapsulation failed."
        ) from exc
