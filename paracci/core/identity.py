"""
Persistent device identity key management.

The identity key signs session handshake files. It is stored alongside other
device metadata, encrypted with the already-unlocked device key.
"""

import json
import time
from typing import NamedTuple

from .crypto import (
    EncryptedBlob,
    NONCE_LEN,
    decrypt,
    encrypt,
    generate_identity_keypair,
)

IDENTITY_META_KEY = "identity_ed25519_v1"
IDENTITY_AAD = b"paracci.device.identity.v1"
IDENTITY_VERSION = 1
ED25519_PRIVATE_LEN = 32
ED25519_PUBLIC_LEN = 32


class IdentityKeypair(NamedTuple):
    private_key: bytes
    public_key: bytes


def get_or_create_device_identity(db, device_key: bytes) -> IdentityKeypair:
    """Loads the encrypted Ed25519 identity keypair or creates it once."""
    encrypted = db.get_device_meta(IDENTITY_META_KEY)
    if encrypted:
        try:
            blob = EncryptedBlob(
                nonce=encrypted[:NONCE_LEN],
                ciphertext=encrypted[NONCE_LEN:],
            )
            raw = decrypt(device_key, blob, aad=IDENTITY_AAD)
            data = json.loads(raw.decode("utf-8"))
            if data.get("version") != IDENTITY_VERSION:
                raise IdentityError("Unsupported identity metadata version.")
            private_key = bytes.fromhex(data["private_key"])
            public_key = bytes.fromhex(data["public_key"])
            _validate_identity_keypair(private_key, public_key)
            return IdentityKeypair(private_key=private_key, public_key=public_key)
        except IdentityError:
            raise
        except Exception as exc:
            raise IdentityError("Device identity metadata is corrupt.") from exc

    private_key, public_key = generate_identity_keypair()
    _validate_identity_keypair(private_key, public_key)
    data = {
        "version": IDENTITY_VERSION,
        "private_key": private_key.hex(),
        "public_key": public_key.hex(),
        "created_at": int(time.time()),
    }
    raw = json.dumps(data, separators=(",", ":"), sort_keys=True).encode("utf-8")
    blob = encrypt(device_key, raw, aad=IDENTITY_AAD)
    db.set_device_meta(IDENTITY_META_KEY, blob.nonce + blob.ciphertext)
    return IdentityKeypair(private_key=private_key, public_key=public_key)


def _validate_identity_keypair(private_key: bytes, public_key: bytes) -> None:
    if len(private_key) != ED25519_PRIVATE_LEN:
        raise IdentityError("Invalid Ed25519 private key length.")
    if len(public_key) != ED25519_PUBLIC_LEN:
        raise IdentityError("Invalid Ed25519 public key length.")


class IdentityError(Exception):
    pass
