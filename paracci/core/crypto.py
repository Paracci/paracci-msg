"""
Paracci — core/crypto.py
Cryptographic base layer.

Algorithms used:
  - X25519            : ECDH key agreement
  - HKDF-SHA512       : Key derivation
  - ChaCha20-Poly1305 : Authenticated encryption (AEAD)
  - CSPRNG            : Secure random generation (os.urandom)
  - SHA3-256          : General hashing (MSG_ID registration, integrity)
"""

import os
import hashlib
import struct
import time
import gc
from typing import Tuple, NamedTuple

from .logger import get_logger
from argon2 import PasswordHasher, Type as Argon2Type
from argon2.low_level import hash_secret_raw, Type as LowLevelArgon2Type

from .constants import (
    DOMAIN_SESSION_MASTER_V3,
    HYBRID_KEM_DOMAIN,
    LABEL_EVO_SEED_V3,
    LABEL_EVO_STEP_V3,
    LABEL_MSG_XY_V3,
    LABEL_MSG_YX_V3,
    LABEL_NEXT_V3,
    LABEL_SYNC_V3,
    SESSION_MASTER_HKDF_LENGTH_V3,
    TRANSCRIPT_DOMAIN,
)

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.hashes import SHA512
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

HKDF_HASH      = SHA512()          # Use SHA-512 for HKDF (PyCA support)
KEY_LEN        = 32                # ChaCha20 key length (bytes)
NONCE_LEN      = 12                # ChaCha20-Poly1305 nonce length (bytes)
# Argon2id parameters for device passphrase protection only.
# t=2 (iterations), m=65536 (64MB RAM), p=4 (parallelism)
ARGON2_TIME    = 2
ARGON2_MEM     = 65536
ARGON2_PAR     = 4

# ---------------------------------------------------------------------------
# Protocol labels
# ---------------------------------------------------------------------------

LABEL_MSG_XY   = LABEL_MSG_XY_V3
LABEL_MSG_YX   = LABEL_MSG_YX_V3
LABEL_SYNC     = LABEL_SYNC_V3
LABEL_EVO_SEED = LABEL_EVO_SEED_V3
LABEL_EVO_STEP = LABEL_EVO_STEP_V3
LABEL_NEXT     = LABEL_NEXT_V3

_log = get_logger("crypto")


# ---------------------------------------------------------------------------
# Type definitions
# ---------------------------------------------------------------------------

class DerivedKeys(NamedTuple):
    """All session keys derived from ECDH + HKDF result."""
    key_x_to_y:   bytes   # Only Y can open (X→Y messages)
    key_y_to_x:   bytes   # Only X can open (Y→X messages)
    sync_key:     bytes   # Encryption for secret metadata block
    evo_seed:     bytes   # Evolution chain starting seed


class EncryptedBlob(NamedTuple):
    """Encrypted data + nonce pair."""
    nonce:      bytes
    ciphertext: bytes     # Includes Poly1305 MAC (16 byte tag at the end)


# ---------------------------------------------------------------------------
# CSPRNG Helpers
# ---------------------------------------------------------------------------

def random_bytes(n: int) -> bytes:
    """Generates n bytes of cryptographically secure random data."""
    return os.urandom(n)


def new_message_id() -> bytes:
    """Generates a 16-byte UUID-like unique message ID."""
    return random_bytes(16)


def current_timestamp() -> int:
    """Returns the current Unix timestamp as an int."""
    return int(time.time())


# ---------------------------------------------------------------------------
# X25519 Key Pair Operations
# ---------------------------------------------------------------------------

def generate_keypair() -> Tuple[bytes, bytes]:
    """
    Generates a new X25519 key pair.
    Returns: (private_key_bytes, public_key_bytes)

    MEMORY HYGIENE LIMITATION: private_bytes is returned as immutable bytes
    because callers persist it to encrypted storage. Conversion to bytearray
    here would change the public API. The caller is responsible for wiping
    their copy when the key is no longer needed.
    """
    private_key = X25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    # The cryptography library owns the private_key object internally;
    # Python cannot zero the C-level key bytes from here.
    return private_bytes, public_bytes


def generate_identity_keypair() -> Tuple[bytes, bytes]:
    """
    Generates a long-term Ed25519 identity key pair.
    Returns: (private_key_bytes, public_key_bytes)

    MEMORY HYGIENE LIMITATION: private_bytes is returned as immutable bytes
    because callers persist it to encrypted storage. The caller is responsible
    for wiping their copy when the key is no longer needed.
    """
    private_key = Ed25519PrivateKey.generate()
    private_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    public_bytes = private_key.public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw
    )
    return private_bytes, public_bytes


def sign_identity(private_key_bytes: bytes, message: bytes) -> bytes:
    """Signs a protocol message with a raw Ed25519 private key."""
    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    return private_key.sign(message)


def verify_identity_signature(
    public_key_bytes: bytes,
    message: bytes,
    signature: bytes,
) -> bool:
    """Verifies an Ed25519 signature and returns False for malformed inputs."""
    try:
        public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def wipe(data: bytes | bytearray | list) -> None:
    """Best-effort zeroing for mutable sensitive containers owned by Paracci.

    Python and native libraries may retain copies outside this buffer.
    This is a best-effort mitigation — Python's memory model does not guarantee
    that wiping a bytearray zeroes every copy the interpreter may have made
    internally.

    Accepts bytes without raising so call sites that pass immutable bytes (e.g.
    from third-party library return values) do not crash. A debug security event
    is logged to record the gap, allowing the auditor to identify remaining
    call sites that should be refactored to use bytearray.
    """
    if isinstance(data, bytes):
        # LIMITATION: bytes is immutable — in-place zeroization is not possible.
        # Log the gap so auditors can identify call sites that need refactoring.
        _log.security(
            "wipe() called on immutable bytes — in-place zeroization is not "
            "possible. Refactor the call site to use bytearray for short-lived "
            "key material."
        )
        return
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, list):
        for i in range(len(data)):
            data[i] = None
    else:
        raise TypeError("wipe() requires a bytearray, bytes, or list.")
    gc.collect()


def ecdh(private_key_bytes: bytes, peer_public_key_bytes: bytes) -> bytes:
    """
    X25519 ECDH: own private key + peer's public key → shared secret.
    """
    try:
        private_key = X25519PrivateKey.from_private_bytes(private_key_bytes)
        peer_public  = X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = private_key.exchange(peer_public)
        return shared_secret
    finally:
        # LIMITATION: X25519PrivateKey is an opaque C object owned by the
        # cryptography library. Python cannot zero its internal key bytes;
        # del only removes this reference, not the underlying memory.
        if 'private_key' in locals():
            del private_key
        # LIMITATION: shared_secret is immutable bytes returned by exchange().
        # wipe() logs the gap but cannot zero it in place. The return value
        # is needed by the caller so we do not zero it here — we call wipe()
        # only to record the gap in the security log.
        if 'shared_secret' in locals():
            wipe(shared_secret)


# ---------------------------------------------------------------------------
# Passphrase Based Key Derivation (KDF)
# ---------------------------------------------------------------------------

def derive_master_key(passphrase: str, salt: bytes) -> bytearray:
    """
    Derives the device master key from the user passphrase.
    Slows down brute-force attacks against low-entropy device passphrases.
    """
    return bytearray(hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_TIME,
        memory_cost=ARGON2_MEM,
        parallelism=ARGON2_PAR,
        hash_len=32,
        type=LowLevelArgon2Type.ID
    ))


def get_fingerprint(public_key1: bytes, public_key2: bytes) -> str:
    """
    Produces an 8-character security code from the public keys of both parties.
    Alphabet: Certain characters are removed to increase readability.
    """
    # Ordering is important: X->Y and Y->X must yield the same result
    keys = sorted([public_key1, public_key2])
    h = hashlib.sha3_256(b"paracci.fingerprint.v1" + keys[0] + keys[1]).digest()
    
    # Take the 32-bit portion and convert to a readable format
    val = struct.unpack(">I", h[:4])[0]
    return f"{val:08X}"


def get_safety_code(
    x_identity_pub: bytes,
    y_identity_pub: bytes,
    x_session_pub: bytes,
    y_session_pub: bytes,
    session_id: bytes,
) -> str:
    """
    Produces a deterministic 24-hex safety code grouped for human comparison.
    """
    h = hashlib.sha3_256(
        b"paracci.safety.v2"
        + session_id
        + x_identity_pub
        + y_identity_pub
        + x_session_pub
        + y_session_pub
    ).digest()
    raw = h[:12].hex().upper()
    return "-".join(raw[i:i + 4] for i in range(0, len(raw), 4))


def compute_handshake_transcript(
    session_id: bytes,
    initiator_identity_pub: bytes,
    responder_identity_pub: bytes,
    ml_kem_algorithm: str,
    ml_kem_public_key: bytes,
    ml_kem_ciphertext: bytes,
) -> bytes:
    """
    Compute a cryptographic transcript of the handshake.

    Hashes all identity-binding material into a single 32-byte digest using
    SHA3-256. This transcript is fed into the hybrid KEM combiner to bind the
    derived session keys to both parties' identities and the exact KEM material.
    """
    if not isinstance(session_id, bytes):
        raise ValueError("Session ID must be bytes.")
    if len(session_id) != 16:
        raise ValueError("Session ID must be 16 bytes.")
    if not isinstance(initiator_identity_pub, bytes):
        raise ValueError("Initiator identity public key must be bytes.")
    if len(initiator_identity_pub) != 32:
        raise ValueError("Initiator identity public key must be 32 bytes.")
    if not isinstance(responder_identity_pub, bytes):
        raise ValueError("Responder identity public key must be bytes.")
    if len(responder_identity_pub) != 32:
        raise ValueError("Responder identity public key must be 32 bytes.")
    if not isinstance(ml_kem_algorithm, str) or not ml_kem_algorithm:
        raise ValueError("ML-KEM algorithm must be a non-empty string.")
    if not isinstance(ml_kem_public_key, bytes) or not ml_kem_public_key:
        raise ValueError("ML-KEM public key must be non-empty bytes.")
    if not isinstance(ml_kem_ciphertext, bytes) or not ml_kem_ciphertext:
        raise ValueError("ML-KEM ciphertext must be non-empty bytes.")

    h = hashlib.sha3_256()
    h.update(TRANSCRIPT_DOMAIN)
    h.update(session_id)
    h.update(initiator_identity_pub)
    h.update(responder_identity_pub)
    h.update(ml_kem_algorithm.encode())
    h.update(ml_kem_public_key)
    h.update(ml_kem_ciphertext)
    return h.digest()


# ---------------------------------------------------------------------------
# HKDF Derivation
# ---------------------------------------------------------------------------

def hkdf_derive(
    input_key_material: bytes,
    length: int,
    info: bytes,
    salt: bytes = b"",
) -> bytes:
    """
    Derives a key of a specified length and label using HKDF-SHA512.
    If salt is left empty, the standard HKDF behavior (zero-filled salt) is applied.
    """
    hkdf = HKDF(
        algorithm=HKDF_HASH,
        length=length,
        salt=salt if salt else None,
        info=info,
    )
    return hkdf.derive(input_key_material)


def derive_hybrid_shared_secret(
    x25519_shared: bytes,
    ml_kem_shared: bytes,
    session_id: bytes,
    transcript: bytes | None = None,
) -> bytes:
    """
    Combines X25519 and ML-KEM shared secrets into one 64-byte hybrid secret.

    When transcript is provided, HKDF-SHA512 binds the result to the signed
    handshake identities and KEM transcript. A missing transcript is retained
    only as the M-1A compatibility path until session.py is integrated in M-1B.
    """
    if not isinstance(x25519_shared, bytes):
        raise ValueError("X25519 shared secret must be bytes.")
    if len(x25519_shared) != 32:
        raise ValueError("X25519 shared secret must be 32 bytes.")
    if not isinstance(ml_kem_shared, bytes):
        raise ValueError("ML-KEM shared secret must be bytes.")
    if len(ml_kem_shared) != 32:
        raise ValueError("ML-KEM shared secret must be 32 bytes.")
    if not isinstance(session_id, bytes):
        raise ValueError("Session ID must be bytes.")
    if len(session_id) != 16:
        raise ValueError("Session ID must be 16 bytes.")
    if transcript is not None:
        if not isinstance(transcript, bytes):
            raise ValueError("Handshake transcript must be bytes.")
        if len(transcript) != 32:
            raise ValueError("Handshake transcript must be 32 bytes.")

    info = HYBRID_KEM_DOMAIN if transcript is None else HYBRID_KEM_DOMAIN + transcript
    # Use bytearray for the concatenated IKM so it can be explicitly zeroed
    # before being dereferenced. hkdf_derive() accepts bytes-like objects.
    ikm = bytearray(x25519_shared) + bytearray(ml_kem_shared)
    try:
        return hkdf_derive(bytes(ikm), length=64, info=info, salt=session_id)
    finally:
        wipe(ikm)


def derive_session_keys(
    shared_secret: bytes,
    x_public: bytes,
    y_public: bytes,
    extra_salt: bytes = b"",
) -> DerivedKeys:
    """
    Derives session keys from the high-entropy hybrid shared secret using HKDF.

    MEMORY HYGIENE: The intermediate `master` key material is held in a
    bytearray and zeroed in a finally block. The four returned sub-keys in
    DerivedKeys remain as immutable bytes because changing their type would
    break the public API and all callers.
    """
    # Deterministic salt: binds the identity of the parties
    salt = hashlib.sha3_256(x_public + y_public + extra_salt).digest()

    # Frozen compatibility length from the original v3 derivation.
    length = SESSION_MASTER_HKDF_LENGTH_V3

    # Hold master in a bytearray so it can be explicitly zeroed after use.
    # hkdf_derive() returns bytes; wrap immediately to minimise the window
    # in which the immutable bytes object coexists with the bytearray.
    master = bytearray(hkdf_derive(
        shared_secret,
        length=length,
        info=DOMAIN_SESSION_MASTER_V3,
        salt=salt,
    ))
    # Shrink the master key back to original length (still a bytearray).
    master = master[:KEY_LEN * 4]

    def _sub(label: bytes) -> bytes:
        """Derives a sub-key via HKDF for a specific label (purpose)."""
        return hkdf_derive(bytes(master), KEY_LEN, info=label)

    try:
        return DerivedKeys(
            key_x_to_y=_sub(LABEL_MSG_XY),
            key_y_to_x=_sub(LABEL_MSG_YX),
            sync_key=_sub(LABEL_SYNC),
            evo_seed=_sub(LABEL_EVO_SEED),
        )
    finally:
        wipe(master)


# ---------------------------------------------------------------------------
# ChaCha20-Poly1305 Encryption / Decryption
# ---------------------------------------------------------------------------

def encrypt(key: bytes | bytearray, plaintext: bytes, aad: bytes = b"") -> EncryptedBlob:
    """
    Authenticated encryption with ChaCha20-Poly1305.

    aad (Additional Authenticated Data): not encrypted but included in integrity
    protection (e.g., file header).

    Returns: EncryptedBlob(nonce, ciphertext_with_tag)
    """
    if len(key) != KEY_LEN:
        raise ValueError(f"Key must be {KEY_LEN} bytes, received: {len(key)}")

    nonce = random_bytes(NONCE_LEN)
    chacha = ChaCha20Poly1305(key)
    ciphertext = chacha.encrypt(nonce, plaintext, aad if aad else None)
    return EncryptedBlob(nonce=nonce, ciphertext=ciphertext)


def decrypt(
    key: bytes | bytearray,
    blob: EncryptedBlob,
    aad: bytes = b"",
) -> bytes:
    """
    Decryption with ChaCha20-Poly1305 + Poly1305 verification.

    If MAC verification fails, raises cryptography.exceptions.InvalidTag.
    This means: file modified, key incorrect, or AAD inconsistent.
    """
    if len(key) != KEY_LEN:
        raise ValueError(f"Key must be {KEY_LEN} bytes, received: {len(key)}")

    chacha = ChaCha20Poly1305(key)
    return chacha.decrypt(blob.nonce, blob.ciphertext, aad if aad else None)


# ---------------------------------------------------------------------------
# Integrity Helpers
# ---------------------------------------------------------------------------

def message_id_fingerprint(msg_id: bytes) -> bytes:
    """
    Generates the fingerprint of MSG_ID to be saved in the DB.
    The hash is stored instead of the raw ID — original ID remains unknown even if DB is compromised.
    """
    return hashlib.sha3_256(b"paracci.msgid." + msg_id).digest()


def secure_hash(data: bytes, label: bytes = b"") -> bytes:
    """General purpose SHA3-256 hashing."""
    return hashlib.sha3_256(label + data).digest()


# ---------------------------------------------------------------------------
# Packing Helpers (struct)
# ---------------------------------------------------------------------------

def pack_uint64(value: int) -> bytes:
    """64-bit unsigned int → 8 byte big-endian."""
    return struct.pack(">Q", value)


def unpack_uint64(data: bytes) -> int:
    """8 byte big-endian → 64-bit unsigned int."""
    return struct.unpack(">Q", data)[0]


def pack_uint32(value: int) -> bytes:
    """32-bit unsigned int → 4 byte big-endian."""
    return struct.pack(">I", value)


def unpack_uint32(data: bytes) -> int:
    """4 byte big-endian → 32-bit unsigned int."""
    return struct.unpack(">I", data)[0]


# ---------------------------------------------------------------------------
# Key Serialization (for session files)
# ---------------------------------------------------------------------------

def encode_public_key(public_key_bytes: bytes) -> bytes:
    """Brings public key into a format writable to a file (raw bytes for now)."""
    if len(public_key_bytes) != 32:
        raise ValueError("X25519 public key must be 32 bytes.")
    return public_key_bytes


def decode_public_key(data: bytes) -> bytes:
    """Verifies and returns the public key read from the file."""
    if len(data) != 32:
        raise ValueError("Invalid public key length.")
    return data
