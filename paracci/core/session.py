"""
Paracci — core/session.py  (v2)
Session setup flow and key management.

CHANGES v1→v2:
  - bond_nonce, bond_seed, tx_count added to SessionMeta.
  - create_initiator_session: evo_duration_sec parameter removed.
  - finalize_initiator_session: generates bond_nonce, computes bond_seed.
  - After bonding: X's bond_seed is ready, Y's bond_seed is set
    when the first message is received.

Bond nonce flow:
  1. X finalize → generates bond_nonce → bond_seed = HKDF(base_evo_seed, bond_nonce)
  2. X first message → sync block (with persistent sync_key) → contains bond_nonce
  3. Y opens first message → receives bond_nonce → computes bond_seed
  4. Now both have bond_seed, all messages are encrypted with it

Init/resp invalidation:
  - Init/resp → only base_evo_seed can be derived (with ECDH private key).
  - bond_seed = HKDF(base_evo_seed, bond_nonce) → impossible without bond_nonce.
  - bond_nonce is only carried in the encrypted sync block → init/resp does not benefit a malicious actor.
"""

import os
import json
import struct
import time
from typing import NamedTuple, Optional

from .crypto import (
    generate_keypair, ecdh, derive_session_keys,
    encrypt, decrypt, EncryptedBlob, DerivedKeys,
    random_bytes, new_message_id, KEY_LEN, NONCE_LEN,
    hkdf_derive
)
from .evolution import (
    EvoConfig, make_evo_config, serialize_evo_config,
    deserialize_evo_config, compute_bond_seed, EVO_UNLIMITED,
)

MAGIC_BYTES     = b"PARC"
FILE_VERSION    = 0x01
TYPE_INITIATOR  = 0x10
TYPE_RESPONDER  = 0x11
TYPE_MESSAGE    = 0x20

SESSION_STATE_PENDING = "pending"
SESSION_STATE_ACTIVE  = "active"
SESSION_STATE_EXPIRED = "expired"

APP_DOMAIN = b"paracci.app.session.file.v1"

# Security Profiles: Argon2id workload settings (Time-Lock)
# t: time_cost (iterations), m: memory_cost (KB), p: parallelism
SECURITY_PROFILES = {
    "standard": {"t": 2,   "m": 65536,   "p": 2},  # 64MB
    "paranoid": {"t": 8,   "m": 262144,  "p": 4},  # 256MB
    "quantum":  {"t": 256, "m": 2097152, "p": 2},  # 2GB (Golden Ratio - Quantum Armor)
}
SESSION_COLORS = [
    "#0a84ff", # Blue
    "#30d158", # Green
    "#ff453a", # Red
    "#ff9f0a", # Orange
    "#bf5af2", # Purple
    "#ff375f", # Pink
    "#64d2ff", # Light Blue
    "#ffd60a", # Yellow
]

import random


# ---------------------------------------------------------------------------
# SessionMeta (v2)
# ---------------------------------------------------------------------------

class SessionMeta(NamedTuple):
    session_id:   bytes
    role:         str            # "X" or "Y"
    my_priv:      bytes
    my_pub:       bytes
    peer_pub:     Optional[bytes]
    keys:         Optional[DerivedKeys]   # Derived from ECDH; sync_key is persistent
    bond_seed:    Optional[bytes]         # Backup (Optional)
    send_seed:    Optional[bytes]         # Ratchet for sent messages
    recv_seed:    Optional[bytes]         # Ratchet for received messages
    bond_nonce:   Optional[bytes]         # X's bond nonce
    tx_count:     int                     # Number of sent messages
    rx_count:     int                     # Number of received messages
    my_qseed:     Optional[bytes]         # Local Quantum Seed (1024-bit)
    peer_qseed:   Optional[bytes]         # Peer's Quantum Seed
    peer_username: Optional[str]
    color:        str            # Hex code
    evo_config:   EvoConfig
    state:        str
    label:        str
    created_at:   int

    @property
    def is_bonded(self) -> bool:
        """Is the bond established?"""
        return self.send_seed is not None and self.recv_seed is not None

    @property
    def can_send(self) -> bool:
        """Can a message be sent?"""
        return self.state == SESSION_STATE_ACTIVE and self.is_bonded

    @property
    def effective_evo_seed(self) -> Optional[bytes]:
        """Active evolution seed: current seed."""
        return self.current_seed


# File encryption helpers

def _file_encryption_key(session_id: bytes, purpose: bytes) -> bytes:
    """Derives a key using HKDF to encrypt session files."""
    return hkdf_derive(APP_DOMAIN + session_id, KEY_LEN, b"paracci.file.enc." + purpose)


def _build_file_header(file_type: int, session_id: bytes) -> bytes:
    """Creates the session file header."""
    return MAGIC_BYTES + bytes([FILE_VERSION, file_type]) + session_id


def _verify_magic(data: bytes) -> bool:
    """Verifies the file signature."""
    return data[:4] == MAGIC_BYTES


# Initiator file

def serialize_initiator_file(meta: SessionMeta, my_username: Optional[str] = None) -> bytes:
    """Creates the session initiator file (.paracci_init)."""
    payload = {
        "session_id": meta.session_id.hex(),
        "x_pub":      meta.my_pub.hex(),
        "x_qseed":    meta.my_qseed.hex() if meta.my_qseed else None,
        "evo_config": serialize_evo_config(meta.evo_config).hex(),
        "label":      meta.label,
        "username":   my_username,
        "created_at": meta.created_at,
    }
    raw = json.dumps(payload, separators=(",", ":")).encode()
    fkey = _file_encryption_key(meta.session_id, b"initiator")
    hdr  = _build_file_header(TYPE_INITIATOR, meta.session_id)
    blob = encrypt(fkey, raw, aad=hdr)
    return hdr + blob.nonce + blob.ciphertext


def parse_initiator_file(data: bytes) -> dict:
    """Parses the initiator file and returns its content."""
    if not _verify_magic(data):
        raise SessionFileError("Invalid file format.")
    if data[4] != FILE_VERSION:
        raise SessionFileError("Unsupported version.")
    if data[5] != TYPE_INITIATOR:
        raise SessionFileError("This is not an initiator file.")
    session_id = data[6:22]
    hdr  = data[:22]
    blob = EncryptedBlob(nonce=data[22:22+NONCE_LEN], ciphertext=data[22+NONCE_LEN:])
    fkey = _file_encryption_key(session_id, b"initiator")
    try:
        raw = decrypt(fkey, blob, aad=hdr)
    except Exception:
        raise SessionFileError("File integrity could not be verified.")
    p = json.loads(raw.decode())
    return {
        "session_id": bytes.fromhex(p["session_id"]),
        "x_pub":      bytes.fromhex(p["x_pub"]),
        "x_qseed":    bytes.fromhex(p["x_qseed"]) if p.get("x_qseed") else None,
        "evo_config": deserialize_evo_config(bytes.fromhex(p["evo_config"])),
        "label":      p["label"],
        "username":   p.get("username"),
        "created_at": p["created_at"],
    }


# Responder file

def serialize_responder_file(session_id: bytes, y_pub: bytes, evo_config: EvoConfig, label: str, username: Optional[str] = None, y_qseed: Optional[bytes] = None) -> bytes:
    """Creates the session responder file (.paracci_resp)."""
    payload = {
        "session_id": session_id.hex(),
        "y_pub":      y_pub.hex(),
        "y_qseed":    (y_qseed.hex() if y_qseed else None),
        "evo_config": serialize_evo_config(evo_config).hex(),
        "label":      label,
        "username":   username,
    }
    raw  = json.dumps(payload, separators=(",", ":")).encode()
    fkey = _file_encryption_key(session_id, b"responder")
    hdr  = _build_file_header(TYPE_RESPONDER, session_id)
    blob = encrypt(fkey, raw, aad=hdr)
    return hdr + blob.nonce + blob.ciphertext


def parse_responder_file(data: bytes) -> dict:
    """Parses the responder file and returns its content."""
    if not _verify_magic(data):
        raise SessionFileError("Invalid file format.")
    if data[5] != TYPE_RESPONDER:
        raise SessionFileError("This is not a responder file.")
    session_id = data[6:22]
    hdr  = data[:22]
    blob = EncryptedBlob(nonce=data[22:22+NONCE_LEN], ciphertext=data[22+NONCE_LEN:])
    fkey = _file_encryption_key(session_id, b"responder")
    try:
        raw = decrypt(fkey, blob, aad=hdr)
    except Exception:
        raise SessionFileError("File integrity could not be verified.")
    p = json.loads(raw.decode())
    return {
        "session_id": bytes.fromhex(p["session_id"]),
        "y_pub":      bytes.fromhex(p["y_pub"]),
        "y_qseed":    bytes.fromhex(p["y_qseed"]) if p.get("y_qseed") else None,
        "evo_config": deserialize_evo_config(bytes.fromhex(p["evo_config"])),
        "label":      p["label"],
        "username":   p.get("username"),
    }


# Session setup

def create_initiator_session(
    label: str,
    session_ttl_sec: int = EVO_UNLIMITED,
    profile: str = "paranoid",
    custom_params: Optional[dict] = None,
    my_username: Optional[str] = None,
    color: Optional[str] = None,
) -> tuple[SessionMeta, bytes]:
    """
    X side: starts a new session.
    If profile is "custom", then custom_params (t, m, p) should be used.
    """
    session_id = new_message_id()
    priv, pub  = generate_keypair()
    qseed      = random_bytes(128) # 1024-bit Quantum Seed
    created_at = int(time.time())
    
    if profile == "custom" and custom_params:
        p = custom_params
    else:
        p = SECURITY_PROFILES.get(profile, SECURITY_PROFILES["paranoid"])

    evo_config = make_evo_config(
        session_ttl_sec=session_ttl_sec, 
        created_at=created_at,
        argon2_time=p["t"],
        argon2_mem=p["m"],
        argon2_par=p["p"]
    )

    meta = SessionMeta(
        session_id=session_id, role="X", my_priv=priv, my_pub=pub,
        peer_pub=None, keys=None,
        bond_seed=None, send_seed=None, recv_seed=None,
        bond_nonce=None, tx_count=0, rx_count=0,
        my_qseed=qseed, peer_qseed=None,
        peer_username=None,
        color=color or random.choice(SESSION_COLORS),
        evo_config=evo_config, state=SESSION_STATE_PENDING,
        label=label, created_at=created_at,
    )
    return meta, serialize_initiator_file(meta, my_username=my_username)


def accept_initiator_and_create_responder(
    initiator_file_bytes: bytes,
    local_label: str,
    my_username: Optional[str] = None,
    color: Optional[str] = None,
) -> tuple[SessionMeta, bytes]:
    """
    Y side: receives init file, sets up session, produces resp file.
    Y's bond_seed is still None — will be set when the first message arrives.
    """
    info = parse_initiator_file(initiator_file_bytes)
    session_id = info["session_id"]
    x_pub      = info["x_pub"]
    x_qseed    = info["x_qseed"]
    evo_config = info["evo_config"]

    y_priv, y_pub = generate_keypair()
    y_qseed       = random_bytes(128) # Generate local quantum seed
    shared_secret = ecdh(y_priv, x_pub)
    
    # Hybrid KDF: ECDH + Quantum Seed (with Argon2id)
    # Safe merging: no crash even if one of the seeds is None
    q_salt = (x_qseed or b"") + (y_qseed or b"")
    keys = derive_session_keys(
        shared_secret, x_public=x_pub, y_public=y_pub, 
        extra_salt=session_id, quantum_salt=q_salt if q_salt else None,
        a_time=evo_config.argon2_time,
        a_mem=evo_config.argon2_mem,
        a_par=evo_config.argon2_par
    )

    meta = SessionMeta(
        session_id=session_id, role="Y", my_priv=y_priv, my_pub=y_pub,
        peer_pub=x_pub, keys=keys,
        bond_seed=None, send_seed=None, recv_seed=None,
        bond_nonce=None,
        tx_count=0, rx_count=0,
        my_qseed=y_qseed, peer_qseed=x_qseed,
        peer_username=info.get("username"),
        color=color or random.choice(SESSION_COLORS),
        evo_config=evo_config, state=SESSION_STATE_ACTIVE,
        label=local_label, created_at=evo_config.created_at,
    )
    resp_bytes = serialize_responder_file(session_id, y_pub, evo_config, info["label"], username=my_username, y_qseed=y_qseed)
    return meta, resp_bytes


def finalize_initiator_session(
    meta: SessionMeta,
    responder_file_bytes: bytes,
) -> SessionMeta:
    """
    X side: receives resp file, performs ECDH, generates bond_nonce, computes bond_seed.

    bond_nonce is generated here and saved to X's SessionMeta.
    bond_nonce will be transmitted encrypted to Y in the sync block of X's FIRST message.
    """
    info = parse_responder_file(responder_file_bytes)
    if info["session_id"] != meta.session_id:
        raise SessionFileError("Session ID mismatch.")

    y_pub   = info["y_pub"]
    y_qseed = info["y_qseed"]
    shared_secret = ecdh(meta.my_priv, y_pub)
    
    # Hybrid KDF: ECDH + Quantum Seed (with Argon2id)
    # Safe merging: no crash even if one of the seeds is None
    q_salt = (meta.my_qseed or b"") + (y_qseed or b"")
    keys = derive_session_keys(
        shared_secret, x_public=meta.my_pub, y_public=y_pub, 
        extra_salt=meta.session_id, quantum_salt=q_salt if q_salt else None,
        a_time=meta.evo_config.argon2_time,
        a_mem=meta.evo_config.argon2_mem,
        a_par=meta.evo_config.argon2_par
    )

    # Generate bond nonce and compute bond_seed
    bond_nonce = random_bytes(32)
    bond_seed  = compute_bond_seed(keys.evo_seed, bond_nonce)

    return SessionMeta(
        session_id=meta.session_id, role="X",
        my_priv=meta.my_priv, my_pub=meta.my_pub,
        peer_pub=y_pub, keys=keys,
        bond_seed=bond_seed,
        send_seed=bond_seed, recv_seed=bond_seed,
        bond_nonce=bond_nonce,
        tx_count=0, rx_count=0,
        my_qseed=meta.my_qseed, peer_qseed=y_qseed,
        peer_username=info.get("username"),
        color=meta.color,
        evo_config=meta.evo_config, state=SESSION_STATE_ACTIVE,
        label=meta.label, created_at=meta.created_at,
    )


def apply_bond_nonce_to_y(meta: SessionMeta, bond_nonce: bytes) -> SessionMeta:
    """
    Y side: computes bond_seed with bond_nonce coming from X.
    This function is called after open_envelope in routes.py.
    """
    if meta.role != "Y":
        raise SessionError("This function is only for the Y role.")
    if meta.keys is None:
        raise SessionError("No session keys found.")
    bond_seed = compute_bond_seed(meta.keys.evo_seed, bond_nonce)
    return meta._replace(
        bond_seed=bond_seed, 
        send_seed=bond_seed,
        recv_seed=bond_seed,
        bond_nonce=bond_nonce
    )


# SessionMeta serialization (for DB)

def serialize_session_meta(meta: SessionMeta, device_key: bytes) -> bytes:
    """Serializes session data (SessionMeta) by encrypting it for the local database."""
    keys_data = None
    if meta.keys:
        keys_data = {
            "x_to_y": meta.keys.key_x_to_y.hex(),
            "y_to_x": meta.keys.key_y_to_x.hex(),
            "sync":   meta.keys.sync_key.hex(),
            "evo":    meta.keys.evo_seed.hex(),
        }
    data = {
        "session_id":   meta.session_id.hex(),
        "role":         meta.role,
        "my_priv":      meta.my_priv.hex(),
        "my_pub":       meta.my_pub.hex(),
        "peer_pub":     meta.peer_pub.hex() if meta.peer_pub else None,
        "keys":         keys_data,
        "bond_seed":  meta.bond_seed.hex() if meta.bond_seed else None,
        "send_seed":  meta.send_seed.hex() if meta.send_seed else None,
        "recv_seed":  meta.recv_seed.hex() if meta.recv_seed else None,
        "bond_nonce": meta.bond_nonce.hex() if meta.bond_nonce else None,
        "tx_count":   meta.tx_count,
        "rx_count":   meta.rx_count,
        "my_qseed":   meta.my_qseed.hex() if meta.my_qseed else None,
        "peer_qseed": meta.peer_qseed.hex() if meta.peer_qseed else None,
        "peer_username": meta.peer_username,
        "color":        meta.color,
        "evo_config":   serialize_evo_config(meta.evo_config).hex(),
        "state":        meta.state,
        "label":        meta.label,
        "created_at":   meta.created_at,
    }
    raw  = json.dumps(data, separators=(",", ":")).encode()
    blob = encrypt(device_key, raw, aad=b"paracci.db.session.v2")
    return blob.nonce + blob.ciphertext


def deserialize_session_meta(encrypted_data: bytes, device_key: bytes) -> SessionMeta:
    """Converts the encrypted database record into a SessionMeta object."""
    nonce = encrypted_data[:NONCE_LEN]
    blob  = EncryptedBlob(nonce=nonce, ciphertext=encrypted_data[NONCE_LEN:])
    try:
        # Try with v2 AAD
        raw = decrypt(device_key, blob, aad=b"paracci.db.session.v2")
    except Exception:
        try:
            # Try with v1 AAD (backward compatibility)
            raw = decrypt(device_key, blob, aad=b"paracci.db.session.v1")
        except Exception:
            raise SessionError("Session data could not be decrypted.")

    data = json.loads(raw.decode())

    keys = None
    if data.get("keys"):
        keys = DerivedKeys(
            key_x_to_y=bytes.fromhex(data["keys"]["x_to_y"]),
            key_y_to_x=bytes.fromhex(data["keys"]["y_to_x"]),
            sync_key=bytes.fromhex(data["keys"]["sync"]),
            evo_seed=bytes.fromhex(data["keys"]["evo"]),
        )

    return SessionMeta(
        session_id=bytes.fromhex(data["session_id"]),
        role=data["role"],
        my_priv=bytes.fromhex(data["my_priv"]),
        my_pub=bytes.fromhex(data["my_pub"]),
        peer_pub=bytes.fromhex(data["peer_pub"]) if data.get("peer_pub") else None,
        keys=keys,
        bond_seed=bytes.fromhex(data["bond_seed"]) if data.get("bond_seed") else None,
        send_seed=bytes.fromhex(data["send_seed"]) if data.get("send_seed") else None,
        recv_seed=bytes.fromhex(data["recv_seed"]) if data.get("recv_seed") else None,
        bond_nonce=bytes.fromhex(data["bond_nonce"]) if data.get("bond_nonce") else None,
        tx_count=data.get("tx_count", 0),
        rx_count=data.get("rx_count", 0),
        my_qseed=bytes.fromhex(data["my_qseed"]) if data.get("my_qseed") else None,
        peer_qseed=bytes.fromhex(data["peer_qseed"]) if data.get("peer_qseed") else None,
        peer_username=data.get("peer_username"),
        color=data.get("color") or SESSION_COLORS[int(data["session_id"], 16) % len(SESSION_COLORS)],
        evo_config=deserialize_evo_config(bytes.fromhex(data["evo_config"])),
        state=data["state"],
        label=data["label"],
        created_at=data["created_at"],
    )


# Error classes

class SessionFileError(Exception):
    pass

class SessionError(Exception):
    pass