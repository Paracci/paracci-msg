"""
Paracci core/session.py
Session setup flow and authenticated handshake management.
"""

import json
import random
import string
import time
from typing import NamedTuple, Optional

from .crypto import (
    DerivedKeys,
    EncryptedBlob,
    KEY_LEN,
    NONCE_LEN,
    decrypt,
    derive_session_keys,
    ecdh,
    encrypt,
    generate_keypair,
    get_safety_code,
    hkdf_derive,
    new_message_id,
    random_bytes,
    sign_identity,
    verify_identity_signature,
)
from .evolution import (
    EVO_UNLIMITED,
    EvoConfig,
    compute_bond_seed,
    deserialize_evo_config,
    make_evo_config,
    serialize_evo_config,
)

MAGIC_BYTES = b"PARC"
FILE_VERSION = 0x01
TYPE_INITIATOR = 0x10
TYPE_RESPONDER = 0x11
TYPE_MESSAGE = 0x20

SESSION_STATE_PENDING = "pending"
SESSION_STATE_UNVERIFIED = "unverified"
SESSION_STATE_ACTIVE = "active"
SESSION_STATE_EXPIRED = "expired"

HANDSHAKE_VERSION = 2
LEGACY_HANDSHAKE_VERSION = 1

APP_DOMAIN = b"paracci.app.session.file.v1"
SIGN_INITIATOR_LABEL = b"paracci.handshake.initiator.v2"
SIGN_RESPONDER_LABEL = b"paracci.handshake.responder.v2"

X25519_KEY_LEN = 32
ED25519_PUBLIC_LEN = 32
ED25519_SIGNATURE_LEN = 64
SESSION_ID_LEN = 16
QSEED_LEN = 128

# Security Profiles: Argon2id workload settings (Time-Lock)
# t: time_cost (iterations), m: memory_cost (KB), p: parallelism
SECURITY_PROFILES = {
    "standard": {"t": 2, "m": 65536, "p": 2},
    "paranoid": {"t": 8, "m": 262144, "p": 4},
    "quantum": {"t": 256, "m": 2097152, "p": 2},
}

SESSION_COLORS = [
    "#0a84ff",
    "#30d158",
    "#ff453a",
    "#ff9f0a",
    "#bf5af2",
    "#ff375f",
    "#64d2ff",
    "#ffd60a",
]


class SessionMeta(NamedTuple):
    session_id: bytes
    role: str
    my_priv: bytes
    my_pub: bytes
    peer_pub: Optional[bytes]
    keys: Optional[DerivedKeys]
    bond_seed: Optional[bytes]
    send_seed: Optional[bytes]
    recv_seed: Optional[bytes]
    bond_nonce: Optional[bytes]
    tx_count: int
    rx_count: int
    my_qseed: Optional[bytes]
    peer_qseed: Optional[bytes]
    peer_username: Optional[str]
    color: str
    evo_config: EvoConfig
    state: str
    label: str
    created_at: int
    my_identity_pub: Optional[bytes]
    peer_identity_pub: Optional[bytes]
    handshake_version: int
    safety_confirmed: bool
    safety_confirmed_at: Optional[int]

    @property
    def is_bonded(self) -> bool:
        """Is the message ratchet bond established?"""
        return self.send_seed is not None and self.recv_seed is not None

    @property
    def can_send(self) -> bool:
        """Can a message be sent?"""
        return (
            self.state == SESSION_STATE_ACTIVE
            and self.is_bonded
            and self.safety_confirmed
        )

    @property
    def can_open(self) -> bool:
        """Can an incoming message be opened?"""
        return (
            self.state == SESSION_STATE_ACTIVE
            and self.keys is not None
            and self.safety_confirmed
        )

    @property
    def effective_evo_seed(self) -> Optional[bytes]:
        """Active evolution seed."""
        return self.send_seed or self.recv_seed or self.bond_seed


def _file_encryption_key(session_id: bytes, purpose: bytes) -> bytes:
    """Derives the wrapper key used for session file AEAD."""
    return hkdf_derive(APP_DOMAIN + session_id, KEY_LEN, b"paracci.file.enc." + purpose)


def _build_file_header(file_type: int, session_id: bytes) -> bytes:
    return MAGIC_BYTES + bytes([FILE_VERSION, file_type]) + session_id


def _verify_magic(data: bytes) -> bool:
    return data[:4] == MAGIC_BYTES


def _canonical_payload(payload: dict) -> bytes:
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def _handshake_signing_bytes(kind: bytes, payload: dict) -> bytes:
    return kind + b"\x00" + _canonical_payload(payload)


def _expect_len(value: bytes, expected: int, label: str) -> bytes:
    if len(value) != expected:
        raise SessionFileError(f"Invalid {label} length.")
    return value


def _hex_to_bytes(value, expected: int, label: str, optional: bool = False) -> Optional[bytes]:
    if value is None and optional:
        return None
    if not isinstance(value, str):
        raise SessionFileError(f"Invalid {label}.")
    try:
        raw = bytes.fromhex(value)
    except ValueError as exc:
        raise SessionFileError(f"Invalid {label}.") from exc
    return _expect_len(raw, expected, label)


def _hex_qseed(value) -> Optional[bytes]:
    return _hex_to_bytes(value, QSEED_LEN, "quantum seed", optional=True)


def _decode_file_payload(data: bytes, expected_type: int, purpose: bytes) -> tuple[bytes, dict]:
    if not _verify_magic(data):
        raise SessionFileError("Invalid file format.")
    if len(data) < 22 + NONCE_LEN:
        raise SessionFileError("File is too short.")
    if data[4] != FILE_VERSION:
        raise SessionFileError("Unsupported version.")
    if data[5] != expected_type:
        raise SessionFileError("Unexpected session file type.")

    session_id = _expect_len(data[6:22], SESSION_ID_LEN, "session id")
    hdr = data[:22]
    blob = EncryptedBlob(nonce=data[22:22 + NONCE_LEN], ciphertext=data[22 + NONCE_LEN:])
    fkey = _file_encryption_key(session_id, purpose)
    try:
        raw = decrypt(fkey, blob, aad=hdr)
        payload = json.loads(raw.decode("utf-8"))
    except SessionFileError:
        raise
    except Exception as exc:
        raise SessionFileError("File integrity could not be verified.") from exc
    if not isinstance(payload, dict):
        raise SessionFileError("Invalid session payload.")
    return session_id, payload


def _verify_signed_payload(kind: bytes, payload: dict, signature_field: str, identity_pub_field: str) -> bytes:
    if payload.get("handshake_version") != HANDSHAKE_VERSION:
        raise SessionFileError("Unsupported or unsigned handshake file.")
    signature = _hex_to_bytes(payload.get(signature_field), ED25519_SIGNATURE_LEN, "signature")
    identity_pub = _hex_to_bytes(payload.get(identity_pub_field), ED25519_PUBLIC_LEN, "identity public key")
    signed = dict(payload)
    signed.pop(signature_field, None)
    if not verify_identity_signature(identity_pub, _handshake_signing_bytes(kind, signed), signature):
        raise SessionFileError("Handshake signature could not be verified.")
    return identity_pub


def _validate_payload_session_id(payload: dict, header_session_id: bytes) -> bytes:
    payload_session_id = _hex_to_bytes(payload.get("session_id"), SESSION_ID_LEN, "session id")
    if payload_session_id != header_session_id:
        raise SessionFileError("Session ID mismatch.")
    return payload_session_id


def _encrypt_handshake_payload(file_type: int, session_id: bytes, purpose: bytes, payload: dict) -> bytes:
    raw = _canonical_payload(payload)
    fkey = _file_encryption_key(session_id, purpose)
    hdr = _build_file_header(file_type, session_id)
    blob = encrypt(fkey, raw, aad=hdr)
    return hdr + blob.nonce + blob.ciphertext


def serialize_initiator_file(
    meta: SessionMeta,
    my_username: Optional[str] = None,
    *,
    identity_priv: bytes,
) -> bytes:
    """Creates the signed session initiator file."""
    if not meta.my_identity_pub:
        raise SessionFileError("Missing local identity key.")

    payload = {
        "handshake_version": HANDSHAKE_VERSION,
        "session_id": meta.session_id.hex(),
        "x_pub": meta.my_pub.hex(),
        "x_identity_pub": meta.my_identity_pub.hex(),
        "x_qseed": meta.my_qseed.hex() if meta.my_qseed else None,
        "evo_config": serialize_evo_config(meta.evo_config).hex(),
        "label": meta.label,
        "username": my_username,
        "created_at": meta.created_at,
    }
    payload["signature"] = sign_identity(
        identity_priv,
        _handshake_signing_bytes(SIGN_INITIATOR_LABEL, payload),
    ).hex()
    return _encrypt_handshake_payload(TYPE_INITIATOR, meta.session_id, b"initiator", payload)


def parse_initiator_file(data: bytes) -> dict:
    """Parses and verifies a signed initiator file."""
    header_session_id, p = _decode_file_payload(data, TYPE_INITIATOR, b"initiator")
    x_identity_pub = _verify_signed_payload(
        SIGN_INITIATOR_LABEL,
        p,
        signature_field="signature",
        identity_pub_field="x_identity_pub",
    )
    session_id = _validate_payload_session_id(p, header_session_id)
    x_pub = _hex_to_bytes(p.get("x_pub"), X25519_KEY_LEN, "X25519 public key")
    x_qseed = _hex_qseed(p.get("x_qseed"))
    try:
        evo_config = deserialize_evo_config(bytes.fromhex(p["evo_config"]))
    except Exception as exc:
        raise SessionFileError("Invalid evolution configuration.") from exc
    return {
        "handshake_version": HANDSHAKE_VERSION,
        "session_id": session_id,
        "x_pub": x_pub,
        "x_identity_pub": x_identity_pub,
        "x_qseed": x_qseed,
        "evo_config": evo_config,
        "label": p["label"],
        "username": p.get("username"),
        "created_at": p["created_at"],
    }


def serialize_responder_file(
    session_id: bytes,
    y_pub: bytes,
    evo_config: EvoConfig,
    label: str,
    username: Optional[str] = None,
    y_qseed: Optional[bytes] = None,
    *,
    x_pub: bytes,
    x_identity_pub: bytes,
    y_identity_pub: bytes,
    identity_priv: bytes,
) -> bytes:
    """Creates the signed session responder file."""
    _expect_len(session_id, SESSION_ID_LEN, "session id")
    _expect_len(x_pub, X25519_KEY_LEN, "X25519 public key")
    _expect_len(y_pub, X25519_KEY_LEN, "X25519 public key")
    _expect_len(x_identity_pub, ED25519_PUBLIC_LEN, "identity public key")
    _expect_len(y_identity_pub, ED25519_PUBLIC_LEN, "identity public key")
    if y_qseed is not None:
        _expect_len(y_qseed, QSEED_LEN, "quantum seed")

    payload = {
        "handshake_version": HANDSHAKE_VERSION,
        "session_id": session_id.hex(),
        "x_pub": x_pub.hex(),
        "x_identity_pub": x_identity_pub.hex(),
        "y_pub": y_pub.hex(),
        "y_identity_pub": y_identity_pub.hex(),
        "y_qseed": y_qseed.hex() if y_qseed else None,
        "evo_config": serialize_evo_config(evo_config).hex(),
        "label": label,
        "username": username,
    }
    payload["signature"] = sign_identity(
        identity_priv,
        _handshake_signing_bytes(SIGN_RESPONDER_LABEL, payload),
    ).hex()
    return _encrypt_handshake_payload(TYPE_RESPONDER, session_id, b"responder", payload)


def parse_responder_file(data: bytes) -> dict:
    """Parses and verifies a signed responder file."""
    header_session_id, p = _decode_file_payload(data, TYPE_RESPONDER, b"responder")
    y_identity_pub = _verify_signed_payload(
        SIGN_RESPONDER_LABEL,
        p,
        signature_field="signature",
        identity_pub_field="y_identity_pub",
    )
    session_id = _validate_payload_session_id(p, header_session_id)
    x_pub = _hex_to_bytes(p.get("x_pub"), X25519_KEY_LEN, "X25519 public key")
    x_identity_pub = _hex_to_bytes(p.get("x_identity_pub"), ED25519_PUBLIC_LEN, "identity public key")
    y_pub = _hex_to_bytes(p.get("y_pub"), X25519_KEY_LEN, "X25519 public key")
    y_qseed = _hex_qseed(p.get("y_qseed"))
    try:
        evo_config = deserialize_evo_config(bytes.fromhex(p["evo_config"]))
    except Exception as exc:
        raise SessionFileError("Invalid evolution configuration.") from exc
    return {
        "handshake_version": HANDSHAKE_VERSION,
        "session_id": session_id,
        "x_pub": x_pub,
        "x_identity_pub": x_identity_pub,
        "y_pub": y_pub,
        "y_identity_pub": y_identity_pub,
        "y_qseed": y_qseed,
        "evo_config": evo_config,
        "label": p["label"],
        "username": p.get("username"),
    }


def create_initiator_session(
    label: str,
    session_ttl_sec: int = EVO_UNLIMITED,
    profile: str = "paranoid",
    custom_params: Optional[dict] = None,
    my_username: Optional[str] = None,
    color: Optional[str] = None,
    *,
    identity_pub: bytes,
    identity_priv: bytes,
) -> tuple[SessionMeta, bytes]:
    """X side: starts a new signed session handshake."""
    _expect_len(identity_pub, ED25519_PUBLIC_LEN, "identity public key")
    session_id = new_message_id()
    priv, pub = generate_keypair()
    qseed = random_bytes(QSEED_LEN)
    created_at = int(time.time())

    params = custom_params if profile == "custom" and custom_params else SECURITY_PROFILES.get(profile, SECURITY_PROFILES["paranoid"])
    evo_config = make_evo_config(
        session_ttl_sec=session_ttl_sec,
        created_at=created_at,
        argon2_time=params["t"],
        argon2_mem=params["m"],
        argon2_par=params["p"],
    )

    meta = SessionMeta(
        session_id=session_id,
        role="X",
        my_priv=priv,
        my_pub=pub,
        peer_pub=None,
        keys=None,
        bond_seed=None,
        send_seed=None,
        recv_seed=None,
        bond_nonce=None,
        tx_count=0,
        rx_count=0,
        my_qseed=qseed,
        peer_qseed=None,
        peer_username=None,
        color=color or random.choice(SESSION_COLORS),
        evo_config=evo_config,
        state=SESSION_STATE_PENDING,
        label=label,
        created_at=created_at,
        my_identity_pub=identity_pub,
        peer_identity_pub=None,
        handshake_version=HANDSHAKE_VERSION,
        safety_confirmed=False,
        safety_confirmed_at=None,
    )
    return meta, serialize_initiator_file(meta, my_username=my_username, identity_priv=identity_priv)


def accept_initiator_and_create_responder(
    initiator_file_bytes: bytes,
    local_label: str,
    my_username: Optional[str] = None,
    color: Optional[str] = None,
    *,
    identity_pub: bytes,
    identity_priv: bytes,
) -> tuple[SessionMeta, bytes]:
    """Y side: verifies the initiator file, creates a signed responder file."""
    _expect_len(identity_pub, ED25519_PUBLIC_LEN, "identity public key")
    info = parse_initiator_file(initiator_file_bytes)
    session_id = info["session_id"]
    x_pub = info["x_pub"]
    x_identity_pub = info["x_identity_pub"]
    x_qseed = info["x_qseed"]
    evo_config = info["evo_config"]

    y_priv, y_pub = generate_keypair()
    y_qseed = random_bytes(QSEED_LEN)
    shared_secret = ecdh(y_priv, x_pub)
    q_salt = (x_qseed or b"") + (y_qseed or b"")
    keys = derive_session_keys(
        shared_secret,
        x_public=x_pub,
        y_public=y_pub,
        extra_salt=session_id,
        quantum_salt=q_salt if q_salt else None,
        a_time=evo_config.argon2_time,
        a_mem=evo_config.argon2_mem,
        a_par=evo_config.argon2_par,
    )

    meta = SessionMeta(
        session_id=session_id,
        role="Y",
        my_priv=y_priv,
        my_pub=y_pub,
        peer_pub=x_pub,
        keys=keys,
        bond_seed=None,
        send_seed=None,
        recv_seed=None,
        bond_nonce=None,
        tx_count=0,
        rx_count=0,
        my_qseed=y_qseed,
        peer_qseed=x_qseed,
        peer_username=info.get("username"),
        color=color or random.choice(SESSION_COLORS),
        evo_config=evo_config,
        state=SESSION_STATE_UNVERIFIED,
        label=local_label,
        created_at=evo_config.created_at,
        my_identity_pub=identity_pub,
        peer_identity_pub=x_identity_pub,
        handshake_version=HANDSHAKE_VERSION,
        safety_confirmed=False,
        safety_confirmed_at=None,
    )
    resp_bytes = serialize_responder_file(
        session_id,
        y_pub,
        evo_config,
        info["label"],
        username=my_username,
        y_qseed=y_qseed,
        x_pub=x_pub,
        x_identity_pub=x_identity_pub,
        y_identity_pub=identity_pub,
        identity_priv=identity_priv,
    )
    return meta, resp_bytes


def finalize_initiator_session(meta: SessionMeta, responder_file_bytes: bytes) -> SessionMeta:
    """X side: verifies responder file, derives keys, and waits for SAS confirmation."""
    info = parse_responder_file(responder_file_bytes)
    if info["session_id"] != meta.session_id:
        raise SessionFileError("Session ID mismatch.")
    if info["x_pub"] != meta.my_pub:
        raise SessionFileError("Responder file does not match this initiator key.")
    if info["x_identity_pub"] != meta.my_identity_pub:
        raise SessionFileError("Responder file does not match this identity.")

    y_pub = info["y_pub"]
    y_qseed = info["y_qseed"]
    shared_secret = ecdh(meta.my_priv, y_pub)
    q_salt = (meta.my_qseed or b"") + (y_qseed or b"")
    keys = derive_session_keys(
        shared_secret,
        x_public=meta.my_pub,
        y_public=y_pub,
        extra_salt=meta.session_id,
        quantum_salt=q_salt if q_salt else None,
        a_time=meta.evo_config.argon2_time,
        a_mem=meta.evo_config.argon2_mem,
        a_par=meta.evo_config.argon2_par,
    )

    bond_nonce = random_bytes(32)
    bond_seed = compute_bond_seed(keys.evo_seed, bond_nonce)

    return meta._replace(
        peer_pub=y_pub,
        keys=keys,
        bond_seed=bond_seed,
        send_seed=bond_seed,
        recv_seed=bond_seed,
        bond_nonce=bond_nonce,
        tx_count=0,
        rx_count=0,
        peer_qseed=y_qseed,
        peer_username=info.get("username"),
        state=SESSION_STATE_UNVERIFIED,
        peer_identity_pub=info["y_identity_pub"],
        handshake_version=HANDSHAKE_VERSION,
        safety_confirmed=False,
        safety_confirmed_at=None,
    )


def apply_bond_nonce_to_y(meta: SessionMeta, bond_nonce: bytes) -> SessionMeta:
    """Y side: computes bond_seed with the nonce carried in X's first message."""
    if meta.role != "Y":
        raise SessionError("This function is only for the Y role.")
    if meta.keys is None:
        raise SessionError("No session keys found.")
    bond_seed = compute_bond_seed(meta.keys.evo_seed, bond_nonce)
    return meta._replace(
        bond_seed=bond_seed,
        send_seed=bond_seed,
        recv_seed=bond_seed,
        bond_nonce=bond_nonce,
    )


def get_session_safety_code(meta: SessionMeta) -> str:
    """Returns the deterministic human safety code for a v2 session."""
    if meta.handshake_version != HANDSHAKE_VERSION:
        raise SessionError("Legacy handshakes do not have a safety code.")
    if not meta.my_identity_pub or not meta.peer_identity_pub or not meta.peer_pub:
        raise SessionError("Session is missing peer key material.")
    if meta.role == "X":
        return get_safety_code(
            meta.my_identity_pub,
            meta.peer_identity_pub,
            meta.my_pub,
            meta.peer_pub,
            meta.session_id,
        )
    if meta.role == "Y":
        return get_safety_code(
            meta.peer_identity_pub,
            meta.my_identity_pub,
            meta.peer_pub,
            meta.my_pub,
            meta.session_id,
        )
    raise SessionError("Invalid session role.")


def normalize_safety_code(value: str) -> str:
    """Normalizes a typed safety code to 24 uppercase hex characters."""
    normalized = "".join(ch for ch in (value or "").upper() if ch not in "- \t\r\n")
    if len(normalized) != 24 or any(ch not in string.hexdigits.upper() for ch in normalized):
        raise SessionError("Invalid safety code format.")
    return normalized


def confirm_safety_code(meta: SessionMeta, user_code: str) -> SessionMeta:
    """Marks a v2 session active only after the local user confirms the SAS."""
    expected = normalize_safety_code(get_session_safety_code(meta))
    provided = normalize_safety_code(user_code)
    if provided != expected:
        raise SessionError("Safety code does not match.")
    return meta._replace(
        state=SESSION_STATE_ACTIVE,
        safety_confirmed=True,
        safety_confirmed_at=int(time.time()),
    )


def serialize_session_meta(meta: SessionMeta, device_key: bytes) -> bytes:
    """Serializes session data by encrypting it for the local database."""
    keys_data = None
    if meta.keys:
        keys_data = {
            "x_to_y": meta.keys.key_x_to_y.hex(),
            "y_to_x": meta.keys.key_y_to_x.hex(),
            "sync": meta.keys.sync_key.hex(),
            "evo": meta.keys.evo_seed.hex(),
        }
    data = {
        "session_id": meta.session_id.hex(),
        "role": meta.role,
        "my_priv": meta.my_priv.hex(),
        "my_pub": meta.my_pub.hex(),
        "peer_pub": meta.peer_pub.hex() if meta.peer_pub else None,
        "keys": keys_data,
        "bond_seed": meta.bond_seed.hex() if meta.bond_seed else None,
        "send_seed": meta.send_seed.hex() if meta.send_seed else None,
        "recv_seed": meta.recv_seed.hex() if meta.recv_seed else None,
        "bond_nonce": meta.bond_nonce.hex() if meta.bond_nonce else None,
        "tx_count": meta.tx_count,
        "rx_count": meta.rx_count,
        "my_qseed": meta.my_qseed.hex() if meta.my_qseed else None,
        "peer_qseed": meta.peer_qseed.hex() if meta.peer_qseed else None,
        "peer_username": meta.peer_username,
        "color": meta.color,
        "evo_config": serialize_evo_config(meta.evo_config).hex(),
        "state": meta.state,
        "label": meta.label,
        "created_at": meta.created_at,
        "my_identity_pub": meta.my_identity_pub.hex() if meta.my_identity_pub else None,
        "peer_identity_pub": meta.peer_identity_pub.hex() if meta.peer_identity_pub else None,
        "handshake_version": meta.handshake_version,
        "safety_confirmed": meta.safety_confirmed,
        "safety_confirmed_at": meta.safety_confirmed_at,
    }
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    blob = encrypt(device_key, raw, aad=b"paracci.db.session.v2")
    return blob.nonce + blob.ciphertext


def deserialize_session_meta(encrypted_data: bytes, device_key: bytes) -> SessionMeta:
    """Converts an encrypted database record into SessionMeta."""
    nonce = encrypted_data[:NONCE_LEN]
    blob = EncryptedBlob(nonce=nonce, ciphertext=encrypted_data[NONCE_LEN:])
    try:
        raw = decrypt(device_key, blob, aad=b"paracci.db.session.v2")
    except Exception:
        try:
            raw = decrypt(device_key, blob, aad=b"paracci.db.session.v1")
        except Exception as exc:
            raise SessionError("Session data could not be decrypted.") from exc

    data = json.loads(raw.decode("utf-8"))
    keys = None
    if data.get("keys"):
        keys = DerivedKeys(
            key_x_to_y=bytes.fromhex(data["keys"]["x_to_y"]),
            key_y_to_x=bytes.fromhex(data["keys"]["y_to_x"]),
            sync_key=bytes.fromhex(data["keys"]["sync"]),
            evo_seed=bytes.fromhex(data["keys"]["evo"]),
        )

    handshake_version = int(data.get("handshake_version", LEGACY_HANDSHAKE_VERSION))
    safety_confirmed = bool(data.get("safety_confirmed", False)) if handshake_version >= HANDSHAKE_VERSION else False
    state = data["state"]
    if handshake_version < HANDSHAKE_VERSION and state == SESSION_STATE_ACTIVE:
        state = SESSION_STATE_UNVERIFIED
    if handshake_version >= HANDSHAKE_VERSION and not safety_confirmed and state == SESSION_STATE_ACTIVE:
        state = SESSION_STATE_UNVERIFIED

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
        state=state,
        label=data["label"],
        created_at=data["created_at"],
        my_identity_pub=bytes.fromhex(data["my_identity_pub"]) if data.get("my_identity_pub") else None,
        peer_identity_pub=bytes.fromhex(data["peer_identity_pub"]) if data.get("peer_identity_pub") else None,
        handshake_version=handshake_version,
        safety_confirmed=safety_confirmed,
        safety_confirmed_at=data.get("safety_confirmed_at"),
    )


class SessionFileError(Exception):
    pass


class SessionError(Exception):
    pass
