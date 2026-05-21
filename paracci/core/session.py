"""
Paracci core/session.py
Session setup flow and authenticated handshake management.
"""

import base64
import json
import random
import string
import time
from binascii import Error as BinasciiError
from typing import NamedTuple, Optional

from cryptography.exceptions import InvalidTag

from .constants import KEM_ALGORITHM, LEGACY_HANDSHAKE_FILE_WRAPPER_DOMAIN_V3
from .crypto import (
    DerivedKeys,
    EncryptedBlob,
    KEY_LEN,
    NONCE_LEN,
    decrypt,
    derive_hybrid_shared_secret,
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
    SECURITY_PROFILES,
    compute_bond_seed,
    deserialize_evo_config,
    make_evo_config,
    serialize_evo_config,
    validate_argon2_params,
    validate_evo_config,
)
from .hybrid_kem import (
    HYBRID_HANDSHAKE_VERSION,
    OLDER_VERSION_ERROR,
    HybridKEMError,
    initiator_kem_complete,
    initiator_kem_setup,
    responder_kem_respond,
    validate_hybrid_handshake_payload,
)

MAGIC_BYTES = b"PARC"
FILE_VERSION = 0x01
LEGACY_WRAPPED_HANDSHAKE_FILE_VERSION = 0x03
HANDSHAKE_FILE_VERSION = 0x04
TYPE_INITIATOR = 0x10
TYPE_RESPONDER = 0x11
TYPE_MESSAGE = 0x20

SESSION_STATE_PENDING = "pending"
SESSION_STATE_UNVERIFIED = "unverified"
SESSION_STATE_ACTIVE = "active"
SESSION_STATE_EXPIRED = "expired"

HANDSHAKE_VERSION = HYBRID_HANDSHAKE_VERSION
SIGNED_X25519_HANDSHAKE_VERSION = 2
LEGACY_HANDSHAKE_VERSION = 1

# Handshake file-header versions:
# v3: signed metadata wrapped in AEAD with a key derived from public session_id.
# v4: signed public metadata stored directly as canonical JSON.
SIGN_INITIATOR_LABEL = b"paracci.handshake.initiator.v3"
SIGN_RESPONDER_LABEL = b"paracci.handshake.responder.v3"

X25519_KEY_LEN = 32
ED25519_PUBLIC_LEN = 32
ED25519_SIGNATURE_LEN = 64
SESSION_ID_LEN = 16
QSEED_LEN = 128

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
    ml_kem_public_key: Optional[bytes] = None
    ml_kem_secret_key: Optional[bytes] = None
    ml_kem_ciphertext: Optional[bytes] = None

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


def _legacy_file_encryption_key(session_id: bytes, purpose: bytes) -> bytes:
    """Derives the legacy v3 wrapper key used only for old setup-file imports."""
    return hkdf_derive(
        LEGACY_HANDSHAKE_FILE_WRAPPER_DOMAIN_V3 + session_id,
        KEY_LEN,
        b"paracci.file.enc." + purpose,
    )


def _build_file_header(file_type: int, session_id: bytes, file_version: int = HANDSHAKE_FILE_VERSION) -> bytes:
    return MAGIC_BYTES + bytes([file_version, file_type]) + session_id


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


def _b64_to_bytes(value, label: str, i18n_key: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise HybridKEMError(f"Invalid {label}.", i18n_key)
    try:
        raw = base64.b64decode(value.encode("ascii"), validate=True)
    except (BinasciiError, UnicodeEncodeError, ValueError) as exc:
        raise HybridKEMError(f"Invalid {label}.", i18n_key) from exc
    if not raw:
        raise HybridKEMError(f"Invalid {label}.", i18n_key)
    return raw


def _b64_from_bytes(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _is_handshake_type(file_type: int) -> bool:
    return file_type in (TYPE_INITIATOR, TYPE_RESPONDER)


def _load_session_payload(raw: bytes) -> dict:
    try:
        payload = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise SessionFileError("Session payload could not be parsed.") from exc
    if not isinstance(payload, dict):
        raise SessionFileError("Invalid session payload.")
    return payload


def _decode_file_payload(data: bytes, expected_type: int, purpose: bytes) -> tuple[bytes, dict]:
    if not _verify_magic(data):
        raise SessionFileError("Invalid file format.")
    if len(data) < 22:
        raise SessionFileError("File is too short.")
    if data[5] != expected_type:
        raise SessionFileError("Unexpected session file type.")
    file_version = data[4]
    if _is_handshake_type(expected_type):
        if file_version not in (LEGACY_WRAPPED_HANDSHAKE_FILE_VERSION, HANDSHAKE_FILE_VERSION):
            if file_version < LEGACY_WRAPPED_HANDSHAKE_FILE_VERSION:
                raise HybridKEMError(OLDER_VERSION_ERROR, "hybrid_kem_legacy_session")
            raise SessionFileError("Unsupported version.")
    elif file_version != FILE_VERSION:
        raise SessionFileError("Unsupported version.")

    session_id = _expect_len(data[6:22], SESSION_ID_LEN, "session id")
    hdr = data[:22]
    if _is_handshake_type(expected_type) and file_version == HANDSHAKE_FILE_VERSION:
        if len(data) <= 22:
            raise SessionFileError("File is too short.")
        return session_id, _load_session_payload(data[22:])

    if len(data) < 22 + NONCE_LEN + 16:
        raise SessionFileError("File is too short.")
    blob = EncryptedBlob(nonce=data[22:22 + NONCE_LEN], ciphertext=data[22 + NONCE_LEN:])
    fkey = _legacy_file_encryption_key(session_id, purpose)
    try:
        raw = decrypt(fkey, blob, aad=hdr)
    except Exception as exc:
        raise SessionFileError("File integrity could not be verified.") from exc
    return session_id, _load_session_payload(raw)


def _verify_signed_payload(kind: bytes, payload: dict, signature_field: str, identity_pub_field: str) -> bytes:
    expected_kind = "initiator" if kind == SIGN_INITIATOR_LABEL else "responder"
    validate_hybrid_handshake_payload(payload, expected_kind=expected_kind)
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


def _serialize_handshake_payload(file_type: int, session_id: bytes, payload: dict) -> bytes:
    raw = _canonical_payload(payload)
    hdr = _build_file_header(file_type, session_id)
    return hdr + raw


def serialize_initiator_file(
    meta: SessionMeta,
    my_username: Optional[str] = None,
    *,
    identity_priv: bytes,
) -> bytes:
    """Creates the signed session initiator file."""
    if not meta.my_identity_pub:
        raise SessionFileError("Missing local identity key.")
    if not meta.ml_kem_public_key:
        raise HybridKEMError("Missing ML-KEM public key.", "hybrid_kem_init_failed")

    payload = {
        "handshake_version": HANDSHAKE_VERSION,
        "session_id": meta.session_id.hex(),
        "x_pub": meta.my_pub.hex(),
        "x_identity_pub": meta.my_identity_pub.hex(),
        "x_qseed": meta.my_qseed.hex() if meta.my_qseed else None,
        "ml_kem_algorithm": KEM_ALGORITHM,
        "ml_kem_public_key": _b64_from_bytes(meta.ml_kem_public_key),
        "evo_config": serialize_evo_config(meta.evo_config).hex(),
        "label": meta.label,
        "username": my_username,
        "created_at": meta.created_at,
    }
    payload["signature"] = sign_identity(
        identity_priv,
        _handshake_signing_bytes(SIGN_INITIATOR_LABEL, payload),
    ).hex()
    return _serialize_handshake_payload(TYPE_INITIATOR, meta.session_id, payload)


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
    ml_kem_public_key = _b64_to_bytes(
        p.get("ml_kem_public_key"),
        "ML-KEM public key",
        "hybrid_kem_respond_failed",
    )
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
        "ml_kem_public_key": ml_kem_public_key,
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
    ml_kem_ciphertext: bytes,
) -> bytes:
    """Creates the signed session responder file."""
    _expect_len(session_id, SESSION_ID_LEN, "session id")
    _expect_len(x_pub, X25519_KEY_LEN, "X25519 public key")
    _expect_len(y_pub, X25519_KEY_LEN, "X25519 public key")
    _expect_len(x_identity_pub, ED25519_PUBLIC_LEN, "identity public key")
    _expect_len(y_identity_pub, ED25519_PUBLIC_LEN, "identity public key")
    if not isinstance(ml_kem_ciphertext, bytes) or not ml_kem_ciphertext:
        raise HybridKEMError("Missing ML-KEM ciphertext.", "hybrid_kem_respond_failed")
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
        "ml_kem_algorithm": KEM_ALGORITHM,
        "ml_kem_ciphertext": _b64_from_bytes(ml_kem_ciphertext),
        "evo_config": serialize_evo_config(evo_config).hex(),
        "label": label,
        "username": username,
    }
    payload["signature"] = sign_identity(
        identity_priv,
        _handshake_signing_bytes(SIGN_RESPONDER_LABEL, payload),
    ).hex()
    return _serialize_handshake_payload(TYPE_RESPONDER, session_id, payload)


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
    ml_kem_ciphertext = _b64_to_bytes(
        p.get("ml_kem_ciphertext"),
        "ML-KEM ciphertext",
        "hybrid_kem_complete_failed",
    )
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
        "ml_kem_ciphertext": ml_kem_ciphertext,
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
    kem_setup = initiator_kem_setup()
    created_at = int(time.time())

    if profile == "custom":
        if not custom_params:
            raise SessionError("Custom security parameters are required.")
        try:
            params = validate_argon2_params(
                custom_params["t"],
                custom_params["m"],
                custom_params["p"],
            )
        except (KeyError, TypeError) as exc:
            raise SessionError("Invalid custom security parameters.") from exc
    elif profile in SECURITY_PROFILES:
        params = SECURITY_PROFILES[profile]
    else:
        raise SessionError("Invalid security profile.")

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
        ml_kem_public_key=kem_setup["ml_kem_public_key"],
        ml_kem_secret_key=kem_setup["ml_kem_secret_key"],
        ml_kem_ciphertext=None,
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
    ml_kem_public_key = info["ml_kem_public_key"]
    evo_config = validate_evo_config(info["evo_config"])

    y_priv, y_pub = generate_keypair()
    y_qseed = random_bytes(QSEED_LEN)
    kem_response = responder_kem_respond(ml_kem_public_key)
    x25519_shared = ecdh(y_priv, x_pub)
    shared_secret = derive_hybrid_shared_secret(
        x25519_shared,
        kem_response["ml_kem_shared_secret"],
        session_id,
    )
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
        ml_kem_public_key=ml_kem_public_key,
        ml_kem_secret_key=None,
        ml_kem_ciphertext=kem_response["ml_kem_ciphertext"],
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
        ml_kem_ciphertext=kem_response["ml_kem_ciphertext"],
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
    ml_kem_ciphertext = info["ml_kem_ciphertext"]
    if not meta.ml_kem_secret_key:
        raise HybridKEMError("Missing ML-KEM secret key.", "hybrid_kem_complete_failed")
    evo_config = validate_evo_config(meta.evo_config)
    ml_kem_shared = initiator_kem_complete(meta.ml_kem_secret_key, ml_kem_ciphertext)
    x25519_shared = ecdh(meta.my_priv, y_pub)
    shared_secret = derive_hybrid_shared_secret(
        x25519_shared,
        ml_kem_shared,
        meta.session_id,
    )
    q_salt = (meta.my_qseed or b"") + (y_qseed or b"")
    keys = derive_session_keys(
        shared_secret,
        x_public=meta.my_pub,
        y_public=y_pub,
        extra_salt=meta.session_id,
        quantum_salt=q_salt if q_salt else None,
        a_time=evo_config.argon2_time,
        a_mem=evo_config.argon2_mem,
        a_par=evo_config.argon2_par,
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
        evo_config=evo_config,
        state=SESSION_STATE_UNVERIFIED,
        peer_identity_pub=info["y_identity_pub"],
        handshake_version=HANDSHAKE_VERSION,
        safety_confirmed=False,
        safety_confirmed_at=None,
        ml_kem_public_key=None,
        ml_kem_secret_key=None,
        ml_kem_ciphertext=ml_kem_ciphertext,
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
    """Returns the deterministic human safety code for a v3 session."""
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
    """Marks a v3 session active only after the local user confirms the SAS."""
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
    if meta.ml_kem_public_key is not None:
        data["ml_kem_public_key"] = meta.ml_kem_public_key.hex()
    if meta.ml_kem_secret_key is not None:
        data["ml_kem_secret_key"] = meta.ml_kem_secret_key.hex()
    if meta.ml_kem_ciphertext is not None:
        data["ml_kem_ciphertext"] = meta.ml_kem_ciphertext.hex()
    raw = json.dumps(data, separators=(",", ":")).encode("utf-8")
    blob = encrypt(device_key, raw, aad=b"paracci.db.session.v2")
    return blob.nonce + blob.ciphertext


def deserialize_session_meta(encrypted_data: bytes, device_key: bytes) -> SessionMeta:
    """Converts an encrypted database record into SessionMeta."""
    nonce = encrypted_data[:NONCE_LEN]
    blob = EncryptedBlob(nonce=nonce, ciphertext=encrypted_data[NONCE_LEN:])
    try:
        raw = decrypt(device_key, blob, aad=b"paracci.db.session.v2")
    except (InvalidTag, ValueError, TypeError):
        try:
            raw = decrypt(device_key, blob, aad=b"paracci.db.session.v1")
        except (InvalidTag, ValueError, TypeError) as exc:
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
        ml_kem_public_key=bytes.fromhex(data["ml_kem_public_key"]) if data.get("ml_kem_public_key") else None,
        ml_kem_secret_key=bytes.fromhex(data["ml_kem_secret_key"]) if data.get("ml_kem_secret_key") else None,
        ml_kem_ciphertext=bytes.fromhex(data["ml_kem_ciphertext"]) if data.get("ml_kem_ciphertext") else None,
    )


class SessionFileError(Exception):
    pass


class SessionError(Exception):
    pass
