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

from .constants import (
    HANDSHAKE_FILE_VERSION_V4,
    HANDSHAKE_FILE_VERSION_V5,
    HANDSHAKE_FILE_VERSION_V6,
    HANDSHAKE_TRANSCRIPT_VERSION,
    KEM_ALGORITHM,
    LEGACY_HANDSHAKE_FILE_WRAPPER_DOMAIN_V3,
)
from .crypto import (
    DerivedKeys,
    EncryptedBlob,
    KEY_LEN,
    NONCE_LEN,
    compute_handshake_transcript,
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
    wipe,
)
from .evolution import (
    EVO_UNLIMITED,
    EvoConfig,
    compute_bond_seed,
    deserialize_evo_config,
    make_evo_config,
    serialize_evo_config,
    validate_evo_config,
)
from .hybrid_kem import (
    HYBRID_HANDSHAKE_VERSION,
    HybridKEMError,
    initiator_kem_complete,
    initiator_kem_setup,
    responder_kem_respond,
    validate_hybrid_handshake_payload,
)

MAGIC_BYTES = b"PARC"
FILE_VERSION = 0x01
LEGACY_WRAPPED_HANDSHAKE_FILE_VERSION = 0x03
HANDSHAKE_FILE_VERSION = HANDSHAKE_FILE_VERSION_V6
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
# v5: signed public metadata with transcript-bound derivation and protocol Argon2.
# v6: transcript-bound hybrid key derivation without protocol Argon2.
SIGN_INITIATOR_LABEL = b"paracci.handshake.initiator.v3"
SIGN_RESPONDER_LABEL = b"paracci.handshake.responder.v3"

X25519_KEY_LEN = 32
ED25519_PUBLIC_LEN = 32
ED25519_SIGNATURE_LEN = 64
SESSION_ID_LEN = 16

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
    handshake_file_version: int = HANDSHAKE_FILE_VERSION
    transcript_version: Optional[int] = None

    @property
    def is_bonded(self) -> bool:
        """Is the message ratchet bond established?"""
        return self.send_seed is not None and self.recv_seed is not None

    @property
    def is_transcript_bound(self) -> bool:
        """Was this session derived with the identity-bound transcript combiner?"""
        return (
            self.handshake_file_version >= HANDSHAKE_FILE_VERSION_V5
            and self.transcript_version == HANDSHAKE_TRANSCRIPT_VERSION
        )

    @property
    def can_send(self) -> bool:
        """Can a message be sent?"""
        return (
            self.state == SESSION_STATE_ACTIVE
            and self.is_bonded
            and self.safety_confirmed
            and self.is_transcript_bound
        )

    @property
    def can_open(self) -> bool:
        """Can an incoming message be opened?"""
        return (
            self.state == SESSION_STATE_ACTIVE
            and self.keys is not None
            and self.safety_confirmed
            and self.is_transcript_bound
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
        if file_version < HANDSHAKE_FILE_VERSION:
            raise HybridKEMError(
                "This setup file uses a retired key-hardening format. Please start a new session.",
                "session.legacy_handshake_version",
            )
        if file_version > HANDSHAKE_FILE_VERSION:
            raise SessionFileError("Unsupported handshake version.")
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
    payload = {
        "handshake_version": HANDSHAKE_VERSION,
        "session_id": session_id.hex(),
        "x_pub": x_pub.hex(),
        "x_identity_pub": x_identity_pub.hex(),
        "y_pub": y_pub.hex(),
        "y_identity_pub": y_identity_pub.hex(),
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
        "ml_kem_ciphertext": ml_kem_ciphertext,
        "evo_config": evo_config,
        "label": p["label"],
        "username": p.get("username"),
    }


def create_initiator_session(
    label: str,
    session_ttl_sec: int = EVO_UNLIMITED,
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
    kem_setup = initiator_kem_setup()
    created_at = int(time.time())

    evo_config = make_evo_config(
        session_ttl_sec=session_ttl_sec,
        created_at=created_at,
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
        my_qseed=None,
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
        handshake_file_version=HANDSHAKE_FILE_VERSION,
        transcript_version=HANDSHAKE_TRANSCRIPT_VERSION,
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
    ml_kem_public_key = info["ml_kem_public_key"]
    evo_config = validate_evo_config(info["evo_config"])

    y_priv, y_pub = generate_keypair()
    try:
        kem_response = responder_kem_respond(ml_kem_public_key)
        ml_kem_ciphertext = kem_response["ml_kem_ciphertext"]
        ml_kem_shared = kem_response["ml_kem_shared_secret"]
        x25519_shared = ecdh(y_priv, x_pub)
        transcript = compute_handshake_transcript(
            session_id=session_id,
            initiator_identity_pub=x_identity_pub,
            responder_identity_pub=identity_pub,
            ml_kem_algorithm=KEM_ALGORITHM,
            ml_kem_public_key=ml_kem_public_key,
            ml_kem_ciphertext=ml_kem_ciphertext,
        )
        shared_secret = derive_hybrid_shared_secret(
            x25519_shared=x25519_shared,
            ml_kem_shared=ml_kem_shared,
            session_id=session_id,
            transcript=transcript,
        )
        keys = derive_session_keys(
            shared_secret,
            x_public=x_pub,
            y_public=y_pub,
            extra_salt=session_id,
        )

        meta = SessionMeta(
            session_id=session_id,
            role="Y",
            my_priv=None,  # Ephemeral private key zeroized, no need to persist
            my_pub=y_pub,
            peer_pub=x_pub,
            keys=keys,
            bond_seed=None,
            send_seed=None,
            recv_seed=None,
            bond_nonce=None,
            tx_count=0,
            rx_count=0,
            my_qseed=None,
            peer_qseed=None,
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
            ml_kem_ciphertext=ml_kem_ciphertext,
            handshake_file_version=HANDSHAKE_FILE_VERSION,
            transcript_version=HANDSHAKE_TRANSCRIPT_VERSION,
        )
        resp_bytes = serialize_responder_file(
            session_id,
            y_pub,
            evo_config,
            info["label"],
            username=my_username,
            x_pub=x_pub,
            x_identity_pub=x_identity_pub,
            y_identity_pub=identity_pub,
            identity_priv=identity_priv,
            ml_kem_ciphertext=ml_kem_ciphertext,
        )
        return meta, resp_bytes
    finally:
        wipe(y_priv)


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
    ml_kem_ciphertext = info["ml_kem_ciphertext"]
    if not meta.ml_kem_secret_key:
        raise HybridKEMError("Missing ML-KEM secret key.", "hybrid_kem_complete_failed")
    if not meta.ml_kem_public_key:
        raise HybridKEMError("Missing ML-KEM public key.", "hybrid_kem_complete_failed")
    evo_config = validate_evo_config(meta.evo_config)
    try:
        ml_kem_shared = initiator_kem_complete(meta.ml_kem_secret_key, ml_kem_ciphertext)
        x25519_shared = ecdh(meta.my_priv, y_pub)
        transcript = compute_handshake_transcript(
            session_id=meta.session_id,
            initiator_identity_pub=meta.my_identity_pub,
            responder_identity_pub=info["y_identity_pub"],
            ml_kem_algorithm=KEM_ALGORITHM,
            ml_kem_public_key=meta.ml_kem_public_key,
            ml_kem_ciphertext=ml_kem_ciphertext,
        )
        shared_secret = derive_hybrid_shared_secret(
            x25519_shared=x25519_shared,
            ml_kem_shared=ml_kem_shared,
            session_id=meta.session_id,
            transcript=transcript,
        )
        keys = derive_session_keys(
            shared_secret,
            x_public=meta.my_pub,
            y_public=y_pub,
            extra_salt=meta.session_id,
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
            peer_qseed=None,
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
            handshake_file_version=HANDSHAKE_FILE_VERSION,
            transcript_version=HANDSHAKE_TRANSCRIPT_VERSION,
        )
    finally:
        if meta.my_priv is not None:
            wipe(meta.my_priv)
        if meta.ml_kem_secret_key is not None:
            wipe(meta.ml_kem_secret_key)


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
    """Returns the deterministic human safety code for a transcript-bound session."""
    if not meta.is_transcript_bound:
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


def require_transcript_bound_session(meta: SessionMeta) -> None:
    """Reject established sessions whose keys were derived without transcript binding."""
    if not meta.is_transcript_bound:
        raise HybridKEMError(
            "This session was created without identity binding. Please ask your contact to start a new session.",
            "session.legacy_session_requires_new",
        )


# ---------------------------------------------------------------------------
# Binary serialization helpers for secret session fields (v3 format)
# ---------------------------------------------------------------------------

_SESSION_BINARY_VERSION = b"\x02"
_SESSION_V3_AAD = b"paracci.db.session.v3"


def _pack_secret_field(buf: bytearray, value: bytes | bytearray | None) -> None:
    """Append a 2-byte length-prefixed raw field to *buf*.

    Uses ``0xFFFF`` as a sentinel to represent an absent (``None``) field so
    that no immutable heap string is ever created for secret key material.
    """
    if value is None:
        buf += (0xFFFF).to_bytes(2, "big")
    else:
        n = len(value)
        if n >= 0xFFFF:
            raise SessionError("Secret field too large to serialize.")
        buf += n.to_bytes(2, "big")
        buf += bytes(value)


def _unpack_secret_field(blob: bytes | bytearray, offset: int) -> tuple:
    """Read one length-prefixed field from *blob* at *offset*.

    Returns ``(bytearray | None, new_offset)``.  The returned bytearray
    is a copy that the caller may wipe independently.
    """
    length = int.from_bytes(blob[offset: offset + 2], "big")
    if length == 0xFFFF:
        return None, offset + 2
    return bytearray(blob[offset + 2: offset + 2 + length]), offset + 2 + length


def serialize_session_meta(meta: SessionMeta, device_key: bytes) -> bytes:
    """Serializes session data by encrypting it for the local database.

    Secret key material (session keys, ratchet seeds, private keys) is packed
    into a raw binary blob that is passed directly to the AEAD cipher — it
    never passes through a Python ``str`` or ``.hex()`` call.  Non-secret,
    public fields (counters, state strings, public keys, timestamps) are
    JSON-encoded as before.

    Wire format (plaintext after AEAD decryption)::

        [1 byte  ] version tag = 0x02
        [4 bytes ] big-endian length of secret blob
        [N bytes ] secret blob  — length-prefixed raw fields (canonical order)
        [4 bytes ] big-endian length of public JSON blob
        [M bytes ] public JSON  — UTF-8

    Old records (v1 / v2 AAD) continue to be readable through the legacy
    fallback path in ``deserialize_session_meta`` and are silently upgraded
    to v3 on the next write.
    """
    # --- 1. Build the secret binary blob (bytearray, never str) ---
    secret_buf = bytearray()
    _pack_secret_field(secret_buf, meta.my_priv)
    _pack_secret_field(secret_buf, meta.keys.key_x_to_y if meta.keys else None)
    _pack_secret_field(secret_buf, meta.keys.key_y_to_x if meta.keys else None)
    _pack_secret_field(secret_buf, meta.keys.sync_key   if meta.keys else None)
    _pack_secret_field(secret_buf, meta.keys.evo_seed   if meta.keys else None)
    _pack_secret_field(secret_buf, meta.bond_seed)
    _pack_secret_field(secret_buf, meta.send_seed)
    _pack_secret_field(secret_buf, meta.recv_seed)
    _pack_secret_field(secret_buf, meta.bond_nonce)
    _pack_secret_field(secret_buf, meta.my_qseed)
    _pack_secret_field(secret_buf, meta.peer_qseed)
    _pack_secret_field(secret_buf, meta.ml_kem_secret_key)

    # --- 2. Build the public JSON blob (non-secret fields only) ---
    public_data: dict = {
        "session_id":             meta.session_id.hex(),
        "role":                   meta.role,
        "my_pub":                 meta.my_pub.hex(),
        "peer_pub":               meta.peer_pub.hex() if meta.peer_pub else None,
        "has_keys":               meta.keys is not None,
        "tx_count":               meta.tx_count,
        "rx_count":               meta.rx_count,
        "peer_username":          meta.peer_username,
        "color":                  meta.color,
        "evo_config":             serialize_evo_config(meta.evo_config).hex(),
        "state":                  meta.state,
        "label":                  meta.label,
        "created_at":             meta.created_at,
        "my_identity_pub":        meta.my_identity_pub.hex() if meta.my_identity_pub else None,
        "peer_identity_pub":      meta.peer_identity_pub.hex() if meta.peer_identity_pub else None,
        "handshake_version":      meta.handshake_version,
        "handshake_file_version": meta.handshake_file_version,
        "transcript_version":     meta.transcript_version,
        "safety_confirmed":       meta.safety_confirmed,
        "safety_confirmed_at":    meta.safety_confirmed_at,
        "ml_kem_public_key":      meta.ml_kem_public_key.hex() if meta.ml_kem_public_key else None,
        "ml_kem_ciphertext":      meta.ml_kem_ciphertext.hex() if meta.ml_kem_ciphertext else None,
    }
    json_bytes = json.dumps(public_data, separators=(",", ":")).encode("utf-8")

    # --- 3. Assemble the versioned envelope ---
    secret_len = len(secret_buf)
    json_len = len(json_bytes)
    envelope = bytearray()
    envelope += _SESSION_BINARY_VERSION
    envelope += secret_len.to_bytes(4, "big")
    envelope += secret_buf
    envelope += json_len.to_bytes(4, "big")
    envelope += json_bytes

    # --- 4. Encrypt then wipe all sensitive buffers ---
    try:
        blob = encrypt(device_key, bytes(envelope), aad=_SESSION_V3_AAD)
        return blob.nonce + blob.ciphertext
    finally:
        wipe(secret_buf)
        wipe(envelope)


def _deserialize_v3(raw: bytes | bytearray) -> "SessionMeta":
    """Reconstruct a ``SessionMeta`` from a decrypted v3 binary envelope."""
    # --- 1. Parse envelope ---
    if len(raw) < 9:  # 1 version + 4 secret_len + 4 json_len minimum
        raise SessionError("Session data is too short.")
    secret_len = int.from_bytes(raw[1:5], "big")
    secret_blob = raw[5: 5 + secret_len]
    json_offset = 5 + secret_len
    json_len = int.from_bytes(raw[json_offset: json_offset + 4], "big")
    json_bytes = raw[json_offset + 4: json_offset + 4 + json_len]

    # --- 2. Unpack secret fields (fixed canonical order — must match serialize) ---
    pos = 0
    my_priv,           pos = _unpack_secret_field(secret_blob, pos)
    keys_x_to_y,       pos = _unpack_secret_field(secret_blob, pos)
    keys_y_to_x,       pos = _unpack_secret_field(secret_blob, pos)
    keys_sync,         pos = _unpack_secret_field(secret_blob, pos)
    keys_evo,          pos = _unpack_secret_field(secret_blob, pos)
    bond_seed,         pos = _unpack_secret_field(secret_blob, pos)
    send_seed,         pos = _unpack_secret_field(secret_blob, pos)
    recv_seed,         pos = _unpack_secret_field(secret_blob, pos)
    bond_nonce,        pos = _unpack_secret_field(secret_blob, pos)
    my_qseed_ba,       pos = _unpack_secret_field(secret_blob, pos)
    peer_qseed_ba,     pos = _unpack_secret_field(secret_blob, pos)
    ml_kem_secret_key, pos = _unpack_secret_field(secret_blob, pos)

    # --- 3. Parse public JSON ---
    data = json.loads(json_bytes.decode("utf-8"))

    # --- 4. Reconstruct DerivedKeys if present ---
    keys = None
    if data.get("has_keys") and all(
        k is not None for k in (keys_x_to_y, keys_y_to_x, keys_sync, keys_evo)
    ):
        keys = DerivedKeys(
            key_x_to_y=keys_x_to_y,
            key_y_to_x=keys_y_to_x,
            sync_key=keys_sync,
            evo_seed=keys_evo,
        )

    # --- 5. Reconstruct version / safety state (same logic as legacy path) ---
    handshake_version = int(data.get("handshake_version", LEGACY_HANDSHAKE_VERSION))
    handshake_file_version = int(data.get("handshake_file_version", HANDSHAKE_FILE_VERSION_V4))
    transcript_version_raw = data.get("transcript_version")
    transcript_version = int(transcript_version_raw) if transcript_version_raw is not None else None
    transcript_bound = (
        handshake_file_version >= HANDSHAKE_FILE_VERSION_V5
        and transcript_version == HANDSHAKE_TRANSCRIPT_VERSION
    )
    safety_confirmed = bool(data.get("safety_confirmed", False)) if transcript_bound else False
    state = data["state"]
    if not transcript_bound and state == SESSION_STATE_ACTIVE:
        state = SESSION_STATE_UNVERIFIED
    if transcript_bound and not safety_confirmed and state == SESSION_STATE_ACTIVE:
        state = SESSION_STATE_UNVERIFIED

    return SessionMeta(
        session_id=bytes.fromhex(data["session_id"]),
        role=data["role"],
        my_priv=my_priv,
        my_pub=bytes.fromhex(data["my_pub"]),
        peer_pub=bytes.fromhex(data["peer_pub"]) if data.get("peer_pub") else None,
        keys=keys,
        bond_seed=bond_seed,
        send_seed=send_seed,
        recv_seed=recv_seed,
        bond_nonce=bond_nonce,
        tx_count=data.get("tx_count", 0),
        rx_count=data.get("rx_count", 0),
        my_qseed=bytes(my_qseed_ba) if my_qseed_ba is not None else None,
        peer_qseed=bytes(peer_qseed_ba) if peer_qseed_ba is not None else None,
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
        ml_kem_secret_key=ml_kem_secret_key,
        ml_kem_ciphertext=bytes.fromhex(data["ml_kem_ciphertext"]) if data.get("ml_kem_ciphertext") else None,
        handshake_file_version=handshake_file_version,
        transcript_version=transcript_version,
    )


def _deserialize_legacy_json(raw: bytes) -> "SessionMeta":
    """Reconstruct a ``SessionMeta`` from a legacy v1/v2 JSON plaintext."""
    data = json.loads(raw.decode("utf-8"))
    keys = None
    if data.get("keys"):
        keys = DerivedKeys(
            key_x_to_y=bytearray(bytes.fromhex(data["keys"]["x_to_y"])),
            key_y_to_x=bytearray(bytes.fromhex(data["keys"]["y_to_x"])),
            sync_key=bytearray(bytes.fromhex(data["keys"]["sync"])),
            evo_seed=bytearray(bytes.fromhex(data["keys"]["evo"])),
        )

    handshake_version = int(data.get("handshake_version", LEGACY_HANDSHAKE_VERSION))
    handshake_file_version = int(data.get("handshake_file_version", HANDSHAKE_FILE_VERSION_V4))
    transcript_version_raw = data.get("transcript_version")
    transcript_version = int(transcript_version_raw) if transcript_version_raw is not None else None
    transcript_bound = (
        handshake_file_version >= HANDSHAKE_FILE_VERSION_V5
        and transcript_version == HANDSHAKE_TRANSCRIPT_VERSION
    )
    safety_confirmed = bool(data.get("safety_confirmed", False)) if transcript_bound else False
    state = data["state"]
    if not transcript_bound and state == SESSION_STATE_ACTIVE:
        state = SESSION_STATE_UNVERIFIED
    if transcript_bound and not safety_confirmed and state == SESSION_STATE_ACTIVE:
        state = SESSION_STATE_UNVERIFIED

    return SessionMeta(
        session_id=bytes.fromhex(data["session_id"]),
        role=data["role"],
        my_priv=bytearray(bytes.fromhex(data["my_priv"])) if data.get("my_priv") else None,
        my_pub=bytes.fromhex(data["my_pub"]),
        peer_pub=bytes.fromhex(data["peer_pub"]) if data.get("peer_pub") else None,
        keys=keys,
        bond_seed=bytearray(bytes.fromhex(data["bond_seed"])) if data.get("bond_seed") else None,
        send_seed=bytearray(bytes.fromhex(data["send_seed"])) if data.get("send_seed") else None,
        recv_seed=bytearray(bytes.fromhex(data["recv_seed"])) if data.get("recv_seed") else None,
        bond_nonce=bytearray(bytes.fromhex(data["bond_nonce"])) if data.get("bond_nonce") else None,
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
        ml_kem_secret_key=bytearray(bytes.fromhex(data["ml_kem_secret_key"])) if data.get("ml_kem_secret_key") else None,
        ml_kem_ciphertext=bytes.fromhex(data["ml_kem_ciphertext"]) if data.get("ml_kem_ciphertext") else None,
        handshake_file_version=handshake_file_version,
        transcript_version=transcript_version,
    )


def deserialize_session_meta(encrypted_data: bytes, device_key: bytes) -> SessionMeta:
    """Converts an encrypted database record into SessionMeta.

    Supports three record versions:

    - **v3** (new): binary envelope, AAD = ``b"paracci.db.session.v3"``
    - **v2** (legacy): JSON plaintext, AAD = ``b"paracci.db.session.v2"``
    - **v1** (legacy): JSON plaintext, AAD = ``b"paracci.db.session.v1"``

    Old records are transparently read through the fallback chain and
    silently upgraded to v3 format on the next ``serialize_session_meta`` call.
    """
    nonce = encrypted_data[:NONCE_LEN]
    blob = EncryptedBlob(nonce=nonce, ciphertext=encrypted_data[NONCE_LEN:])

    # --- Try v3 first ---
    # Only catch InvalidTag here (= decryption key mismatch / wrong AAD).
    # ValueError / TypeError raised by _deserialize_v3 (e.g. from a malicious
    # evo_config or structural corruption of a successfully-decrypted envelope)
    # must propagate directly to the caller — swallowing them would let the
    # fallback chain silently discard tampered data instead of rejecting it.
    try:
        raw = decrypt(device_key, blob, aad=_SESSION_V3_AAD)
    except InvalidTag:
        pass
    else:
        if raw[:1] == _SESSION_BINARY_VERSION:
            return _deserialize_v3(raw)
        raise SessionError("Session data format is unrecognized.")

    # --- Fall back to legacy JSON paths (v2 then v1) ---
    try:
        raw = decrypt(device_key, blob, aad=b"paracci.db.session.v2")
        return _deserialize_legacy_json(raw)
    except (InvalidTag, ValueError, TypeError):
        pass

    try:
        raw = decrypt(device_key, blob, aad=b"paracci.db.session.v1")
        return _deserialize_legacy_json(raw)
    except (InvalidTag, ValueError, TypeError) as exc:
        raise SessionError("Session data could not be decrypted.") from exc
class SessionFileError(Exception):
    pass


class SessionError(Exception):
    pass
