"""
Paracci envelope protocol.

The public API is intentionally small because both the legacy Flask layer and
the native desktop layer depend on this module:

    seal_envelope(payload_bytes, session, single_use=True, ttl_seconds=0)
    open_envelope(file_bytes, session)

The on-disk format is preserved:
HEADER(52) + payload_len(4) + payload_nonce(12) + payload_ciphertext
+ sync_nonce(12) + sync_ciphertext + authenticity_seal(16).
"""

import json
import logging
import time
from typing import NamedTuple, Optional

from argon2.low_level import Type as LowLevelArgon2Type, hash_secret_raw

from .crypto import (
    EncryptedBlob,
    NONCE_LEN,
    encrypt,
    decrypt,
    new_message_id,
    pack_uint32,
    pack_uint64,
    unpack_uint32,
    unpack_uint64,
)
from .evolution import (
    EvoConfig,
    MAX_EVO_STEP,
    _advance_seed,
    _derive_msg_keys,
    check_session_ttl,
    compute_bond_seed,
    validate_evo_config,
    validate_evo_step,
)
from .integrity import generate_file_seal, verify_file_seal
from .session import SessionMeta

logger = logging.getLogger(__name__)

MAGIC_BYTES = b"PARC"
FILE_VERSION = 0x01
TYPE_MESSAGE = 0x20

DIR_X_TO_Y = 0x01
DIR_Y_TO_X = 0x02
FLAG_SINGLE_USE = 0x01
FLAG_HAS_TTL = 0x02

HEADER_SIZE = 52
SEAL_SIZE = 16


class EnvelopeHeader(NamedTuple):
    """Parsed message header."""

    magic: bytes
    version: int
    msg_type: int
    session_id: bytes
    msg_id: bytes
    direction: int
    flags: int
    evo_step: int
    expire_at: int


class OpenedEnvelope(NamedTuple):
    """Result of a successful envelope open operation."""

    msg_id: bytes
    session_id: bytes
    direction: int
    payload: bytes
    evo_step: int
    expire_at: int
    single_use: bool
    sync_data: dict
    bond_nonce: Optional[bytes]
    next_seed: bytes
    next_step: int

    @property
    def text(self) -> str:
        """Compatibility helper for callers that open text-only envelopes."""
        return self.payload.decode("utf-8")


class SealedEnvelope(NamedTuple):
    """Result of sealing a payload."""

    file_bytes: bytes
    msg_id: bytes
    session_id: bytes
    next_seed: bytes
    next_step: int


def _build_header(
    session_id: bytes,
    msg_id: bytes,
    direction: int,
    single_use: bool,
    evo_step: int,
    expire_at: int,
) -> bytes:
    flags = 0
    if single_use:
        flags |= FLAG_SINGLE_USE
    if expire_at > 0:
        flags |= FLAG_HAS_TTL

    return (
        MAGIC_BYTES
        + bytes([FILE_VERSION, TYPE_MESSAGE])
        + session_id
        + msg_id
        + bytes([direction, flags])
        + pack_uint32(evo_step)
        + pack_uint64(expire_at)
    )


def _parse_header(data: bytes) -> EnvelopeHeader:
    if len(data) < HEADER_SIZE:
        raise EnvelopeError("File too short.")
    if data[:4] != MAGIC_BYTES:
        raise EnvelopeError("Invalid file signature.")
    if data[4] != FILE_VERSION:
        raise EnvelopeError("Unsupported version.")
    if data[5] != TYPE_MESSAGE:
        raise EnvelopeError("Not a message file.")

    offset = 6
    session_id = data[offset : offset + 16]
    offset += 16
    msg_id = data[offset : offset + 16]
    offset += 16
    direction = data[offset]
    offset += 1
    flags = data[offset]
    offset += 1
    evo_step = unpack_uint32(data[offset : offset + 4])
    offset += 4
    expire_at = unpack_uint64(data[offset : offset + 8])

    if direction not in (DIR_X_TO_Y, DIR_Y_TO_X):
        raise EnvelopeDirectionError("Invalid message direction.")
    try:
        validate_evo_step(evo_step)
    except Exception as exc:
        raise EnvelopeError("Evolution step too large.") from exc

    return EnvelopeHeader(
        magic=MAGIC_BYTES,
        version=FILE_VERSION,
        msg_type=TYPE_MESSAGE,
        session_id=session_id,
        msg_id=msg_id,
        direction=direction,
        flags=flags,
        evo_step=evo_step,
        expire_at=expire_at,
    )


def _build_sync_payload(
    sender_role: str,
    evo_step: int,
    msg_id: bytes,
    bond_nonce: Optional[bytes],
) -> bytes:
    payload = {
        "sender": sender_role,
        "step": evo_step,
        "mid": msg_id.hex(),
        "ts": int(time.time()),
    }
    if bond_nonce is not None:
        payload["bond_nonce"] = bond_nonce.hex()
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _parse_sync_payload(raw: bytes) -> dict:
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise EnvelopeError("Sync block is malformed.") from exc


def _validate_seal_session(session: SessionMeta) -> None:
    if session.keys is None:
        raise EnvelopeError("Session not initialized.")
    if session.state != "active":
        raise EnvelopeError("Session not active.")
    if not session.safety_confirmed:
        raise EnvelopeError("Session safety code has not been confirmed.")
    if not session.is_bonded:
        if session.role == "X":
            raise EnvelopeError("Bond not established. X must finalize first.")
        raise EnvelopeError("Bond not established. Y must receive X's first message.")
    try:
        validate_evo_config(session.evo_config)
    except Exception as exc:
        raise EnvelopeError("Invalid evolution configuration.") from exc
    check_session_ttl(session.evo_config)


def _prepare_seal_keys(session: SessionMeta) -> tuple[int, bytes, bytes, int]:
    current_seed = session.send_seed or session.bond_seed
    if current_seed is None:
        raise EnvelopeError("No sending seed available.")

    try:
        step = validate_evo_step(session.tx_count)
    except Exception as exc:
        raise EnvelopeError("Invalid evolution step.") from exc
    kxy, kyx, next_seed = _derive_msg_keys(current_seed, step)
    if session.role == "X":
        return DIR_X_TO_Y, kxy, next_seed, step
    if session.role == "Y":
        return DIR_Y_TO_X, kyx, next_seed, step
    raise EnvelopeError("Invalid session role.")


def _compute_work_key(
    msg_key: bytes,
    header: bytes,
    qseed: Optional[bytes],
    config: EvoConfig,
) -> bytes:
    """Computes a key derived with Argon2id for Quantum Armor (Time-Lock)."""
    config = validate_evo_config(config)
    return hash_secret_raw(
        secret=msg_key,
        salt=header + (qseed or b"no-quantum-armor"),
        time_cost=config.argon2_time,
        memory_cost=config.argon2_mem,
        parallelism=config.argon2_par,
        hash_len=32,
        type=LowLevelArgon2Type.ID,
    )


def seal_envelope(
    payload_bytes: bytes | str,
    session: SessionMeta,
    single_use: bool = True,
    ttl_seconds: int = 0,
) -> SealedEnvelope:
    """Encrypts a payload into a .paracci message envelope."""
    if isinstance(payload_bytes, str):
        payload_bytes = payload_bytes.encode("utf-8")
    if ttl_seconds < 0:
        raise EnvelopeError("Message TTL cannot be negative.")

    _validate_seal_session(session)
    direction, msg_key, next_seed, step = _prepare_seal_keys(session)

    msg_id = new_message_id()
    expire_at = int(time.time()) + ttl_seconds if ttl_seconds > 0 else 0
    header = _build_header(
        session.session_id,
        msg_id,
        direction,
        single_use,
        step,
        expire_at,
    )

    work_key = _compute_work_key(msg_key, header, session.my_qseed, session.evo_config)
    payload_blob = encrypt(work_key, payload_bytes, aad=header)

    is_bond_init = session.role == "X" and step == 0 and session.bond_nonce is not None
    sync_raw = _build_sync_payload(
        session.role,
        step,
        msg_id,
        session.bond_nonce if is_bond_init else None,
    )
    sync_blob = encrypt(session.keys.sync_key, sync_raw, aad=header + b"sync")

    content = (
        header
        + pack_uint32(len(payload_blob.ciphertext))
        + payload_blob.nonce
        + payload_blob.ciphertext
        + sync_blob.nonce
        + sync_blob.ciphertext
    )
    file_bytes = content + generate_file_seal(content)

    return SealedEnvelope(
        file_bytes=file_bytes,
        msg_id=msg_id,
        session_id=session.session_id,
        next_seed=next_seed,
        next_step=step + 1,
    )


def open_envelope(file_bytes: bytes, session: SessionMeta) -> OpenedEnvelope:
    """Parses and decrypts a .paracci message envelope."""
    if len(file_bytes) < HEADER_SIZE + 4 + (NONCE_LEN * 2) + SEAL_SIZE:
        raise EnvelopeError("File too small.")

    seal = file_bytes[-SEAL_SIZE:]
    content = file_bytes[:-SEAL_SIZE]
    if not verify_file_seal(content, seal):
        logger.warning("Envelope authenticity seal did not verify.")
        raise EnvelopeError("Envelope authenticity seal did not verify.")

    header_bytes = content[:HEADER_SIZE]
    header = _parse_header(header_bytes)
    _validate_envelope_context(header, session)

    payload_blob, sync_blob = _split_body(content[HEADER_SIZE:])
    sync_data, bond_nonce = _decrypt_sync_block(header_bytes, sync_blob, session)
    msg_key, next_seed = _derive_receive_keys(header, bond_nonce, session)

    work_key = _compute_work_key(msg_key, header_bytes, session.peer_qseed, session.evo_config)

    try:
        plaintext = decrypt(work_key, payload_blob, aad=header_bytes)
    except Exception as exc:
        detail = str(exc) or "Integrity verification failed."
        raise EnvelopeError(f"Payload decryption failed. Detail: {detail}") from exc

    return OpenedEnvelope(
        msg_id=header.msg_id,
        session_id=header.session_id,
        direction=header.direction,
        payload=plaintext,
        evo_step=header.evo_step,
        expire_at=header.expire_at,
        single_use=bool(header.flags & FLAG_SINGLE_USE),
        sync_data=sync_data,
        bond_nonce=bond_nonce,
        next_seed=next_seed,
        next_step=header.evo_step + 1,
    )


def _validate_envelope_context(header: EnvelopeHeader, session: SessionMeta) -> None:
    if header.session_id != session.session_id:
        raise EnvelopeError("This file does not belong to this session.")
    if session.keys is None:
        raise EnvelopeError("Session keys missing.")
    if not session.can_open:
        raise EnvelopeError("Session safety code has not been confirmed.")
    if session.role == "X" and header.direction == DIR_X_TO_Y:
        raise EnvelopeError("Cannot open your own message.")
    if session.role == "Y" and header.direction == DIR_Y_TO_X:
        raise EnvelopeError("Cannot open your own message.")
    if header.expire_at > 0 and int(time.time()) >= header.expire_at:
        raise EnvelopeTTLError("Message expired. Cannot open.")
    try:
        validate_evo_config(session.evo_config)
    except Exception as exc:
        raise EnvelopeError("Invalid evolution configuration.") from exc
    check_session_ttl(session.evo_config)


def _decrypt_sync_block(
    header_bytes: bytes,
    sync_blob: EncryptedBlob,
    session: SessionMeta,
) -> tuple[dict, Optional[bytes]]:
    try:
        sync_raw = decrypt(session.keys.sync_key, sync_blob, aad=header_bytes + b"sync")
    except Exception as exc:
        raise EnvelopeError("Sync block decryption failed.") from exc

    sync_data = _parse_sync_payload(sync_raw)
    bond_nonce = None
    if "bond_nonce" in sync_data:
        try:
            bond_nonce = bytes.fromhex(sync_data["bond_nonce"])
        except ValueError as exc:
            raise EnvelopeError("Sync block contains an invalid bond nonce.") from exc
    return sync_data, bond_nonce


def _derive_receive_keys(
    header: EnvelopeHeader,
    bond_nonce: Optional[bytes],
    session: SessionMeta,
) -> tuple[bytes, bytes]:
    try:
        header_step = validate_evo_step(header.evo_step)
        rx_count = validate_evo_step(session.rx_count)
    except Exception as exc:
        raise EnvelopeError("Invalid evolution step.") from exc

    if bond_nonce is not None:
        current_seed = compute_bond_seed(session.keys.evo_seed, bond_nonce)
        start_step = 0
    elif session.recv_seed is not None:
        current_seed = session.recv_seed
        start_step = rx_count
    else:
        raise EnvelopeError("Bond not established. X's first message is required.")

    if header_step < rx_count:
        raise EnvelopeError(
            f"Old message rejected (step {header_step} < current {rx_count})."
        )

    for step in range(start_step, header_step):
        current_seed = _advance_seed(current_seed, step)

    kxy, kyx, next_seed = _derive_msg_keys(current_seed, header_step)
    if header.direction == DIR_X_TO_Y and session.role == "Y":
        return kxy, next_seed
    if header.direction == DIR_Y_TO_X and session.role == "X":
        return kyx, next_seed
    raise EnvelopeDirectionError("Envelope direction does not match this session role.")


def _split_body(body: bytes) -> tuple[EncryptedBlob, EncryptedBlob]:
    if len(body) < 4 + (NONCE_LEN * 2) + 16:
        raise EnvelopeError("File content too short.")

    payload_ct_len = unpack_uint32(body[:4])
    offset = 4
    payload_nonce = body[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    payload_ct = body[offset : offset + payload_ct_len]
    offset += payload_ct_len
    sync_nonce = body[offset : offset + NONCE_LEN]
    offset += NONCE_LEN
    sync_ct = body[offset:]

    if len(payload_nonce) != NONCE_LEN or len(sync_nonce) != NONCE_LEN:
        raise EnvelopeError("File content is truncated.")
    if len(payload_ct) != payload_ct_len:
        raise EnvelopeError("Payload length mismatch.")
    if len(sync_ct) < 16:
        raise EnvelopeError("Sync block is truncated.")

    return (
        EncryptedBlob(nonce=payload_nonce, ciphertext=payload_ct),
        EncryptedBlob(nonce=sync_nonce, ciphertext=sync_ct),
    )


class EnvelopeError(Exception):
    """Base envelope error."""


class EnvelopeTTLError(EnvelopeError):
    """Envelope or session TTL has expired."""


class EnvelopeDirectionError(EnvelopeError):
    """Envelope direction is invalid for the active session."""
