import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import session as session_module
from core.burn import BurnDB
from core.crypto import (
    EncryptedBlob,
    NONCE_LEN,
    decrypt,
    encrypt,
    generate_identity_keypair,
    random_bytes,
)
from core.envelope import EnvelopeError, open_envelope, seal_envelope
from core.evolution import EVO_UNLIMITED, serialize_evo_config
from core.identity import get_or_create_device_identity
from core.session import (
    SESSION_STATE_ACTIVE,
    SESSION_STATE_UNVERIFIED,
    accept_initiator_and_create_responder,
    confirm_safety_code,
    create_initiator_session,
    deserialize_session_meta,
    finalize_initiator_session,
    get_session_safety_code,
)


def _identity():
    private_key, public_key = generate_identity_keypair()
    return private_key, public_key


def _handshake():
    x_identity_priv, x_identity_pub = _identity()
    y_identity_priv, y_identity_pub = _identity()
    meta_x, init_file = create_initiator_session(
        "X",
        session_ttl_sec=EVO_UNLIMITED,
        profile="standard",
        identity_pub=x_identity_pub,
        identity_priv=x_identity_priv,
    )
    meta_y, resp_file = accept_initiator_and_create_responder(
        init_file,
        "Y",
        identity_pub=y_identity_pub,
        identity_priv=y_identity_priv,
    )
    meta_x = finalize_initiator_session(meta_x, resp_file)
    return meta_x, meta_y, init_file, resp_file


def _confirmed_handshake():
    meta_x, meta_y, init_file, resp_file = _handshake()
    code = get_session_safety_code(meta_x)
    assert code == get_session_safety_code(meta_y)
    return confirm_safety_code(meta_x, code), confirm_safety_code(meta_y, code), init_file, resp_file


def _tamper_and_reencrypt(file_bytes: bytes, purpose: bytes, mutator) -> bytes:
    session_id = file_bytes[6:22]
    header = file_bytes[:22]
    blob = EncryptedBlob(
        nonce=file_bytes[22:22 + NONCE_LEN],
        ciphertext=file_bytes[22 + NONCE_LEN:],
    )
    fkey = session_module._file_encryption_key(session_id, purpose)
    payload = json.loads(decrypt(fkey, blob, aad=header).decode("utf-8"))
    mutator(payload)
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    sealed = encrypt(fkey, raw, aad=header)
    return header + sealed.nonce + sealed.ciphertext


def test_signed_handshake_requires_safety_confirmation_before_messages():
    meta_x, meta_y, _init_file, _resp_file = _handshake()

    assert meta_x.state == SESSION_STATE_UNVERIFIED
    assert meta_y.state == SESSION_STATE_UNVERIFIED
    assert not meta_x.can_send
    assert not meta_y.can_open

    with pytest.raises(EnvelopeError):
        seal_envelope(b"blocked", meta_x)

    code = get_session_safety_code(meta_x)
    assert code == get_session_safety_code(meta_y)
    assert len(code.replace("-", "")) == 24

    meta_x = confirm_safety_code(meta_x, code)
    meta_y = confirm_safety_code(meta_y, code)
    assert meta_x.state == SESSION_STATE_ACTIVE
    assert meta_x.can_send
    assert meta_y.can_open

    sealed = seal_envelope(b"hello", meta_x)
    opened = open_envelope(sealed.file_bytes, meta_y)
    assert opened.payload == b"hello"


def test_modified_initiator_payload_is_rejected_after_reencrypt():
    _meta_x, _meta_y, init_file, _resp_file = _handshake()
    y_identity_priv, y_identity_pub = _identity()
    tampered = _tamper_and_reencrypt(
        init_file,
        b"initiator",
        lambda payload: payload.__setitem__("label", "attacker label"),
    )

    with pytest.raises(Exception):
        accept_initiator_and_create_responder(
            tampered,
            "Y",
            identity_pub=y_identity_pub,
            identity_priv=y_identity_priv,
        )


def test_modified_responder_payload_is_rejected_after_reencrypt():
    meta_x, _meta_y, _init_file, resp_file = _handshake()
    tampered = _tamper_and_reencrypt(
        resp_file,
        b"responder",
        lambda payload: payload.__setitem__("username", "attacker"),
    )

    with pytest.raises(Exception):
        finalize_initiator_session(meta_x, tampered)


def test_unsigned_legacy_initiator_file_is_rejected():
    x_priv, x_pub = _identity()
    del x_priv
    session_id = random_bytes(16)
    payload = {
        "session_id": session_id.hex(),
        "x_pub": random_bytes(32).hex(),
        "x_qseed": random_bytes(128).hex(),
        "evo_config": serialize_evo_config(
            session_module.make_evo_config(session_ttl_sec=EVO_UNLIMITED)
        ).hex(),
        "label": "legacy",
        "username": "legacy",
        "created_at": 1,
    }
    header = session_module._build_file_header(session_module.TYPE_INITIATOR, session_id)
    fkey = session_module._file_encryption_key(session_id, b"initiator")
    blob = encrypt(fkey, json.dumps(payload, separators=(",", ":")).encode("utf-8"), aad=header)
    legacy_file = header + blob.nonce + blob.ciphertext
    y_identity_priv, y_identity_pub = _identity()

    with pytest.raises(Exception):
        accept_initiator_and_create_responder(
            legacy_file,
            "Y",
            identity_pub=y_identity_pub,
            identity_priv=y_identity_priv,
        )


def test_safety_confirmation_rejects_wrong_code():
    meta_x, _meta_y, _init_file, _resp_file = _handshake()

    with pytest.raises(Exception):
        confirm_safety_code(meta_x, "0000-0000-0000-0000-0000-0000")


def test_identity_keypair_persists_encrypted_in_device_metadata(tmp_path):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = random_bytes(32)

    first = get_or_create_device_identity(db, device_key)
    second = get_or_create_device_identity(db, device_key)

    assert first == second
    assert db.get_device_meta("identity_ed25519_v1") is not None
    assert first.private_key not in db.get_device_meta("identity_ed25519_v1")


def test_legacy_session_metadata_deserializes_as_unverified():
    meta_x, _meta_y, _init_file, _resp_file = _confirmed_handshake()
    device_key = random_bytes(32)
    keys_data = {
        "x_to_y": meta_x.keys.key_x_to_y.hex(),
        "y_to_x": meta_x.keys.key_y_to_x.hex(),
        "sync": meta_x.keys.sync_key.hex(),
        "evo": meta_x.keys.evo_seed.hex(),
    }
    legacy_data = {
        "session_id": meta_x.session_id.hex(),
        "role": meta_x.role,
        "my_priv": meta_x.my_priv.hex(),
        "my_pub": meta_x.my_pub.hex(),
        "peer_pub": meta_x.peer_pub.hex(),
        "keys": keys_data,
        "bond_seed": meta_x.bond_seed.hex(),
        "send_seed": meta_x.send_seed.hex(),
        "recv_seed": meta_x.recv_seed.hex(),
        "bond_nonce": meta_x.bond_nonce.hex(),
        "tx_count": meta_x.tx_count,
        "rx_count": meta_x.rx_count,
        "my_qseed": meta_x.my_qseed.hex(),
        "peer_qseed": meta_x.peer_qseed.hex(),
        "peer_username": meta_x.peer_username,
        "color": meta_x.color,
        "evo_config": serialize_evo_config(meta_x.evo_config).hex(),
        "state": SESSION_STATE_ACTIVE,
        "label": meta_x.label,
        "created_at": meta_x.created_at,
    }
    blob = encrypt(
        device_key,
        json.dumps(legacy_data, separators=(",", ":")).encode("utf-8"),
        aad=b"paracci.db.session.v2",
    )

    restored = deserialize_session_meta(blob.nonce + blob.ciphertext, device_key)

    assert restored.handshake_version == 1
    assert restored.state == SESSION_STATE_UNVERIFIED
    assert not restored.safety_confirmed
    assert not restored.can_send
