import importlib
import json
import sys
from pathlib import Path

import pytest

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import session as session_module
from core.burn import BurnDB, init_device
from core.crypto import EncryptedBlob, NONCE_LEN, decrypt, encrypt, generate_identity_keypair, random_bytes
from core.evolution import EVO_UNLIMITED, serialize_evo_config
from core.hybrid_kem import HybridKEMError
from core.session import (
    HANDSHAKE_FILE_VERSION,
    TYPE_INITIATOR,
    accept_initiator_and_create_responder,
    confirm_safety_code,
    create_initiator_session,
    deserialize_session_meta,
    finalize_initiator_session,
    get_session_safety_code,
    serialize_session_meta,
)


TOKEN = "test-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"


def _identity():
    private_key, public_key = generate_identity_keypair()
    return private_key, public_key


def _handshake():
    x_identity_priv, x_identity_pub = _identity()
    y_identity_priv, y_identity_pub = _identity()
    meta_x, init_file = create_initiator_session(
        "Alice",
        session_ttl_sec=EVO_UNLIMITED,
        profile="standard",
        identity_pub=x_identity_pub,
        identity_priv=x_identity_priv,
    )
    meta_y, resp_file = accept_initiator_and_create_responder(
        init_file,
        "Bob",
        identity_pub=y_identity_pub,
        identity_priv=y_identity_priv,
    )
    finalized_x = finalize_initiator_session(meta_x, resp_file)
    return meta_x, finalized_x, meta_y, init_file, resp_file


def _decrypt_setup_payload(file_bytes: bytes, purpose: bytes) -> dict:
    session_id = file_bytes[6:22]
    header = file_bytes[:22]
    blob = EncryptedBlob(
        nonce=file_bytes[22:22 + NONCE_LEN],
        ciphertext=file_bytes[22 + NONCE_LEN:],
    )
    file_key = session_module._file_encryption_key(session_id, purpose)
    return json.loads(decrypt(file_key, blob, aad=header).decode("utf-8"))


def _tamper_and_reencrypt(file_bytes: bytes, purpose: bytes, mutator) -> bytes:
    session_id = file_bytes[6:22]
    header = file_bytes[:22]
    payload = _decrypt_setup_payload(file_bytes, purpose)
    mutator(payload)
    file_key = session_module._file_encryption_key(session_id, purpose)
    blob = encrypt(file_key, session_module._canonical_payload(payload), aad=header)
    return header + blob.nonce + blob.ciphertext


def _legacy_initiator_file(handshake_version: int) -> bytes:
    session_id = random_bytes(16)
    payload = {
        "handshake_version": handshake_version,
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
    header = session_module._build_file_header(
        TYPE_INITIATOR,
        session_id,
        file_version=session_module.FILE_VERSION,
    )
    file_key = session_module._file_encryption_key(session_id, b"initiator")
    blob = encrypt(file_key, session_module._canonical_payload(payload), aad=header)
    return header + blob.nonce + blob.ciphertext


def _save_meta(db: BurnDB, device_key: bytes, meta) -> None:
    db.save_session(
        session_id=meta.session_id,
        label=meta.label,
        state=meta.state,
        encrypted_meta=serialize_session_meta(meta, device_key),
        created_at=meta.created_at,
    )


def _decrypt_session_row(db: BurnDB, device_key: bytes, session_id: bytes) -> dict:
    row = db.load_session(session_id)
    blob = EncryptedBlob(row[2][:NONCE_LEN], row[2][NONCE_LEN:])
    return json.loads(decrypt(device_key, blob, aad=b"paracci.db.session.v2").decode("utf-8"))


@oqs_required
def test_full_v3_hybrid_handshake_roundtrip():
    _pending_x, meta_x, meta_y, init_file, resp_file = _handshake()

    assert init_file[4] == HANDSHAKE_FILE_VERSION
    assert resp_file[4] == HANDSHAKE_FILE_VERSION
    assert meta_x.handshake_version == 3
    assert meta_y.handshake_version == 3
    assert meta_x.keys == meta_y.keys
    assert get_session_safety_code(meta_x) == get_session_safety_code(meta_y)

    code = get_session_safety_code(meta_x)
    active_x = confirm_safety_code(meta_x, code)
    active_y = confirm_safety_code(meta_y, code)
    assert active_x.can_send
    assert active_y.can_open


def test_v1_and_v2_initiator_files_are_rejected_with_legacy_i18n_key():
    y_identity_priv, y_identity_pub = _identity()
    for handshake_version in (1, 2):
        with pytest.raises(HybridKEMError) as exc_info:
            accept_initiator_and_create_responder(
                _legacy_initiator_file(handshake_version),
                "Bob",
                identity_pub=y_identity_pub,
                identity_priv=y_identity_priv,
            )
        assert exc_info.value.i18n_key == "hybrid_kem_legacy_session"


@oqs_required
def test_v3_initiator_missing_ml_kem_public_key_raises_hybrid_error():
    x_identity_priv, x_identity_pub = _identity()
    y_identity_priv, y_identity_pub = _identity()
    _meta_x, init_file = create_initiator_session(
        "Alice",
        profile="standard",
        identity_pub=x_identity_pub,
        identity_priv=x_identity_priv,
    )
    tampered = _tamper_and_reencrypt(
        init_file,
        b"initiator",
        lambda payload: payload.pop("ml_kem_public_key", None),
    )

    with pytest.raises(HybridKEMError) as exc_info:
        accept_initiator_and_create_responder(
            tampered,
            "Bob",
            identity_pub=y_identity_pub,
            identity_priv=y_identity_priv,
        )
    assert exc_info.value.i18n_key == "hybrid_kem_respond_failed"


@oqs_required
def test_ml_kem_secret_key_is_absent_from_database_after_bond_completes(tmp_path):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = random_bytes(32)
    pending_x, finalized_x, _meta_y, _init_file, _resp_file = _handshake()

    _save_meta(db, device_key, pending_x)
    pending_data = _decrypt_session_row(db, device_key, pending_x.session_id)
    assert pending_data["ml_kem_secret_key"] == pending_x.ml_kem_secret_key.hex()

    _save_meta(db, device_key, finalized_x)
    finalized_data = _decrypt_session_row(db, device_key, finalized_x.session_id)
    assert "ml_kem_secret_key" not in finalized_data

    restored = deserialize_session_meta(db.load_session(finalized_x.session_id)[2], device_key)
    assert restored.ml_kem_secret_key is None
    assert restored.keys == finalized_x.keys


def test_hybrid_kem_error_in_initiator_setup_uses_safe_route_message(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_TOKEN", TOKEN)
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "1")

    import app as ag_app

    ag_app = importlib.reload(ag_app)
    flask_app = ag_app.create_app()
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()
    client.get(
        f"/__paracci_bootstrap?token={TOKEN}&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )
    ag_app.device_key = init_device(ag_app.db, "Correct-Horse-95175328")
    with client.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]
        csrf_token = sess["csrf_token"]

    def fail_setup():
        raise HybridKEMError("internal mock KEM failure", "hybrid_kem_init_failed")

    monkeypatch.setattr(session_module, "initiator_kem_setup", fail_setup)
    response = client.post(
        "/session/new",
        base_url=ORIGIN,
        data={"label": "Alice", "session_ttl": "0", "security_profile": "standard"},
        headers={
            "Host": HOST,
            "X-Paracci-Token": TOKEN,
            "X-CSRF-Token": csrf_token,
            "Origin": ORIGIN,
        },
    )

    assert response.status_code == 200
    assert b"Post-quantum key generation failed. Please try again." in response.data
    assert b"internal mock KEM failure" not in response.data
    assert ag_app.db.list_sessions() == []
