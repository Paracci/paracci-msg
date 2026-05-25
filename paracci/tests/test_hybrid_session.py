import importlib
import json
import sys
from pathlib import Path

import pytest

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import crypto as crypto_module
from core import session as session_module
from core.burn import BurnDB, init_device
from core.crypto import EncryptedBlob, NONCE_LEN, decrypt, generate_identity_keypair, random_bytes
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


def _load_setup_payload(file_bytes: bytes) -> dict:
    return json.loads(file_bytes[22:].decode("utf-8"))


def _tamper_signed_payload(file_bytes: bytes, mutator) -> bytes:
    payload = _load_setup_payload(file_bytes)
    mutator(payload)
    return file_bytes[:22] + session_module._canonical_payload(payload)


def _legacy_initiator_file(handshake_version: int) -> bytes:
    session_id = random_bytes(16)
    payload = {
        "handshake_version": handshake_version,
        "session_id": session_id.hex(),
        "x_pub": random_bytes(32).hex(),
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
        file_version=handshake_version,
    )
    return header + session_module._canonical_payload(payload)


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
def test_full_v6_hybrid_handshake_roundtrip(monkeypatch):
    transcript_calls = []
    real_compute_transcript = session_module.compute_handshake_transcript

    def capture_transcript(**kwargs):
        transcript_calls.append(dict(kwargs))
        return real_compute_transcript(**kwargs)

    monkeypatch.setattr(session_module, "compute_handshake_transcript", capture_transcript)
    pending_x, meta_x, meta_y, init_file, resp_file = _handshake()

    assert init_file[4] == HANDSHAKE_FILE_VERSION
    assert resp_file[4] == HANDSHAKE_FILE_VERSION
    assert _load_setup_payload(init_file)["session_id"] == meta_x.session_id.hex()
    assert _load_setup_payload(resp_file)["session_id"] == meta_x.session_id.hex()
    assert meta_x.handshake_version == session_module.HANDSHAKE_VERSION
    assert meta_y.handshake_version == session_module.HANDSHAKE_VERSION
    assert meta_x.handshake_file_version == HANDSHAKE_FILE_VERSION
    assert meta_y.handshake_file_version == HANDSHAKE_FILE_VERSION
    assert "x_qseed" not in _load_setup_payload(init_file)
    assert "y_qseed" not in _load_setup_payload(resp_file)
    assert meta_x.transcript_version == 1
    assert meta_y.transcript_version == 1
    assert meta_x.is_transcript_bound
    assert meta_y.is_transcript_bound
    assert meta_x.keys == meta_y.keys
    assert get_session_safety_code(meta_x) == get_session_safety_code(meta_y)
    assert len(transcript_calls) == 2
    assert transcript_calls[0]["initiator_identity_pub"] == transcript_calls[1]["initiator_identity_pub"]
    assert transcript_calls[0]["responder_identity_pub"] == transcript_calls[1]["responder_identity_pub"]
    assert transcript_calls[0]["initiator_identity_pub"] == pending_x.my_identity_pub
    assert transcript_calls[0]["responder_identity_pub"] == meta_y.my_identity_pub
    assert transcript_calls[0]["ml_kem_public_key"] == transcript_calls[1]["ml_kem_public_key"]
    assert transcript_calls[0]["ml_kem_ciphertext"] == transcript_calls[1]["ml_kem_ciphertext"]
    assert real_compute_transcript(**transcript_calls[0]) == real_compute_transcript(**transcript_calls[1])

    code = get_session_safety_code(meta_x)
    active_x = confirm_safety_code(meta_x, code)
    active_y = confirm_safety_code(meta_y, code)
    assert active_x.can_send
    assert active_y.can_open


def test_pre_v6_initiator_files_are_rejected_with_migration_i18n_key():
    y_identity_priv, y_identity_pub = _identity()
    for handshake_version in (1, 2, 4, 5):
        with pytest.raises(HybridKEMError) as exc_info:
            accept_initiator_and_create_responder(
                _legacy_initiator_file(handshake_version),
                "Bob",
                identity_pub=y_identity_pub,
                identity_priv=y_identity_priv,
            )
        assert exc_info.value.i18n_key == "session.legacy_handshake_version"


@oqs_required
def test_v5_responder_file_is_rejected_with_migration_i18n_key():
    pending_x, _meta_x, _meta_y, _init_file, resp_file = _handshake()
    legacy_resp = bytearray(resp_file)
    legacy_resp[4] = session_module.HANDSHAKE_FILE_VERSION_V5

    with pytest.raises(HybridKEMError) as exc_info:
        finalize_initiator_session(pending_x, bytes(legacy_resp))

    assert exc_info.value.i18n_key == "session.legacy_handshake_version"


@oqs_required
def test_v6_initiator_missing_ml_kem_public_key_raises_hybrid_error():
    x_identity_priv, x_identity_pub = _identity()
    y_identity_priv, y_identity_pub = _identity()
    _meta_x, init_file = create_initiator_session(
        "Alice",
        identity_pub=x_identity_pub,
        identity_priv=x_identity_priv,
    )
    tampered = _tamper_signed_payload(
        init_file,
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
def test_v6_handshake_session_derivation_does_not_call_argon2(monkeypatch):
    def fail_protocol_argon(*_args, **_kwargs):
        pytest.fail("new handshake session derivation must not invoke Argon2id")

    monkeypatch.setattr(crypto_module, "hash_secret_raw", fail_protocol_argon)
    _pending_x, meta_x, meta_y, _init_file, _resp_file = _handshake()
    assert meta_x.keys == meta_y.keys


@oqs_required
def test_ml_kem_secret_key_is_absent_from_database_after_bond_completes(tmp_path):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = random_bytes(32)
    pending_x, finalized_x, _meta_y, _init_file, resp_file = _handshake()

    _save_meta(db, device_key, pending_x)
    pending_data = _decrypt_session_row(db, device_key, pending_x.session_id)
    assert pending_data["ml_kem_secret_key"] == pending_x.ml_kem_secret_key.hex()
    assert pending_data["ml_kem_public_key"] == pending_x.ml_kem_public_key.hex()
    restored_pending = deserialize_session_meta(db.load_session(pending_x.session_id)[2], device_key)
    assert restored_pending.ml_kem_public_key == pending_x.ml_kem_public_key
    assert finalize_initiator_session(restored_pending, resp_file).keys == _meta_y.keys

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
        data={"label": "Alice", "session_ttl": "0"},
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
