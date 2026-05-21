import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import crypto
from core.burn import BurnDB
from core.crypto import EncryptedBlob, decrypt, encrypt, random_bytes
from core.evolution import EVO_UNLIMITED, make_evo_config
from core.session import (
    LEGACY_HANDSHAKE_VERSION,
    NONCE_LEN,
    SESSION_STATE_UNVERIFIED,
    SessionMeta,
    deserialize_session_meta,
    serialize_session_meta,
)
from desktop import device_key_binding as binding
from desktop.device_key_binding import initialize_device_with_binding, unlock_device_with_binding


PASSPHRASE = "Correct-Horse-95175328"


def _fake_windows_dpapi(monkeypatch):
    monkeypatch.setattr(binding.sys, "platform", "win32")
    monkeypatch.setattr(binding, "wrap_with_dpapi", lambda data: b"fake-dpapi:" + data)
    monkeypatch.setattr(binding, "unwrap_with_dpapi", lambda blob: blob.removeprefix(b"fake-dpapi:"))


def test_verify_identity_signature_rejects_bad_input_but_propagates_unexpected(monkeypatch):
    _private_key, public_key = crypto.generate_identity_keypair()

    assert crypto.verify_identity_signature(public_key, b"message", b"\x00" * 64) is False
    assert crypto.verify_identity_signature(b"too-short", b"message", b"\x00" * 64) is False

    class BrokenEd25519PublicKey:
        @staticmethod
        def from_public_bytes(_public_key_bytes):
            raise RuntimeError("unexpected verification bug")

    monkeypatch.setattr(crypto, "Ed25519PublicKey", BrokenEd25519PublicKey)

    with pytest.raises(RuntimeError, match="unexpected verification bug"):
        crypto.verify_identity_signature(public_key, b"message", b"\x00" * 64)


def test_deserialize_session_meta_preserves_legacy_v1_aad_fallback():
    device_key = random_bytes(32)
    meta = SessionMeta(
        session_id=random_bytes(16),
        role="X",
        my_priv=random_bytes(32),
        my_pub=random_bytes(32),
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
        color="#0a84ff",
        evo_config=make_evo_config(EVO_UNLIMITED),
        state=SESSION_STATE_UNVERIFIED,
        label="Legacy",
        created_at=1,
        my_identity_pub=None,
        peer_identity_pub=None,
        handshake_version=LEGACY_HANDSHAKE_VERSION,
        safety_confirmed=False,
        safety_confirmed_at=None,
    )
    encrypted_v2 = serialize_session_meta(meta, device_key)
    blob_v2 = EncryptedBlob(
        nonce=encrypted_v2[:NONCE_LEN],
        ciphertext=encrypted_v2[NONCE_LEN:],
    )
    raw = decrypt(device_key, blob_v2, aad=b"paracci.db.session.v2")
    encrypted_v1 = encrypt(device_key, raw, aad=b"paracci.db.session.v1")

    restored = deserialize_session_meta(encrypted_v1.nonce + encrypted_v1.ciphertext, device_key)

    assert restored.session_id == meta.session_id
    assert restored.state == SESSION_STATE_UNVERIFIED
    assert restored.safety_confirmed is False


def test_windows_bound_unlock_does_not_recast_sqlite_errors(tmp_path, monkeypatch):
    _fake_windows_dpapi(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")
    initialize_device_with_binding(db, PASSPHRASE)

    def raise_sqlite_error(*_args, **_kwargs):
        raise sqlite3.OperationalError("database is locked")

    monkeypatch.setattr(binding, "_decrypt_stored_device_key", raise_sqlite_error)

    with pytest.raises(sqlite3.OperationalError, match="database is locked"):
        unlock_device_with_binding(db, PASSPHRASE)
