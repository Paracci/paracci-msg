import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import burn as burn_module
from core.burn import (
    BURN_STATUS_FAILED,
    PROTECTED_VALUE_PREFIX,
    STORAGE_MIGRATION_COMPLETE,
    STORAGE_MIGRATION_KEY,
    UNLOCK_EVER_SUCCEEDED_KEY,
    UNLOCK_RATE_LIMIT_KEY,
    BurnDB,
    DeviceError,
)
from core.crypto import message_id_fingerprint, new_message_id, random_bytes


def _raw_row(db_path, query, params=()):
    with sqlite3.connect(db_path) as conn:
        return conn.execute(query, params).fetchone()


def test_protected_fields_round_trip_without_plaintext_in_raw_storage(tmp_path):
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path, device_key=random_bytes(32))
    session_id = new_message_id()
    msg_id = new_message_id()
    label = "Alice Confidential"
    failure_reason = "Decryption failed for Alice Confidential"
    device_value = b"private profile metadata"

    db.save_session(session_id, label, "active", b"encrypted-session-meta", 1)
    db.set_device_meta("private_note", device_value)
    assert db.reserve_open(msg_id) is True
    db.mark_open_failed(msg_id, failure_reason)

    assert db.load_session(session_id)[0] == label
    assert db.get_device_meta("private_note") == device_value

    raw_label = _raw_row(
        db_path, "SELECT label FROM sessions WHERE session_id=?", (session_id,)
    )[0]
    raw_reason = _raw_row(
        db_path,
        "SELECT failure_reason FROM burned_messages WHERE fingerprint=?",
        (message_id_fingerprint(msg_id),),
    )[0]
    raw_device = _raw_row(
        db_path, "SELECT value FROM device_meta WHERE key='private_note'"
    )[0]

    for value, plaintext in (
        (raw_label, label.encode("utf-8")),
        (raw_reason, failure_reason.encode("utf-8")),
        (raw_device, device_value),
    ):
        assert isinstance(value, bytes)
        assert value.startswith(PROTECTED_VALUE_PREFIX)
        assert plaintext not in value


def test_equal_labels_use_distinct_ciphertext_and_are_row_bound(tmp_path):
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path, device_key=random_bytes(32))
    first_id = new_message_id()
    second_id = new_message_id()

    db.save_session(first_id, "Same Label", "active", b"one", 1)
    db.save_session(second_id, "Same Label", "active", b"two", 1)

    first_value = _raw_row(
        db_path, "SELECT label FROM sessions WHERE session_id=?", (first_id,)
    )[0]
    second_value = _raw_row(
        db_path, "SELECT label FROM sessions WHERE session_id=?", (second_id,)
    )[0]
    assert first_value != second_value

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE sessions SET label=? WHERE session_id=?",
            (first_value, second_id),
        )
    with pytest.raises(DeviceError, match="Invalid protected metadata"):
        db.load_session(second_id)


def test_wrong_key_and_locked_access_fail_closed_while_bootstrap_remains_available(tmp_path):
    db_path = tmp_path / "sessions.db"
    key = random_bytes(32)
    db = BurnDB(db_path, device_key=key)
    session_id = new_message_id()
    db.save_session(session_id, "Protected Label", "active", b"metadata", 1)
    db.set_device_meta("private_note", b"protected")
    db.set_device_meta("pin_salt", b"bootstrap-salt")
    db.set_device_meta(UNLOCK_RATE_LIMIT_KEY, b'{"failed_attempts":0}')
    db.set_device_meta(UNLOCK_EVER_SUCCEEDED_KEY, b"1")

    locked = BurnDB(db_path)
    assert locked.session_exists(session_id) is True
    assert locked.get_device_meta("pin_salt") == b"bootstrap-salt"
    assert locked.get_device_meta(UNLOCK_RATE_LIMIT_KEY) == b'{"failed_attempts":0}'
    assert locked.get_device_meta(UNLOCK_EVER_SUCCEEDED_KEY) == b"1"
    with pytest.raises(DeviceError, match="protected metadata"):
        locked.load_session(session_id)
    with pytest.raises(DeviceError, match="protected metadata"):
        locked.get_device_meta("private_note")
    with pytest.raises(DeviceError, match="protected metadata"):
        locked.set_device_meta("private_note", b"replacement")

    with pytest.raises(DeviceError, match="Invalid protected metadata"):
        BurnDB(db_path, device_key=random_bytes(32))


def test_legacy_plaintext_rows_are_migrated_and_scrubbed_on_first_keyed_open(tmp_path):
    db_path = tmp_path / "sessions.db"
    BurnDB(db_path)
    key = random_bytes(32)
    session_id = new_message_id()
    msg_id = new_message_id()
    fingerprint = message_id_fingerprint(msg_id)
    label = "Legacy Alice Contact"
    failure_reason = "Legacy Alice failure detail"
    private_value = b"legacy private device value"

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO sessions
                (session_id, label, state, encrypted_meta, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, label, "active", b"encrypted-meta", 1, 1),
        )
        conn.execute(
            """
            INSERT INTO burned_messages
                (fingerprint, status, reserved_at, burned_at, failed_at,
                 session_id, failure_reason, direction)
            VALUES (?, ?, ?, NULL, ?, ?, ?, ?)
            """,
            (fingerprint, BURN_STATUS_FAILED, 1, 1, session_id, failure_reason, 1),
        )
        conn.execute(
            "INSERT INTO device_meta (key, value) VALUES (?, ?)",
            ("private_note", private_value),
        )
        conn.execute(
            "INSERT INTO device_meta (key, value) VALUES (?, ?)",
            ("pin_salt", b"plain-bootstrap"),
        )
        conn.execute(
            "INSERT INTO device_meta (key, value) VALUES (?, ?)",
            (UNLOCK_RATE_LIMIT_KEY, b'{"failed_attempts":0}'),
        )
        conn.execute(
            "INSERT INTO device_meta (key, value) VALUES (?, ?)",
            (UNLOCK_EVER_SUCCEEDED_KEY, b"1"),
        )

    db = BurnDB(db_path, device_key=key)
    assert db.load_session(session_id)[0] == label
    assert db.get_device_meta("private_note") == private_value
    assert db.get_device_meta("pin_salt") == b"plain-bootstrap"
    assert db.get_device_meta(UNLOCK_RATE_LIMIT_KEY) == b'{"failed_attempts":0}'
    assert db.get_device_meta(UNLOCK_EVER_SUCCEEDED_KEY) == b"1"

    raw_label = _raw_row(
        db_path, "SELECT label FROM sessions WHERE session_id=?", (session_id,)
    )[0]
    raw_reason = _raw_row(
        db_path,
        "SELECT failure_reason FROM burned_messages WHERE fingerprint=?",
        (fingerprint,),
    )[0]
    raw_device = _raw_row(
        db_path, "SELECT value FROM device_meta WHERE key='private_note'"
    )[0]
    marker = _raw_row(
        db_path, "SELECT value FROM burn_internal_meta WHERE key=?", (STORAGE_MIGRATION_KEY,)
    )[0]

    assert label.encode("utf-8") not in raw_label
    assert failure_reason.encode("utf-8") not in raw_reason
    assert private_value not in raw_device
    assert (
        db._decrypt_protected_value(
            "burn_internal_meta", "value", STORAGE_MIGRATION_KEY, marker
        )
        == STORAGE_MIGRATION_COMPLETE
    )

    current_files = [db_path, Path(f"{db_path}-wal")]
    for path in current_files:
        if path.exists():
            contents = path.read_bytes()
            assert label.encode("utf-8") not in contents
            assert failure_reason.encode("utf-8") not in contents
            assert private_value not in contents

    assert db.reserve_open(msg_id) is True


def test_legacy_migration_rolls_back_if_encryption_fails(tmp_path, monkeypatch):
    db_path = tmp_path / "sessions.db"
    BurnDB(db_path)
    session_id = new_message_id()
    failing_value = b"rollback private metadata"

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO sessions
                (session_id, label, state, encrypted_meta, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, "Rollback Label", "active", b"encrypted-meta", 1, 1),
        )
        conn.execute(
            "INSERT INTO device_meta (key, value) VALUES (?, ?)",
            ("private_note", failing_value),
        )

    real_encrypt = burn_module.encrypt

    def fail_private_value(key, plaintext, aad=b""):
        if plaintext == failing_value:
            raise RuntimeError("forced migration failure")
        return real_encrypt(key, plaintext, aad=aad)

    monkeypatch.setattr(burn_module, "encrypt", fail_private_value)
    with pytest.raises(RuntimeError, match="forced migration failure"):
        BurnDB(db_path, device_key=random_bytes(32))

    assert _raw_row(
        db_path, "SELECT label FROM sessions WHERE session_id=?", (session_id,)
    )[0] == "Rollback Label"
    assert _raw_row(
        db_path, "SELECT value FROM device_meta WHERE key='private_note'"
    )[0] == failing_value
    assert _raw_row(
        db_path, "SELECT value FROM burn_internal_meta WHERE key=?", (STORAGE_MIGRATION_KEY,)
    ) is None
