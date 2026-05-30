import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import burn as burn_module
import sqlite3
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


def _raw_row(db_path, query, params=(), key=None):
    if key is not None:
        burn_module.MIGRATION_CONTEXT.device_key = key
        burn_module.MIGRATION_CONTEXT.db_path = db_path
    try:
        with sqlite3.connect(db_path) as conn:
            return conn.execute(query, params).fetchone()
    finally:
        if key is not None:
            burn_module.MIGRATION_CONTEXT.device_key = None
            burn_module.MIGRATION_CONTEXT.db_path = None


def _init_legacy_plaintext_db(db_path):
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id      BLOB PRIMARY KEY,
                label           BLOB NOT NULL,
                state           BLOB NOT NULL,
                encrypted_meta  BLOB NOT NULL,
                created_at      BLOB NOT NULL,
                updated_at      BLOB NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS burned_messages (
                fingerprint     BLOB PRIMARY KEY,
                status          BLOB NOT NULL,
                reserved_at     BLOB NOT NULL,
                burned_at       BLOB,
                failed_at       BLOB,
                session_id      BLOB,
                direction       BLOB,
                failure_reason  BLOB
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS device_meta (
                key             TEXT PRIMARY KEY,
                value           BLOB NOT NULL
            );
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS burn_internal_meta (
                key             TEXT PRIMARY KEY,
                value           BLOB NOT NULL
            );
            """
        )


def test_protected_fields_round_trip_without_plaintext_in_raw_storage(tmp_path):
    db_path = tmp_path / "sessions.db"
    device_key = random_bytes(32)
    db = BurnDB(db_path, device_key=device_key)
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
        db_path, "SELECT label FROM sessions WHERE session_id=?", (session_id,), key=device_key
    )[0]
    raw_reason = _raw_row(
        db_path,
        "SELECT failure_reason FROM burned_messages WHERE fingerprint=?",
        (message_id_fingerprint(msg_id),),
        key=device_key
    )[0]
    raw_device = _raw_row(
        str(db_path) + ".meta", "SELECT value FROM device_meta WHERE key='private_note'"
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
    device_key = random_bytes(32)
    db = BurnDB(db_path, device_key=device_key)
    first_id = new_message_id()
    second_id = new_message_id()

    db.save_session(first_id, "Same Label", "active", b"one", 1)
    db.save_session(second_id, "Same Label", "active", b"two", 1)

    first_value = _raw_row(
        db_path, "SELECT label FROM sessions WHERE session_id=?", (first_id,), key=device_key
    )[0]
    second_value = _raw_row(
        db_path, "SELECT label FROM sessions WHERE session_id=?", (second_id,), key=device_key
    )[0]
    assert first_value != second_value

    burn_module.MIGRATION_CONTEXT.device_key = device_key
    burn_module.MIGRATION_CONTEXT.db_path = db_path
    try:
        with sqlite3.connect(db_path) as conn:
            conn.execute(
                "UPDATE sessions SET label=? WHERE session_id=?",
                (first_value, second_id),
            )
    finally:
        burn_module.MIGRATION_CONTEXT.device_key = None
        burn_module.MIGRATION_CONTEXT.db_path = None
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
    _init_legacy_plaintext_db(db_path)
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
        db_path, "SELECT label FROM sessions WHERE session_id=?", (session_id,), key=key
    )[0]
    raw_reason = _raw_row(
        db_path,
        "SELECT failure_reason FROM burned_messages WHERE fingerprint=?",
        (fingerprint,),
        key=key
    )[0]
    raw_device = _raw_row(
        str(db_path) + ".meta", "SELECT value FROM device_meta WHERE key='private_note'"
    )[0]
    marker = _raw_row(
        str(db_path) + ".meta", "SELECT value FROM burn_internal_meta WHERE key=?", (STORAGE_MIGRATION_KEY,)
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
    _init_legacy_plaintext_db(db_path)
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
    device_key = random_bytes(32)
    monkeypatch.setattr(burn_module, "encrypt", fail_private_value)
    with pytest.raises(RuntimeError, match="forced migration failure"):
        BurnDB(db_path, device_key=device_key)

    assert _raw_row(
        db_path, "SELECT label FROM sessions WHERE session_id=?", (session_id,), key=device_key
    )[0] == "Rollback Label"
    assert _raw_row(
        str(db_path) + ".meta", "SELECT value FROM device_meta WHERE key='private_note'"
    )[0] == failing_value
    assert _raw_row(
        str(db_path) + ".meta", "SELECT value FROM burn_internal_meta WHERE key=?", (STORAGE_MIGRATION_KEY,)
    ) is None


def test_v2_protected_fields_and_migration(tmp_path):
    from core.burn import STORAGE_MIGRATION_V2_KEY
    db_path = tmp_path / "sessions.db"
    key = random_bytes(32)
    session_id = new_message_id()
    msg_id = new_message_id()
    fingerprint = message_id_fingerprint(msg_id)

    # Part 1: Test encryption on write for new fields
    db = BurnDB(db_path, device_key=key)
    db.save_session(session_id, "Label V2", "active_v2", b"encrypted-session-meta", 12345)
    assert db.reserve_open(msg_id) is True
    db.mark_open_burned(msg_id, session_id, 2)

    # Check raw DB has encrypted fields
    raw_state = _raw_row(db_path, "SELECT state FROM sessions WHERE session_id=?", (session_id,), key=key)[0]
    raw_created_at = _raw_row(db_path, "SELECT created_at FROM sessions WHERE session_id=?", (session_id,), key=key)[0]
    raw_updated_at = _raw_row(db_path, "SELECT updated_at FROM sessions WHERE session_id=?", (session_id,), key=key)[0]

    raw_status = _raw_row(db_path, "SELECT status FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]
    raw_reserved_at = _raw_row(db_path, "SELECT reserved_at FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]
    raw_burned_at = _raw_row(db_path, "SELECT burned_at FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]
    raw_session_id = _raw_row(db_path, "SELECT session_id FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]
    raw_direction = _raw_row(db_path, "SELECT direction FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]

    for val in (raw_state, raw_created_at, raw_updated_at, raw_status, raw_reserved_at, raw_burned_at, raw_session_id, raw_direction):
        assert isinstance(val, bytes)
        assert val.startswith(PROTECTED_VALUE_PREFIX)

    # API readback checks
    loaded = db.load_session(session_id)
    assert loaded[1] == "active_v2"
    assert loaded[3] == 12345

    sessions = db.list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["state"] == "active_v2"
    assert sessions[0]["created_at"] == 12345

    enc_label = db._encrypt_protected_value("sessions", "label", session_id, "Legacy V1 Label")
    enc_reason = db._encrypt_protected_value("burned_messages", "failure_reason", fingerprint, "Failed V1 Reason")
    enc_v1_complete = db._encrypt_protected_value("burn_internal_meta", "value", STORAGE_MIGRATION_KEY, STORAGE_MIGRATION_COMPLETE)

    db.release_device_key()

    # Part 2: Test migration of V2 fields from legacy plaintext database state
    # We clear the DB path and write raw legacy plaintext/v1-encrypted values
    if db_path.exists():
        db_path.unlink()
    # Delete WAL/shm files if they exist
    for suffix in ("-wal", "-shm"):
        p = Path(str(db_path) + suffix)
        if p.exists():
            p.unlink()

    # Initialize empty tables
    _init_legacy_plaintext_db(db_path)

    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            INSERT INTO sessions
                (session_id, label, state, encrypted_meta, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (session_id, enc_label, "legacy_active", b"enc-meta", 54321, 54322),
        )
        conn.execute(
            """
            INSERT INTO burned_messages
                (fingerprint, status, reserved_at, burned_at, failed_at,
                 session_id, failure_reason, direction)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (fingerprint, "failed", 54321, 54321, 54322, session_id, enc_reason, 1),
        )
        # Mark V1 migration complete, but no V2 migration entry
        conn.execute(
            "INSERT INTO burn_internal_meta (key, value) VALUES (?, ?)",
            (STORAGE_MIGRATION_KEY, enc_v1_complete),
        )

    # Open with key to trigger migration
    db_migrated = BurnDB(db_path, device_key=key)

    # Check that V2 fields are now encrypted in storage
    raw_state = _raw_row(db_path, "SELECT state FROM sessions WHERE session_id=?", (session_id,), key=key)[0]
    raw_created_at = _raw_row(db_path, "SELECT created_at FROM sessions WHERE session_id=?", (session_id,), key=key)[0]
    raw_updated_at = _raw_row(db_path, "SELECT updated_at FROM sessions WHERE session_id=?", (session_id,), key=key)[0]
    raw_status = _raw_row(db_path, "SELECT status FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]
    raw_reserved_at = _raw_row(db_path, "SELECT reserved_at FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]
    raw_burned_at = _raw_row(db_path, "SELECT burned_at FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]
    raw_failed_at = _raw_row(db_path, "SELECT failed_at FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]
    raw_session_id = _raw_row(db_path, "SELECT session_id FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]
    raw_direction = _raw_row(db_path, "SELECT direction FROM burned_messages WHERE fingerprint=?", (fingerprint,), key=key)[0]

    for val in (raw_state, raw_created_at, raw_updated_at, raw_status, raw_reserved_at, raw_burned_at, raw_failed_at, raw_session_id, raw_direction):
        assert isinstance(val, bytes)
        assert val.startswith(PROTECTED_VALUE_PREFIX)

    # Verify migration status
    marker_v2 = _raw_row(str(db_path) + ".meta", "SELECT value FROM burn_internal_meta WHERE key=?", (STORAGE_MIGRATION_V2_KEY,))[0]
    assert (
        db_migrated._decrypt_protected_value("burn_internal_meta", "value", STORAGE_MIGRATION_V2_KEY, marker_v2)
        == STORAGE_MIGRATION_COMPLETE
    )

    # API check readback of migrated data
    loaded = db_migrated.load_session(session_id)
    assert loaded[0] == "Legacy V1 Label"
    assert loaded[1] == "legacy_active"
    assert loaded[3] == 54321

    sessions = db_migrated.list_sessions()
    assert len(sessions) == 1
    assert sessions[0]["label"] == "Legacy V1 Label"
    assert sessions[0]["state"] == "legacy_active"
    assert sessions[0]["created_at"] == 54321
    assert sessions[0]["updated_at"] == 54322

