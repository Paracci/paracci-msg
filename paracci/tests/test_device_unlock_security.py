import json
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import burn as burn_module
import sqlite3
from core.burn import (
    UNLOCK_EVER_SUCCEEDED_KEY,
    UNLOCK_FAILURE_DELAYS,
    UNLOCK_MAX_FAILED_ATTEMPTS,
    UNLOCK_RATE_LIMIT_KEY,
    BurnDB,
    DeviceError,
    DeviceLockedError,
    init_device,
    unlock_device,
)
from core.crypto import derive_master_key, encrypt, random_bytes


STRONG_PASSPHRASE = "Correct-Horse-95175328"


def _stored_unlock_state(db):
    raw = db.get_device_meta(UNLOCK_RATE_LIMIT_KEY)
    if raw is None:
        return None
    # Use database's secure decoder to decrypt/verify the rate limit state
    decoded = db._decode_unlock_rate_limit(raw)
    decoded.pop("retry_after_seconds", None)
    return decoded


@pytest.mark.parametrize(
    "passphrase",
    [
        "short-12345",
        "aaaaaaaaaaaa",
        "abcabcabcabc",
        "abcdefghijkl",
        "password123456",
        "123456789012",
    ],
)
def test_weak_new_device_passphrases_are_rejected(tmp_path, passphrase):
    db = BurnDB(tmp_path / "sessions.db")

    with pytest.raises(DeviceError):
        init_device(db, passphrase)


def test_new_device_missing_rate_state_is_permissive_until_first_success(tmp_path):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, STRONG_PASSPHRASE)

    assert db.get_device_meta(UNLOCK_EVER_SUCCEEDED_KEY) is None
    assert db.get_device_meta(UNLOCK_RATE_LIMIT_KEY) is None
    db.assert_unlock_allowed(now=1000)
    assert db.get_device_meta(UNLOCK_RATE_LIMIT_KEY) is None

    assert unlock_device(db, STRONG_PASSPHRASE) == device_key
    assert db.get_device_meta(UNLOCK_EVER_SUCCEEDED_KEY) == b"1"
    assert _stored_unlock_state(db) == {
        "failed_attempts": 0,
        "last_failed_at": 0,
        "locked_until": 0,
    }


def test_strong_passphrase_unlocks_and_resets_failed_counter(tmp_path):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, STRONG_PASSPHRASE)

    with pytest.raises(DeviceError, match="Incorrect passphrase"):
        unlock_device(db, "Wrong-Horse-95175328")

    assert db.get_unlock_rate_limit()["failed_attempts"] == 1
    assert unlock_device(db, STRONG_PASSPHRASE) == device_key
    assert db.get_unlock_rate_limit()["failed_attempts"] == 0


def test_deleted_rate_state_after_success_is_delayed_and_repaired(tmp_path):
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path)
    init_device(db, STRONG_PASSPHRASE)
    unlock_device(db, STRONG_PASSPHRASE)
    db.delete_device_meta(UNLOCK_RATE_LIMIT_KEY)

    restarted = BurnDB(db_path)
    delay = UNLOCK_FAILURE_DELAYS[UNLOCK_MAX_FAILED_ATTEMPTS - 1]
    with pytest.raises(DeviceLockedError) as locked:
        restarted.assert_unlock_allowed(now=1000)
    assert locked.value.retry_after_seconds == delay
    assert _stored_unlock_state(restarted) == {
        "failed_attempts": UNLOCK_MAX_FAILED_ATTEMPTS - 1,
        "last_failed_at": 1000,
        "locked_until": 1000 + delay,
    }

    with pytest.raises(DeviceLockedError) as locked_again:
        restarted.reserve_unlock_attempt(now=1001)
    assert locked_again.value.retry_after_seconds == delay - 1
    assert _stored_unlock_state(restarted)["locked_until"] == 1000 + delay


def test_sessions_force_delay_if_both_unlock_policy_rows_are_deleted(tmp_path):
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path)
    device_key = init_device(db, STRONG_PASSPHRASE)
    keyed = db.with_device_key(device_key)
    try:
        keyed.save_session(random_bytes(16), "Existing Session", "active", b"metadata", 1)
    finally:
        keyed.release_device_key()

    with sqlite3.connect(str(db_path) + ".meta") as conn:
        conn.execute(
            "DELETE FROM device_meta WHERE key IN (?, ?)",
            (UNLOCK_RATE_LIMIT_KEY, UNLOCK_EVER_SUCCEEDED_KEY),
        )

    restarted = BurnDB(db_path)
    delay = UNLOCK_FAILURE_DELAYS[UNLOCK_MAX_FAILED_ATTEMPTS - 1]
    with pytest.raises(DeviceLockedError) as locked:
        restarted.assert_unlock_allowed(now=2000)
    assert locked.value.retry_after_seconds == delay
    assert _stored_unlock_state(restarted)["failed_attempts"] == UNLOCK_MAX_FAILED_ATTEMPTS - 1


def test_blocked_attempt_repersist_existing_rate_state(tmp_path):
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path)
    db.set_device_meta(UNLOCK_EVER_SUCCEEDED_KEY, b"1")
    db.set_device_meta(
        UNLOCK_RATE_LIMIT_KEY,
        db._encode_unlock_rate_limit(
            {"failed_attempts": 5, "last_failed_at": 1000, "locked_until": 1300}
        ),
    )
    with sqlite3.connect(str(db_path) + ".meta") as conn:
        conn.execute("CREATE TABLE unlock_rate_writes (id INTEGER PRIMARY KEY)")
        conn.execute(
            """
            CREATE TRIGGER capture_unlock_rate_rewrite
            AFTER INSERT ON device_meta
            WHEN NEW.key = 'unlock_rate_limit_v1'
            BEGIN
                INSERT INTO unlock_rate_writes (id) VALUES (NULL);
            END
            """
        )

    with pytest.raises(DeviceLockedError):
        db.reserve_unlock_attempt(now=1001)

    with sqlite3.connect(str(db_path) + ".meta") as conn:
        writes = conn.execute("SELECT COUNT(*) FROM unlock_rate_writes").fetchone()[0]
    assert writes == 1
    assert _stored_unlock_state(db)["locked_until"] == 1300


def test_successful_unlock_reserves_attempt_before_kdf_and_clears_it(tmp_path, monkeypatch):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, STRONG_PASSPHRASE)
    observed_failed_attempts = []
    real_derive_master_key = burn_module.derive_master_key

    def observed_derive_master_key(passphrase, salt):
        observed_failed_attempts.append(db.get_unlock_rate_limit()["failed_attempts"])
        return real_derive_master_key(passphrase, salt)

    monkeypatch.setattr(burn_module, "derive_master_key", observed_derive_master_key)

    assert burn_module.unlock_device(db, STRONG_PASSPHRASE) == device_key
    assert observed_failed_attempts == [1]
    assert db.get_unlock_rate_limit()["failed_attempts"] == 0


def test_parallel_wrong_unlocks_are_serialized_and_stopped_before_kdf(tmp_path, monkeypatch):
    db = BurnDB(tmp_path / "sessions.db")
    init_device(db, STRONG_PASSPHRASE)
    workers = 8
    start = threading.Barrier(workers)
    metrics_lock = threading.Lock()
    kdf_calls = 0
    active_kdfs = 0
    maximum_active_kdfs = 0

    def slow_wrong_derive_master_key(_passphrase, _salt):
        nonlocal kdf_calls, active_kdfs, maximum_active_kdfs
        with metrics_lock:
            kdf_calls += 1
            active_kdfs += 1
            maximum_active_kdfs = max(maximum_active_kdfs, active_kdfs)
        time.sleep(0.05)
        with metrics_lock:
            active_kdfs -= 1
        return bytearray(b"\x00" * 32)

    monkeypatch.setattr(burn_module, "derive_master_key", slow_wrong_derive_master_key)

    def attempt_unlock():
        start.wait(timeout=2)
        with pytest.raises(DeviceError):
            burn_module.unlock_device(db, "Wrong-Horse-95175328")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(lambda _index: attempt_unlock(), range(workers)))

    assert kdf_calls == 2
    assert maximum_active_kdfs == 1
    assert db.get_unlock_rate_limit()["failed_attempts"] == 2


def test_atomic_reservations_enforce_shared_database_budget(tmp_path, monkeypatch):
    db_path = tmp_path / "sessions.db"
    workers = 10
    dbs = [BurnDB(db_path) for _index in range(workers)]
    start = threading.Barrier(workers)
    monkeypatch.setattr(burn_module, "UNLOCK_FAILURE_DELAYS", {})

    def reserve_attempt(db):
        start.wait(timeout=2)
        try:
            db.reserve_unlock_attempt(now=1000)
        except DeviceLockedError:
            return False
        return True

    with ThreadPoolExecutor(max_workers=workers) as executor:
        admitted = list(executor.map(reserve_attempt, dbs))

    assert sum(admitted) == 5
    state = dbs[0].get_unlock_rate_limit(now=1000)
    assert state["failed_attempts"] == 5
    assert state["retry_after_seconds"] == 300


def test_unlock_lockout_state_is_durable(tmp_path):
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path)

    first = db.record_unlock_failure(now=1000)
    assert first["failed_attempts"] == 1
    assert first["retry_after_seconds"] == 0

    second = db.record_unlock_failure(now=1010)
    assert second["failed_attempts"] == 2
    assert second["retry_after_seconds"] == 2

    restarted = BurnDB(db_path)
    with pytest.raises(DeviceLockedError) as locked:
        restarted.assert_unlock_allowed(now=1011)
    assert locked.value.retry_after_seconds == 1

    restarted.assert_unlock_allowed(now=1013)

    third = restarted.record_unlock_failure(now=1013)
    assert third["failed_attempts"] == 3
    assert third["retry_after_seconds"] == 5

    fourth = restarted.record_unlock_failure(now=1019)
    assert fourth["failed_attempts"] == 4
    assert fourth["retry_after_seconds"] == 15

    fifth = restarted.record_unlock_failure(now=1035)
    assert fifth["failed_attempts"] == 5
    assert fifth["retry_after_seconds"] == 300

    after_restart = BurnDB(db_path)
    with pytest.raises(DeviceLockedError) as locked_again:
        after_restart.assert_unlock_allowed(now=1040)
    assert locked_again.value.retry_after_seconds == 295


def test_existing_short_legacy_pin_can_still_unlock(tmp_path):
    db = BurnDB(tmp_path / "sessions.db")
    legacy_passphrase = "95175328"
    passphrase_salt = random_bytes(16)
    master_key = derive_master_key(legacy_passphrase, passphrase_salt)
    device_key = random_bytes(32)
    blob = encrypt(master_key, device_key, aad=b"paracci.device_key.v1")

    # "pin_salt" is retained in device metadata keys to avoid breaking database compatibility
    db.set_device_meta("pin_salt", passphrase_salt)
    db.set_device_meta("encrypted_device_key", blob.nonce + blob.ciphertext)

    assert unlock_device(db, legacy_passphrase) == device_key


def test_device_master_keys_are_mutable_and_zeroed_after_use(tmp_path, monkeypatch):
    db = BurnDB(tmp_path / "sessions.db")
    wiped = []
    real_wipe = burn_module.wipe

    def track_wipe(value):
        assert isinstance(value, bytearray)
        real_wipe(value)
        wiped.append(value)

    monkeypatch.setattr(burn_module, "wipe", track_wipe)

    burn_module.init_device(db, STRONG_PASSPHRASE)
    burn_module.unlock_device(db, STRONG_PASSPHRASE)

    assert len(wiped) == 2
    assert all(value == bytearray(len(value)) for value in wiped)


def test_legacy_plaintext_rate_limit_migration(tmp_path):
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path)
    init_device(db, STRONG_PASSPHRASE)

    # Manually write a legacy plaintext JSON record directly to the database
    legacy_json = b'{"failed_attempts":2,"last_failed_at":100,"locked_until":200}'
    with sqlite3.connect(str(db_path) + ".meta") as conn:
        conn.execute(
            "INSERT OR REPLACE INTO device_meta (key, value) VALUES (?, ?)",
            (UNLOCK_RATE_LIMIT_KEY, legacy_json),
        )

    # Reload the database and verify it parses the legacy plaintext JSON correctly
    db_reload = BurnDB(db_path)
    state = db_reload.get_unlock_rate_limit(now=250)
    assert state["failed_attempts"] == 2
    assert state["locked_until"] == 200

    # Write a new state and verify it gets encrypted/signed securely
    db_reload.record_unlock_failure(now=300)
    with sqlite3.connect(str(db_path) + ".meta") as conn:
        row = conn.execute(
            "SELECT value FROM device_meta WHERE key=?", (UNLOCK_RATE_LIMIT_KEY,)
        ).fetchone()
    raw_val = row[0]
    assert raw_val.startswith(b"dpapi:") or raw_val.startswith(b"hmac:")


def test_rate_limit_tamper_detection(tmp_path):
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path)
    init_device(db, STRONG_PASSPHRASE)

    # Write a valid protected rate limit record
    db.record_unlock_failure(now=1000)

    # Read the valid raw value from the database
    with sqlite3.connect(str(db_path) + ".meta") as conn:
        row = conn.execute(
            "SELECT value FROM device_meta WHERE key=?", (UNLOCK_RATE_LIMIT_KEY,)
        ).fetchone()
    raw_val = row[0]

    # Tamper by corrupting a byte in the middle of the payload/signature
    tampered_val = bytearray(raw_val)
    if len(tampered_val) > 50:
        tampered_val[50] ^= 0xFF
    else:
        tampered_val = tampered_val[:-2]
    tampered_val = bytes(tampered_val)

    with sqlite3.connect(str(db_path) + ".meta") as conn:
        conn.execute(
            "UPDATE device_meta SET value=? WHERE key=?",
            (tampered_val, UNLOCK_RATE_LIMIT_KEY),
        )

    # Verify that loading the tampered state fails closed (triggers full lockout)
    db_reload = BurnDB(db_path)
    state = db_reload.get_unlock_rate_limit(now=1000)
    assert state["failed_attempts"] == UNLOCK_MAX_FAILED_ATTEMPTS
    assert state["retry_after_seconds"] == burn_module.UNLOCK_LOCKOUT_SECONDS


def test_non_windows_hmac_rate_limit_protection(tmp_path, monkeypatch):
    # Mock platform to darwin to force the HMAC-SHA256 path
    monkeypatch.setattr(sys, "platform", "darwin")

    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path)
    init_device(db, STRONG_PASSPHRASE)

    # Record a failure
    db.record_unlock_failure(now=1000)

    # Check key file creation and file permissions (except on OSes like Windows that don't support full chmod)
    key_path = tmp_path / ".rate_limit.key"
    assert key_path.exists()
    import os
    if os.name != "nt":
        assert (key_path.stat().st_mode & 0o777) == 0o600

    # Verify that the value is stored with 'hmac:' prefix
    with sqlite3.connect(str(db_path) + ".meta") as conn:
        row = conn.execute(
            "SELECT value FROM device_meta WHERE key=?", (UNLOCK_RATE_LIMIT_KEY,)
        ).fetchone()
    assert row[0].startswith(b"hmac:")
