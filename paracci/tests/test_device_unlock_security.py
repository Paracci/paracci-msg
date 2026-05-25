import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import burn as burn_module
from core.burn import (
    BurnDB,
    DeviceError,
    DeviceLockedError,
    init_device,
    unlock_device,
)
from core.crypto import derive_master_key, encrypt, random_bytes


STRONG_PASSPHRASE = "Correct-Horse-95175328"


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


def test_strong_passphrase_unlocks_and_resets_failed_counter(tmp_path):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, STRONG_PASSPHRASE)

    with pytest.raises(DeviceError, match="Incorrect passphrase"):
        unlock_device(db, "Wrong-Horse-95175328")

    assert db.get_unlock_rate_limit()["failed_attempts"] == 1
    assert unlock_device(db, STRONG_PASSPHRASE) == device_key
    assert db.get_unlock_rate_limit()["failed_attempts"] == 0


def test_successful_unlock_reserves_attempt_before_kdf_and_clears_it(tmp_path, monkeypatch):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, STRONG_PASSPHRASE)
    observed_failed_attempts = []
    real_derive_master_key = burn_module.derive_master_key

    def observed_derive_master_key(pin, salt):
        observed_failed_attempts.append(db.get_unlock_rate_limit()["failed_attempts"])
        return real_derive_master_key(pin, salt)

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

    def slow_wrong_derive_master_key(_pin, _salt):
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
    legacy_pin = "95175328"
    pin_salt = random_bytes(16)
    master_key = derive_master_key(legacy_pin, pin_salt)
    device_key = random_bytes(32)
    blob = encrypt(master_key, device_key, aad=b"paracci.device_key.v1")

    db.set_device_meta("pin_salt", pin_salt)
    db.set_device_meta("encrypted_device_key", blob.nonce + blob.ciphertext)

    assert unlock_device(db, legacy_pin) == device_key


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
