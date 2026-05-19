import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

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
