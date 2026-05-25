import sys
import sqlite3
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.burn import BurnDB, DeviceError, init_device


PASS_PHRASE = "Correct-Horse-95175328"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def _initialized_db(tmp_path):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, PASS_PHRASE)
    return db.with_device_key(device_key), device_key


def test_set_2fa_secret_encrypts_metadata(tmp_path):
    db, device_key = _initialized_db(tmp_path)

    db.set_2fa_secret(TOTP_SECRET, device_key)

    stored = db.get_device_meta("2fa_secret")
    assert isinstance(stored, bytes)
    assert TOTP_SECRET.encode("ascii") not in stored
    assert db.get_2fa_secret(device_key) == TOTP_SECRET


def test_legacy_plaintext_2fa_secret_is_migrated(tmp_path):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, PASS_PHRASE)
    with sqlite3.connect(db.db_path) as conn:
        conn.execute(
            "INSERT INTO device_meta (key, value) VALUES (?, ?)",
            ("2fa_secret", TOTP_SECRET),
        )
    db = db.with_device_key(device_key)

    assert db.get_2fa_secret(device_key) == TOTP_SECRET

    migrated = db.get_device_meta("2fa_secret")
    assert isinstance(migrated, bytes)
    assert TOTP_SECRET.encode("ascii") not in migrated


def test_malformed_2fa_secret_is_rejected(tmp_path):
    db, device_key = _initialized_db(tmp_path)
    db.set_device_meta("2fa_secret", b"SHORT")

    with pytest.raises(DeviceError, match="Invalid 2FA secret metadata"):
        db.get_2fa_secret(device_key)
