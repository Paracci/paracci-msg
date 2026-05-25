import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.burn import BurnDB, DeviceError, init_device
from core.crypto import EncryptedBlob, decrypt
from desktop import device_key_binding as binding
from desktop.device_key_binding import (
    DPAPI_BLOB_META_KEY,
    DPAPI_BLOB_PREFIX,
    BOUND_DEVICE_KEY_AAD,
    DPAPI_DIFFERENT_ACCOUNT_CODE,
    DPAPI_DIFFERENT_ACCOUNT_I18N,
    DPAPI_DIFFERENT_ACCOUNT_MESSAGE,
    DPAPI_KEYFILE_DAMAGED_CODE,
    DeviceBindingError,
    initialize_device_with_binding,
    unlock_device_with_binding,
)
from desktop.dpapi_win import DPAPIError


PASSPHRASE = "Correct-Horse-95175328"


def enable_fake_windows_dpapi(monkeypatch):
    monkeypatch.setattr(binding.sys, "platform", "win32")
    monkeypatch.setattr(binding, "wrap_with_dpapi", lambda data: b"fake-dpapi:" + data)

    def fake_unwrap(blob: bytes) -> bytes:
        if not blob.startswith(b"fake-dpapi:"):
            raise DPAPIError("unwrap", "mock DPAPI failure")
        return blob.removeprefix(b"fake-dpapi:")

    monkeypatch.setattr(binding, "unwrap_with_dpapi", fake_unwrap)


def test_windows_profile_creation_writes_dpapi_blob(tmp_path, monkeypatch):
    enable_fake_windows_dpapi(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")

    device_key = initialize_device_with_binding(db, PASSPHRASE)

    assert len(device_key) == 32
    assert db.get_device_meta("pin_salt") is not None
    assert db.get_device_meta("encrypted_device_key") is not None
    assert db.get_device_meta(DPAPI_BLOB_META_KEY).startswith(DPAPI_BLOB_PREFIX + b"fake-dpapi:")


def test_windows_bound_unlock_requires_dpapi_and_passphrase(tmp_path, monkeypatch):
    enable_fake_windows_dpapi(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")
    device_key = initialize_device_with_binding(db, PASSPHRASE)

    assert unlock_device_with_binding(db, PASSPHRASE) == device_key
    with pytest.raises(DeviceError, match="Incorrect passphrase"):
        unlock_device_with_binding(db, "Wrong-Horse-95175328")
    assert db.get_unlock_rate_limit()["failed_attempts"] == 1


def test_parallel_windows_bound_wrong_unlocks_are_serialized_before_kdf(tmp_path, monkeypatch):
    enable_fake_windows_dpapi(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")
    initialize_device_with_binding(db, PASSPHRASE)
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

    monkeypatch.setattr(binding, "derive_master_key", slow_wrong_derive_master_key)

    def attempt_unlock():
        start.wait(timeout=2)
        with pytest.raises(DeviceError):
            unlock_device_with_binding(db, "Wrong-Horse-95175328")

    with ThreadPoolExecutor(max_workers=workers) as executor:
        list(executor.map(lambda _index: attempt_unlock(), range(workers)))

    assert kdf_calls == 2
    assert maximum_active_kdfs == 1
    assert db.get_unlock_rate_limit()["failed_attempts"] == 2


def test_unwrapped_dpapi_factor_cannot_decrypt_device_key_by_itself(tmp_path, monkeypatch):
    enable_fake_windows_dpapi(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")
    initialize_device_with_binding(db, PASSPHRASE)

    stored_dpapi_blob = db.get_device_meta(DPAPI_BLOB_META_KEY)
    dpapi_factor = stored_dpapi_blob.removeprefix(DPAPI_BLOB_PREFIX).removeprefix(b"fake-dpapi:")
    encrypted_device_key = db.get_device_meta("encrypted_device_key")
    blob = EncryptedBlob(
        nonce=encrypted_device_key[:12],
        ciphertext=encrypted_device_key[12:],
    )

    with pytest.raises(Exception):
        decrypt(dpapi_factor, blob, aad=BOUND_DEVICE_KEY_AAD)


def test_legacy_windows_profile_is_bound_after_successful_unlock(tmp_path, monkeypatch):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, PASSPHRASE)
    assert db.get_device_meta(DPAPI_BLOB_META_KEY) is None

    enable_fake_windows_dpapi(monkeypatch)

    assert unlock_device_with_binding(db, PASSPHRASE) == device_key
    assert db.get_device_meta(DPAPI_BLOB_META_KEY).startswith(DPAPI_BLOB_PREFIX + b"fake-dpapi:")
    assert unlock_device_with_binding(db, PASSPHRASE) == device_key


def test_dpapi_unwrap_failure_reports_different_windows_account(tmp_path, monkeypatch):
    enable_fake_windows_dpapi(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")
    initialize_device_with_binding(db, PASSPHRASE)
    monkeypatch.setattr(
        binding,
        "unwrap_with_dpapi",
        lambda blob: (_ for _ in ()).throw(DPAPIError("unwrap", "access denied")),
    )

    with pytest.raises(DeviceBindingError) as exc:
        unlock_device_with_binding(db, PASSPHRASE)

    assert exc.value.code == DPAPI_DIFFERENT_ACCOUNT_CODE
    assert exc.value.i18n_key == DPAPI_DIFFERENT_ACCOUNT_I18N
    assert str(exc.value) == DPAPI_DIFFERENT_ACCOUNT_MESSAGE


def test_corrupt_dpapi_metadata_reports_damaged_keyfile(tmp_path, monkeypatch):
    enable_fake_windows_dpapi(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")
    initialize_device_with_binding(db, PASSPHRASE)
    db.set_device_meta(DPAPI_BLOB_META_KEY, b"not-a-paracci-dpapi-blob")

    with pytest.raises(DeviceBindingError) as exc:
        unlock_device_with_binding(db, PASSPHRASE)

    assert exc.value.code == DPAPI_KEYFILE_DAMAGED_CODE


def test_unsupported_platform_path_stays_passphrase_only(tmp_path, monkeypatch):
    monkeypatch.setattr(binding.sys, "platform", "freebsd13")
    db = BurnDB(tmp_path / "sessions.db")

    device_key = initialize_device_with_binding(db, PASSPHRASE)

    assert db.get_device_meta(DPAPI_BLOB_META_KEY) is None
    assert unlock_device_with_binding(db, PASSPHRASE) == device_key


def test_windows_binding_wipes_mutable_intermediate_keys(tmp_path, monkeypatch):
    enable_fake_windows_dpapi(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")
    wiped = []
    real_wipe = binding.wipe

    def track_wipe(value):
        assert isinstance(value, bytearray)
        real_wipe(value)
        wiped.append(value)

    monkeypatch.setattr(binding, "wipe", track_wipe)

    initialize_device_with_binding(db, PASSPHRASE)
    unlock_device_with_binding(db, PASSPHRASE)

    assert len(wiped) == 6
    assert all(value == bytearray(len(value)) for value in wiped)
