import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.burn import (
    UNLOCK_EVER_SUCCEEDED_KEY,
    UNLOCK_RATE_LIMIT_KEY,
    BurnDB,
    init_device,
)
from desktop import device_key_binding as binding
from desktop.device_key_binding import (
    LINUX_SECRET_SERVICE_KIND,
    MACOS_KEYCHAIN_KIND,
    PLATFORM_BINDING_KIND_META_KEY,
    PLATFORM_BINDING_PROFILE_ID_META_KEY,
    SECRET_SERVICE_FAILED_CODE,
    SECRET_SERVICE_UNAVAILABLE_CODE,
    DeviceBindingError,
    consume_device_binding_warning,
    initialize_device_with_binding,
    unlock_device_with_binding,
)
from desktop.dpapi_win import DPAPIError
from desktop.keychain_mac import KeychainError
from desktop.secret_service_linux import SecretServiceError


PASSPHRASE = "Correct-Horse-95175328"


def fake_windows_dpapi(monkeypatch, calls=None):
    monkeypatch.setattr(binding.sys, "platform", "win32")
    if calls is None:
        calls = []

    def fake_wrap(data: bytes) -> bytes:
        calls.append("dpapi_wrap")
        return b"fake-dpapi:" + data

    def fake_unwrap(blob: bytes) -> bytes:
        calls.append("dpapi_unwrap")
        if not blob.startswith(b"fake-dpapi:"):
            raise DPAPIError("unwrap", "mock DPAPI failure")
        return blob.removeprefix(b"fake-dpapi:")

    monkeypatch.setattr(binding, "wrap_with_dpapi", fake_wrap)
    monkeypatch.setattr(binding, "unwrap_with_dpapi", fake_unwrap)
    return calls


def fake_keychain(monkeypatch):
    store = {}
    monkeypatch.setattr(binding.sys, "platform", "darwin")
    monkeypatch.setattr(binding, "wrap_with_keychain", lambda profile_id, data: store.__setitem__(profile_id, bytes(data)))
    monkeypatch.setattr(binding, "unwrap_with_keychain", lambda profile_id: store[profile_id])
    monkeypatch.setattr(binding, "delete_from_keychain", lambda profile_id: store.pop(profile_id, None))
    return store


def fake_secret_service(monkeypatch):
    store = {}
    monkeypatch.setattr(binding.sys, "platform", "linux")
    monkeypatch.setattr(
        binding,
        "wrap_with_secret_service",
        lambda profile_id, data: store.__setitem__(profile_id, bytes(data)),
    )
    monkeypatch.setattr(binding, "unwrap_with_secret_service", lambda profile_id: store[profile_id])
    monkeypatch.setattr(binding, "delete_from_secret_service", lambda profile_id: store.pop(profile_id, None))
    return store


def test_windows_dispatch_still_uses_dpapi(tmp_path, monkeypatch):
    calls = fake_windows_dpapi(monkeypatch)
    monkeypatch.setattr(binding, "wrap_with_keychain", lambda *_args: pytest.fail("keychain called"))
    monkeypatch.setattr(binding, "wrap_with_secret_service", lambda *_args: pytest.fail("secret service called"))
    db = BurnDB(tmp_path / "sessions.db")

    device_key = initialize_device_with_binding(db, PASSPHRASE)

    assert len(device_key) == 32
    assert calls == ["dpapi_wrap"]


def test_macos_creation_and_unlock_use_keychain(tmp_path, monkeypatch):
    store = fake_keychain(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")

    device_key = initialize_device_with_binding(db, PASSPHRASE)

    profile_id = db.get_device_meta(PLATFORM_BINDING_PROFILE_ID_META_KEY).decode("ascii")
    assert db.get_device_meta(PLATFORM_BINDING_KIND_META_KEY) == MACOS_KEYCHAIN_KIND
    assert profile_id in store
    assert unlock_device_with_binding(db, PASSPHRASE) == device_key
    assert db.get_device_meta(UNLOCK_EVER_SUCCEEDED_KEY) == b"1"
    assert db.get_device_meta(UNLOCK_RATE_LIMIT_KEY) is not None
    assert db.get_unlock_rate_limit()["failed_attempts"] == 0


def test_linux_creation_and_unlock_use_secret_service(tmp_path, monkeypatch):
    store = fake_secret_service(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")

    device_key = initialize_device_with_binding(db, PASSPHRASE)

    profile_id = db.get_device_meta(PLATFORM_BINDING_PROFILE_ID_META_KEY).decode("ascii")
    assert db.get_device_meta(PLATFORM_BINDING_KIND_META_KEY) == LINUX_SECRET_SERVICE_KIND
    assert profile_id in store
    assert unlock_device_with_binding(db, PASSPHRASE) == device_key
    assert db.get_device_meta(UNLOCK_EVER_SUCCEEDED_KEY) == b"1"
    assert db.get_device_meta(UNLOCK_RATE_LIMIT_KEY) is not None
    assert db.get_unlock_rate_limit()["failed_attempts"] == 0


def test_macos_keychain_failure_before_kdf_does_not_consume_unlock_attempt(tmp_path, monkeypatch):
    fake_keychain(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")
    initialize_device_with_binding(db, PASSPHRASE)
    monkeypatch.setattr(
        binding,
        "unwrap_with_keychain",
        lambda _profile_id: (_ for _ in ()).throw(KeychainError("unwrap", "not available")),
    )

    with pytest.raises(DeviceBindingError):
        unlock_device_with_binding(db, PASSPHRASE)

    assert db.get_unlock_rate_limit()["failed_attempts"] == 0


def test_legacy_macos_profile_is_bound_after_successful_unlock(tmp_path, monkeypatch):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, PASSPHRASE)
    store = fake_keychain(monkeypatch)

    assert unlock_device_with_binding(db, PASSPHRASE) == device_key
    profile_id = db.get_device_meta(PLATFORM_BINDING_PROFILE_ID_META_KEY).decode("ascii")
    assert profile_id in store

    monkeypatch.setattr(
        binding,
        "legacy_unlock_device",
        lambda *_args: pytest.fail("legacy unlock should not run after binding"),
    )
    assert unlock_device_with_binding(db, PASSPHRASE) == device_key


def test_legacy_linux_profile_is_bound_after_successful_unlock(tmp_path, monkeypatch):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, PASSPHRASE)
    store = fake_secret_service(monkeypatch)

    assert unlock_device_with_binding(db, PASSPHRASE) == device_key
    profile_id = db.get_device_meta(PLATFORM_BINDING_PROFILE_ID_META_KEY).decode("ascii")
    assert profile_id in store

    monkeypatch.setattr(
        binding,
        "legacy_unlock_device",
        lambda *_args: pytest.fail("legacy unlock should not run after binding"),
    )
    assert unlock_device_with_binding(db, PASSPHRASE) == device_key


def test_linux_no_daemon_initialization_falls_back_to_passphrase_only(tmp_path, monkeypatch):
    monkeypatch.setattr(binding.sys, "platform", "linux")
    monkeypatch.setattr(
        binding,
        "wrap_with_secret_service",
        lambda *_args: (_ for _ in ()).throw(
            SecretServiceError("wrap", "no daemon", code="unavailable")
        ),
    )
    db = BurnDB(tmp_path / "sessions.db")

    device_key = initialize_device_with_binding(db, PASSPHRASE)
    warning = consume_device_binding_warning()

    assert len(device_key) == 32
    assert warning is not None
    assert warning.code == SECRET_SERVICE_UNAVAILABLE_CODE
    assert db.get_device_meta(PLATFORM_BINDING_PROFILE_ID_META_KEY) is None
    assert unlock_device_with_binding(db, PASSPHRASE) == device_key


def test_linux_no_daemon_unlock_migration_falls_back_to_passphrase_only(tmp_path, monkeypatch):
    db = BurnDB(tmp_path / "sessions.db")
    device_key = init_device(db, PASSPHRASE)
    monkeypatch.setattr(binding.sys, "platform", "linux")
    monkeypatch.setattr(
        binding,
        "wrap_with_secret_service",
        lambda *_args: (_ for _ in ()).throw(
            SecretServiceError("wrap", "no daemon", code="unavailable")
        ),
    )

    assert unlock_device_with_binding(db, PASSPHRASE) == device_key
    warning = consume_device_binding_warning()

    assert warning is not None
    assert warning.code == SECRET_SERVICE_UNAVAILABLE_CODE
    assert db.get_device_meta(PLATFORM_BINDING_PROFILE_ID_META_KEY) is None


def test_linux_no_daemon_on_bound_profile_does_not_downgrade(tmp_path, monkeypatch):
    fake_secret_service(monkeypatch)
    db = BurnDB(tmp_path / "sessions.db")
    device_key = initialize_device_with_binding(db, PASSPHRASE)
    profile_id = db.get_device_meta(PLATFORM_BINDING_PROFILE_ID_META_KEY)
    assert profile_id is not None

    monkeypatch.setattr(
        binding,
        "unwrap_with_secret_service",
        lambda *_args: (_ for _ in ()).throw(
            SecretServiceError("unwrap", "no daemon", code="unavailable")
        ),
    )

    with pytest.raises(DeviceBindingError) as exc:
        unlock_device_with_binding(db, PASSPHRASE)

    assert exc.value.code == SECRET_SERVICE_FAILED_CODE
    assert db.get_device_meta(PLATFORM_BINDING_PROFILE_ID_META_KEY) == profile_id
    assert db.get_unlock_rate_limit()["failed_attempts"] == 0
    assert device_key != b""


def test_macos_binding_wipes_mutable_intermediate_keys(tmp_path, monkeypatch):
    fake_keychain(monkeypatch)
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


def test_legacy_platform_binding_wipes_mutable_intermediate_keys(tmp_path, monkeypatch):
    db = BurnDB(tmp_path / "sessions.db")
    init_device(db, PASSPHRASE)
    fake_keychain(monkeypatch)
    wiped = []
    real_wipe = binding.wipe

    def track_wipe(value):
        assert isinstance(value, bytearray)
        real_wipe(value)
        wiped.append(value)

    monkeypatch.setattr(binding, "wipe", track_wipe)

    unlock_device_with_binding(db, PASSPHRASE)

    assert len(wiped) == 3
    assert all(value == bytearray(len(value)) for value in wiped)
