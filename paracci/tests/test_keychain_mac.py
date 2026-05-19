import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from desktop import keychain_mac
from desktop.keychain_mac import (
    KeychainError,
    delete_from_keychain,
    unwrap_with_keychain,
    wrap_with_keychain,
)


class FakeKeychainAdapter:
    def __init__(self):
        self.items = {}

    def store(self, profile_id: str, data: bytes) -> None:
        self.items[(keychain_mac.SERVICE_NAME, profile_id)] = data

    def load(self, profile_id: str) -> bytes:
        key = (keychain_mac.SERVICE_NAME, profile_id)
        if key not in self.items:
            raise KeychainError("unwrap", "missing", code="missing")
        return self.items[key]

    def delete(self, profile_id: str) -> None:
        self.items.pop((keychain_mac.SERVICE_NAME, profile_id), None)


def test_keychain_calls_fail_cleanly_on_non_macos(monkeypatch):
    monkeypatch.setattr(keychain_mac.sys, "platform", "linux")

    with pytest.raises(KeychainError, match="available only on macOS"):
        wrap_with_keychain("profile", b"secret")

    with pytest.raises(KeychainError, match="available only on macOS"):
        unwrap_with_keychain("profile")

    with pytest.raises(KeychainError, match="available only on macOS"):
        delete_from_keychain("profile")


def test_keychain_public_api_is_mockable_without_macos(monkeypatch):
    adapter = FakeKeychainAdapter()
    monkeypatch.setattr(keychain_mac.sys, "platform", "darwin")
    monkeypatch.setattr(keychain_mac, "_get_adapter", lambda: adapter)

    wrap_with_keychain("profile-a", b"binding-factor")

    assert unwrap_with_keychain("profile-a") == b"binding-factor"
    delete_from_keychain("profile-a")
    with pytest.raises(KeychainError) as exc:
        unwrap_with_keychain("profile-a")
    assert exc.value.code == "missing"


def test_keychain_missing_item_maps_to_missing_code(monkeypatch):
    adapter = FakeKeychainAdapter()
    monkeypatch.setattr(keychain_mac.sys, "platform", "darwin")
    monkeypatch.setattr(keychain_mac, "_get_adapter", lambda: adapter)

    with pytest.raises(KeychainError) as exc:
        unwrap_with_keychain("missing-profile")

    assert exc.value.code == "missing"


@pytest.mark.skipif(sys.platform != "darwin", reason="real Keychain is macOS-only")
def test_keychain_real_round_trip_on_macos():
    profile_id = f"pytest-{uuid.uuid4().hex}"
    try:
        wrap_with_keychain(profile_id, b"real-macos-round-trip")
        assert unwrap_with_keychain(profile_id) == b"real-macos-round-trip"
    finally:
        delete_from_keychain(profile_id)
