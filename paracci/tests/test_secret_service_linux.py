import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from desktop import secret_service_linux
from desktop.secret_service_linux import (
    SecretServiceError,
    delete_from_secret_service,
    unwrap_with_secret_service,
    wrap_with_secret_service,
)


class FakeSecretServiceBackend:
    def __init__(self):
        self.items = {}

    def store(self, profile_id: str, data: bytes) -> None:
        self.items[profile_id] = data

    def load(self, profile_id: str) -> bytes:
        if profile_id not in self.items:
            raise SecretServiceError("unwrap", "missing", code="missing")
        return self.items[profile_id]

    def delete(self, profile_id: str) -> None:
        self.items.pop(profile_id, None)


def test_secret_service_calls_fail_cleanly_on_non_linux(monkeypatch):
    monkeypatch.setattr(secret_service_linux.sys, "platform", "win32")

    with pytest.raises(SecretServiceError, match="available only on Linux"):
        wrap_with_secret_service("profile", b"secret")

    with pytest.raises(SecretServiceError, match="available only on Linux"):
        unwrap_with_secret_service("profile")

    with pytest.raises(SecretServiceError, match="available only on Linux"):
        delete_from_secret_service("profile")


def test_secret_service_public_api_is_mockable(monkeypatch):
    backend = FakeSecretServiceBackend()
    monkeypatch.setattr(secret_service_linux.sys, "platform", "linux")
    monkeypatch.setattr(secret_service_linux, "_get_backend", lambda: backend)

    wrap_with_secret_service("profile-a", b"binding-factor")

    assert unwrap_with_secret_service("profile-a") == b"binding-factor"
    delete_from_secret_service("profile-a")
    with pytest.raises(SecretServiceError) as exc:
        unwrap_with_secret_service("profile-a")
    assert exc.value.code == "missing"


def test_secret_service_unavailable_maps_to_unavailable_code(monkeypatch):
    monkeypatch.setattr(secret_service_linux.sys, "platform", "linux")

    def unavailable_backend():
        raise SecretServiceError("load", "no daemon", code="unavailable")

    monkeypatch.setattr(secret_service_linux, "_get_backend", unavailable_backend)

    with pytest.raises(SecretServiceError) as exc:
        wrap_with_secret_service("profile", b"secret")

    assert exc.value.code == "unavailable"


def test_secret_service_missing_item_maps_to_missing_code(monkeypatch):
    backend = FakeSecretServiceBackend()
    monkeypatch.setattr(secret_service_linux.sys, "platform", "linux")
    monkeypatch.setattr(secret_service_linux, "_get_backend", lambda: backend)

    with pytest.raises(SecretServiceError) as exc:
        unwrap_with_secret_service("missing-profile")

    assert exc.value.code == "missing"
