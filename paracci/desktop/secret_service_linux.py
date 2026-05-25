"""Linux Secret Service helpers for Paracci device binding.

The module is importable on every platform. Calls fail with SecretServiceError
when Linux Secret Service or dbus-python is unavailable.
"""

from __future__ import annotations

import logging
import sys


logger = logging.getLogger(__name__)

BUS_NAME = "org.freedesktop.secrets"
SERVICE_PATH = "/org/freedesktop/secrets"
SERVICE_IFACE = "org.freedesktop.Secret.Service"
COLLECTION_IFACE = "org.freedesktop.Secret.Collection"
ITEM_IFACE = "org.freedesktop.Secret.Item"
ATTRIBUTES = {"application": "paracci"}
LABEL_PREFIX = "Paracci - "
CONTENT_TYPE = "application/octet-stream"
PROMPT_NONE = "/"


class SecretServiceError(Exception):
    """Catchable Linux Secret Service operation failure."""

    def __init__(self, operation: str, message: str | None = None, code: str = "failed"):
        self.operation = operation
        self.code = code
        if message is None:
            message = f"Linux Secret Service {operation} failed."
        super().__init__(message)


def wrap_with_secret_service(profile_id: str, data: bytes | bytearray) -> None:
    """Store bytes-like data in the default Secret Service collection."""
    _validate_profile_id(profile_id)
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    try:
        _get_backend().store(profile_id, data)
    except SecretServiceError:
        raise
    except Exception as exc:
        raise SecretServiceError("wrap", "Linux Secret Service storage failed.") from exc


def unwrap_with_secret_service(profile_id: str) -> bytearray:
    """Retrieve secret-service data into a mutable caller-owned buffer."""
    _validate_profile_id(profile_id)
    try:
        return _as_mutable_secret(_get_backend().load(profile_id))
    except SecretServiceError:
        raise
    except Exception as exc:
        raise SecretServiceError("unwrap", "Linux Secret Service lookup failed.") from exc


def delete_from_secret_service(profile_id: str) -> None:
    """Delete the profile binding item from Secret Service."""
    _validate_profile_id(profile_id)
    try:
        _get_backend().delete(profile_id)
    except SecretServiceError:
        raise
    except Exception as exc:
        raise SecretServiceError("delete", "Linux Secret Service delete failed.") from exc


def _validate_profile_id(profile_id: str) -> None:
    if not isinstance(profile_id, str) or not profile_id:
        raise ValueError("profile_id must be a non-empty string")


def _ensure_linux(operation: str = "operation") -> None:
    if not sys.platform.startswith("linux"):
        raise SecretServiceError(
            operation,
            "Linux Secret Service is available only on Linux.",
            code="unavailable",
        )


def _get_backend():
    _ensure_linux("load")
    try:
        import dbus  # type: ignore
    except Exception as exc:
        raise SecretServiceError(
            "load",
            "dbus-python is not available; Linux Secret Service cannot be used.",
            code="unavailable",
        ) from exc
    return _DBusSecretServiceBackend(dbus)


class _DBusSecretServiceBackend:
    """Minimal raw org.freedesktop.secrets D-Bus backend."""

    def __init__(self, dbus_module):
        self.dbus = dbus_module
        try:
            self.bus = dbus_module.SessionBus()
            service_obj = self.bus.get_object(BUS_NAME, SERVICE_PATH)
            self.service = dbus_module.Interface(service_obj, SERVICE_IFACE)
            _output, session = self.service.OpenSession("plain", "")
            self.session = session
        except Exception as exc:
            raise SecretServiceError(
                "load",
                "No Secret Service daemon is available on the session bus.",
                code="unavailable",
            ) from exc

    def store(self, profile_id: str, data: bytes | bytearray) -> None:
        attributes = self._attributes(profile_id)
        collection_path = self._default_collection_path()
        collection = self._interface(collection_path, COLLECTION_IFACE)
        properties = self.dbus.Dictionary(
            {
                f"{ITEM_IFACE}.Label": self.dbus.String(f"{LABEL_PREFIX}{profile_id}"),
                f"{ITEM_IFACE}.Attributes": self.dbus.Dictionary(
                    attributes,
                    signature="ss",
                ),
            },
            signature="sv",
        )
        secret = self.dbus.Struct(
            (
                self.dbus.ObjectPath(self.session),
                self.dbus.Array([], signature="y"),
                self.dbus.ByteArray(data),
                self.dbus.String(CONTENT_TYPE),
            ),
            signature="oayays",
        )
        try:
            _item, prompt = collection.CreateItem(properties, secret, True)
            self._reject_prompt(prompt, "wrap")
        except SecretServiceError:
            raise
        except Exception as exc:
            raise SecretServiceError("wrap", "Linux Secret Service storage failed.") from exc

    def load(self, profile_id: str) -> bytearray:
        items = self._search_unlocked(profile_id, "unwrap")
        if not items:
            raise SecretServiceError(
                "unwrap",
                "Linux Secret Service item was not found.",
                code="missing",
            )
        item = self._interface(items[0], ITEM_IFACE)
        try:
            secret = item.GetSecret(self.dbus.ObjectPath(self.session))
            return bytearray(secret[2])
        except Exception as exc:
            raise SecretServiceError("unwrap", "Linux Secret Service lookup failed.") from exc

    def delete(self, profile_id: str) -> None:
        items = self._search_unlocked(profile_id, "delete")
        if not items:
            return
        for item_path in items:
            item = self._interface(item_path, ITEM_IFACE)
            try:
                prompt = item.Delete()
                self._reject_prompt(prompt, "delete")
            except SecretServiceError:
                raise
            except Exception as exc:
                raise SecretServiceError("delete", "Linux Secret Service delete failed.") from exc

    def _default_collection_path(self):
        try:
            path = self.service.ReadAlias("default")
        except Exception as exc:
            raise SecretServiceError(
                "load",
                "Default Secret Service collection is unavailable.",
                code="unavailable",
            ) from exc
        if not path or str(path) == PROMPT_NONE:
            raise SecretServiceError(
                "load",
                "Default Secret Service collection is unavailable.",
                code="unavailable",
            )
        return path

    def _search_unlocked(self, profile_id: str, operation: str):
        attributes = self._attributes(profile_id)
        try:
            collection = self._interface(self._default_collection_path(), COLLECTION_IFACE)
            items = collection.SearchItems(
                self.dbus.Dictionary(attributes, signature="ss")
            )
        except Exception as exc:
            raise SecretServiceError(
                operation,
                "Linux Secret Service search failed.",
                code="unavailable",
            ) from exc
        if not items:
            return []
        try:
            unlocked, prompt = self.service.Unlock(items)
            self._reject_prompt(prompt, operation)
            return list(unlocked)
        except SecretServiceError:
            raise
        except Exception as exc:
            raise SecretServiceError(
                operation,
                "Linux Secret Service keyring is locked or unavailable.",
                code="unavailable",
            ) from exc

    def _interface(self, path, interface: str):
        return self.dbus.Interface(self.bus.get_object(BUS_NAME, path), interface)

    def _reject_prompt(self, prompt, operation: str) -> None:
        if prompt and str(prompt) != PROMPT_NONE:
            raise SecretServiceError(
                operation,
                "Linux Secret Service requires an interactive prompt.",
                code="unavailable",
            )

    def _attributes(self, profile_id: str) -> dict[str, str]:
        return {**ATTRIBUTES, "profile_id": profile_id}


def _as_mutable_secret(data: bytes | bytearray) -> bytearray:
    if isinstance(data, bytearray):
        return data
    return bytearray(data)
