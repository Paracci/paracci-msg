"""macOS Keychain helpers for Paracci device binding.

The module is importable on every platform. Calls fail with KeychainError when
macOS Security.framework is unavailable.
"""

from __future__ import annotations

import ctypes
import sys


SERVICE_NAME = "Paracci"
ERR_SEC_SUCCESS = 0
ERR_SEC_DUPLICATE_ITEM = -25299
ERR_SEC_ITEM_NOT_FOUND = -25300
K_CF_STRING_ENCODING_UTF8 = 0x08000100

_security = None
_corefoundation = None


class KeychainError(Exception):
    """Catchable macOS Keychain operation failure."""

    def __init__(
        self,
        operation: str,
        message: str | None = None,
        status: int | None = None,
        code: str = "failed",
    ):
        self.operation = operation
        self.status = status
        self.code = code
        if message is None:
            message = f"macOS Keychain {operation} failed."
        super().__init__(message)


def wrap_with_keychain(profile_id: str, data: bytes) -> None:
    """Store bytes as a non-syncing generic password item in macOS Keychain."""
    _validate_profile_id(profile_id)
    if not isinstance(data, bytes):
        raise TypeError("data must be bytes")
    try:
        _get_adapter().store(profile_id, data)
    except KeychainError:
        raise
    except Exception as exc:
        raise KeychainError("wrap", "macOS Keychain storage failed.") from exc


def unwrap_with_keychain(profile_id: str) -> bytes:
    """Retrieve bytes from a macOS Keychain generic password item."""
    _validate_profile_id(profile_id)
    try:
        return _get_adapter().load(profile_id)
    except KeychainError:
        raise
    except Exception as exc:
        raise KeychainError("unwrap", "macOS Keychain lookup failed.") from exc


def delete_from_keychain(profile_id: str) -> None:
    """Delete the profile binding item from macOS Keychain."""
    _validate_profile_id(profile_id)
    try:
        _get_adapter().delete(profile_id)
    except KeychainError:
        raise
    except Exception as exc:
        raise KeychainError("delete", "macOS Keychain delete failed.") from exc


def _validate_profile_id(profile_id: str) -> None:
    if not isinstance(profile_id, str) or not profile_id:
        raise ValueError("profile_id must be a non-empty string")


def _ensure_macos(operation: str = "operation") -> None:
    if sys.platform != "darwin":
        raise KeychainError(
            operation,
            "macOS Keychain is available only on macOS.",
            code="unavailable",
        )


def _get_adapter():
    _ensure_macos("load")
    return _SecurityKeychainAdapter()


def _load_frameworks():
    global _security, _corefoundation
    _ensure_macos("load")
    if _security is not None and _corefoundation is not None:
        return _security, _corefoundation

    security = ctypes.CDLL(
        "/System/Library/Frameworks/Security.framework/Security",
        use_errno=True,
    )
    corefoundation = ctypes.CDLL(
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation",
        use_errno=True,
    )

    corefoundation.CFStringCreateWithCString.argtypes = [
        ctypes.c_void_p,
        ctypes.c_char_p,
        ctypes.c_uint32,
    ]
    corefoundation.CFStringCreateWithCString.restype = ctypes.c_void_p
    corefoundation.CFDataCreate.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_long,
    ]
    corefoundation.CFDataCreate.restype = ctypes.c_void_p
    corefoundation.CFDataGetLength.argtypes = [ctypes.c_void_p]
    corefoundation.CFDataGetLength.restype = ctypes.c_long
    corefoundation.CFDataGetBytePtr.argtypes = [ctypes.c_void_p]
    corefoundation.CFDataGetBytePtr.restype = ctypes.c_void_p
    corefoundation.CFDictionaryCreate.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.c_long,
        ctypes.c_void_p,
        ctypes.c_void_p,
    ]
    corefoundation.CFDictionaryCreate.restype = ctypes.c_void_p
    corefoundation.CFRelease.argtypes = [ctypes.c_void_p]
    corefoundation.CFRelease.restype = None

    security.SecItemAdd.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    security.SecItemAdd.restype = ctypes.c_int32
    security.SecItemUpdate.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    security.SecItemUpdate.restype = ctypes.c_int32
    security.SecItemCopyMatching.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    security.SecItemCopyMatching.restype = ctypes.c_int32
    security.SecItemDelete.argtypes = [ctypes.c_void_p]
    security.SecItemDelete.restype = ctypes.c_int32

    _security = security
    _corefoundation = corefoundation
    return _security, _corefoundation


class _SecurityKeychainAdapter:
    """Thin ctypes adapter over Security.framework item APIs."""

    def __init__(self):
        self.security, self.cf = _load_frameworks()

    def store(self, profile_id: str, data: bytes) -> None:
        query, refs = self._item_query(profile_id, data=data)
        try:
            status = self.security.SecItemAdd(query, None)
            if status == ERR_SEC_DUPLICATE_ITEM:
                attrs, attr_refs = self._value_attrs(data)
                try:
                    status = self.security.SecItemUpdate(query, attrs)
                finally:
                    self._release_refs(attr_refs + [attrs])
            if status != ERR_SEC_SUCCESS:
                raise self._error("wrap", status)
        finally:
            self._release_refs(refs + [query])

    def load(self, profile_id: str) -> bytes:
        query, refs = self._item_query(profile_id, return_data=True)
        result = ctypes.c_void_p()
        try:
            status = self.security.SecItemCopyMatching(query, ctypes.byref(result))
            if status != ERR_SEC_SUCCESS:
                raise self._error("unwrap", status)
            if not result.value:
                raise KeychainError("unwrap", "macOS Keychain returned no data.")
            return self._cfdata_to_bytes(result.value)
        finally:
            if result.value:
                self.cf.CFRelease(result)
            self._release_refs(refs + [query])

    def delete(self, profile_id: str) -> None:
        query, refs = self._item_query(profile_id)
        try:
            status = self.security.SecItemDelete(query)
            if status in (ERR_SEC_SUCCESS, ERR_SEC_ITEM_NOT_FOUND):
                return
            raise self._error("delete", status)
        finally:
            self._release_refs(refs + [query])

    def _item_query(
        self,
        profile_id: str,
        data: bytes | None = None,
        return_data: bool = False,
    ) -> tuple[int, list[int]]:
        keys: list[int] = [
            self._sec_const("kSecClass"),
            self._sec_const("kSecAttrService"),
            self._sec_const("kSecAttrAccount"),
        ]
        service = self._cfstring(SERVICE_NAME)
        account = self._cfstring(profile_id)
        values: list[int] = [
            self._sec_const("kSecClassGenericPassword"),
            service,
            account,
        ]
        refs = [service, account]

        if data is not None:
            data_ref = self._cfdata(data)
            keys.extend(
                [
                    self._sec_const("kSecAttrAccessible"),
                    self._sec_const("kSecValueData"),
                ]
            )
            values.extend(
                [
                    self._sec_const("kSecAttrAccessibleWhenUnlockedThisDeviceOnly"),
                    data_ref,
                ]
            )
            refs.append(data_ref)

        if return_data:
            keys.extend(
                [
                    self._sec_const("kSecReturnData"),
                    self._sec_const("kSecMatchLimit"),
                ]
            )
            values.extend([self._cf_bool(True), self._sec_const("kSecMatchLimitOne")])

        return self._cfdict(keys, values), refs

    def _value_attrs(self, data: bytes) -> tuple[int, list[int]]:
        data_ref = self._cfdata(data)
        return self._cfdict([self._sec_const("kSecValueData")], [data_ref]), [data_ref]

    def _sec_const(self, name: str) -> int:
        return ctypes.c_void_p.in_dll(self.security, name).value

    def _cf_bool(self, value: bool) -> int:
        return ctypes.c_void_p.in_dll(
            self.cf,
            "kCFBooleanTrue" if value else "kCFBooleanFalse",
        ).value

    def _cfstring(self, value: str) -> int:
        result = self.cf.CFStringCreateWithCString(
            None,
            value.encode("utf-8"),
            K_CF_STRING_ENCODING_UTF8,
        )
        if not result:
            raise KeychainError("wrap", "Failed to create Keychain string.")
        return result

    def _cfdata(self, data: bytes) -> int:
        buffer = ctypes.create_string_buffer(data, len(data))
        result = self.cf.CFDataCreate(None, ctypes.cast(buffer, ctypes.c_void_p), len(data))
        if not result:
            raise KeychainError("wrap", "Failed to create Keychain data.")
        return result

    def _cfdict(self, keys: list[int], values: list[int]) -> int:
        key_array = (ctypes.c_void_p * len(keys))(*keys)
        value_array = (ctypes.c_void_p * len(values))(*values)
        result = self.cf.CFDictionaryCreate(
            None,
            key_array,
            value_array,
            len(keys),
            None,
            None,
        )
        if not result:
            raise KeychainError("wrap", "Failed to create Keychain query.")
        return result

    def _cfdata_to_bytes(self, data_ref: int) -> bytes:
        length = self.cf.CFDataGetLength(data_ref)
        if length <= 0:
            return b""
        pointer = self.cf.CFDataGetBytePtr(data_ref)
        if not pointer:
            raise KeychainError("unwrap", "macOS Keychain returned invalid data.")
        return ctypes.string_at(pointer, length)

    def _release_refs(self, refs: list[int]) -> None:
        for ref in refs:
            if ref:
                self.cf.CFRelease(ctypes.c_void_p(ref))

    def _error(self, operation: str, status: int) -> KeychainError:
        if status == ERR_SEC_ITEM_NOT_FOUND:
            return KeychainError(
                operation,
                "macOS Keychain item was not found.",
                status=status,
                code="missing",
            )
        return KeychainError(
            operation,
            f"macOS Keychain {operation} failed with OSStatus {status}.",
            status=status,
        )
