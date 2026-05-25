"""Windows DPAPI helpers for current-user device key binding.

The module is importable on every platform. Calls fail with DPAPIError when
Windows DPAPI is unavailable.
"""

from __future__ import annotations

import ctypes
import sys
from ctypes import wintypes

from core.constants import DPAPI_DEVICE_KEY_ENTROPY_V1


CRYPTPROTECT_UI_FORBIDDEN = 0x01
_DESCRIPTION = "Paracci device key binding"

_crypt32 = None
_kernel32 = None


class DPAPIError(Exception):
    """Catchable DPAPI operation failure."""

    def __init__(self, operation: str, message: str | None = None, winerror: int | None = None):
        self.operation = operation
        self.winerror = winerror
        if message is None:
            message = f"Windows DPAPI {operation} failed."
        super().__init__(message)


class DATA_BLOB(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


def wrap_with_dpapi(data: bytes | bytearray) -> bytes:
    """Protect bytes-like data with Windows DPAPI using CURRENT_USER scope."""
    _ensure_windows("wrap")
    if not isinstance(data, (bytes, bytearray)):
        raise TypeError("data must be bytes or bytearray")
    try:
        return _call_crypt_protect(data)
    except DPAPIError:
        raise
    except Exception as exc:
        raise DPAPIError("wrap", "Windows DPAPI protection failed.") from exc


def unwrap_with_dpapi(blob: bytes) -> bytearray:
    """Unprotect a DPAPI blob into a mutable buffer owned by the caller."""
    _ensure_windows("unwrap")
    if not isinstance(blob, bytes):
        raise TypeError("blob must be bytes")
    try:
        return _as_mutable_secret(_call_crypt_unprotect(blob))
    except DPAPIError:
        raise
    except Exception as exc:
        raise DPAPIError("unwrap", "Windows DPAPI unprotection failed.") from exc


def _ensure_windows(operation: str = "operation") -> None:
    if sys.platform != "win32":
        raise DPAPIError(operation, "Windows DPAPI is available only on Windows.")


def _load_apis():
    global _crypt32, _kernel32
    _ensure_windows("load")
    if _crypt32 is not None and _kernel32 is not None:
        return _crypt32, _kernel32

    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        wintypes.LPCWSTR,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptProtectData.restype = wintypes.BOOL

    crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.POINTER(DATA_BLOB),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(DATA_BLOB),
    ]
    crypt32.CryptUnprotectData.restype = wintypes.BOOL

    kernel32.LocalFree.argtypes = [wintypes.HLOCAL]
    kernel32.LocalFree.restype = wintypes.HLOCAL

    _crypt32 = crypt32
    _kernel32 = kernel32
    return _crypt32, _kernel32


def _bytes_to_blob(data: bytes | bytearray) -> tuple[DATA_BLOB, object | None]:
    if data:
        if isinstance(data, bytearray):
            buffer = (ctypes.c_byte * len(data)).from_buffer(data)
        else:
            buffer = ctypes.create_string_buffer(data, len(data))
        pointer = ctypes.cast(buffer, ctypes.POINTER(ctypes.c_byte))
    else:
        buffer = None
        pointer = None
    return DATA_BLOB(len(data), pointer), buffer


def _blob_to_bytes(blob: DATA_BLOB) -> bytes:
    if not blob.pbData or blob.cbData == 0:
        return b""
    return ctypes.string_at(blob.pbData, blob.cbData)


def _blob_to_bytearray(blob: DATA_BLOB) -> bytearray:
    if not blob.pbData or blob.cbData == 0:
        return bytearray()
    result = bytearray(blob.cbData)
    buffer = (ctypes.c_byte * len(result)).from_buffer(result)
    ctypes.memmove(buffer, blob.pbData, blob.cbData)
    return result


def _as_mutable_secret(data: bytes | bytearray) -> bytearray:
    if isinstance(data, bytearray):
        return data
    return bytearray(data)


def _free_blob(blob: DATA_BLOB) -> None:
    if not blob.pbData:
        return
    _load_apis()[1].LocalFree(ctypes.cast(blob.pbData, wintypes.HLOCAL))


def _format_last_error() -> tuple[int, str]:
    winerror = ctypes.get_last_error()
    try:
        detail = ctypes.FormatError(winerror).strip()
    except Exception:
        detail = f"Win32 error {winerror}"
    return winerror, detail


def _call_crypt_protect(data: bytes | bytearray) -> bytes:
    crypt32, _kernel = _load_apis()
    data_blob, data_buffer = _bytes_to_blob(data)
    entropy_blob, entropy_buffer = _bytes_to_blob(DPAPI_DEVICE_KEY_ENTROPY_V1)
    out_blob = DATA_BLOB()

    # Keep buffers alive until the Win32 call returns.
    _ = (data_buffer, entropy_buffer)
    ok = crypt32.CryptProtectData(
        ctypes.byref(data_blob),
        _DESCRIPTION,
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        winerror, detail = _format_last_error()
        raise DPAPIError("wrap", f"Windows DPAPI protection failed: {detail}", winerror)

    try:
        return _blob_to_bytes(out_blob)
    finally:
        _free_blob(out_blob)


def _call_crypt_unprotect(blob: bytes) -> bytearray:
    crypt32, _kernel = _load_apis()
    data_blob, data_buffer = _bytes_to_blob(blob)
    entropy_blob, entropy_buffer = _bytes_to_blob(DPAPI_DEVICE_KEY_ENTROPY_V1)
    out_blob = DATA_BLOB()

    _ = (data_buffer, entropy_buffer)
    ok = crypt32.CryptUnprotectData(
        ctypes.byref(data_blob),
        None,
        ctypes.byref(entropy_blob),
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        winerror, detail = _format_last_error()
        raise DPAPIError("unwrap", f"Windows DPAPI unprotection failed: {detail}", winerror)

    try:
        return _blob_to_bytearray(out_blob)
    finally:
        if out_blob.pbData and out_blob.cbData:
            ctypes.memset(out_blob.pbData, 0, out_blob.cbData)
        _free_blob(out_blob)
