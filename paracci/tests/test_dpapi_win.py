import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from desktop import dpapi_win
from desktop.dpapi_win import DPAPIError, unwrap_with_dpapi, wrap_with_dpapi


def test_dpapi_calls_fail_cleanly_on_non_windows(monkeypatch):
    monkeypatch.setattr(dpapi_win.sys, "platform", "linux")

    with pytest.raises(DPAPIError, match="available only on Windows"):
        wrap_with_dpapi(b"secret")

    with pytest.raises(DPAPIError, match="available only on Windows"):
        unwrap_with_dpapi(b"blob")


def test_dpapi_public_api_is_mockable_without_windows(monkeypatch):
    monkeypatch.setattr(dpapi_win.sys, "platform", "win32")
    monkeypatch.setattr(dpapi_win, "_call_crypt_protect", lambda data: b"mock-dpapi:" + data)

    def fake_unprotect(blob: bytes) -> bytes:
        if not blob.startswith(b"mock-dpapi:"):
            raise DPAPIError("unwrap", "mock unwrap failed")
        return blob.removeprefix(b"mock-dpapi:")

    monkeypatch.setattr(dpapi_win, "_call_crypt_unprotect", fake_unprotect)

    wrapped = wrap_with_dpapi(b"intermediate-key")

    assert wrapped == b"mock-dpapi:intermediate-key"
    assert unwrap_with_dpapi(wrapped) == b"intermediate-key"
    with pytest.raises(DPAPIError, match="mock unwrap failed"):
        unwrap_with_dpapi(b"bad")


@pytest.mark.skipif(sys.platform != "win32", reason="real DPAPI is Windows-only")
def test_dpapi_real_round_trip_on_windows():
    wrapped = wrap_with_dpapi(b"real-windows-round-trip")

    assert wrapped != b"real-windows-round-trip"
    assert unwrap_with_dpapi(wrapped) == b"real-windows-round-trip"
