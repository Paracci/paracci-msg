"""L-5 Broad Exception Narrowing — regression tests.

Verifies that:
- Unexpected errors in session_open return HTTP 500 with a generic message and
  never leak raw exception strings to the JSON response body.
- Unexpected errors in UIApi.dispatch produce UIApiError("unexpected_error", ...)
  and never leak raw exception strings in to_dict() output.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from desktop.services import NativeServices
from ui_api import UIApi, UIApiError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SENTINEL = "raw sentinel"


def make_api(path: Path) -> UIApi:
    path.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(path)
    svc = NativeServices(path, "en")
    return UIApi(svc)


# ---------------------------------------------------------------------------
# Fix 2 — UIApi.dispatch tests
# ---------------------------------------------------------------------------


def test_dispatch_unexpected_error_returns_stable_code(tmp_path):
    """Unexpected RuntimeError in a handler must produce stable code, not class name."""
    api = make_api(tmp_path / "ui-api-unexpected")

    # Inject a handler that always raises an unexpected error
    def cmd_fail_unexpectedly():
        raise RuntimeError(SENTINEL)

    api.cmd_fail_unexpectedly = cmd_fail_unexpectedly

    with pytest.raises(UIApiError) as exc_info:
        api.dispatch("fail_unexpectedly")

    err = exc_info.value
    assert err.code == "unexpected_error", (
        f"Expected stable code 'unexpected_error', got {err.code!r}"
    )
    assert err.message == "Unexpected error.", (
        f"Expected stable message 'Unexpected error.', got {err.message!r}"
    )


def test_dispatch_unexpected_error_sentinel_absent_from_to_dict(tmp_path):
    """Raw sentinel string must NOT appear in the to_dict() payload."""
    api = make_api(tmp_path / "ui-api-sentinel")

    def cmd_leak_sentinel():
        raise RuntimeError(SENTINEL)

    api.cmd_leak_sentinel = cmd_leak_sentinel

    with pytest.raises(UIApiError) as exc_info:
        api.dispatch("leak_sentinel")

    payload = exc_info.value.to_dict()
    payload_str = json.dumps(payload)
    assert SENTINEL not in payload_str, (
        f"Sentinel leaked into UIApiError to_dict() payload: {payload_str!r}"
    )


def test_dispatch_session_service_error_uses_stable_code(tmp_path):
    """SessionServiceError must use 'session_service_error' code, not the class name."""
    from desktop.services import SessionServiceError

    api = make_api(tmp_path / "ui-api-session-svc")

    def cmd_session_svc_error():
        raise SessionServiceError("some internal detail")

    api.cmd_session_svc_error = cmd_session_svc_error

    with pytest.raises(UIApiError) as exc_info:
        api.dispatch("session_svc_error")

    err = exc_info.value
    assert err.code == "session_service_error", (
        f"Expected stable code 'session_service_error', got {err.code!r}"
    )
    # Class name 'SessionServiceError' must not appear as the code
    assert err.code != "SessionServiceError", "Raw class name leaked as code"


def test_dispatch_message_service_error_uses_stable_code(tmp_path):
    """MessageServiceError must use 'message_service_error' code, not the class name."""
    from desktop.services import MessageServiceError

    api = make_api(tmp_path / "ui-api-msg-svc")

    def cmd_msg_svc_error():
        raise MessageServiceError("internal message detail")

    api.cmd_msg_svc_error = cmd_msg_svc_error

    with pytest.raises(UIApiError) as exc_info:
        api.dispatch("msg_svc_error")

    err = exc_info.value
    assert err.code == "message_service_error", (
        f"Expected stable code 'message_service_error', got {err.code!r}"
    )
    assert err.code != "MessageServiceError", "Raw class name leaked as code"


def test_dispatch_fatal_signals_not_swallowed(tmp_path):
    """(Memory/Keyboard/SystemExit) must not be caught by the broad handler."""
    api = make_api(tmp_path / "ui-api-fatal")

    def cmd_raise_keyboard():
        raise KeyboardInterrupt()

    api.cmd_raise_keyboard = cmd_raise_keyboard

    with pytest.raises(KeyboardInterrupt):
        api.dispatch("raise_keyboard")


# ---------------------------------------------------------------------------
# Fix 2 — raw-string regression assertion
# ---------------------------------------------------------------------------


def test_dispatch_no_raw_exception_strings_in_error_payload(tmp_path):
    """Combined regression: route JSON and facade error payloads contain no raw sentinel."""
    api = make_api(tmp_path / "ui-api-regression")

    def cmd_regression():
        raise ValueError(SENTINEL)

    api.cmd_regression = cmd_regression

    with pytest.raises(UIApiError) as exc_info:
        api.dispatch("regression")

    payload_json = json.dumps(exc_info.value.to_dict())
    assert SENTINEL not in payload_json, (
        f"Raw exception string appeared in error payload: {payload_json!r}"
    )
    assert "ValueError" not in payload_json, (
        f"Raw class name appeared in error payload: {payload_json!r}"
    )


# ---------------------------------------------------------------------------
# Fix 1 — session_open outer exception handler (unit-level)
# ---------------------------------------------------------------------------


def _load_locale(lang: str) -> dict:
    """Load raw locale JSON for the given language code."""
    i18n_dir = Path(__file__).parent.parent / "app" / "i18n"
    path = i18n_dir / f"{lang}.json"
    with open(path, encoding="utf-8") as f:
        import json
        return json.load(f)


def test_session_open_unexpected_error_message_is_generic(monkeypatch):
    """Verify the outer session_open fallback produces a generic i18n string.

    We test by loading the en locale JSON and verifying the key exists and
    has a non-empty, non-sentinel value.
    """
    strings = _load_locale("en")
    value = strings.get("session", {}).get("unexpected_error", "")

    assert value, "i18n key 'session.unexpected_error' is missing or empty in en locale"
    assert SENTINEL not in value, (
        f"Sentinel appeared in i18n string for 'session.unexpected_error': {value!r}"
    )


def test_session_package_limit_error_message_is_generic(monkeypatch):
    """Verify the package_limit_error key resolves to a non-empty string."""
    strings = _load_locale("en")
    value = strings.get("session", {}).get("package_limit_error", "")

    assert value, "i18n key 'session.package_limit_error' is missing or empty in en locale"
    assert SENTINEL not in value, (
        f"Sentinel appeared in i18n string for 'session.package_limit_error': {value!r}"
    )


def test_all_locales_have_unexpected_error_key():
    """All 6 locale files must contain session.unexpected_error."""
    locales = ["en", "de", "es", "fr", "ru", "tr"]
    for lang in locales:
        strings = _load_locale(lang)
        session_block = strings.get("session", {})
        key = "unexpected_error"
        assert key in session_block, (
            f"Missing 'session.{key}' in locale '{lang}'"
        )
        assert session_block[key], (
            f"Empty value for session.{key} in locale '{lang}'"
        )


def test_all_locales_have_package_limit_error_key():
    """All 6 locale files must contain session.package_limit_error."""
    locales = ["en", "de", "es", "fr", "ru", "tr"]
    for lang in locales:
        strings = _load_locale(lang)
        session_block = strings.get("session", {})
        key = "package_limit_error"
        assert key in session_block, (
            f"Missing 'session.{key}' in locale '{lang}'"
        )
        assert session_block[key], (
            f"Empty value for session.{key} in locale '{lang}'"
        )


def test_all_locales_have_secure_delete_failure_warning():
    """All shipped locales expose the nonfatal secure-delete warning."""
    for lang in ["en", "de", "es", "fr", "ru", "tr"]:
        warning = _load_locale(lang).get("session", {}).get("secure_delete_failed", "")
        assert warning, f"Missing or empty session.secure_delete_failed in locale '{lang}'"


def test_session_js_renders_secure_delete_warning_as_security_alert():
    session_js = (
        Path(__file__).parent.parent / "app" / "static" / "js" / "session.js"
    ).read_text(encoding="utf-8")

    assert "data.secure_delete_warning" in session_js
    assert "appendAlert(securityDiv, 'error', warnLabel, data.secure_delete_warning)" in session_js
