import logging
import sys
from pathlib import Path

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from core.shields.windows import (  # noqa: E402
    CF_UNICODETEXT,
    CLIPBOARD_HISTORY_EXCLUSION_FORMAT,
    WindowsShield,
)


class FakeUser32:
    def __init__(self, register_result=0xC001):
        self.register_result = register_result
        self.registered_names = []
        self.open_calls = 0
        self.empty_calls = 0
        self.close_calls = 0

    def OpenClipboard(self, _owner):
        self.open_calls += 1
        return True

    def EmptyClipboard(self):
        self.empty_calls += 1
        return True

    def CloseClipboard(self):
        self.close_calls += 1
        return True

    def RegisterClipboardFormatW(self, name):
        self.registered_names.append(name)
        return self.register_result


def make_shield(*, register_result=0xC001, rejected_format=None):
    shield = WindowsShield.__new__(WindowsShield)
    user32 = FakeUser32(register_result=register_result)
    placements = []

    def place(format_id, payload):
        placements.append((format_id, payload))
        return format_id != rejected_format

    shield._user32 = user32
    shield._place_clipboard_data = place
    return shield, user32, placements


def test_sensitive_windows_copy_places_history_exclusion_before_text():
    shield, user32, placements = make_shield()

    assert shield.copy_to_clipboard("secret", clear_delay=0) is True

    assert user32.registered_names == [CLIPBOARD_HISTORY_EXCLUSION_FORMAT]
    assert placements == [
        (0xC001, b"\x00"),
        (CF_UNICODETEXT, "secret".encode("utf-16le") + b"\x00\x00"),
    ]
    assert user32.empty_calls == 1
    assert user32.close_calls == 1


@pytest.mark.parametrize(
    ("register_result", "rejected_format"),
    [(0, None), (0xC001, 0xC001)],
)
def test_sensitive_windows_copy_fails_closed_without_history_exclusion(
    register_result, rejected_format, caplog
):
    shield, _user32, placements = make_shield(
        register_result=register_result,
        rejected_format=rejected_format,
    )

    with caplog.at_level(logging.WARNING):
        assert shield.copy_to_clipboard("secret", clear_delay=0) is False

    assert all(format_id != CF_UNICODETEXT for format_id, _payload in placements)
    assert "copy rejected" in caplog.text


def test_empty_windows_clear_does_not_attempt_history_mutation():
    shield, user32, placements = make_shield()

    assert shield.copy_to_clipboard("", clear_delay=0) is True

    assert user32.registered_names == []
    assert placements == []
    assert user32.empty_calls == 1
    assert user32.close_calls == 1
