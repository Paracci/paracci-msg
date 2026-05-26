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
from core.shields.base import BaseShield  # noqa: E402


class FakeUser32:
    def __init__(self, register_result=0xC001, sequence_result=None):
        self.register_result = register_result
        self.sequence_result = sequence_result
        self.registered_names = []
        self.open_calls = 0
        self.empty_calls = 0
        self.close_calls = 0
        self.sequence_number = 100
        self.content = ""

    def OpenClipboard(self, _owner):
        self.open_calls += 1
        return True

    def EmptyClipboard(self):
        self.empty_calls += 1
        self.sequence_number += 1
        self.content = ""
        return True

    def CloseClipboard(self):
        self.close_calls += 1
        return True

    def RegisterClipboardFormatW(self, name):
        self.registered_names.append(name)
        return self.register_result

    def GetClipboardSequenceNumber(self):
        if self.sequence_result is not None:
            return self.sequence_result
        return self.sequence_number

    def replace_externally(self, content, *, advance_sequence=True):
        self.content = content
        if advance_sequence:
            self.sequence_number += 1


def make_shield(*, register_result=0xC001, rejected_format=None, sequence_result=None):
    shield = WindowsShield.__new__(WindowsShield)
    BaseShield.__init__(shield)
    user32 = FakeUser32(register_result=register_result, sequence_result=sequence_result)
    placements = []

    def place(format_id, payload):
        placements.append((format_id, payload))
        if format_id == rejected_format:
            return False
        user32.sequence_number += 1
        if format_id == CF_UNICODETEXT:
            user32.content = payload[:-2].decode("utf-16le").split("\x00", 1)[0]
        return True

    shield._user32 = user32
    shield._place_clipboard_data = place
    shield._read_open_clipboard_text = lambda: user32.content
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


def test_empty_windows_clear_without_owner_does_not_wipe_clipboard():
    shield, user32, placements = make_shield()
    user32.replace_externally("foreign")

    assert shield.copy_to_clipboard("", clear_delay=0) is True

    assert user32.registered_names == []
    assert placements == []
    assert user32.content == "foreign"
    assert user32.empty_calls == 0
    assert user32.close_calls == 0


def test_windows_exit_cleanup_clears_active_owned_content():
    shield, user32, _placements = make_shield()
    assert shield.copy_to_clipboard("secret", clear_delay=0) is True

    assert shield.clear_owned_clipboard() is True

    assert user32.content == ""
    assert user32.empty_calls == 2
    assert shield._clipboard_owner is None


def test_windows_exit_cleanup_skips_foreign_clipboard_content():
    shield, user32, _placements = make_shield()
    assert shield.copy_to_clipboard("secret", clear_delay=0) is True
    user32.replace_externally("foreign")

    assert shield.clear_owned_clipboard() is True

    assert user32.content == "foreign"
    assert user32.empty_calls == 1
    assert shield._clipboard_owner is None


def test_windows_content_mismatch_skips_clear_even_without_sequence_change():
    shield, user32, _placements = make_shield()
    assert shield.copy_to_clipboard("secret", clear_delay=0) is True
    user32.replace_externally("foreign", advance_sequence=False)

    assert shield.clear_owned_clipboard() is True

    assert user32.content == "foreign"
    assert user32.empty_calls == 1


def test_windows_sequence_change_skips_clear_even_when_text_matches():
    shield, user32, _placements = make_shield()
    assert shield.copy_to_clipboard("secret", clear_delay=0) is True
    user32.replace_externally("secret")

    assert shield.clear_owned_clipboard() is True

    assert user32.content == "secret"
    assert user32.empty_calls == 1


def test_stale_windows_clear_cannot_wipe_new_identical_copy():
    shield, user32, _placements = make_shield()
    assert shield.copy_to_clipboard("same", clear_delay=0) is True
    stale_owner = shield._clipboard_owner
    assert shield.copy_to_clipboard("same", clear_delay=0) is True
    active_owner = shield._clipboard_owner

    assert shield.clear_owned_clipboard(stale_owner) is True
    assert user32.content == "same"
    assert shield.clear_owned_clipboard(active_owner) is True
    assert user32.content == ""


def test_empty_windows_request_clears_only_active_owned_content():
    shield, user32, _placements = make_shield()
    assert shield.copy_to_clipboard("secret", clear_delay=0) is True

    assert shield.copy_to_clipboard("", clear_delay=0) is True
    assert user32.content == ""

    assert shield.copy_to_clipboard("secret", clear_delay=0) is True
    user32.replace_externally("foreign")
    assert shield.copy_to_clipboard("", clear_delay=0) is True
    assert user32.content == "foreign"


def test_windows_copy_rejects_untracked_plaintext_when_sequence_number_unavailable():
    shield, user32, _placements = make_shield(sequence_result=0)

    assert shield.copy_to_clipboard("secret", clear_delay=0) is False

    assert user32.content == ""
    assert user32.empty_calls == 2
    assert shield._clipboard_owner is None


def test_failed_windows_replacement_preserves_unchanged_owned_content():
    shield, user32, _placements = make_shield()
    assert shield.copy_to_clipboard("secret", clear_delay=0) is True
    active_owner = shield._clipboard_owner

    def reject_empty():
        user32.empty_calls += 1
        return False

    user32.EmptyClipboard = reject_empty
    assert shield.copy_to_clipboard("replacement", clear_delay=0) is False

    assert user32.content == "secret"
    assert shield._clipboard_owner is active_owner


def test_windows_owner_tracks_text_representable_before_embedded_nul():
    shield, user32, _placements = make_shield()

    assert shield.copy_to_clipboard("secret\x00ignored", clear_delay=0) is True
    assert shield.clear_owned_clipboard() is True

    assert user32.content == ""
