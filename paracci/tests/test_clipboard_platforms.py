import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from core.shields import linux as linux_module  # noqa: E402
from core.shields import macos as macos_module  # noqa: E402
from core.shields.linux import LinuxShield  # noqa: E402
from core.shields.macos import MacOSShield  # noqa: E402


class MacClipboardRunner:
    def __init__(self):
        self.content = b""
        self.commands = []

    def __call__(self, command, **kwargs):
        self.commands.append((list(command), kwargs.get("input")))
        if command == ["pbcopy"]:
            self.content = kwargs["input"]
            return SimpleNamespace(returncode=0)
        if command == ["pbpaste"]:
            return SimpleNamespace(returncode=0, stdout=self.content)
        raise AssertionError(f"Unexpected macOS clipboard command: {command}")


class LinuxClipboardRunner:
    def __init__(self, *, fail_xclip=False):
        self.fail_xclip = fail_xclip
        self.content = b""
        self.commands = []

    def __call__(self, command, **kwargs):
        command = list(command)
        self.commands.append((command, kwargs.get("input")))
        if command == ["xclip", "-selection", "clipboard"]:
            if self.fail_xclip:
                raise FileNotFoundError("xclip unavailable")
            self.content = kwargs["input"]
            return SimpleNamespace(returncode=0)
        if command == ["wl-copy"]:
            self.content = kwargs["input"]
            return SimpleNamespace(returncode=0)
        if command == ["xclip", "-selection", "clipboard", "-out"]:
            return SimpleNamespace(returncode=0, stdout=self.content)
        if command == ["wl-paste", "--no-newline"]:
            return SimpleNamespace(returncode=0, stdout=self.content)
        raise AssertionError(f"Unexpected Linux clipboard command: {command}")


@pytest.fixture(params=["macos", "linux"])
def clipboard_harness(request, monkeypatch):
    if request.param == "macos":
        runner = MacClipboardRunner()
        monkeypatch.setattr(macos_module.subprocess, "run", runner)
        return MacOSShield(), runner

    runner = LinuxClipboardRunner()
    monkeypatch.setattr(linux_module.subprocess, "run", runner)
    return LinuxShield(), runner


def test_exit_cleanup_clears_owned_platform_clipboard_content(clipboard_harness):
    shield, runner = clipboard_harness
    assert shield.copy_to_clipboard("secret", clear_delay=0) is True

    assert shield.clear_owned_clipboard() is True

    assert runner.content == b""
    assert shield._clipboard_owner is None


def test_exit_cleanup_does_not_clear_foreign_platform_content(clipboard_harness):
    shield, runner = clipboard_harness
    assert shield.copy_to_clipboard("secret", clear_delay=0) is True
    runner.content = b"foreign"

    assert shield.clear_owned_clipboard() is True

    assert runner.content == b"foreign"
    assert shield._clipboard_owner is None


def test_stale_platform_callback_cannot_clear_new_identical_copy(clipboard_harness):
    shield, runner = clipboard_harness
    assert shield.copy_to_clipboard("same", clear_delay=0) is True
    stale_owner = shield._clipboard_owner
    assert shield.copy_to_clipboard("same", clear_delay=0) is True
    active_owner = shield._clipboard_owner

    assert shield.clear_owned_clipboard(stale_owner) is True
    assert runner.content == b"same"
    assert shield.clear_owned_clipboard(active_owner) is True
    assert runner.content == b""


def test_empty_platform_request_does_not_clear_foreign_content(clipboard_harness):
    shield, runner = clipboard_harness
    assert shield.copy_to_clipboard("secret", clear_delay=0) is True
    runner.content = b"foreign"

    assert shield.copy_to_clipboard("", clear_delay=0) is True

    assert runner.content == b"foreign"


def test_linux_reads_and_clears_through_successful_wayland_backend(monkeypatch):
    runner = LinuxClipboardRunner(fail_xclip=True)
    monkeypatch.setattr(linux_module.subprocess, "run", runner)
    shield = LinuxShield()

    assert shield.copy_to_clipboard("secret", clear_delay=0) is True
    assert shield.clear_owned_clipboard() is True

    assert runner.commands == [
        (["xclip", "-selection", "clipboard"], b"secret"),
        (["wl-copy"], b"secret"),
        (["wl-paste", "--no-newline"], None),
        (["wl-copy"], b""),
    ]
