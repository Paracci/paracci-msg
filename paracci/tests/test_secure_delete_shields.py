import builtins
import ctypes
import errno
import logging
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

PACKAGE_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PACKAGE_ROOT))

from core.shields import linux as linux_module  # noqa: E402
from core.shields import macos as macos_module  # noqa: E402
from core.shields import windows as windows_module  # noqa: E402
from core.shields.linux import LinuxShield  # noqa: E402
from core.shields.macos import MacOSShield  # noqa: E402
from core.shields.windows import WindowsShield  # noqa: E402


ORIGINAL = b"original-sensitive-envelope-content"


def make_sensitive_file(tmp_path):
    path = tmp_path / "sensitive.paracci"
    path.write_bytes(ORIGINAL)
    return path


def capture_unlink(module, monkeypatch, events):
    original_remove = module.os.remove

    def remove(path):
        events.append(("unlink", Path(path).read_bytes()))
        original_remove(path)

    monkeypatch.setattr(module.os, "remove", remove)


def capture_open_modes(monkeypatch, path):
    modes = []
    original_open = builtins.open

    def open_file(target, mode="r", *args, **kwargs):
        if Path(target) == path:
            modes.append(mode)
        return original_open(target, mode, *args, **kwargs)

    monkeypatch.setattr(builtins, "open", open_file)
    return modes


class FakeKernel32:
    def __init__(self, events, result=True, raises=False):
        self.events = events
        self.result = result
        self.raises = raises

    def DeviceIoControl(self, _handle, code, input_buffer, *_args):
        if self.raises:
            raise OSError("trim rejected")
        trim = ctypes.cast(
            input_buffer, ctypes.POINTER(windows_module.FILE_LEVEL_TRIM)
        ).contents
        self.events.append(
            (
                "trim",
                code,
                trim.NumRanges,
                trim.Ranges[0].Offset,
                trim.Ranges[0].Length,
            )
        )
        return self.result


def make_windows_shield(events, result=True, raises=False):
    shield = WindowsShield.__new__(WindowsShield)
    shield._kernel32 = FakeKernel32(events, result=result, raises=raises)
    return shield


def test_windows_secure_delete_syncs_trims_full_range_and_unlinks(tmp_path, monkeypatch):
    path = make_sensitive_file(tmp_path)
    events = []
    shield = make_windows_shield(events)
    modes = capture_open_modes(monkeypatch, path)
    monkeypatch.setattr(windows_module, "msvcrt", SimpleNamespace(get_osfhandle=lambda _fd: 77))
    monkeypatch.setattr(windows_module.os, "urandom", lambda size: b"X" * size)
    monkeypatch.setattr(windows_module.os, "fsync", lambda _fd: events.append("fsync"))
    capture_unlink(windows_module, monkeypatch, events)

    assert shield.secure_delete(str(path)) is True

    assert events[0] == "fsync"
    assert events[1] == (
        "trim",
        windows_module.FSCTL_FILE_LEVEL_TRIM,
        1,
        0,
        len(ORIGINAL),
    )
    assert events[2] == ("unlink", b"X" * len(ORIGINAL))
    assert modes == ["r+b"]
    assert not path.exists()


@pytest.mark.parametrize("raises", [False, True])
def test_windows_trim_failures_are_debug_only_and_do_not_block_unlink(
    tmp_path, monkeypatch, caplog, raises
):
    path = make_sensitive_file(tmp_path)
    events = []
    shield = make_windows_shield(events, result=False, raises=raises)
    monkeypatch.setattr(windows_module, "msvcrt", SimpleNamespace(get_osfhandle=lambda _fd: 77))
    monkeypatch.setattr(windows_module.os, "urandom", lambda size: b"W" * size)
    capture_unlink(windows_module, monkeypatch, events)

    with caplog.at_level(logging.DEBUG):
        assert shield.secure_delete(str(path)) is True

    assert not path.exists()
    assert ("unlink", b"W" * len(ORIGINAL)) in events
    assert "FSCTL_FILE_LEVEL_TRIM" in caplog.text


def test_windows_trim_unavailable_is_debug_only_and_does_not_block_unlink(
    tmp_path, monkeypatch, caplog
):
    path = make_sensitive_file(tmp_path)
    events = []
    shield = make_windows_shield(events)
    monkeypatch.setattr(windows_module, "msvcrt", None)
    monkeypatch.setattr(windows_module.os, "urandom", lambda size: b"U" * size)
    capture_unlink(windows_module, monkeypatch, events)

    with caplog.at_level(logging.DEBUG):
        assert shield.secure_delete(str(path)) is True

    assert events == [("unlink", b"U" * len(ORIGINAL))]
    assert "FSCTL_FILE_LEVEL_TRIM hint unavailable" in caplog.text
    assert not path.exists()


def test_macos_secure_delete_uses_fullfsync_and_unlinks(tmp_path, monkeypatch):
    path = make_sensitive_file(tmp_path)
    events = []
    shield = MacOSShield()
    modes = capture_open_modes(monkeypatch, path)
    monkeypatch.setattr(
        macos_module,
        "fcntl",
        SimpleNamespace(F_FULLFSYNC=51, fcntl=lambda _fd, cmd: events.append(("fullfsync", cmd))),
    )
    monkeypatch.setattr(macos_module.os, "urandom", lambda size: b"M" * size)
    monkeypatch.setattr(
        macos_module.os,
        "fsync",
        lambda _fd: pytest.fail("fsync fallback should not run after F_FULLFSYNC succeeds"),
    )
    capture_unlink(macos_module, monkeypatch, events)

    assert shield.secure_delete(str(path)) is True

    assert events == [("fullfsync", 51), ("unlink", b"M" * len(ORIGINAL))]
    assert modes == ["r+b"]
    assert not path.exists()


def test_macos_fullfsync_failure_falls_back_and_unlinks(tmp_path, monkeypatch, caplog):
    path = make_sensitive_file(tmp_path)
    events = []
    shield = MacOSShield()

    def fail_fullfsync(_fd, _cmd):
        raise OSError("unsupported")

    monkeypatch.setattr(
        macos_module,
        "fcntl",
        SimpleNamespace(F_FULLFSYNC=51, fcntl=fail_fullfsync),
    )
    monkeypatch.setattr(macos_module.os, "urandom", lambda size: b"F" * size)
    monkeypatch.setattr(macos_module.os, "fsync", lambda _fd: events.append("fsync"))
    capture_unlink(macos_module, monkeypatch, events)

    with caplog.at_level(logging.DEBUG):
        assert shield.secure_delete(str(path)) is True

    assert events == ["fsync", ("unlink", b"F" * len(ORIGINAL))]
    assert "F_FULLFSYNC failed" in caplog.text
    assert not path.exists()


def test_macos_flush_failures_are_debug_only_and_do_not_block_unlink(
    tmp_path, monkeypatch, caplog
):
    path = make_sensitive_file(tmp_path)
    events = []
    shield = MacOSShield()
    monkeypatch.setattr(macos_module, "fcntl", None)
    monkeypatch.setattr(macos_module.os, "urandom", lambda size: b"N" * size)

    def fail_fsync(_fd):
        raise OSError("fsync rejected")

    monkeypatch.setattr(macos_module.os, "fsync", fail_fsync)
    capture_unlink(macos_module, monkeypatch, events)

    with caplog.at_level(logging.DEBUG):
        assert shield.secure_delete(str(path)) is True

    assert events == [("unlink", b"N" * len(ORIGINAL))]
    assert "F_FULLFSYNC unavailable" in caplog.text
    assert "fsync fallback failed" in caplog.text
    assert not path.exists()


class FakeFallocate:
    def __init__(self, events, result=0):
        self.events = events
        self.result = result
        self.argtypes = None
        self.restype = None

    def __call__(self, _fd, mode, offset, size):
        self.events.append(("punch", mode, offset, size))
        return self.result


def test_linux_secure_delete_syncs_punches_hole_and_unlinks(tmp_path, monkeypatch):
    path = make_sensitive_file(tmp_path)
    events = []
    shield = LinuxShield()
    modes = capture_open_modes(monkeypatch, path)
    fallocate = FakeFallocate(events)
    monkeypatch.setattr(
        linux_module.ctypes, "CDLL", lambda *_args, **_kwargs: SimpleNamespace(fallocate=fallocate)
    )
    monkeypatch.setattr(linux_module.os, "urandom", lambda size: b"L" * size)
    monkeypatch.setattr(
        linux_module.os,
        "fdatasync",
        lambda _fd: events.append("fdatasync"),
        raising=False,
    )
    capture_unlink(linux_module, monkeypatch, events)

    assert shield.secure_delete(str(path)) is True

    assert events == [
        "fdatasync",
        (
            "punch",
            linux_module.FALLOC_FL_PUNCH_HOLE | linux_module.FALLOC_FL_KEEP_SIZE,
            0,
            len(ORIGINAL),
        ),
        "fdatasync",
        ("unlink", b"L" * len(ORIGINAL)),
    ]
    assert modes == ["r+b"]
    assert not path.exists()


def test_linux_sync_and_punch_failures_are_debug_only_and_do_not_block_unlink(
    tmp_path, monkeypatch, caplog
):
    path = make_sensitive_file(tmp_path)
    events = []
    shield = LinuxShield()
    fallocate = FakeFallocate(events, result=-1)
    monkeypatch.setattr(
        linux_module.ctypes, "CDLL", lambda *_args, **_kwargs: SimpleNamespace(fallocate=fallocate)
    )
    monkeypatch.setattr(linux_module.ctypes, "get_errno", lambda: errno.EOPNOTSUPP)
    monkeypatch.setattr(linux_module.os, "urandom", lambda size: b"D" * size)

    def fail_fdatasync(_fd):
        raise OSError("sync rejected")

    monkeypatch.setattr(linux_module.os, "fdatasync", fail_fdatasync, raising=False)
    capture_unlink(linux_module, monkeypatch, events)

    with caplog.at_level(logging.DEBUG):
        assert shield.secure_delete(str(path)) is True

    assert events[-1] == ("unlink", b"D" * len(ORIGINAL))
    assert "fdatasync unavailable or failed" in caplog.text
    assert "FALLOC_FL_PUNCH_HOLE unavailable or failed" in caplog.text
    assert not path.exists()


@pytest.mark.parametrize(
    ("method", "api_name"),
    [
        (WindowsShield.secure_delete, "FSCTL_FILE_LEVEL_TRIM"),
        (MacOSShield.secure_delete, "F_FULLFSYNC"),
        (LinuxShield.secure_delete, "FALLOC_FL_PUNCH_HOLE"),
    ],
)
def test_secure_delete_docstrings_state_api_and_residual_limit(method, api_name):
    doc = " ".join((method.__doc__ or "").split())

    assert api_name in doc
    assert "physical erasure cannot be guaranteed from userspace" in doc
    assert "encryption key" in doc
