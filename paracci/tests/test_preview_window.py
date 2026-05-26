import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "paracci"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

import run


TOKEN_A = "a" * 64
TOKEN_B = "b" * 64


class EventHook:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, handler):
        self.handlers.append(handler)
        return self

    def fire(self):
        for handler in list(self.handlers):
            handler()


class FakeWindow:
    def __init__(self, **kwargs):
        self.kwargs = kwargs
        self.destroyed = False
        self.dialog_path = None
        self.confirmation_result = True
        self.confirmations = []
        self.evaluated_js = []
        self.events = SimpleNamespace(closed=EventHook())

    def destroy(self):
        self.destroyed = True

    def create_file_dialog(self, *args, **kwargs):
        return self.dialog_path

    def create_confirmation_dialog(self, title, message):
        self.confirmations.append((title, message))
        return self.confirmation_result

    def evaluate_js(self, script):
        self.evaluated_js.append(script)


class RecordingPreviewStore:
    def __init__(self):
        self.revoked = []
        self.entries = {}

    def revoke(self, token):
        self.revoked.append(token)

    def get(self, token):
        return self.entries.get(token)


@pytest.fixture(autouse=True)
def reset_preview_window_state(monkeypatch):
    created = []
    store = RecordingPreviewStore()

    def fake_create_window(**kwargs):
        window = FakeWindow(**kwargs)
        created.append(window)
        return window

    with run._preview_windows_lock:
        run._preview_windows.clear()
    run._configure_preview_window_context("127.0.0.1", 18080)
    monkeypatch.setattr(run.webview, "create_window", fake_create_window)
    monkeypatch.setattr(run, "preview_store", store)

    yield created, store

    with run._preview_windows_lock:
        run._preview_windows.clear()


def test_open_preview_window_registers_window_and_token_url(reset_preview_window_state):
    created, _store = reset_preview_window_state

    run.open_preview_window(TOKEN_A, "picture.png", "image/png", 123)

    assert run._preview_windows[TOKEN_A] is created[0]
    assert created[0].kwargs["url"] == f"http://127.0.0.1:18080/preview/{TOKEN_A}"
    assert created[0].kwargs["title"] == "picture.png"
    assert created[0].kwargs["width"] == 900
    assert created[0].kwargs["height"] == 700
    assert created[0].kwargs["resizable"] is True
    assert created[0].kwargs["on_top"] is False
    assert created[0].kwargs["text_select"] is True
    assert created[0].kwargs["js_api"].token == TOKEN_A
    assert hasattr(created[0].kwargs["js_api"], "close_preview_window")
    assert hasattr(created[0].kwargs["js_api"], "download_preview_file")


@pytest.mark.parametrize(
    ("filename", "mime_type", "expected"),
    [
        ("image.jpg", "image/jpeg", (900, 700)),
        ("movie.mp4", "video/mp4", (1024, 640)),
        ("song.mp3", "audio/mpeg", (500, 200)),
        ("notes.md", "text/markdown", (900, 700)),
        ("report.pdf", "application/pdf", (900, 800)),
        ("archive.bin", "application/octet-stream", (800, 600)),
    ],
)
def test_open_preview_window_uses_mime_specific_sizes(
    reset_preview_window_state,
    filename,
    mime_type,
    expected,
):
    created, _store = reset_preview_window_state

    run.open_preview_window(TOKEN_A, filename, mime_type, 123)

    assert (created[0].kwargs["width"], created[0].kwargs["height"]) == expected


def test_open_preview_window_truncates_long_titles(reset_preview_window_state):
    created, _store = reset_preview_window_state
    filename = "a" * 80 + ".txt"

    run.open_preview_window(TOKEN_A, filename, "text/plain", 123)

    assert len(created[0].kwargs["title"]) == 60
    assert created[0].kwargs["title"].endswith("...")


def test_preview_closed_removes_registry_entry_and_revokes_token(reset_preview_window_state):
    created, store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "note.txt", "text/plain", 123)

    created[0].events.closed.fire()

    assert TOKEN_A not in run._preview_windows
    assert store.revoked == [TOKEN_A]


def test_preview_api_close_destroys_only_matching_window(reset_preview_window_state):
    created, store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "a.txt", "text/plain", 1)
    run.open_preview_window(TOKEN_B, "b.txt", "text/plain", 1)

    result = created[0].kwargs["js_api"].close_preview_window(TOKEN_A)

    assert result == {"success": True}
    assert created[0].destroyed is True
    assert created[1].destroyed is False
    assert TOKEN_A not in run._preview_windows
    assert TOKEN_B in run._preview_windows
    assert store.revoked == [TOKEN_A]


def test_preview_api_rejects_wrong_close_token(reset_preview_window_state):
    created, store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "a.txt", "text/plain", 1)

    result = created[0].kwargs["js_api"].close_preview_window(TOKEN_B)

    assert result["success"] is False
    assert created[0].destroyed is False
    assert TOKEN_A in run._preview_windows
    assert store.revoked == []


def test_preview_api_download_saves_to_downloads_folder(
    reset_preview_window_state,
    tmp_path,
    monkeypatch,
):
    created, store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "note.txt", "text/plain", 12)
    from core.config import ParacciConfig
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    store.entries[TOKEN_A] = SimpleNamespace(
        file_bytes=b"preview-bytes",
        filename="note.txt",
        allow_download=True,
    )

    result = created[0].kwargs["js_api"].download_preview_file(TOKEN_A)

    target = downloads / "note.txt"
    assert result["success"] is True
    assert result["path"] == str(target)
    assert result["filename"] == "note.txt"
    assert target.read_bytes() == b"preview-bytes"
    assert created[0].evaluated_js == ['window.showDownloadSuccess("note.txt");']
    assert created[0].confirmations == [
        ("Confirm download", "Save note.txt to Paracci Downloads?")
    ]


def test_preview_api_download_uses_collision_safe_downloads_filename(
    reset_preview_window_state,
    tmp_path,
    monkeypatch,
):
    created, store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "note.txt", "text/plain", 12)
    from core.config import ParacciConfig
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(tmp_path / "Downloads")))
    downloads = tmp_path / "Downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    (downloads / "note.txt").write_bytes(b"existing")
    store.entries[TOKEN_A] = SimpleNamespace(
        file_bytes=b"preview-bytes",
        filename="note.txt",
        allow_download=True,
    )

    result = created[0].kwargs["js_api"].download_preview_file(TOKEN_A)

    target = downloads / "note_1.txt"
    assert result["success"] is True
    assert target.read_bytes() == b"preview-bytes"
    assert created[0].evaluated_js == ['window.showDownloadSuccess("note_1.txt");']


def test_preview_api_download_declines_without_writing(
    reset_preview_window_state,
    tmp_path,
    monkeypatch,
):
    created, store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "note.txt", "text/plain", 12)
    created[0].confirmation_result = False
    from core.config import ParacciConfig
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    store.entries[TOKEN_A] = SimpleNamespace(
        file_bytes=b"preview-bytes",
        filename="note.txt",
        allow_download=True,
    )

    result = created[0].kwargs["js_api"].download_preview_file(TOKEN_A)

    assert result == {"success": False, "cancelled": True}
    assert list(downloads.iterdir()) == []


def test_preview_api_download_rejects_filename_outside_strict_native_policy(
    reset_preview_window_state,
    tmp_path,
    monkeypatch,
):
    created, store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "quarterly report.txt", "text/plain", 12)
    from core.config import ParacciConfig
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    store.entries[TOKEN_A] = SimpleNamespace(
        file_bytes=b"preview-bytes",
        filename="quarterly report.txt",
        allow_download=True,
    )

    result = created[0].kwargs["js_api"].download_preview_file(TOKEN_A)

    assert result["success"] is False
    assert result["error"] == "Invalid download filename."
    assert created[0].confirmations == []
    assert list(downloads.iterdir()) == []


def test_preview_api_download_rejects_non_downloadable_entry(reset_preview_window_state, tmp_path):
    created, store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "note.txt", "text/plain", 12)
    created[0].dialog_path = str(tmp_path / "saved.txt")
    store.entries[TOKEN_A] = SimpleNamespace(
        file_bytes=b"preview-bytes",
        filename="note.txt",
        allow_download=False,
    )

    result = created[0].kwargs["js_api"].download_preview_file(TOKEN_A)

    assert result["success"] is False
    assert result["error"] == "Download not permitted."


def test_preview_api_open_file_location_uses_validated_explorer_arguments(
    reset_preview_window_state,
    tmp_path,
    monkeypatch,
):
    created, _store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "note.txt", "text/plain", 12)
    from core.config import ParacciConfig
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    target = downloads / "note.txt"
    target.write_bytes(b"preview-bytes")
    launches = []
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    monkeypatch.setattr(run.subprocess, "Popen", lambda args: launches.append(args))

    result = created[0].kwargs["js_api"].open_file_location(str(target))

    assert result == {"success": True}
    assert launches == [["explorer", f"/select,{os.path.normpath(str(target.resolve()))}"]]


def test_preview_api_open_file_location_rejects_path_outside_downloads(
    reset_preview_window_state,
    tmp_path,
    monkeypatch,
):
    created, _store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "note.txt", "text/plain", 12)
    from core.config import ParacciConfig
    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    launches = []
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    monkeypatch.setattr(run.subprocess, "Popen", lambda args: launches.append(args))

    result = created[0].kwargs["js_api"].open_file_location(str(outside))

    assert result == {"success": False, "error": "File location is unavailable."}
    assert launches == []


def test_multiple_preview_windows_can_be_open(reset_preview_window_state):
    created, _store = reset_preview_window_state

    run.open_preview_window(TOKEN_A, "a.txt", "text/plain", 1)
    run.open_preview_window(TOKEN_B, "b.png", "image/png", 2)

    assert run._preview_windows[TOKEN_A] is created[0]
    assert run._preview_windows[TOKEN_B] is created[1]
    assert created[0] is not created[1]


def test_main_window_close_cleans_all_previews(reset_preview_window_state):
    created, store = reset_preview_window_state
    run.open_preview_window(TOKEN_A, "a.txt", "text/plain", 1)
    run.open_preview_window(TOKEN_B, "b.png", "image/png", 2)

    run._on_main_window_closed()

    assert run._preview_windows == {}
    assert [window.destroyed for window in created] == [True, True]
    assert store.revoked == [TOKEN_A, TOKEN_B]
