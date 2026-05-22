import base64
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "paracci"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

import run


class RecordingEventHook:
    def __init__(self):
        self.handlers = []

    def __iadd__(self, handler):
        self.handlers.append(handler)
        return self


class FakeMainWindow:
    def __init__(self, loaded):
        self.events = SimpleNamespace(loaded=loaded)
        self.destroyed = False
        self.scripts = []

    def destroy(self):
        self.destroyed = True

    def evaluate_js(self, script):
        self.scripts.append(script)


def test_navigation_guard_install_success_records_loaded_handler(monkeypatch):
    monkeypatch.setattr(run, "_preview_close_guard_active", lambda: False)
    hook = RecordingEventHook()
    window = FakeMainWindow(hook)
    script = "window.__test_guard = true;"

    run._install_navigation_guard_or_exit(window, script)

    assert len(hook.handlers) == 1
    hook.handlers[0]()
    assert window.scripts == [script]
    assert window.destroyed is False


def test_navigation_guard_loaded_handler_skips_preview_close(monkeypatch):
    monkeypatch.setattr(run, "_preview_close_guard_active", lambda: True)
    hook = RecordingEventHook()
    window = FakeMainWindow(hook)

    run._install_navigation_guard_or_exit(window, "window.__test_guard = true;")

    hook.handlers[0]()
    assert window.scripts == []
    assert window.destroyed is False


def test_main_navigation_guard_script_blocks_external_links():
    script = run._build_main_navigation_guard_script("127.0.0.1", 18080)

    assert "document.addEventListener('click'" in script
    assert "document.addEventListener('auxclick'" in script
    assert "document.addEventListener('submit'" in script
    assert "window.open = function(url)" in script
    assert '"127.0.0.1"' in script
    assert '"18080"' in script


@pytest.mark.parametrize(
    "needle",
    [
        "window.__PARACCI_NAVIGATION_GUARD_INSTALLED__",
        "function isAllowedHref(href)",
        "target.protocol === 'http:'",
        "target.hostname === allowedHost",
        "target.port === allowedPort",
        "target.username === ''",
        "target.password === ''",
        "event.preventDefault();",
        "event.stopImmediatePropagation();",
        "console.warn('Paracci blocked external navigation:', href);",
    ],
)
def test_main_navigation_guard_script_contains_loopback_policy(needle):
    script = run._build_main_navigation_guard_script("127.0.0.1", 18080)

    assert needle in script


def test_main_pro_api_exposes_expected_methods():
    api = run.ProApi()

    for method in [
        "close",
        "minimize",
        "select_file",
        "select_attachments",
        "save_file",
        "save_file_silent",
        "open_file_location",
        "copy_and_clear",
        "open_preview_window",
    ]:
        assert callable(getattr(api, method))


def test_session_markdown_uses_fragment_only_uri_policy():
    session_js = (PACKAGE_ROOT / "app" / "static" / "js" / "session.js").read_text(encoding="utf-8")

    assert "function renderSafeMarkdown" in session_js
    assert "function sanitizeRenderedMarkdown" in session_js
    assert "ALLOWED_URI_REGEXP: MARKDOWN_FRAGMENT_HREF_RE" in session_js
    assert "FORBID_ATTR: ['target']" in session_js
    assert "innerHTML = sanitizer.sanitize(rawHtml)" not in session_js
    assert "innerHTML = renderSafeMarkdown(data.text, sanitizer)" in session_js
    assert "const MARKDOWN_FRAGMENT_HREF_RE = /^#[^\\s\"'<>]*$/;" in session_js


def test_save_file_silent_strips_path_traversal_filename(tmp_path, monkeypatch):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    content_b64 = base64.b64encode(b"payload").decode("ascii")

    saved_path = run.ProApi().save_file_silent(content_b64, "../../../evil.exe")

    target = downloads / "evil.exe"
    assert saved_path == str(target)
    assert target.read_bytes() == b"payload"
    assert not (tmp_path / "evil.exe").exists()


def test_save_file_silent_uses_attachment_fallback_for_empty_filename(tmp_path, monkeypatch):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    content_b64 = base64.b64encode(b"payload").decode("ascii")

    saved_path = run.ProApi().save_file_silent(content_b64, "...")

    target = downloads / "attachment"
    assert saved_path == str(target)
    assert target.read_bytes() == b"payload"
