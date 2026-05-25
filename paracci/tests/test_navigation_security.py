import base64
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


def test_browser_bootstrap_seeds_memory_only_service_worker_before_navigation():
    bootstrap_js = (PACKAGE_ROOT / "app" / "static" / "js" / "bootstrap.js").read_text(encoding="utf-8")
    worker_js = (PACKAGE_ROOT / "app" / "static" / "js" / "loopback-auth-sw.js").read_text(encoding="utf-8")

    assert "navigator.serviceWorker.register(workerUrl, { scope: '/' })" in bootstrap_js
    assert "paracci:set-loopback-token" in bootstrap_js
    assert "window.location.replace(target)" in bootstrap_js
    assert "start().catch(failClosed)" in bootstrap_js
    assert "let loopbackToken = '';" in worker_js
    assert "X-Paracci-Token" in worker_js
    assert "localStorage" not in worker_js
    assert "indexedDB" not in worker_js


def test_app_navigation_reseeds_worker_for_protected_documents():
    app_js = (PACKAGE_ROOT / "app" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    session_js = (PACKAGE_ROOT / "app" / "static" / "js" / "session.js").read_text(encoding="utf-8")

    assert "async function seedLoopbackWorker()" in app_js
    assert "async function navigateAuthorized(url" in app_js
    assert "void navigateAuthorized(link.href);" in app_js
    assert "form.requestSubmit(submitter || undefined);" in app_js
    assert "window.location.href = response.url;" not in session_js
    assert "await window.ParacciSecurity.navigateAuthorized(response.url);" in session_js
    assert "await window.ParacciSecurity.seedLoopbackWorker()" in session_js
    assert "navigateAuthorized(tokenPreviewUrl(token)" in session_js


def test_native_drop_navigation_uses_authenticated_browser_helper():
    source = (REPO_ROOT / "run.py").read_text(encoding="utf-8")

    assert "window.ParacciSecurity.navigateAuthorized(target);" in source
    assert "window.location.href = '/session/import?native_file_id='" not in source


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
        "install_verified_update",
    ]:
        assert callable(getattr(api, method))


def test_open_file_location_launches_explorer_with_managed_file_as_single_argument(tmp_path, monkeypatch):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    target = downloads / "message.paracci"
    target.write_bytes(b"message")
    launches = []
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    monkeypatch.setattr(run.subprocess, "Popen", lambda args: launches.append(args))

    result = run.ProApi().open_file_location(str(target))

    assert result == {"success": True}
    assert launches == [["explorer", f"/select,{os.path.normpath(str(target.resolve()))}"]]


def test_open_file_location_rejects_traversal_to_existing_file_outside_managed_downloads(tmp_path, monkeypatch):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_bytes(b"outside")
    traversal = downloads / ".." / "outside.txt"
    launches = []
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    monkeypatch.setattr(run.subprocess, "Popen", lambda args: launches.append(args))

    result = run.ProApi().open_file_location(str(traversal))

    assert result == {"success": False, "error": "File location is unavailable."}
    assert launches == []


@pytest.mark.parametrize("path", ["relative.txt", "bad\x00name.txt"])
def test_open_file_location_rejects_relative_and_null_byte_paths(tmp_path, monkeypatch, path):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    launches = []
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    monkeypatch.setattr(run.subprocess, "Popen", lambda args: launches.append(args))

    result = run.ProApi().open_file_location(path)

    assert result == {"success": False, "error": "File location is unavailable."}
    assert launches == []


def test_open_file_location_keeps_metacharacters_inside_single_explorer_argument(tmp_path, monkeypatch):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    target = downloads / "report;& notes.txt"
    target.write_bytes(b"report")
    launches = []
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    monkeypatch.setattr(run.subprocess, "Popen", lambda args: launches.append(args))

    result = run.ProApi().open_file_location(str(target))

    assert result == {"success": True}
    assert launches == [["explorer", f"/select,{os.path.normpath(str(target.resolve()))}"]]


def test_open_file_location_rejects_attack_shaped_nonexistent_input(tmp_path, monkeypatch):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    launches = []
    attack_path = f'{downloads / "report.txt"}" | calc.exe'
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    monkeypatch.setattr(run.subprocess, "Popen", lambda args: launches.append(args))

    result = run.ProApi().open_file_location(attack_path)

    assert result == {"success": False, "error": "File location is unavailable."}
    assert launches == []


def test_install_update_bridge_closes_only_after_verified_path(tmp_path):
    class VerifiedUpdate:
        def prepare_installer_launch(self):
            return tmp_path / "Paracci-Setup-v1.4.2.exe"

    window = FakeMainWindow(RecordingEventHook())
    api = run.ProApi(update_manager=VerifiedUpdate()).bind_window(window)

    result = api.install_verified_update()

    assert result == {"success": True}
    assert api.installer_to_launch == tmp_path / "Paracci-Setup-v1.4.2.exe"
    assert window.destroyed is True


def test_desktop_shutdown_launches_installer_after_resource_cleanup(tmp_path, monkeypatch):
    operations = []
    installer = tmp_path / "Paracci-Setup-v1.4.2.exe"

    class Server:
        def shutdown(self):
            operations.append("server_shutdown")

        def server_close(self):
            operations.append("server_close")

    class Thread:
        def join(self, timeout):
            operations.append(("thread_join", timeout))

    class Broker:
        def close(self):
            operations.append("broker_close")

    class Manager:
        def close(self, *, preserve_handoff):
            operations.append(("manager_close", preserve_handoff))

    monkeypatch.setattr(run, "_close_all_preview_windows", lambda: operations.append("previews_close"))
    monkeypatch.setattr(
        run.subprocess,
        "Popen",
        lambda args, close_fds: operations.append(("launch", args, close_fds)),
    )

    run._shutdown_desktop_runtime(Server(), Thread(), Broker(), Manager(), installer)

    assert operations == [
        "previews_close",
        ("manager_close", True),
        "server_shutdown",
        ("thread_join", 2.0),
        "server_close",
        "broker_close",
        ("launch", [str(installer)], True),
    ]


def test_session_markdown_uses_fragment_only_uri_policy():
    session_js = (PACKAGE_ROOT / "app" / "static" / "js" / "session.js").read_text(encoding="utf-8")

    assert "function renderSafeMarkdown" in session_js
    assert "function sanitizeRenderedMarkdown" in session_js
    assert "ALLOWED_URI_REGEXP: MARKDOWN_FRAGMENT_HREF_RE" in session_js
    assert "FORBID_ATTR: ['target']" in session_js
    assert "innerHTML = sanitizer.sanitize(rawHtml)" not in session_js
    assert "innerHTML = renderSafeMarkdown(data.text, sanitizer)" in session_js
    assert "const MARKDOWN_FRAGMENT_HREF_RE = /^#[^\\s\"'<>]*$/;" in session_js


def test_vendored_dompurify_does_not_request_missing_source_map():
    purify_js = (PACKAGE_ROOT / "app" / "static" / "js" / "lib" / "purify.min.js").read_text(encoding="utf-8")

    assert "sourceMappingURL=purify.min.js.map" not in purify_js


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
