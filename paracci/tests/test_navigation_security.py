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
from core.preview_store import NativeSaveGrantStore


LOOPBACK_TOKEN = "native-loopback-token"


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
        self.dialog_path = None
        self.confirmation_result = True
        self.confirmations = []

    def destroy(self):
        self.destroyed = True

    def evaluate_js(self, script):
        self.scripts.append(script)

    def create_file_dialog(self, *args, **kwargs):
        return self.dialog_path

    def create_confirmation_dialog(self, title, message):
        self.confirmations.append((title, message))
        return self.confirmation_result


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


def _authorized_save_api(tmp_path, monkeypatch, confirmation=True):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    grants = NativeSaveGrantStore()
    monkeypatch.setattr(run, "native_save_grants", grants)
    window = FakeMainWindow(RecordingEventHook())
    window.confirmation_result = confirmation
    api = run.ProApi(loopback_token=LOOPBACK_TOKEN).bind_window(window)
    return api, window, grants, downloads


@pytest.mark.parametrize("candidate", ["", "wrong-token"])
def test_save_file_silent_rejects_unauthenticated_call(tmp_path, monkeypatch, candidate):
    api, _window, grants, downloads = _authorized_save_api(tmp_path, monkeypatch)
    grant = grants.issue(b"payload", "payload.bin")

    with pytest.raises(PermissionError, match="authorization failed"):
        api.save_file_silent(grant, candidate)

    assert list(downloads.iterdir()) == []


def test_save_file_silent_rejects_arbitrary_page_payload_without_grant(tmp_path, monkeypatch):
    api, _window, _grants, downloads = _authorized_save_api(tmp_path, monkeypatch)

    with pytest.raises(PermissionError, match="grant is invalid"):
        api.save_file_silent(base64.b64encode(b"payload").decode("ascii"), LOOPBACK_TOKEN)

    assert list(downloads.iterdir()) == []


def test_save_file_silent_writes_confirmed_authenticated_grant(tmp_path, monkeypatch):
    api, window, grants, downloads = _authorized_save_api(tmp_path, monkeypatch)
    grant = grants.issue(b"payload", "payload.bin")

    saved_path = api.save_file_silent(grant, LOOPBACK_TOKEN)

    target = downloads / "payload.bin"
    assert saved_path == str(target)
    assert target.read_bytes() == b"payload"
    assert window.confirmations == [
        ("Confirm download", "Save payload.bin to Paracci Downloads?")
    ]
    assert grants.consume(grant) is None


def test_save_file_silent_declined_confirmation_consumes_grant(tmp_path, monkeypatch):
    api, _window, grants, downloads = _authorized_save_api(tmp_path, monkeypatch, confirmation=False)
    grant = grants.issue(b"payload", "payload.bin")

    assert api.save_file_silent(grant, LOOPBACK_TOKEN) is None
    assert grants.consume(grant) is None
    assert list(downloads.iterdir()) == []


@pytest.mark.parametrize(
    "filename",
    [
        "../evil.exe",
        "C:\\evil.exe",
        "bad\x00name.txt",
        "quarterly report.pdf",
        "a" * 181,
        "report.",
        "CON.txt",
    ],
)
def test_native_download_writer_rejects_unsafe_filename(tmp_path, monkeypatch, filename):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))

    with pytest.raises(ValueError, match="Invalid download filename"):
        run._write_native_download(b"payload", filename)

    assert list(downloads.iterdir()) == []


def test_native_download_writer_does_not_follow_existing_symlink(tmp_path, monkeypatch):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    symlink = downloads / "payload.bin"
    try:
        symlink.symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation is not available on this platform.")
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))

    saved_path = run._write_native_download(b"payload", "payload.bin")

    assert saved_path == downloads / "payload_1.bin"
    assert outside.read_bytes() == b"outside"
    assert saved_path.read_bytes() == b"payload"


def test_save_file_preserves_user_selected_destination_after_authentication(tmp_path, monkeypatch):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    chosen = downloads / "chosen-location.paracci"
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    window = FakeMainWindow(RecordingEventHook())
    window.dialog_path = str(chosen)
    api = run.ProApi(loopback_token=LOOPBACK_TOKEN).bind_window(window)

    result = api.save_file(
        base64.b64encode(b"payload").decode("ascii"),
        "message.paracci",
        LOOPBACK_TOKEN,
    )

    assert result == str(chosen)
    assert chosen.read_bytes() == b"payload"


def test_save_file_rejects_destination_outside_downloads(tmp_path, monkeypatch):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    chosen = tmp_path / "outside-location.paracci"
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    window = FakeMainWindow(RecordingEventHook())
    window.dialog_path = str(chosen)
    api = run.ProApi(loopback_token=LOOPBACK_TOKEN).bind_window(window)

    result = api.save_file(
        base64.b64encode(b"payload").decode("ascii"),
        "message.paracci",
        LOOPBACK_TOKEN,
    )

    assert result is None
    assert not chosen.exists()


@pytest.mark.parametrize("content_b64", ["%%%bad-base64%%%", base64.b64encode(b"payload").decode("ascii")])
def test_save_file_rejects_invalid_or_oversized_payload_before_dialog(
    tmp_path,
    monkeypatch,
    content_b64,
):
    from core.config import ParacciConfig

    downloads = tmp_path / "Downloads"
    downloads.mkdir()
    monkeypatch.setattr(ParacciConfig, "__init__", lambda self: setattr(self, "full_downloads_path", str(downloads)))
    if content_b64 != "%%%bad-base64%%%":
        monkeypatch.setattr(run, "MAX_NATIVE_SAVE_BYTES", 2)
    window = FakeMainWindow(RecordingEventHook())
    window.dialog_path = str(tmp_path / "should-not-exist.paracci")
    api = run.ProApi(loopback_token=LOOPBACK_TOKEN).bind_window(window)

    with pytest.raises(ValueError):
        api.save_file(content_b64, "message.paracci", LOOPBACK_TOKEN)

    assert not Path(window.dialog_path).exists()


def test_session_native_download_uses_grant_instead_of_page_base64():
    session_js = (PACKAGE_ROOT / "app" / "static" / "js" / "session.js").read_text(encoding="utf-8")

    assert "'X-Paracci-Native-Save': '1'" in session_js
    assert "save_file_silent(grant.native_save_token, loopbackToken)" in session_js
    assert "save_file_silent(b64" not in session_js
