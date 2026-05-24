import hashlib
import importlib
import io
import json
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "paracci"
sys.path.insert(0, str(PACKAGE_ROOT))

from app.build_info import APP_VERSION, SESSION_PROTOCOL_VERSION
from core.session import HANDSHAKE_VERSION
from desktop.updater import (
    CHECKSUM_FILENAME,
    LATEST_RELEASE_URL,
    RECENT_RELEASES_URL,
    UpdateManager,
    expected_checksum,
    extract_protocol_version,
    is_newer_version,
)


TOKEN = "test-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"
INSTALLER_BYTES = b"verified installer payload"
INSTALLER_NAME = "Paracci-Setup-v1.4.2.exe"


class FakeResponse(io.BytesIO):
    def __init__(self, data: bytes, url: str, status: int = 200):
        super().__init__(data)
        self._url = url
        self.status = status

    def geturl(self):
        return self._url


def release_payload(
    *,
    body='<!-- paracci-update: {"protocol_version": 3} --> Notes',
    installer=True,
    version="1.4.2",
    published_at="2026-05-20T10:00:00Z",
):
    assets = []
    if installer:
        assets.append(
            {
                "name": INSTALLER_NAME,
                "browser_download_url": "https://github.com/Paracci/paracci-msg/releases/download/v1.4.2/" + INSTALLER_NAME,
                "size": len(INSTALLER_BYTES),
            }
        )
        assets.append(
            {
                "name": CHECKSUM_FILENAME,
                "browser_download_url": "https://github.com/Paracci/paracci-msg/releases/download/v1.4.2/SHA256SUMS.txt",
                "size": 100,
            }
        )
    return {
        "tag_name": f"v{version}",
        "assets": assets,
        "body": body,
        "published_at": published_at,
        "draft": False,
        "prerelease": False,
    }


def queued_urlopen(
    payload,
    *,
    installer_bytes=INSTALLER_BYTES,
    checksum_bytes=INSTALLER_BYTES,
    checksum_filename=INSTALLER_NAME,
):
    checksum = hashlib.sha256(checksum_bytes).hexdigest()
    responses = {
        LATEST_RELEASE_URL: json.dumps(payload).encode("utf-8"),
        "https://github.com/Paracci/paracci-msg/releases/download/v1.4.2/SHA256SUMS.txt": (
            f"{checksum}  {checksum_filename}\n".encode("utf-8")
        ),
        "https://github.com/Paracci/paracci-msg/releases/download/v1.4.2/" + INSTALLER_NAME: installer_bytes,
    }

    def opener(request, timeout):
        assert timeout <= 5
        url = request.full_url
        return FakeResponse(responses[url], url)

    return opener


def finish_worker(manager):
    assert manager._worker is not None
    manager._worker.join(timeout=2)
    assert not manager._worker.is_alive()


@pytest.mark.parametrize(
    ("current", "latest", "expected"),
    [
        ("1.4.0", "1.4.1", True),
        ("1.4.1", "1.4.1", False),
        ("1.4.2", "1.4.1", False),
    ],
)
def test_version_comparison(current, latest, expected):
    assert is_newer_version(current, latest) is expected


def test_build_protocol_version_tracks_active_handshake():
    assert APP_VERSION == (REPO_ROOT / "VERSION").read_text(encoding="ascii").strip()
    assert SESSION_PROTOCOL_VERSION == HANDSHAKE_VERSION


def test_installed_version_matching_latest_release_does_not_show_update():
    manager = UpdateManager(
        current_version=APP_VERSION,
        urlopen=queued_urlopen(release_payload(version=APP_VERSION, installer=False)),
    )
    manager.check_now()
    assert manager.public_status()["state"] == "no_update"
    assert manager.public_status()["visible"] is False


def test_release_notes_retain_markdown_but_remove_protocol_marker():
    manager = UpdateManager(
        current_version="1.4.0",
        urlopen=queued_urlopen(
            release_payload(body='<!-- paracci-update: {"protocol_version": 3} -->\n## Changes\n\n* Fixed updates')
        ),
    )
    manager.check_now()
    notes = manager.public_status()["release_notes"]
    assert notes == "## Changes\n\n* Fixed updates"
    assert "paracci-update" not in notes


def test_protocol_marker_detection_and_warning_state():
    assert extract_protocol_version('text <!-- paracci-update: {"protocol_version": 4} -->') == 4
    assert extract_protocol_version("no marker") is None
    manager = UpdateManager(
        current_version="1.4.0",
        protocol_version=3,
        platform_id="win32",
        distribution_mode="standard",
        urlopen=queued_urlopen(release_payload(body='<!-- paracci-update: {"protocol_version": 4} -->')),
    )
    manager.check_now()
    assert manager.public_status()["protocol_warning"] is True
    assert manager.public_status()["protocol_unknown"] is False


def test_missing_protocol_marker_requires_warning():
    manager = UpdateManager(
        current_version="1.4.0",
        platform_id="win32",
        distribution_mode="standard",
        urlopen=queued_urlopen(release_payload(body="legacy release notes")),
    )
    manager.check_now()
    status = manager.public_status()
    assert status["protocol_warning"] is True
    assert status["protocol_unknown"] is True


def test_exact_checksum_matching_rejects_missing_or_duplicate_entry():
    digest = hashlib.sha256(INSTALLER_BYTES).hexdigest()
    assert expected_checksum(f"{digest}  {INSTALLER_NAME}\n", INSTALLER_NAME) == digest
    assert expected_checksum(f"{digest}  different.exe\n", INSTALLER_NAME) is None
    assert expected_checksum(f"{digest}  {INSTALLER_NAME}\n{digest}  {INSTALLER_NAME}\n", INSTALLER_NAME) is None


def test_valid_installer_is_downloaded_only_to_temp_and_prepared_for_launch(tmp_path):
    manager = UpdateManager(
        current_version="1.4.0",
        platform_id="win32",
        distribution_mode="standard",
        urlopen=queued_urlopen(release_payload()),
        temp_root=tmp_path,
    )
    manager.check_now()
    assert manager.public_status()["action"] == "download"
    manager.begin_update()
    finish_worker(manager)

    status = manager.public_status()
    assert status["state"] == "ready"
    assert status["verification_status"] == "verified"
    installer = manager.prepare_installer_launch()
    assert installer is not None
    assert tmp_path in installer.parents
    assert installer.read_bytes() == INSTALLER_BYTES
    manager.close()
    assert not installer.exists()


@pytest.mark.parametrize(
    ("checksum_filename", "installer_bytes", "error_code"),
    [
        ("other.exe", INSTALLER_BYTES, "checksum_missing"),
        (INSTALLER_NAME, b"x" * len(INSTALLER_BYTES), "checksum_failed"),
        (INSTALLER_NAME, INSTALLER_BYTES + b"x", "size_mismatch"),
    ],
)
def test_invalid_installer_never_reaches_ready_state(tmp_path, checksum_filename, installer_bytes, error_code):
    manager = UpdateManager(
        current_version="1.4.0",
        platform_id="win32",
        distribution_mode="standard",
        urlopen=queued_urlopen(
            release_payload(),
            installer_bytes=installer_bytes,
            checksum_filename=checksum_filename,
        ),
        temp_root=tmp_path,
    )
    manager.check_now()
    manager.begin_update()
    finish_worker(manager)

    status = manager.public_status()
    assert status["state"] == "failed"
    assert status["error_code"] == error_code
    assert list(tmp_path.iterdir()) == []
    assert manager.prepare_installer_launch() is None


def test_network_timeout_during_check_is_silent():
    def timeout(_request, timeout):
        assert timeout <= 5
        raise TimeoutError()

    manager = UpdateManager(urlopen=timeout)
    manager.check_now()
    assert manager.public_status()["state"] == "no_update"
    assert manager.public_status()["visible"] is False
    assert manager.public_status()["error_code"] == ""


def test_user_initiated_network_failure_is_reported():
    manager = UpdateManager(urlopen=lambda _request, timeout: (_ for _ in ()).throw(TimeoutError()))
    manager.check_now(user_initiated=True)
    assert manager.public_status()["state"] == "check_failed"
    assert manager.public_status()["visible"] is False
    assert manager.public_status()["error_code"] == "check_failed"


@pytest.mark.parametrize(("response_body", "status_code"), [(b"{invalid", 200), (b"{}", 503)])
def test_malformed_or_error_response_during_check_is_silent(response_body, status_code):
    def opener(request, timeout):
        assert timeout <= 5
        return FakeResponse(response_body, request.full_url, status=status_code)

    manager = UpdateManager(urlopen=opener)
    manager.check_now()
    assert manager.public_status()["state"] == "no_update"
    assert manager.public_status()["visible"] is False
    assert manager.public_status()["error_code"] == ""


@pytest.mark.parametrize(
    ("platform_id", "distribution_mode", "installer", "expected_action"),
    [
        ("win32", "standard", True, "download"),
        ("win32", "portable", True, "browser"),
        ("win32", "override", True, "browser"),
        ("linux", "standard", True, "browser"),
        ("win32", "standard", False, "browser"),
    ],
)
def test_distribution_mode_and_asset_policy(platform_id, distribution_mode, installer, expected_action):
    manager = UpdateManager(
        current_version="1.4.0",
        platform_id=platform_id,
        distribution_mode=distribution_mode,
        urlopen=queued_urlopen(release_payload(installer=installer)),
    )
    manager.check_now()
    assert manager.public_status()["action"] == expected_action


def test_installer_asset_name_requires_v_prefixed_version():
    payload = release_payload()
    payload["assets"][0]["name"] = "Paracci-Setup-1.4.2.exe"
    manager = UpdateManager(
        current_version="1.4.0",
        platform_id="win32",
        distribution_mode="standard",
        urlopen=queued_urlopen(payload),
    )
    manager.check_now()
    assert manager.public_status()["action"] == "browser"


def test_browser_fallback_opens_only_fixed_releases_page():
    opened = []
    manager = UpdateManager(
        current_version="1.4.0",
        platform_id="linux",
        distribution_mode="standard",
        urlopen=queued_urlopen(release_payload()),
        browser_open=lambda url: opened.append(url) or True,
    )
    manager.check_now()
    manager.begin_update()
    assert opened == ["https://github.com/Paracci/paracci-msg/releases"]
    assert manager.public_status()["visible"] is False


def test_cancelled_download_removes_partial_temp_artifact(tmp_path):
    manager_ref = {}
    normal_opener = queued_urlopen(release_payload())

    class CancellingResponse(FakeResponse):
        def read(self, size=-1):
            data = super().read(size)
            if data:
                manager_ref["manager"].cancel_download()
            return data

    def opener(request, timeout):
        response = normal_opener(request, timeout)
        if request.full_url.endswith(INSTALLER_NAME):
            return CancellingResponse(INSTALLER_BYTES, request.full_url)
        return response

    manager = UpdateManager(
        current_version="1.4.0",
        platform_id="win32",
        distribution_mode="standard",
        urlopen=opener,
        temp_root=tmp_path,
    )
    manager_ref["manager"] = manager
    manager.check_now()
    manager.begin_update()
    finish_worker(manager)
    assert manager.public_status()["state"] == "cancelled"
    assert list(tmp_path.iterdir()) == []
    assert manager.prepare_installer_launch() is None


def test_recent_release_history_filters_unstable_releases_and_exposes_full_notes():
    releases = [
        release_payload(body="## Latest", version="1.5.0", installer=False),
        {**release_payload(body="beta", version="1.5.1", installer=False), "prerelease": True},
        release_payload(body="## Earlier", version="1.4.2", installer=False),
    ]

    def opener(request, timeout):
        assert timeout <= 5
        assert request.full_url == RECENT_RELEASES_URL
        return FakeResponse(json.dumps(releases).encode("utf-8"), request.full_url)

    history = UpdateManager(urlopen=opener).recent_releases()
    assert [item["version"] for item in history] == ["1.5.0", "1.4.2"]
    assert history[0]["release_notes"] == "## Latest"
    assert history[0]["published_at"] == "2026-05-20T10:00:00Z"


def make_flask_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_TOKEN", TOKEN)
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "0")
    import app as ag_app

    ag_app = importlib.reload(ag_app)
    flask_app = ag_app.create_app()
    flask_app.config["TESTING"] = True
    return flask_app


def bootstrap(client):
    return client.get(
        f"/__paracci_bootstrap?token={TOKEN}&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )


def csrf_from(client):
    with client.session_transaction(base_url=ORIGIN) as sess:
        return sess["csrf_token"]


def auth_headers(client):
    return {
        "Host": HOST,
        "X-Paracci-Token": TOKEN,
        "X-CSRF-Token": csrf_from(client),
        "Origin": ORIGIN,
    }


def test_update_routes_are_authenticated_but_available_while_device_locked(tmp_path, monkeypatch):
    flask_app = make_flask_app(tmp_path, monkeypatch)
    manager = UpdateManager(
        current_version="1.4.0",
        platform_id="linux",
        urlopen=queued_urlopen(release_payload()),
        browser_open=lambda _url: True,
    )
    manager.check_now()
    flask_app.extensions["paracci_updater"] = manager
    client = flask_app.test_client()
    bootstrap(client)

    rejected = client.get("/api/update/status", base_url=ORIGIN, headers={"Host": HOST})
    status = client.get("/api/update/status", base_url=ORIGIN, headers=auth_headers(client))
    download = client.post(
        "/api/update/download",
        base_url=ORIGIN,
        json={},
        headers=auth_headers(client),
    )

    assert rejected.status_code == 403
    assert status.status_code == 200
    assert status.get_json()["latest_version"] == "1.4.2"
    assert download.status_code == 200


def test_manual_check_and_history_routes_use_update_manager_while_locked(tmp_path, monkeypatch):
    flask_app = make_flask_app(tmp_path, monkeypatch)

    class RouteManager:
        def __init__(self):
            self.started = False

        def start_check(self, *, user_initiated=False):
            self.started = user_initiated
            return True

        def public_status(self):
            return {"state": "checking", "current_version": APP_VERSION}

        def recent_releases(self):
            return [{"version": "1.5.0", "published_at": "2026-05-20T10:00:00Z", "release_notes": "## Notes"}]

    manager = RouteManager()
    flask_app.extensions["paracci_updater"] = manager
    client = flask_app.test_client()
    bootstrap(client)

    check = client.post("/api/update/check", base_url=ORIGIN, json={}, headers=auth_headers(client))
    history = client.get("/api/update/history", base_url=ORIGIN, headers=auth_headers(client))

    assert check.status_code == 200
    assert manager.started is True
    assert history.status_code == 200
    assert history.get_json()["releases"][0]["release_notes"] == "## Notes"


def test_update_post_action_requires_csrf_while_locked(tmp_path, monkeypatch):
    flask_app = make_flask_app(tmp_path, monkeypatch)
    manager = UpdateManager(
        current_version="1.4.0",
        platform_id="linux",
        urlopen=queued_urlopen(release_payload()),
    )
    manager.check_now()
    flask_app.extensions["paracci_updater"] = manager
    client = flask_app.test_client()
    bootstrap(client)

    rejected = client.post(
        "/api/update/dismiss",
        base_url=ORIGIN,
        json={},
        headers={"Host": HOST, "Origin": ORIGIN, "X-Paracci-Token": TOKEN},
    )
    rejected_check = client.post(
        "/api/update/check",
        base_url=ORIGIN,
        json={},
        headers={"Host": HOST, "Origin": ORIGIN, "X-Paracci-Token": TOKEN},
    )

    assert rejected.status_code == 403
    assert rejected_check.status_code == 403
    assert manager.public_status()["visible"] is True


def test_update_banner_and_release_workflow_contracts_are_present():
    template = (PACKAGE_ROOT / "app" / "templates" / "base.html").read_text(encoding="utf-8")
    js = (PACKAGE_ROOT / "app" / "static" / "js" / "app.js").read_text(encoding="utf-8")
    css = (PACKAGE_ROOT / "app" / "static" / "css" / "components.css").read_text(encoding="utf-8")
    updates_css = (PACKAGE_ROOT / "app" / "static" / "css" / "pages" / "updates.css").read_text(encoding="utf-8")
    updates_template = (PACKAGE_ROOT / "app" / "templates" / "updates.html").read_text(encoding="utf-8")
    runtime = (REPO_ROOT / "run.py").read_text(encoding="utf-8")
    workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    for marker in (
        'id="update-banner"',
        'id="update-protocol-warning"',
        'id="update-progress-fill"',
        'id="update-cancel-btn"',
    ):
        assert marker in template
    assert "renderUpdateMarkdown(notes, status.release_notes)" in js
    assert "window.DOMPurify.sanitize" in js
    assert "window.marked.parse" in js
    assert "_updatesManualCheckPending" in js
    assert "source.content?.textContent" in js
    assert "This update changes the session protocol. After updating, you will need to establish new sessions with your contacts." in js
    assert "function startUpdateStatusPollingWhenAuthorized()" in js
    assert "window.ParacciSecurity?.getLoopbackToken?.()" in js
    assert "window.addEventListener('pywebviewready', startUpdateStatusPollingWhenAuthorized)" in js
    assert "window.addEventListener('paracci:loopback-token-ready', startUpdateStatusPollingWhenAuthorized)" in js
    assert "window.dispatchEvent(new CustomEvent('paracci:loopback-token-ready'))" in runtime
    assert ".update-banner[hidden]" in css
    assert "overflow-y: auto" in css
    assert ".updates-page-actions [hidden]" in updates_css
    assert "/api/update/download" in js
    assert 'Path("VERSION").read_text' in workflow
    assert 'id="updates-check-btn"' in updates_template
    assert 'id="updates-history-list"' in updates_template
    assert '<!-- paracci-update: {"protocol_version": 3} -->' in workflow


def test_all_locales_contain_update_warning_text():
    required = "This update changes the session protocol. After updating, you will need to establish new sessions with your contacts."
    english = json.loads((PACKAGE_ROOT / "app" / "i18n" / "en.json").read_text(encoding="utf-8"))
    assert english["update"]["protocol_warning"] == required
    for locale_file in (PACKAGE_ROOT / "app" / "i18n").glob("*.json"):
        payload = json.loads(locale_file.read_text(encoding="utf-8"))
        assert payload["update"]["update_now"]
        assert payload["update"]["protocol_warning"]
        assert payload["update"]["check_now"]
        assert payload["update"]["history_title"]
        assert payload["settings"]["updates_title"]
