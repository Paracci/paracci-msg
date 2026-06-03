import importlib
import io
import logging
import os
import sys
import time
from pathlib import Path

import pyotp
import pytest

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from envelope_helpers import craft_bond_nonce_envelope


TOKEN = "test-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"


def make_flask_app(tmp_path, monkeypatch, no_gui=True):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "1" if no_gui else "0")

    import app as ag_app

    ag_app = importlib.reload(ag_app)
    flask_app = ag_app.create_app(loopback_auth_token=TOKEN)
    flask_app.config["TESTING"] = True
    return ag_app, flask_app


def bootstrap(client):
    return client.get(
        f"/__paracci_bootstrap?token={TOKEN}&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )


def csrf_from(client):
    with client.session_transaction(base_url=ORIGIN) as sess:
        return sess["csrf_token"]


def auth_headers(client, **extra):
    headers = {
        "Host": HOST,
        "X-Paracci-Token": TOKEN,
        "X-CSRF-Token": csrf_from(client),
        "Origin": ORIGIN,
    }
    headers.update(extra)
    return headers


def assert_sensitive_absent(label: str, sensitive_value: str, text: str) -> None:
    if sensitive_value and sensitive_value in text:
        raise AssertionError(f"{label} leaked into rejection logs")


def assert_legacy_rejection_debug_dumps_absent(text: str) -> None:
    for marker in [
        "Request URL",
        "Request Headers",
        "Request Cookies",
        "Session Contents",
    ]:
        assert marker not in text


def seed_downloadable_preview(routes_module, filename="report.txt"):
    routes_module.PREVIEW_CACHE.clear()
    routes_module.PREVIEW_CACHE["native-download"] = {
        "filename": filename,
        "content": b"download bytes",
        "mime": "text/plain",
        "expires": time.time() + 600,
        "allow_download": True,
        "access_token": "preview-access-token",
    }


def test_gui_native_preview_download_returns_one_shot_grant(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch, no_gui=False)
    import app.routes as routes_module
    from core.preview_store import NativeSaveGrantStore

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    grants = NativeSaveGrantStore()
    monkeypatch.setattr(routes_module, "native_save_grants", grants)
    seed_downloadable_preview(routes_module)

    response = client.get(
        "/preview/native-download/download?preview_token=preview-access-token",
        base_url=ORIGIN,
        headers={
            "Host": HOST,
            "X-Paracci-Token": TOKEN,
            "X-Paracci-Native-Save": "1",
        },
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["filename"] == "report.txt"
    grant = grants.consume(payload["native_save_token"])
    assert grant is not None
    assert grant.filename == "report.txt"
    assert grant.file_bytes == b"download bytes"
    assert grants.consume(payload["native_save_token"]) is None


def test_gui_native_preview_download_still_requires_loopback_auth(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch, no_gui=False)
    import app.routes as routes_module
    from core.preview_store import NativeSaveGrantStore

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    grants = NativeSaveGrantStore()
    monkeypatch.setattr(routes_module, "native_save_grants", grants)
    seed_downloadable_preview(routes_module)

    response = client.get(
        "/preview/native-download/download?preview_token=preview-access-token",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Native-Save": "1"},
    )

    assert response.status_code == 403


def test_gui_preview_download_without_native_header_retains_byte_response(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch, no_gui=False)
    import app.routes as routes_module

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    seed_downloadable_preview(routes_module)
    response = client.get(
        "/preview/native-download/download?preview_token=preview-access-token",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    assert response.status_code == 200
    assert response.data == b"download bytes"
    assert "attachment" in response.headers["Content-Disposition"]


def test_gui_native_preview_download_rejects_non_native_filename(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch, no_gui=False)
    import app.routes as routes_module

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    seed_downloadable_preview(routes_module, filename="quarterly report.txt")
    response = client.get(
        "/preview/native-download/download?preview_token=preview-access-token",
        base_url=ORIGIN,
        headers={
            "Host": HOST,
            "X-Paracci-Token": TOKEN,
            "X-Paracci-Native-Save": "1",
        },
    )

    assert response.status_code == 400
    assert response.get_json()["success"] is False


def test_root_requires_bootstrap(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    response = flask_app.test_client().get("/", base_url=ORIGIN, headers={"Host": HOST})

    assert response.status_code == 403


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/session/new",
        "/session/import",
        "/session/00112233445566778899aabbccddeeff",
        "/session/00112233445566778899aabbccddeeff/settings",
        "/session/00112233445566778899aabbccddeeff/export",
        "/updates",
        "/settings",
        "/settings/2fa",
        "/profile",
        "/unlock/2fa/setup",
        "/unlock/2fa/verify",
    ],
)
def test_sensitive_get_rejects_bootstrapped_cookie_without_bearer(tmp_path, monkeypatch, path):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    response = client.get(path, base_url=ORIGIN, headers={"Host": HOST})

    assert response.status_code == 403


@pytest.mark.parametrize(
    "path",
    [
        "/",
        "/session/new",
        "/session/import",
        "/session/00112233445566778899aabbccddeeff",
        "/session/00112233445566778899aabbccddeeff/settings",
        "/session/00112233445566778899aabbccddeeff/export",
        "/updates",
        "/settings",
        "/settings/2fa",
        "/profile",
        "/unlock/2fa/setup",
        "/unlock/2fa/verify",
    ],
)
def test_sensitive_get_with_session_and_bearer_passes_security_gate(tmp_path, monkeypatch, path):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    response = client.get(path, base_url=ORIGIN, headers=auth_headers(client))

    assert response.status_code != 403


@pytest.mark.parametrize("path", ["/unlock", "/static/js/app.js", "/favicon.ico", "/api/capabilities"])
def test_public_routes_remain_accessible_without_bearer(tmp_path, monkeypatch, path):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    response = flask_app.test_client().get(path, base_url=ORIGIN, headers={"Host": HOST})

    assert response.status_code == 200


def test_bootstrap_rejects_bad_token(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    response = flask_app.test_client().get(
        "/__paracci_bootstrap?token=bad&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert response.status_code == 403


def test_bootstrap_sets_authorized_client_session(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()

    response = bootstrap(client)

    assert response.status_code == 200
    assert b"/static/js/bootstrap.js" in response.data
    assert f'data-token="{TOKEN}"'.encode("utf-8") in response.data
    assert b'data-target="/"' in response.data
    with client.session_transaction(base_url=ORIGIN) as sess:
        assert sess["paracci_client_ok"] is True
        assert sess["paracci_client_id"]
        assert sess["csrf_token"]


def test_legacy_environment_token_is_purged_and_not_authorized(tmp_path, monkeypatch):
    monkeypatch.setenv("PARACCI_LOOPBACK_TOKEN", "legacy-env-token")
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()

    response = client.get(
        "/__paracci_bootstrap?token=legacy-env-token&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert "PARACCI_LOOPBACK_TOKEN" not in os.environ
    assert response.status_code == 403
    assert bootstrap(client).status_code == 200


@pytest.mark.parametrize("bad_token", ["", None, b"not-a-string"])
def test_create_app_rejects_invalid_in_process_token(tmp_path, monkeypatch, bad_token):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_TOKEN", "legacy-env-token")
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")

    import app as ag_app

    ag_app = importlib.reload(ag_app)
    with pytest.raises(RuntimeError, match="must be supplied directly"):
        ag_app.create_app(loopback_auth_token=bad_token)

    assert "PARACCI_LOOPBACK_TOKEN" not in os.environ


def test_planted_loopback_token_file_is_ignored(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    token_path = data_dir / ".loopback_token"
    token_path.write_text("planted-token", encoding="utf-8")
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()

    response = client.get(
        "/__paracci_bootstrap?token=planted-token&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert token_path.read_text(encoding="utf-8") == "planted-token"
    assert response.status_code == 403
    assert bootstrap(client).status_code == 200


def test_app_initialization_does_not_create_loopback_token_file(tmp_path, monkeypatch):
    make_flask_app(tmp_path, monkeypatch)

    assert not (tmp_path / "data" / ".loopback_token").exists()


def test_api_rejects_missing_bearer_after_bootstrap(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    response = client.post(
        "/api/stage-attachment",
        base_url=ORIGIN,
        json={"path": str(tmp_path / "missing.txt")},
        headers={"Host": HOST},
    )

    assert response.status_code == 403


def test_loopback_rejection_logs_safe_metadata_without_auth_or_session_secrets(
    tmp_path, monkeypatch, caplog
):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    sentinels = {
        "loopback header token": "loopback-header-token-log-sentinel",
        "csrf header token": "csrf-header-token-log-sentinel",
        "authorization token": "authorization-header-token-log-sentinel",
        "custom key header": "device-key-header-log-sentinel",
        "otp header": "otp-header-log-sentinel",
        "preview header token": "preview-header-token-log-sentinel",
        "secret header": "secret-header-log-sentinel",
        "query bootstrap token": "bootstrap-query-token-log-sentinel",
        "query preview token": "preview-query-token-log-sentinel",
        "query local path": "query-local-path-log-sentinel",
        "cookie name": "token_cookie_name_log_sentinel",
        "cookie value": "cookie-value-log-sentinel",
        "session csrf": "csrf-session-token-log-sentinel",
        "2fa setup secret": "totp-setup-secret-log-sentinel",
        "pending unlock": "pending-unlock-log-sentinel",
        "passphrase": "passphrase-log-sentinel",
        "device key": "device-key-log-sentinel",
        "private key": "private-key-log-sentinel",
        "decrypted data": "decrypted-data-log-sentinel",
        "session token": "session-token-log-sentinel",
        "local filesystem path": str(tmp_path / "private" / "pending-unlock.paracci"),
        "session csrf key": "csrf_token",
        "2fa setup key": "2fa_setup_secret",
        "unlock id key": "unlock_id",
    }
    with client.session_transaction(base_url=ORIGIN) as sess:
        sess["csrf_token"] = sentinels["session csrf"]
        sess["2fa_setup_secret"] = sentinels["2fa setup secret"]
        sess["unlock_id"] = sentinels["pending unlock"]
        sess["passphrase_material"] = sentinels["passphrase"]
        sess["device_key_material"] = sentinels["device key"]
        sess["private_key_material"] = sentinels["private key"]
        sess["decrypted_data"] = sentinels["decrypted data"]
        sess["preview_token_material"] = sentinels["session token"]
        sess["sensitive_local_path"] = sentinels["local filesystem path"]

    client.set_cookie(
        sentinels["cookie name"],
        sentinels["cookie value"],
        domain="127.0.0.1",
    )

    headers = {
        "Host": HOST,
        "Origin": "http://evil.test",
        "X-Paracci-Token": sentinels["loopback header token"],
        "X-CSRF-Token": sentinels["csrf header token"],
        "Authorization": f"Bearer {sentinels['authorization token']}",
        "X-Device-Key": sentinels["custom key header"],
        "X-TOTP-Code": sentinels["otp header"],
        "X-Paracci-Preview-Token": sentinels["preview header token"],
        "X-Secret-Material": sentinels["secret header"],
    }
    target = (
        "/api/stage-attachment"
        f"?token={sentinels['query bootstrap token']}"
        f"&preview_token={sentinels['query preview token']}"
        f"&next={sentinels['query local path']}"
    )

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="app.routes"):
        response = client.post(
            target,
            base_url=ORIGIN,
            json={"path": sentinels["local filesystem path"]},
            headers=headers,
        )

    assert response.status_code == 403
    log_text = caplog.text
    assert "Loopback request rejected" in log_text
    assert "unexpected origin" in log_text
    assert "POST" in log_text
    assert "/api/stage-attachment" in log_text
    assert "query_present" in log_text
    assert "cookie_present" in log_text
    assert "auth_material_present" in log_text
    assert "session_present" in log_text
    for label, value in sentinels.items():
        assert_sensitive_absent(label, value, log_text)
    for header_name in ["X-Paracci-Token", "X-CSRF-Token", "Authorization"]:
        assert header_name not in log_text
    assert_legacy_rejection_debug_dumps_absent(log_text)


def test_bootstrap_rejection_logs_route_without_query_token_values(
    tmp_path, monkeypatch, caplog
):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    bootstrap_token = "bootstrap-url-token-log-sentinel"
    next_token = "next-url-token-log-sentinel"
    next_path = "<local-user-path>/private-bootstrap.paracci"

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="app.routes"):
        response = flask_app.test_client().get(
            f"/__paracci_bootstrap?token={bootstrap_token}&next=/{next_token}&path={next_path}",
            base_url=ORIGIN,
            headers={"Host": HOST},
        )

    assert response.status_code == 403
    log_text = caplog.text
    assert "Loopback request rejected" in log_text
    assert "invalid bootstrap token" in log_text
    assert "GET" in log_text
    assert "/__paracci_bootstrap" in log_text
    for label, value in {
        "bootstrap query token": bootstrap_token,
        "next query token": next_token,
        "query local filesystem path": next_path,
    }.items():
        assert_sensitive_absent(label, value, log_text)
    assert_legacy_rejection_debug_dumps_absent(log_text)


def test_preview_rejection_logs_route_without_preview_capability_tokens(
    tmp_path, monkeypatch, caplog
):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    path_token = "preview-capability-path-token-log-sentinel"
    query_token = "preview-capability-query-token-log-sentinel"
    header_token = "preview-capability-header-token-log-sentinel"

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="app.routes"):
        response = flask_app.test_client().get(
            f"/preview/{path_token}?preview_token={query_token}",
            base_url=ORIGIN,
            headers={"Host": HOST, "X-Paracci-Preview-Token": header_token},
        )

    assert response.status_code == 403
    log_text = caplog.text
    assert "Loopback request rejected" in log_text
    assert "missing source headers" in log_text
    assert "GET" in log_text
    assert "/preview/<pid>" in log_text
    for label, value in {
        "preview path token": path_token,
        "preview query token": query_token,
        "preview header token": header_token,
    }.items():
        assert_sensitive_absent(label, value, log_text)
    assert_legacy_rejection_debug_dumps_absent(log_text)


def test_public_unlock_does_not_expose_auth_shell_state_for_cookie_only_request(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    csrf_token = csrf_from(client)

    response = client.get("/unlock", base_url=ORIGIN, headers={"Host": HOST})

    assert response.status_code == 200
    assert TOKEN.encode("utf-8") not in response.data
    assert csrf_token.encode("utf-8") not in response.data


def test_unlock_post_rejects_bootstrapped_cookie_without_bearer(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    response = client.post(
        "/unlock",
        base_url=ORIGIN,
        data={"pin": "Correct-Horse-95175328"},
        headers={"Host": HOST},
    )

    assert response.status_code == 403


def test_api_rejects_missing_csrf_after_bootstrap(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    response = client.post(
        "/api/stage-attachment",
        base_url=ORIGIN,
        json={"path": str(tmp_path / "missing.txt")},
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    assert response.status_code == 403


def test_api_rejects_cross_site_source_headers(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    bad_origin = client.post(
        "/api/stage-attachment",
        base_url=ORIGIN,
        json={"path": str(tmp_path / "missing.txt")},
        headers=auth_headers(client, Origin="http://evil.test"),
    )
    bad_fetch_site = client.post(
        "/api/stage-attachment",
        base_url=ORIGIN,
        json={"path": str(tmp_path / "missing.txt")},
        headers=auth_headers(client, **{"Sec-Fetch-Site": "cross-site"}),
    )

    assert bad_origin.status_code == 403
    assert bad_fetch_site.status_code == 403


def test_stage_attachment_rejects_web_submitted_path_without_disk_read(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    import app.routes as routes_module

    _unlock_test_client(ag_app, client)

    def fail_if_called(_path):
        raise AssertionError("web-submitted paths must not reach disk reads")

    monkeypatch.setattr(routes_module, "_import_from_native", fail_if_called)

    response = client.post(
        "/api/stage-attachment",
        base_url=ORIGIN,
        json={"path": str(tmp_path / "missing.txt")},
        headers=auth_headers(client),
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Native attachment staging must use the desktop file picker."


def test_native_attachment_staging_helper_consumes_python_selected_paths(tmp_path, monkeypatch):
    make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module

    selected = tmp_path / "note.txt"
    selected.write_bytes(b"native selected content")

    staged = routes_module.stage_native_attachment_paths([selected])

    assert len(staged) == 1
    assert set(staged[0]) == {"id", "filename", "size"}
    assert staged[0]["filename"] == "note.txt"
    assert "path" not in staged[0]

    files, error = routes_module._gather_attachments([], staged[0]["id"])
    assert error is None
    assert len(files) == 1
    assert files[0][0] == "note.txt"
    assert isinstance(files[0][1], (str, Path))
    assert Path(files[0][1]).read_bytes() == b"native selected content"


def test_frontend_no_longer_posts_attachment_paths():
    app_js = Path("paracci/app/static/js/app.js").read_text(encoding="utf-8")

    assert "/api/stage-attachment" not in app_js
    assert "JSON.stringify({ path" not in app_js


def test_session_new_no_longer_exposes_custom_message_kdf_inputs(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    response = client.get(
        "/session/new",
        base_url=ORIGIN,
        headers=auth_headers(client),
    )

    assert response.status_code == 200
    assert b"security_profile" not in response.data
    assert b"custom_t" not in response.data
    assert b"custom_m" not in response.data
    assert b"custom_p" not in response.data


def test_settings_rejects_over_limit_default_ttl(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    response = client.post(
        "/settings",
        base_url=ORIGIN,
        data={
            "default_ttl": "2592001",
            "auto_cleanup_hours": "24",
        },
        headers=auth_headers(client),
    )

    assert response.status_code == 302
    from core.config import ParacciConfig

    assert ParacciConfig().get("default_ttl") == 0


def test_settings_2fa_confirm_stores_encrypted_secret(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    secret = "JBSWY3DPEHPK3PXP"
    with client.session_transaction(base_url=ORIGIN) as sess:
        sess["2fa_setup_secret"] = secret

    response = client.post(
        "/settings/2fa",
        base_url=ORIGIN,
        data={"action": "confirm_setup", "code": pyotp.TOTP(secret).now()},
        headers=auth_headers(client),
    )

    stored = ag_app.db.get_device_meta("2fa_secret")
    assert response.status_code == 302
    assert ag_app.db.is_2fa_enabled() is True
    assert isinstance(stored, (bytes, bytearray))
    assert secret.encode("ascii") not in stored
    assert ag_app.db.get_2fa_secret(ag_app.device_key) == secret



def test_unexpected_host_is_rejected(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    response = flask_app.test_client().get(
        "/",
        base_url="http://attacker.test:18080",
        headers={"Host": "attacker.test:18080"},
    )

    assert response.status_code == 403


def test_second_bootstrapped_client_cannot_reuse_unlocked_device_key(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client_one = flask_app.test_client()
    client_two = flask_app.test_client()
    bootstrap(client_one)
    bootstrap(client_two)

    _unlock_test_client(ag_app, client_one)

    response = client_two.get(
        "/",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    assert response.status_code == 403


def test_unlock_route_renders_durable_lockout_state(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    from core.burn import init_device

    init_device(ag_app.db, "Correct-Horse-95175328")
    now = int(time.time())
    for failed_at in (now - 1000, now - 990, now - 980, now - 960, now):
        ag_app.db.record_unlock_failure(now=failed_at)

    response = client.get("/unlock", base_url=ORIGIN, headers={"Host": HOST})

    assert response.status_code == 200
    assert b'maxlength="128"' in response.data
    assert b"id=\"lockoutCountdown\"" in response.data
    assert any(
        f"data-lockout-seconds=\"{seconds}\"".encode("utf-8") in response.data
        for seconds in range(295, 301)
    )


def test_unlock_route_repairs_deleted_rate_state_after_success(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    from core.burn import (
        UNLOCK_MAX_FAILED_ATTEMPTS,
        UNLOCK_RATE_LIMIT_KEY,
        init_device,
        unlock_device,
    )

    init_device(ag_app.db, "Correct-Horse-95175328")
    unlock_device(ag_app.db, "Correct-Horse-95175328")
    ag_app.db.delete_device_meta(UNLOCK_RATE_LIMIT_KEY)

    response = client.get("/unlock", base_url=ORIGIN, headers={"Host": HOST})
    repaired = ag_app.db.get_unlock_rate_limit()

    assert response.status_code == 200
    assert b"id=\"lockoutCountdown\"" in response.data
    assert any(
        f"data-lockout-seconds=\"{seconds}\"".encode("utf-8") in response.data
        for seconds in range(10, 16)
    )
    assert repaired["failed_attempts"] == UNLOCK_MAX_FAILED_ATTEMPTS - 1
    assert repaired["retry_after_seconds"] > 0
    assert ag_app.db.get_device_meta(UNLOCK_RATE_LIMIT_KEY) is not None


def test_unlock_route_renders_dpapi_binding_error(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    from core.burn import init_device
    from desktop.device_key_binding import (
        DPAPI_DIFFERENT_ACCOUNT_CODE,
        DPAPI_DIFFERENT_ACCOUNT_I18N,
        DPAPI_DIFFERENT_ACCOUNT_MESSAGE,
        DeviceBindingError,
    )
    import app.routes as routes_module

    init_device(ag_app.db, "Correct-Horse-95175328")

    def fail_unlock(_db, _pin):
        raise DeviceBindingError(
            DPAPI_DIFFERENT_ACCOUNT_CODE,
            DPAPI_DIFFERENT_ACCOUNT_I18N,
            DPAPI_DIFFERENT_ACCOUNT_MESSAGE,
        )

    monkeypatch.setattr(routes_module, "unlock_device_with_binding", fail_unlock)

    response = client.post(
        "/unlock",
        base_url=ORIGIN,
        data={"pin": "Correct-Horse-95175328"},
        headers=auth_headers(client),
    )

    assert response.status_code == 200
    assert DPAPI_DIFFERENT_ACCOUNT_MESSAGE.encode("utf-8") in response.data


def _unlock_test_client(ag_app, client):
    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "Correct-Horse-95175328")
    ag_app.db = ag_app.db.with_device_key(ag_app.device_key)
    with client.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]


def _save_meta(ag_app, meta):
    from core.session import serialize_session_meta

    ag_app.db.save_session(
        session_id=meta.session_id,
        label=meta.label,
        state=meta.state,
        encrypted_meta=serialize_session_meta(meta, ag_app.device_key),
        created_at=meta.created_at,
    )


def _load_meta(ag_app, meta):
    from core.session import deserialize_session_meta

    row = ag_app.db.load_session(meta.session_id)
    return deserialize_session_meta(row[2], ag_app.device_key)


def _make_unverified_handshake():
    from core.crypto import generate_identity_keypair
    from core.session import (
        accept_initiator_and_create_responder,
        create_initiator_session,
        finalize_initiator_session,
        get_session_safety_code,
    )

    x_identity_priv, x_identity_pub = generate_identity_keypair()
    y_identity_priv, y_identity_pub = generate_identity_keypair()
    meta_x, init_file = create_initiator_session(
        "X",
        identity_pub=x_identity_pub,
        identity_priv=x_identity_priv,
    )
    meta_y, resp_file = accept_initiator_and_create_responder(
        init_file,
        "Y",
        identity_pub=y_identity_pub,
        identity_priv=y_identity_priv,
    )
    meta_x = finalize_initiator_session(meta_x, resp_file)
    return meta_x, meta_y, get_session_safety_code(meta_x)


def _make_active_handshake():
    from core.session import confirm_safety_code

    meta_x, meta_y, safety_code = _make_unverified_handshake()
    return (
        confirm_safety_code(meta_x, safety_code),
        confirm_safety_code(meta_y, safety_code),
    )


def test_flask_setup_upload_rejects_oversized_file_before_parse(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    monkeypatch.setattr(routes_module, "MAX_SETUP_FILE_BYTES", 32)
    monkeypatch.setattr(
        routes_module,
        "_parse_file_header_raw",
        lambda *_args, **_kwargs: pytest.fail("oversized setup reached header parser"),
    )
    sentinel = "flask-setup-secret"

    response = client.post(
        "/session/import",
        base_url=ORIGIN,
        data={
            "label": "Y",
            "paracci_file": (io.BytesIO(sentinel.encode("ascii") + b"x" * 64), "setup.paracci"),
        },
        headers=auth_headers(client),
        content_type="multipart/form-data",
    )

    assert response.status_code == 200
    assert b"too large" in response.data
    assert sentinel.encode("ascii") not in response.data


def test_flask_setup_native_ref_rejects_oversized_file_before_parse(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    selected = tmp_path / "oversized-setup.paracci"
    sentinel = "native-setup-secret"
    selected.write_bytes(sentinel.encode("ascii") + b"x" * 64)
    native_ref = routes_module.register_native_file_path(selected)
    monkeypatch.setattr(routes_module, "MAX_SETUP_FILE_BYTES", 32)
    monkeypatch.setattr(
        routes_module,
        "_parse_file_header_raw",
        lambda *_args, **_kwargs: pytest.fail("oversized setup reached header parser"),
    )

    response = client.post(
        "/session/import",
        base_url=ORIGIN,
        data={"label": "Y", "native_file_id": native_ref["id"]},
        headers=auth_headers(client),
    )

    assert response.status_code == 200
    assert b"too large" in response.data
    assert sentinel.encode("ascii") not in response.data
    assert str(selected).encode("utf-8") not in response.data


@oqs_required
def test_flask_message_upload_rejects_oversized_envelope_before_open(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    _meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_y)
    monkeypatch.setattr(routes_module, "MAX_MESSAGE_ENVELOPE_BYTES", 32)
    monkeypatch.setattr(
        routes_module,
        "open_envelope",
        lambda *_args, **_kwargs: pytest.fail("oversized envelope reached decrypt/open"),
    )
    sentinel = "flask-message-secret"

    response = client.post(
        f"/session/{meta_y.session_id.hex()}/open?ajax=1",
        base_url=ORIGIN,
        data={
            "paracci_file": (io.BytesIO(sentinel.encode("ascii") + b"x" * 64), "message.paracci"),
        },
        headers=auth_headers(client, **{"X-Requested-With": "XMLHttpRequest"}),
        content_type="multipart/form-data",
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert "too large" in payload["error"]
    assert sentinel not in payload["error"]


@oqs_required
def test_flask_message_native_ref_rejects_oversized_envelope_before_open(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    _meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_y)
    selected = tmp_path / "oversized-message.paracci"
    sentinel = "native-message-secret"
    selected.write_bytes(sentinel.encode("ascii") + b"x" * 64)
    native_ref = routes_module.register_native_file_path(selected)
    monkeypatch.setattr(routes_module, "MAX_MESSAGE_ENVELOPE_BYTES", 32)
    monkeypatch.setattr(
        routes_module,
        "open_envelope",
        lambda *_args, **_kwargs: pytest.fail("oversized envelope reached decrypt/open"),
    )

    response = client.post(
        f"/session/{meta_y.session_id.hex()}/open?ajax=1",
        base_url=ORIGIN,
        data={"native_file_id": native_ref["id"]},
        headers=auth_headers(client, **{"X-Requested-With": "XMLHttpRequest"}),
    )

    assert response.status_code == 400
    payload = response.get_json()
    assert "too large" in payload["error"]
    assert sentinel not in payload["error"]
    assert str(selected) not in payload["error"]


@oqs_required
def test_file_activation_queues_native_message_after_unlock(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    import app.routes as routes_module

    meta_x, _meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_x)
    selected = tmp_path / "incoming.paracci"
    selected.write_bytes(b"queued only")
    native_ref = routes_module.register_native_file_path(selected)
    target = f"/session/{meta_x.session_id.hex()}?native_file_id={native_ref['id']}"
    unlocked_key = ag_app.device_key
    ag_app.device_key = None
    ag_app.active_client_id = None

    locked = client.get(
        target,
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )
    assert locked.status_code == 302
    assert locked.headers["Location"].endswith("/unlock")

    monkeypatch.setattr(routes_module, "unlock_device_with_binding", lambda _db, _pin: unlocked_key)
    unlocked = client.post(
        "/unlock",
        base_url=ORIGIN,
        data={"pin": "Correct-Horse-95175328"},
        headers=auth_headers(client),
    )
    assert unlocked.status_code == 302
    assert unlocked.headers["Location"] == target

    page = client.get(
        target,
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )
    assert page.status_code == 200
    assert f'value="{native_ref["id"]}"'.encode("utf-8") in page.data
    assert b"incoming.paracci" in page.data


@oqs_required
def test_file_activation_queues_native_message_after_2fa_unlock(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    import app.routes as routes_module

    meta_x, _meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_x)
    selected = tmp_path / "incoming-2fa.paracci"
    selected.write_bytes(b"queued only")
    native_ref = routes_module.register_native_file_path(selected)
    target = f"/session/{meta_x.session_id.hex()}?native_file_id={native_ref['id']}"
    secret = pyotp.random_base32()
    unlocked_key = ag_app.device_key
    ag_app.db.set_2fa_secret(secret, unlocked_key)
    ag_app.db.set_2fa_enabled(True)
    ag_app.device_key = None
    ag_app.active_client_id = None

    assert client.get(
        target,
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    ).status_code == 302
    monkeypatch.setattr(routes_module, "unlock_device_with_binding", lambda _db, _pin: unlocked_key)
    first_step = client.post(
        "/unlock",
        base_url=ORIGIN,
        data={"pin": "Correct-Horse-95175328"},
        headers=auth_headers(client),
    )
    assert first_step.headers["Location"].endswith("/unlock/2fa/verify")
    assert ag_app.db.has_device_key is False

    second_step = client.post(
        "/unlock/2fa/verify",
        base_url=ORIGIN,
        data={"code": pyotp.TOTP(secret).now()},
        headers=auth_headers(client),
    )
    assert second_step.status_code == 302
    assert second_step.headers["Location"] == target


def test_file_activation_unknown_session_notice_survives_unlock_without_identifier(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    from core.burn import init_device
    import app.routes as routes_module

    unlocked_key = init_device(ag_app.db, "Correct-Horse-95175328")
    with client.session_transaction(base_url=ORIGIN) as sess:
        sess["locale"] = "en"

    locked = client.get(
        "/?file_activation_error=1",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )
    assert locked.status_code == 302
    assert locked.headers["Location"].endswith("/unlock")

    monkeypatch.setattr(routes_module, "unlock_device_with_binding", lambda _db, _pin: unlocked_key)
    response = client.post(
        "/unlock",
        base_url=ORIGIN,
        data={"pin": "Correct-Horse-95175328"},
        headers=auth_headers(client),
        follow_redirects=True,
    )

    assert response.status_code == 200
    assert b"This message file does not match any session on this device." in response.data
    assert b"00112233445566778899aabbccddeeff" not in response.data


@oqs_required
def test_flask_seal_rejects_unconfirmed_safety_code(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, _meta_y, _safety_code = _make_unverified_handshake()
    _save_meta(ag_app, meta_x)

    response = client.post(
        f"/session/{meta_x.session_id.hex()}/seal",
        base_url=ORIGIN,
        data={"message": "blocked", "ttl_seconds": "0"},
        headers=auth_headers(client),
    )

    assert response.status_code == 302
    restored = _load_meta(ag_app, meta_x)
    assert restored.safety_confirmed is False
    assert restored.state == "unverified"


@pytest.mark.parametrize("allow_download", [False, True])
@oqs_required
def test_flask_seal_binds_download_policy_in_envelope_header(tmp_path, monkeypatch, allow_download):
    from core.envelope import FLAG_ALLOW_DOWNLOAD, FLAG_HAS_DOWNLOAD_POLICY

    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, _meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_x)
    data = {"message": "bound policy", "ttl_seconds": "0"}
    if allow_download:
        data["allow_download"] = "on"

    response = client.post(
        f"/session/{meta_x.session_id.hex()}/seal",
        base_url=ORIGIN,
        data=data,
        headers=auth_headers(client),
    )

    assert response.status_code == 200
    flags = response.data[39]
    assert bool(flags & FLAG_HAS_DOWNLOAD_POLICY) is True
    assert bool(flags & FLAG_ALLOW_DOWNLOAD) is allow_download


@oqs_required
def test_gui_native_seal_and_export_return_download_grants(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch, no_gui=False)
    import app.routes as routes_module
    from core.preview_store import NativeSaveGrantStore

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_x)
    grants = NativeSaveGrantStore()
    monkeypatch.setattr(routes_module, "native_save_grants", grants)

    sealed = client.post(
        f"/session/{meta_x.session_id.hex()}/seal",
        base_url=ORIGIN,
        data={"message": "native grant", "ttl_seconds": "0"},
        headers=auth_headers(client, **{"X-Paracci-Native-Save": "1"}),
    )
    assert sealed.status_code == 200
    sealed_payload = sealed.get_json()
    assert sealed_payload["filename"].endswith(".paracci")
    sealed_grant = grants.consume(sealed_payload["native_save_token"])
    assert sealed_grant is not None
    assert sealed_grant.filename == sealed_payload["filename"]
    assert sealed_grant.file_bytes

    _save_meta(ag_app, meta_y)
    exported = client.get(
        f"/session/{meta_y.session_id.hex()}/export",
        base_url=ORIGIN,
        headers=auth_headers(client, **{"X-Paracci-Native-Save": "1"}),
    )
    assert exported.status_code == 200
    exported_payload = exported.get_json()
    assert exported_payload["filename"].startswith("session_resp_")
    exported_grant = grants.consume(exported_payload["native_save_token"])
    assert exported_grant is not None
    assert exported_grant.filename == exported_payload["filename"]
    assert exported_grant.file_bytes


@oqs_required
def test_flask_open_uses_bound_header_policy_over_package_metadata(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module
    from core.package import create_package

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_x)
    routes_module.PREVIEW_CACHE.clear()
    monkeypatch.setattr(
        routes_module,
        "create_package",
        lambda text, files, allow_download: create_package(text, files, allow_download=True),
    )

    sealed = client.post(
        f"/session/{meta_x.session_id.hex()}/seal",
        base_url=ORIGIN,
        data={
            "message": "header protected",
            "ttl_seconds": "0",
            "attachments": (io.BytesIO(b"original bytes"), "secret.txt"),
        },
        headers=auth_headers(client),
        content_type="multipart/form-data",
    )
    assert sealed.status_code == 200

    _save_meta(ag_app, meta_y)
    opened = client.post(
        f"/session/{meta_y.session_id.hex()}/open?ajax=1",
        base_url=ORIGIN,
        data={"paracci_file": (io.BytesIO(sealed.data), "message.paracci")},
        headers=auth_headers(client, **{"X-Requested-With": "XMLHttpRequest"}),
        content_type="multipart/form-data",
    )

    assert opened.status_code == 200
    payload = opened.get_json()
    assert payload["allow_download"] is False
    assert payload["secure_delete_warning"] is None
    assert len(payload["attachments"]) == 1
    attachment_ref = payload["attachments"][0]["pid"]
    assert routes_module.PREVIEW_CACHE[attachment_ref]["allow_download"] is False

    prepared = client.post(
        "/api/prepare-preview",
        base_url=ORIGIN,
        json={"attachment_ref": attachment_ref},
        headers=auth_headers(client),
    )
    assert prepared.status_code == 200
    preview_token = prepared.get_json()["preview_token"]

    inline_response = client.get(
        f"/preview/{preview_token}/content",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )
    forged_download_response = client.get(
        f"/preview/{preview_token}/content?download=1",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    assert inline_response.status_code == 415
    assert inline_response.data != b"original bytes"
    assert forged_download_response.status_code == 403
    assert forged_download_response.data != b"original bytes"


@oqs_required
def test_flask_open_rejects_post_bond_bond_nonce_without_persisting(
    tmp_path,
    monkeypatch,
):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    from core.package import create_package

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_x)

    initial = client.post(
        f"/session/{meta_x.session_id.hex()}/seal",
        base_url=ORIGIN,
        data={"message": "Initial bond", "ttl_seconds": "0"},
        headers=auth_headers(client),
    )
    assert initial.status_code == 200

    _save_meta(ag_app, meta_y)
    opened = client.post(
        f"/session/{meta_y.session_id.hex()}/open?ajax=1",
        base_url=ORIGIN,
        data={"paracci_file": (io.BytesIO(initial.data), "message.paracci")},
        headers=auth_headers(client, **{"X-Requested-With": "XMLHttpRequest"}),
        content_type="multipart/form-data",
    )
    assert opened.status_code == 200

    before = _load_meta(ag_app, meta_y)
    sender = _load_meta(ag_app, meta_x)
    forged_payload = create_package("Forged branch", [], allow_download=False)
    forged = craft_bond_nonce_envelope(forged_payload, sender, b"\xa7" * 32)

    rejected = client.post(
        f"/session/{meta_y.session_id.hex()}/open?ajax=1",
        base_url=ORIGIN,
        data={"paracci_file": (io.BytesIO(forged), "message.paracci")},
        headers=auth_headers(client, **{"X-Requested-With": "XMLHttpRequest"}),
        content_type="multipart/form-data",
    )

    assert rejected.status_code == 400
    assert rejected.get_json()["success"] is False
    after = _load_meta(ag_app, meta_y)
    assert after.rx_count == before.rx_count
    assert bytes(after.recv_seed) == bytes(before.recv_seed)


@oqs_required
def test_flask_native_open_surfaces_secure_delete_failure_without_hiding_message(
    tmp_path, monkeypatch
):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module
    import core.burn as burn_module

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_x)
    with client.session_transaction(base_url=ORIGIN) as sess:
        sess["locale"] = "en"

    sealed = client.post(
        f"/session/{meta_x.session_id.hex()}/seal",
        base_url=ORIGIN,
        data={"message": "must remain readable", "ttl_seconds": "0"},
        headers=auth_headers(client),
    )
    assert sealed.status_code == 200

    _save_meta(ag_app, meta_y)
    selected = tmp_path / "incoming.paracci"
    selected.write_bytes(sealed.data)
    native_ref = routes_module.register_native_file_path(selected)
    monkeypatch.setattr(burn_module.shield, "secure_delete", lambda _path: False)

    opened = client.post(
        f"/session/{meta_y.session_id.hex()}/open?ajax=1",
        base_url=ORIGIN,
        data={"native_file_id": native_ref["id"]},
        headers=auth_headers(client, **{"X-Requested-With": "XMLHttpRequest"}),
    )

    assert opened.status_code == 200
    payload = opened.get_json()
    assert payload["success"] is True
    assert payload["text"] == "must remain readable"
    assert payload["secure_delete_warning"] == (
        "The source .paracci file could not be securely deleted. Treat the remaining "
        "file as sensitive and delete it using a secure deletion method."
    )
    assert selected.exists()


@oqs_required
def test_flask_safety_confirmation_route_rejects_wrong_and_accepts_correct_code(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, _meta_y, safety_code = _make_unverified_handshake()
    _save_meta(ag_app, meta_x)

    bad = client.post(
        f"/session/{meta_x.session_id.hex()}/confirm-safety",
        base_url=ORIGIN,
        data={"safety_code": "0000-0000-0000-0000-0000-0000"},
        headers=auth_headers(client),
    )
    assert bad.status_code == 302
    assert _load_meta(ag_app, meta_x).safety_confirmed is False

    good = client.post(
        f"/session/{meta_x.session_id.hex()}/confirm-safety",
        base_url=ORIGIN,
        data={"safety_code": safety_code},
        headers=auth_headers(client),
    )

    assert good.status_code == 302
    restored = _load_meta(ag_app, meta_x)
    assert restored.safety_confirmed is True
    assert restored.state == "active"


def test_favicon_route(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    
    response = client.get("/favicon.ico", base_url=ORIGIN, headers={"Host": HOST})
    assert response.status_code == 200
    assert response.mimetype == "image/vnd.microsoft.icon"
    assert len(response.data) > 0


def test_preview_sw_bypass_valid_token(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module
    from core.preview_store import preview_store

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    # Seed a preview store entry
    token = preview_store.generate_token(b"preview data", "test_file.txt", "text/plain", True)

    # Make a GET request without X-Paracci-Token / CSRF headers (i.e. simulating fresh preview window)
    response = client.get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    # Should not be 403
    assert response.status_code != 403
    assert response.status_code == 200
    assert b"test_file.txt" in response.data

    # Cleanup
    preview_store.revoke(token)


def test_preview_sw_bypass_invalid_token(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    # 1. Preview GET with non-64-hex token (e.g. UUID) without loopback token
    response_uuid = client.get(
        "/preview/123e4567-e89b-12d3-a456-426614174000",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )
    assert response_uuid.status_code == 403

    # 2. Preview GET with a valid-looking 64-hex token but not seeded in store
    # It passes the lookalike check so it bypasses security gate, but should fail with token not found (not 403)
    fake_token = "a" * 64
    response_fake = client.get(
        f"/preview/{fake_token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )
    assert response_fake.status_code != 403
    assert "Preview unavailable" in response_fake.data.decode("utf-8")


def test_preview_post_still_requires_loopback(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    # Seed token
    from core.preview_store import preview_store
    token = preview_store.generate_token(b"preview data", "test_file.txt", "text/plain", True)

    # Preview endpoints only accept GET/HEAD. POST should be rejected (either 405 or 403 depending on routing/security)
    response = client.post(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
        data={"some": "data"}
    )
    assert response.status_code in {403, 405}

    # Cleanup
    preview_store.revoke(token)
