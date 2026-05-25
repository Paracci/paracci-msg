import importlib
import io
import sys
import time
from pathlib import Path

import pyotp
import pytest

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))


TOKEN = "test-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"


def make_flask_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_TOKEN", TOKEN)
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "1")

    import app as ag_app

    ag_app = importlib.reload(ag_app)
    flask_app = ag_app.create_app()
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


def test_root_requires_bootstrap(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    response = flask_app.test_client().get("/", base_url=ORIGIN, headers={"Host": HOST})

    assert response.status_code == 403


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

    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    with client.session_transaction(base_url=ORIGIN) as sess:
        assert sess["paracci_client_ok"] is True
        assert sess["paracci_client_id"]
        assert sess["csrf_token"]


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
    assert files == [("note.txt", b"native selected content")]


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
    assert isinstance(stored, bytes)
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

    response = client_two.get("/", base_url=ORIGIN, headers={"Host": HOST})

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

    locked = client.get(target, base_url=ORIGIN, headers={"Host": HOST})
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

    page = client.get(target, base_url=ORIGIN, headers={"Host": HOST})
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

    assert client.get(target, base_url=ORIGIN, headers={"Host": HOST}).status_code == 302
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

    locked = client.get("/?file_activation_error=1", base_url=ORIGIN, headers={"Host": HOST})
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
        headers={"Host": HOST},
    )
    forged_download_response = client.get(
        f"/preview/{preview_token}/content?download=1",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert inline_response.status_code == 415
    assert inline_response.data != b"original bytes"
    assert forged_download_response.status_code == 403
    assert forged_download_response.data != b"original bytes"


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
