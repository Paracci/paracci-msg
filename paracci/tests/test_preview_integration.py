import importlib
import sys
import time
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "paracci"
sys.path.insert(0, str(PACKAGE_ROOT))


TOKEN = "test-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"


def make_flask_app(tmp_path, monkeypatch, no_gui=True):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_TOKEN", TOKEN)
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "1" if no_gui else "0")

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


def unlock_test_client(ag_app, client):
    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "Correct-Horse-95175328")
    with client.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]


def fresh_preview_store(monkeypatch):
    from app import routes
    from core.preview_store import PreviewStore

    store = PreviewStore()
    monkeypatch.setattr(routes, "preview_store", store)
    return routes, store


def test_prepare_preview_then_token_page_returns_html(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    routes, _store = fresh_preview_store(monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    unlock_test_client(ag_app, client)
    routes.PREVIEW_CACHE.clear()
    routes.PREVIEW_CACHE["ref-1"] = {
        "filename": "report.pdf",
        "content": b"%PDF-preview-bytes",
        "mime": "application/octet-stream",
        "expires": time.time() + 600,
        "allow_download": True,
        "access_token": "legacy-token",
    }

    prepare_response = client.post(
        "/api/prepare-preview",
        base_url=ORIGIN,
        json={"attachment_ref": "ref-1"},
        headers=auth_headers(client),
    )

    assert prepare_response.status_code == 200
    preview_token = prepare_response.get_json()["preview_token"]

    preview_response = flask_app.test_client().get(
        f"/preview/{preview_token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert preview_response.status_code == 200
    assert preview_response.mimetype == "text/html"
    assert b"report.pdf" in preview_response.data
    assert b"%PDF-preview-bytes" not in preview_response.data


def test_preview_request_and_close_do_not_affect_main_session_state(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    routes, store = fresh_preview_store(monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    unlock_test_client(ag_app, client)
    token = store.generate_token(b"preview bytes", "note.txt", "text/plain")

    with client.session_transaction(base_url=ORIGIN) as sess:
        original_client_id = sess["paracci_client_id"]
        original_csrf = sess["csrf_token"]

    preview_response = client.get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )
    routes.preview_store.revoke(token)
    clear_response = client.post(
        "/api/sensitive-cache/clear",
        base_url=ORIGIN,
        json={"preview_ids": [], "staged_attachment_ids": []},
        headers=auth_headers(client),
    )
    settings_response = client.get(
        "/settings",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    with client.session_transaction(base_url=ORIGIN) as sess:
        assert sess["paracci_client_ok"] is True
        assert sess["paracci_client_id"] == original_client_id
        assert sess["csrf_token"] == original_csrf
    assert preview_response.status_code == 200
    assert "Set-Cookie" not in preview_response.headers
    assert clear_response.status_code == 200
    assert settings_response.status_code == 200


def test_capabilities_reports_no_native_window_in_no_gui(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch, no_gui=True)
    client = flask_app.test_client()
    bootstrap(client)
    unlock_test_client(ag_app, client)

    response = client.get(
        "/api/capabilities",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert response.status_code == 200
    assert response.get_json() == {"has_native_window": False}


def test_capabilities_reports_native_window_in_gui_mode(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch, no_gui=False)
    client = flask_app.test_client()
    bootstrap(client)
    unlock_test_client(ag_app, client)

    response = client.get(
        "/api/capabilities",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert response.status_code == 200
    assert response.get_json() == {"has_native_window": True}


def test_capabilities_still_rejects_bad_host_without_bearer(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch, no_gui=True)

    response = flask_app.test_client().get(
        "/api/capabilities",
        base_url=ORIGIN,
        headers={"Host": "attacker.test:18080"},
    )

    assert response.status_code == 403


def test_session_js_uses_prepare_preview_and_native_window_api():
    js = (PACKAGE_ROOT / "app" / "static" / "js" / "session.js").read_text(encoding="utf-8")

    assert "/api/prepare-preview" in js
    assert "open_preview_window" in js
    assert "api.open_preview(" not in js
