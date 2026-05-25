import importlib
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


TOKEN = "test-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"


def make_flask_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "1")

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


def preview_headers(**extra):
    headers = {"Host": HOST, "X-Paracci-Token": TOKEN}
    headers.update(extra)
    return headers


def unlock_test_client(ag_app, client):
    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "Correct-Horse-95175328")
    ag_app.db = ag_app.db.with_device_key(ag_app.device_key)
    with client.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]


def fresh_preview_store(monkeypatch):
    from app import routes
    from core.preview_store import PreviewStore

    store = PreviewStore()
    monkeypatch.setattr(routes, "preview_store", store)
    return routes, store


def test_preview_token_page_returns_html(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    _routes, store = fresh_preview_store(monkeypatch)
    token = store.generate_token(b"secret-content", "note.txt", "text/plain")

    response = flask_app.test_client().get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers=preview_headers(),
    )

    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert b"note.txt" in response.data
    assert b"secret-content" not in response.data


def test_preview_token_without_main_bearer_returns_403(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    _routes, store = fresh_preview_store(monkeypatch)
    token = store.generate_token(b"secret-content", "note.txt", "text/plain")

    response = flask_app.test_client().get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert response.status_code == 403


def test_preview_token_page_returns_404_for_invalid_token(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    fresh_preview_store(monkeypatch)

    response = flask_app.test_client().get(
        f"/preview/{'a' * 64}",
        base_url=ORIGIN,
        headers=preview_headers(),
    )

    assert response.status_code == 404


def test_preview_token_page_returns_404_for_expired_token(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    from app import routes
    from core.preview_store import PreviewStore

    now = [100.0]
    store = PreviewStore(ttl_seconds=5, clock=lambda: now[0])
    monkeypatch.setattr(routes, "preview_store", store)
    token = store.generate_token(b"expired", "expired.txt", "text/plain")
    now[0] = 106.0

    response = flask_app.test_client().get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers=preview_headers(),
    )

    assert response.status_code == 404


def test_preview_content_returns_bytes_and_content_type(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    _routes, store = fresh_preview_store(monkeypatch)
    file_bytes = b"\x89PNG\r\npreview-bytes"
    token = store.generate_token(file_bytes, "preview.png", "image/png")

    response = flask_app.test_client().get(
        f"/preview/{token}/content",
        base_url=ORIGIN,
        headers=preview_headers(),
    )

    assert response.status_code == 200
    assert response.data == file_bytes
    assert response.mimetype == "image/png"


def test_preview_content_download_sets_attachment_disposition(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    _routes, store = fresh_preview_store(monkeypatch)
    token = store.generate_token(b"download me", "report.txt", "text/plain")

    response = flask_app.test_client().get(
        f"/preview/{token}/content?download=1",
        base_url=ORIGIN,
        headers=preview_headers(),
    )

    assert response.status_code == 200
    assert "attachment" in response.headers["Content-Disposition"]
    assert "report.txt" in response.headers["Content-Disposition"]


def test_preview_content_rejects_non_downloadable_non_image_token_bytes(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    _routes, store = fresh_preview_store(monkeypatch)
    token = store.generate_token(
        b"do not download",
        "private.txt",
        "text/plain",
        allow_download=False,
    )

    inline_response = flask_app.test_client().get(
        f"/preview/{token}/content",
        base_url=ORIGIN,
        headers=preview_headers(),
    )
    download_response = flask_app.test_client().get(
        f"/preview/{token}/content?download=1",
        base_url=ORIGIN,
        headers=preview_headers(),
    )

    assert inline_response.status_code == 415
    assert inline_response.data != b"do not download"
    assert download_response.status_code == 403


def test_preview_token_routes_still_validate_host_header(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    _routes, store = fresh_preview_store(monkeypatch)
    token = store.generate_token(b"hello", "hello.txt", "text/plain")

    response = flask_app.test_client().get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers=preview_headers(Host="attacker.test:18080"),
    )

    assert response.status_code == 403


def test_prepare_preview_without_bearer_returns_401(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    response = flask_app.test_client().post(
        "/api/prepare-preview",
        base_url=ORIGIN,
        json={"attachment_ref": "missing"},
        headers={"Host": HOST},
    )

    assert response.status_code == 401


def test_prepare_preview_with_valid_attachment_ref_returns_token(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    routes, store = fresh_preview_store(monkeypatch)
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

    response = client.post(
        "/api/prepare-preview",
        base_url=ORIGIN,
        json={"attachment_ref": "ref-1"},
        headers=auth_headers(client),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload["preview_token"]) == 64
    assert payload["filename"] == "report.pdf"
    assert payload["mime_type"] == "application/pdf"
    assert payload["file_size"] == len(b"%PDF-preview-bytes")
    assert payload["downloadable"] is True
    entry = store.get(payload["preview_token"])
    assert entry.file_bytes == b"%PDF-preview-bytes"
    assert entry.allow_download is True


def test_prepare_preview_marks_non_downloadable_attachment(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    routes, store = fresh_preview_store(monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    unlock_test_client(ag_app, client)
    routes.PREVIEW_CACHE.clear()
    routes.PREVIEW_CACHE["ref-1"] = {
        "filename": "private.txt",
        "content": b"private text",
        "mime": "text/plain",
        "expires": time.time() + 600,
        "allow_download": False,
        "access_token": "legacy-token",
    }

    response = client.post(
        "/api/prepare-preview",
        base_url=ORIGIN,
        json={"attachment_ref": "ref-1"},
        headers=auth_headers(client),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["downloadable"] is False
    assert payload["allow_download"] is False
    assert store.get(payload["preview_token"]).allow_download is False
