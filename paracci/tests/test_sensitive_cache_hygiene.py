import importlib
import io
import sys
import time
from pathlib import Path

from PIL import Image

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


def auth_headers(client):
    return {
        "Host": HOST,
        "X-Paracci-Token": TOKEN,
        "X-CSRF-Token": csrf_from(client),
        "Origin": ORIGIN,
    }


def unlock_test_client(ag_app, client):
    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "Correct-Horse-95175328")
    ag_app.db = ag_app.db.with_device_key(ag_app.device_key)
    with client.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]


def auth_client(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    unlock_test_client(ag_app, client)
    return ag_app, client


def png_bytes(size=(1400, 900), color=(14, 80, 130, 255)):
    image = Image.new("RGBA", size, color)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def seed_preview(pid, content=b"preview-bytes", expires=None, allow_download=False):
    from app import routes

    routes.PREVIEW_CACHE[pid] = {
        "filename": "preview.png",
        "content": content,
        "mime": "image/png",
        "expires": time.time() + 600 if expires is None else expires,
        "allow_download": allow_download,
    }


def seed_staged(attachment_id, content=b"staged-bytes", expires=None):
    from app import routes

    routes.STAGED_ATTACHMENT_CACHE[attachment_id] = {
        "filename": "note.txt",
        "content": content,
        "expires": time.time() + 600 if expires is None else expires,
    }


def test_sensitive_cache_clear_removes_only_requested_preview_ids(tmp_path, monkeypatch):
    _ag_app, client = auth_client(tmp_path, monkeypatch)
    from app import routes

    routes.PREVIEW_CACHE.clear()
    seed_preview("remove-me")
    seed_preview("keep-me")

    response = client.post(
        "/api/sensitive-cache/clear",
        base_url=ORIGIN,
        json={"preview_ids": ["remove-me"], "staged_attachment_ids": []},
        headers=auth_headers(client),
    )

    assert response.status_code == 200
    assert response.get_json()["cleared_preview"] == 1
    assert "remove-me" not in routes.PREVIEW_CACHE
    assert "keep-me" in routes.PREVIEW_CACHE


def test_sensitive_cache_clear_removes_requested_staged_ids(tmp_path, monkeypatch):
    _ag_app, client = auth_client(tmp_path, monkeypatch)
    from app import routes

    routes.STAGED_ATTACHMENT_CACHE.clear()
    seed_staged("remove-me")
    seed_staged("keep-me")

    response = client.post(
        "/api/sensitive-cache/clear",
        base_url=ORIGIN,
        json={"preview_ids": [], "staged_attachment_ids": ["remove-me"]},
        headers=auth_headers(client),
    )

    assert response.status_code == 200
    assert response.get_json()["cleared_staged"] == 1
    assert "remove-me" not in routes.STAGED_ATTACHMENT_CACHE
    assert "keep-me" in routes.STAGED_ATTACHMENT_CACHE


def test_expired_preview_cleanup_drops_only_expired_entries(tmp_path, monkeypatch):
    auth_client(tmp_path, monkeypatch)
    from app import routes

    routes.PREVIEW_CACHE.clear()
    seed_preview("expired", expires=time.time() - 1)
    seed_preview("current")

    assert routes._cleanup_preview_cache() == 1
    assert "expired" not in routes.PREVIEW_CACHE
    assert "current" in routes.PREVIEW_CACHE


def test_no_download_preview_variant_does_not_cache_preview_bytes(tmp_path, monkeypatch):
    _ag_app, client = auth_client(tmp_path, monkeypatch)
    from app import routes

    routes.PREVIEW_CACHE.clear()
    original = png_bytes()
    seed_preview("no-download-image", content=original, allow_download=False)

    response = client.get(
        "/preview/no-download-image?variant=preview",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    assert response.status_code == 200
    assert response.mimetype == "image/jpeg"
    assert "preview_content" not in routes.PREVIEW_CACHE["no-download-image"]
    assert "preview_mime" not in routes.PREVIEW_CACHE["no-download-image"]
    assert response.headers["Cache-Control"] == "no-store, max-age=0"


def test_locked_device_redirect_clears_sensitive_caches(tmp_path, monkeypatch):
    ag_app, client = auth_client(tmp_path, monkeypatch)
    from app import routes

    routes.PREVIEW_CACHE.clear()
    routes.STAGED_ATTACHMENT_CACHE.clear()
    seed_preview("preview")
    seed_staged("staged")
    ag_app.device_key = None

    response = client.get(
        "/settings",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    assert response.status_code == 302
    assert response.headers["Location"].endswith("/unlock")
    assert routes.PREVIEW_CACHE == {}
    assert routes.STAGED_ATTACHMENT_CACHE == {}


def test_security_shields_doc_names_limits_and_wording_rules():
    doc = (Path(__file__).parent.parent / "docs" / "SECURITY_SHIELDS.md").read_text(encoding="utf-8")

    for term in [
        "Windows",
        "macOS",
        "Linux",
        "clipboard",
        "Secure-delete",
        "Python `bytes`",
        "best-effort",
        "FSCTL_FILE_LEVEL_TRIM",
        "F_FULLFSYNC",
        "FALLOC_FL_PUNCH_HOLE",
    ]:
        assert term.lower() in doc.lower()
    for forbidden in ["prevents screenshots", "guarantees deletion", "wipes instantly", "securely deletes"]:
        assert forbidden in doc
