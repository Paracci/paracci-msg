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
    return client


def fresh_preview_store(monkeypatch):
    from app import routes
    from core.preview_store import PreviewStore

    store = PreviewStore()
    monkeypatch.setattr(routes, "preview_store", store)
    return store


def png_bytes(size=(1400, 900), color=(14, 80, 130, 255)):
    image = Image.new("RGBA", size, color)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def seed_preview(pid, content, mime, allow_download):
    from app import routes

    routes.PREVIEW_CACHE.clear()
    routes.PREVIEW_CACHE[pid] = {
        "filename": "preview.png" if mime.startswith("image/") else "preview.mp4",
        "content": content,
        "mime": mime,
        "expires": time.time() + 600,
        "allow_download": allow_download,
    }


def seed_token_preview(pid, content, mime, allow_download, access_token="preview-access-token"):
    from app import routes

    routes.PREVIEW_CACHE.clear()
    routes.PREVIEW_CACHE[pid] = {
        "filename": "preview.png" if mime.startswith("image/") else "preview.mp4",
        "content": content,
        "mime": mime,
        "expires": time.time() + 600,
        "allow_download": allow_download,
        "access_token": access_token,
    }
    return access_token


def get(client, path):
    return client.get(
        path,
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )


def test_no_download_token_image_content_is_degraded_preview_only(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    store = fresh_preview_store(monkeypatch)
    original = png_bytes()
    token = store.generate_token(
        original,
        "preview.png",
        "image/png",
        allow_download=False,
    )

    inline_response = get(client, f"/preview/{token}/content")
    download_response = get(client, f"/preview/{token}/content?download=1")

    assert inline_response.status_code == 200
    assert inline_response.data != original
    assert inline_response.mimetype == "image/jpeg"
    preview = Image.open(io.BytesIO(inline_response.data))
    assert preview.width <= 1024
    assert preview.height <= 1024
    disposition = inline_response.headers.get("Content-Disposition", "").lower()
    assert "attachment" not in disposition
    assert download_response.status_code == 403
    assert download_response.data != original


def test_no_download_token_text_content_is_not_exposed_inline(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    store = fresh_preview_store(monkeypatch)
    token = store.generate_token(
        b"private text",
        "private.txt",
        "text/plain",
        allow_download=False,
    )

    inline_response = get(client, f"/preview/{token}/content")
    download_response = get(client, f"/preview/{token}/content?download=1")

    assert inline_response.status_code == 415
    assert inline_response.data != b"private text"
    assert download_response.status_code == 403
    assert download_response.data != b"private text"


def test_no_download_token_pdf_content_is_not_exposed_inline(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    store = fresh_preview_store(monkeypatch)
    token = store.generate_token(
        b"%PDF-private",
        "private.pdf",
        "application/pdf",
        allow_download=False,
    )

    inline_response = get(client, f"/preview/{token}/content")
    download_response = get(client, f"/preview/{token}/content?download=1")

    assert inline_response.status_code == 415
    assert inline_response.data != b"%PDF-private"
    assert download_response.status_code == 403
    assert download_response.data != b"%PDF-private"


def test_no_download_token_video_content_is_not_exposed_inline(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    store = fresh_preview_store(monkeypatch)
    token = store.generate_token(
        b"private-video-bytes",
        "private.mp4",
        "video/mp4",
        allow_download=False,
    )

    inline_response = get(client, f"/preview/{token}/content")
    download_response = get(client, f"/preview/{token}/content?download=1")

    assert inline_response.status_code == 415
    assert inline_response.data != b"private-video-bytes"
    assert download_response.status_code == 403
    assert download_response.data != b"private-video-bytes"


def test_no_download_token_invalid_image_content_fails_closed(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    store = fresh_preview_store(monkeypatch)
    original = b"\x89PNG\r\nnot-a-real-image"
    token = store.generate_token(
        original,
        "preview.png",
        "image/png",
        allow_download=False,
    )

    response = get(client, f"/preview/{token}/content")

    assert response.status_code == 415
    assert response.data != original


def test_no_download_raw_preview_rejects_original_bytes(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    original = png_bytes()
    seed_preview("no-download-image", original, "image/png", allow_download=False)

    response = get(client, "/preview/no-download-image?raw=1")

    assert response.status_code == 403
    assert response.data != original


def test_no_download_image_preview_is_transformed_jpeg(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    original = png_bytes()
    seed_preview("no-download-image", original, "image/png", allow_download=False)

    response = get(client, "/preview/no-download-image?variant=preview")

    assert response.status_code == 200
    assert response.mimetype == "image/jpeg"
    assert response.data != original
    preview = Image.open(io.BytesIO(response.data))
    assert preview.width <= 1024
    assert preview.height <= 1024


def test_allow_download_raw_and_attachment_download_return_original_bytes(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    original = png_bytes()
    seed_preview("downloadable-image", original, "image/png", allow_download=True)

    raw_response = get(client, "/preview/downloadable-image?raw=1")
    download_response = get(client, "/preview/downloadable-image/download")

    assert raw_response.status_code == 200
    assert raw_response.data == original
    assert download_response.status_code == 200
    assert download_response.data == original
    assert "attachment" in download_response.headers["Content-Disposition"]


def test_allow_download_token_content_and_download_return_original_bytes(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    store = fresh_preview_store(monkeypatch)
    original = png_bytes()
    token = store.generate_token(
        original,
        "preview.png",
        "image/png",
        allow_download=True,
    )

    inline_response = get(client, f"/preview/{token}/content")
    download_response = get(client, f"/preview/{token}/content?download=1")

    assert inline_response.status_code == 200
    assert inline_response.data == original
    assert inline_response.mimetype == "image/png"
    assert download_response.status_code == 200
    assert download_response.data == original
    assert "attachment" in download_response.headers["Content-Disposition"]


def test_preview_token_and_main_bearer_allow_child_window_without_bootstrap_session(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "Correct-Horse-95175328")
    ag_app.db = ag_app.db.with_device_key(ag_app.device_key)
    ag_app.active_client_id = "already-unlocked-parent"
    original = png_bytes()
    token = seed_token_preview("child-window-image", original, "image/png", allow_download=True)

    child_client = flask_app.test_client()
    response = child_client.get(
        f"/preview/child-window-image?preview_token={token}",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    assert response.status_code == 200
    html = response.data.decode("utf-8")
    assert f"/preview/child-window-image?raw=1&amp;preview_token={token}" in html
    assert f"/preview/child-window-image/download?preview_token={token}" in html


def test_preview_token_download_respects_allow_download_boundary(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "Correct-Horse-95175328")
    ag_app.db = ag_app.db.with_device_key(ag_app.device_key)
    ag_app.active_client_id = "already-unlocked-parent"
    original = png_bytes()
    token = seed_token_preview("child-window-image", original, "image/png", allow_download=True)
    child_client = flask_app.test_client()

    download_response = child_client.get(
        f"/preview/child-window-image/download?preview_token={token}",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    assert download_response.status_code == 200
    assert download_response.data == original

    no_download_token = seed_token_preview("no-download-image", original, "image/png", allow_download=False)
    rejected_response = child_client.get(
        f"/preview/no-download-image/download?preview_token={no_download_token}",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    assert rejected_response.status_code == 403


def test_generated_preview_urls_include_child_window_access_token(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    from app import routes

    with flask_app.test_request_context("/", base_url=ORIGIN, headers={"Host": HOST}):
        pid = routes._add_to_preview_cache("preview.png", png_bytes(), "image/png", True)
        token = routes.PREVIEW_CACHE[pid]["access_token"]

        preview_url = routes._preview_url("main.preview", pid)
        download_url = routes._preview_url("main.preview_download", pid)

    assert preview_url == f"/preview/{pid}?preview_token={token}"
    assert download_url == f"/preview/{pid}/download?preview_token={token}"


def test_no_download_image_html_embeds_transformed_preview_not_raw(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    original = png_bytes()
    seed_preview("no-download-image", original, "image/png", allow_download=False)

    response = get(client, "/preview/no-download-image")

    assert response.status_code == 200
    html = response.data.decode("utf-8")
    assert "variant=preview" in html
    assert "raw=1" not in html


def test_no_download_video_preview_does_not_embed_raw_source(tmp_path, monkeypatch):
    client = auth_client(tmp_path, monkeypatch)
    original = b"fake-video-bytes"
    seed_preview("no-download-video", original, "video/mp4", allow_download=False)

    raw_response = get(client, "/preview/no-download-video?raw=1")
    preview_response = get(client, "/preview/no-download-video")

    assert raw_response.status_code == 403
    assert preview_response.status_code == 200
    html = preview_response.data.decode("utf-8")
    assert "<source" not in html
    assert "raw=1" not in html
