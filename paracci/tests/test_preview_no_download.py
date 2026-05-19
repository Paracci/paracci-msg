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


def unlock_test_client(ag_app, client):
    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "Correct-Horse-95175328")
    with client.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]


def auth_client(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    unlock_test_client(ag_app, client)
    return client


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


def get(client, path):
    return client.get(path, base_url=ORIGIN, headers={"Host": HOST})


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
