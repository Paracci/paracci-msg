import importlib
import sys
from pathlib import Path

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
    return flask_app


def fresh_preview_store(monkeypatch, ttl_seconds=300, clock=None):
    from app import routes
    from core.preview_store import PreviewStore

    store = PreviewStore(ttl_seconds=ttl_seconds, clock=clock)
    monkeypatch.setattr(routes, "preview_store", store)
    return store


def test_preview_template_is_standalone_and_receives_metadata(tmp_path, monkeypatch):
    flask_app = make_flask_app(tmp_path, monkeypatch)
    store = fresh_preview_store(monkeypatch)
    token = store.generate_token(b"secret-content", "document.pdf", "application/pdf")

    response = flask_app.test_client().get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    html = response.data.decode("utf-8")
    assert response.status_code == 200
    assert response.mimetype == "text/html"
    assert "document.pdf" in html
    assert token in html
    assert f"/preview/{token}/content" in html
    assert "static/js/preview.js" in html
    assert "secret-content" not in html

    for shell_marker in (
        "desktop-shell",
        "app-sidebar",
        "sidebar-session-list",
        "workspace-content",
        "static/js/app.js",
    ):
        assert shell_marker not in html


def test_preview_template_csp_allows_standalone_preview_runtime(tmp_path, monkeypatch):
    flask_app = make_flask_app(tmp_path, monkeypatch)
    store = fresh_preview_store(monkeypatch)
    token = store.generate_token(b"# Preview", "note.md", "text/markdown")

    response = flask_app.test_client().get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    csp = response.headers["Content-Security-Policy"]
    assert response.status_code == 200
    assert "'unsafe-inline'" not in csp.split("script-src", 1)[1].split(";", 1)[0]
    assert "https://cdn.jsdelivr.net" in csp
    assert "https://cdnjs.cloudflare.com" in csp
    assert "object-src 'self' blob:" in csp
    assert "frame-src 'self' blob:" in csp


def test_preview_token_page_does_not_overwrite_main_session_cookie(tmp_path, monkeypatch):
    flask_app = make_flask_app(tmp_path, monkeypatch)
    store = fresh_preview_store(monkeypatch)
    token = store.generate_token(b"secret-content", "document.pdf", "application/pdf")

    response = flask_app.test_client().get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert response.status_code == 200
    assert "Set-Cookie" not in response.headers


def test_preview_template_hides_download_for_non_downloadable_token(tmp_path, monkeypatch):
    flask_app = make_flask_app(tmp_path, monkeypatch)
    store = fresh_preview_store(monkeypatch)
    token = store.generate_token(
        b"private",
        "private.txt",
        "text/plain",
        allow_download=False,
    )

    response = flask_app.test_client().get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    html = response.data.decode("utf-8")
    assert response.status_code == 200
    assert 'data-allow-download="false"' in html
    assert 'id="downloadBtn" hidden' in html
    assert f"/preview/{token}/content?download=1" not in html


def test_preview_runtime_uses_custom_media_controls():
    preview_html = Path("paracci/app/templates/preview.html").read_text(encoding="utf-8")
    preview_js = Path("paracci/app/static/js/preview.js").read_text(encoding="utf-8")

    assert "video.controls = true" not in preview_js
    assert "audio.controls = true" not in preview_js
    assert "media-controls" in preview_html
    assert "customMediaPlayer" in preview_js
    assert "download-success-toast" in preview_html
    assert "showDownloadSuccess" in preview_js
    assert "▶" in preview_js
    assert "⏸" in preview_js
    assert "toggleFullscreen" in preview_js
    assert "exitFullscreen" in preview_js


def test_preview_template_returns_404_for_expired_token(tmp_path, monkeypatch):
    flask_app = make_flask_app(tmp_path, monkeypatch)
    now = [100.0]
    store = fresh_preview_store(monkeypatch, ttl_seconds=5, clock=lambda: now[0])
    token = store.generate_token(b"expired-content", "expired.txt", "text/plain")
    now[0] = 106.0

    response = flask_app.test_client().get(
        f"/preview/{token}",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert response.status_code == 404
