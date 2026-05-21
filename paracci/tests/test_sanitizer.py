import importlib
import io
import sys
from pathlib import Path

import pytest
from flask import g
from werkzeug.datastructures import FileStorage

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.sanitizer import SanitizationError, sanitize_image


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


def test_sanitize_image_rejects_malformed_supported_image():
    with pytest.raises(SanitizationError) as exc:
        sanitize_image(b"not a valid png", "bad.png")

    assert exc.value.filename == "bad.png"
    assert str(exc.value) == SanitizationError.user_message


def test_sanitize_image_leaves_non_image_bytes_unchanged():
    original = b"not an image but not a supported image extension"

    assert sanitize_image(original, "note.txt") == original


def test_gather_attachments_returns_localized_sanitization_error(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module

    def reject_image(_content, filename):
        raise SanitizationError(filename)

    monkeypatch.setattr(routes_module, "sanitize_image", reject_image)

    upload = FileStorage(stream=io.BytesIO(b"bad image"), filename="bad.png")
    with flask_app.test_request_context("/"):
        g.locale = "en"
        files, error = routes_module._gather_attachments([upload])

    assert files is None
    assert error == SanitizationError.user_message


def test_native_attachment_staging_rejects_sanitization_error_and_clears_cache(tmp_path, monkeypatch):
    make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module

    routes_module.STAGED_ATTACHMENT_CACHE.clear()
    selected = tmp_path / "bad.png"
    selected.write_bytes(b"bad image")

    def reject_image(_content, filename):
        raise SanitizationError(filename)

    monkeypatch.setattr(routes_module, "sanitize_image", reject_image)

    with pytest.raises(routes_module.NativeAttachmentStagingError) as exc:
        routes_module.stage_native_attachment_paths([selected])

    assert str(exc.value) == SanitizationError.user_message
    assert routes_module.STAGED_ATTACHMENT_CACHE == {}
