import importlib
import io
import logging
import struct
import sys
import zlib
from pathlib import Path

import pytest
from flask import g
from PIL import Image, ImageOps
from werkzeug.datastructures import FileStorage

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import sanitizer as sanitizer_module
from core.sanitizer import (
    MAX_IMAGE_DIMENSION,
    SanitizationError,
    build_no_download_image_preview,
    sanitize_image,
    sanitize_text,
)


# ---------------------------------------------------------------------------
# sanitize_text() — defense-in-depth HTML escaping
# ---------------------------------------------------------------------------

def test_sanitize_text_escapes_html_special_characters():
    """All five HTML-sensitive characters must be converted to named entities."""
    result = sanitize_text('<script>alert("it\'s XSS")&danger</script>')
    assert "&lt;" in result, "< must be escaped to &lt;"
    assert "&gt;" in result, "> must be escaped to &gt;"
    assert "&amp;" in result, "& must be escaped to &amp;"
    assert "&quot;" in result, '\" must be escaped to &quot;'
    assert "&#x27;" in result, "' must be escaped to &#x27;"
    # Original dangerous characters must not appear verbatim
    assert "<" not in result
    assert ">" not in result


def test_sanitize_text_handles_none_input():
    """None must be coerced to an empty string without raising."""
    result = sanitize_text(None)
    assert result == "", f"Expected empty string for None, got {result!r}"


def test_sanitize_text_handles_non_string_inputs():
    """Non-string inputs must be coerced to str and then escaped."""
    assert sanitize_text(42) == "42"
    assert sanitize_text(3.14) == "3.14"
    assert sanitize_text(True) == "True"
    # A list whose repr contains angle brackets must not leak raw HTML
    dangerous_obj = type("T", (), {"__str__": lambda self: "<evil>"})()
    result = sanitize_text(dangerous_obj)
    assert "<" not in result
    assert "&lt;" in result


def test_sanitize_text_neutralizes_xss_payload():
    """A classic XSS payload must be fully neutralized so it cannot execute."""
    payload = "<script>alert(document.cookie)</script>"
    result = sanitize_text(payload)
    # Must not contain any unescaped tags
    assert "<script>" not in result
    assert "</script>" not in result
    # Must contain the escaped equivalents
    assert "&lt;script&gt;" in result
    assert "&lt;/script&gt;" in result
    # The overall string must be safe to embed verbatim in an HTML attribute
    # (no unescaped <, >, &, ", ' characters)
    for ch in ("<", ">"):
        assert ch not in result, f"Raw character {ch!r} found in sanitized output"




TOKEN = "test-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"


def png_metadata_bytes(width, height):
    def chunk(kind, data):
        crc = zlib.crc32(kind + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr) + chunk(b"IEND", b"")


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


def test_sanitize_image_rejects_malformed_supported_image():
    with pytest.raises(SanitizationError) as exc:
        sanitize_image(b"not a valid png", "bad.png")

    assert exc.value.filename == "bad.png"
    assert str(exc.value) == SanitizationError.user_message


def test_sanitize_image_leaves_non_image_bytes_unchanged():
    original = b"not an image but not a supported image extension"

    assert sanitize_image(original, "note.txt") == original


@pytest.mark.parametrize(("image_format", "filename"), [("PNG", "safe.png"), ("JPEG", "safe.jpg")])
def test_sanitize_image_accepts_valid_small_raster_images(image_format, filename):
    source = io.BytesIO()
    Image.new("RGB", (64, 48), (14, 80, 130)).save(source, format=image_format)

    sanitized = sanitize_image(source.getvalue(), filename)

    rendered = Image.open(io.BytesIO(sanitized))
    assert rendered.size == (64, 48)


def test_sanitize_image_rejects_over_pixel_budget_before_conversion(monkeypatch):
    def fail_convert(_image, *_args, **_kwargs):
        pytest.fail("over-budget image reached Pillow conversion")

    monkeypatch.setattr(Image.Image, "convert", fail_convert)

    with pytest.raises(SanitizationError):
        sanitize_image(png_metadata_bytes(6000, 5000), "huge.png")


def test_build_no_download_preview_rejects_over_dimension_before_thumbnail(monkeypatch):
    def fail_processing(*_args, **_kwargs):
        pytest.fail("over-dimension image reached preview processing")

    monkeypatch.setattr(ImageOps, "exif_transpose", fail_processing)
    monkeypatch.setattr(Image.Image, "thumbnail", fail_processing)

    assert (
        build_no_download_image_preview(
            png_metadata_bytes(MAX_IMAGE_DIMENSION + 1, 1),
            "image/png",
        )
        is None
    )


def test_sanitize_image_converts_decompression_bomb_warning_to_safe_rejection():
    with pytest.raises(SanitizationError):
        sanitize_image(png_metadata_bytes(5001, 5001), "bomb-warning.png")


def test_no_download_preview_converts_decompression_bomb_error_to_safe_rejection():
    assert build_no_download_image_preview(png_metadata_bytes(10000, 6000), "image/png") is None


def test_build_no_download_preview_rejects_svg_without_raster_decoder(monkeypatch):
    monkeypatch.setattr(
        sanitizer_module.Image,
        "open",
        lambda *_args, **_kwargs: pytest.fail("SVG reached Pillow raster decoder"),
    )

    assert build_no_download_image_preview(b"<svg><script></script></svg>", "image/svg+xml") is None


def test_image_rejection_logs_are_generic(caplog):
    sentinel = "preview-token-local-path-secret"
    secret_filename = r"tests/fixtures/preview-token-local-path-secret.png"

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="core.sanitizer"):
        with pytest.raises(SanitizationError) as exc_info:
            sanitize_image(
                png_metadata_bytes(MAX_IMAGE_DIMENSION + 1, 1) + sentinel.encode("ascii"),
                secret_filename,
            )

    log_text = caplog.text
    assert "Image attachment rejected during sanitization." in log_text
    assert sentinel not in log_text
    assert secret_filename not in log_text
    assert sentinel not in str(exc_info.value)
    assert secret_filename not in str(exc_info.value)


def test_build_no_download_image_preview_returns_lossy_bounded_jpeg():
    source = io.BytesIO()
    Image.new("RGBA", (1400, 900), (14, 80, 130, 255)).save(source, format="PNG")
    original = source.getvalue()

    preview_data = build_no_download_image_preview(original, "image/png")

    assert preview_data is not None
    preview_bytes, preview_mime = preview_data
    assert preview_mime == "image/jpeg"
    assert preview_bytes != original
    preview = Image.open(io.BytesIO(preview_bytes))
    assert preview.width <= 1024
    assert preview.height <= 1024


def test_build_no_download_image_preview_fails_closed_for_invalid_or_non_image_content():
    assert build_no_download_image_preview(b"not a valid png", "image/png") is None
    assert build_no_download_image_preview(b"private text", "text/plain") is None


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
