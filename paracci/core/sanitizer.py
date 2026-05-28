import io
import logging
from pathlib import Path

from PIL import Image, ImageDraw, ImageOps, UnidentifiedImageError


logger = logging.getLogger(__name__)

NO_DOWNLOAD_PREVIEW_MAX_DIMENSION = 1024
NO_DOWNLOAD_PREVIEW_JPEG_QUALITY = 60
NO_DOWNLOAD_PREVIEW_WATERMARK = "PARACCI PREVIEW"


class SanitizationError(Exception):
    """Raised when an attachment cannot be sanitized safely."""

    i18n_key = "session.attachment_sanitization_failed"
    user_message = (
        "This image attachment could not be processed and was rejected for safety. "
        "Please try a different file."
    )

    def __init__(self, filename: str):
        self.filename = filename
        super().__init__(self.user_message)


def sanitize_image(image_bytes: bytes, filename: str) -> bytes:
    """
    Cleans EXIF and other metadata from image files.
    Keeps only basic image data.
    """
    try:
        ext = filename.split('.')[-1].lower()
        if ext not in ['jpg', 'jpeg', 'png', 'webp']:
            return image_bytes

        img = Image.open(io.BytesIO(image_bytes))

        # Take only the data part (save to a new buffer without EXIF)
        output = io.BytesIO()

        # Maintain transparency for PNG/WebP
        if img.mode in ("RGBA", "P"):
            img = img.convert("RGBA")
        else:
            img = img.convert("RGB")

        save_format = "JPEG" if ext in ['jpg', 'jpeg'] else ext.upper()

        # Save without adding EXIF
        img.save(output, format=save_format, optimize=True)
        return output.getvalue()
    except Exception as e:
        logger.error(f"Image cleaning error ({filename}): {e}")
        raise SanitizationError(filename) from e


def build_no_download_image_preview(
    image_bytes: bytes | None = None,
    mime_type: str = "",
    *,
    image_path: str | Path | None = None
) -> tuple[bytes, str] | None:
    """Build a lossy, marked derivative for a restricted inline image preview."""
    if not str(mime_type or "").lower().startswith("image/"):
        return None

    try:
        image_source = image_path if image_path else io.BytesIO(image_bytes)
        with Image.open(image_source) as image:
            image = ImageOps.exif_transpose(image)
            image.thumbnail(
                (NO_DOWNLOAD_PREVIEW_MAX_DIMENSION, NO_DOWNLOAD_PREVIEW_MAX_DIMENSION)
            )

            has_alpha = image.mode in ("RGBA", "LA") or (
                image.mode == "P" and "transparency" in image.info
            )
            if has_alpha:
                rgba = image.convert("RGBA")
                background = Image.new("RGBA", rgba.size, (255, 255, 255, 255))
                background.alpha_composite(rgba)
                image = background.convert("RGB")
            else:
                image = image.convert("RGB")

            draw = ImageDraw.Draw(image)
            text = NO_DOWNLOAD_PREVIEW_WATERMARK
            try:
                left, top, right, bottom = draw.textbbox((0, 0), text)
                text_width = right - left
                text_height = bottom - top
            except AttributeError:
                text_width, text_height = draw.textsize(text)

            margin = max(12, min(image.size) // 40)
            pad = 6
            x = max(margin, image.width - text_width - margin)
            y = max(margin, image.height - text_height - margin)
            draw.rectangle(
                [x - pad, y - pad, x + text_width + pad, y + text_height + pad],
                fill=(255, 255, 255),
                outline=(30, 30, 30),
            )
            draw.text((x, y), text, fill=(30, 30, 30))

            output = io.BytesIO()
            image.save(
                output,
                format="JPEG",
                quality=NO_DOWNLOAD_PREVIEW_JPEG_QUALITY,
                optimize=True,
            )
            return output.getvalue(), "image/jpeg"
    except (UnidentifiedImageError, OSError, ValueError, KeyError) as exc:
        logger.warning("Could not build no-download image preview: %s", exc)
        return None


def sanitize_text(text: str) -> str:
    """Escape HTML special characters in user-controlled text (defense-in-depth).

    This is a *second* line of defence that works alongside Jinja2 auto-escaping
    and frontend DOMPurify — it is not a replacement for either.  Applying
    ``html.escape()`` before any render boundary ensures that even if a template
    mistakenly uses ``|safe``, or a JS renderer passes raw text to the DOM, the
    five HTML-sensitive characters are already neutralised:

        < → &lt;     > → &gt;     & → &amp;
        " → &quot;   ' → &#x27;

    The ``quote=True`` argument (Python default since 3.2) ensures that both
    double- and single-quote characters are escaped, which matters when the
    value appears inside an HTML attribute.

    Accepts ``None`` or non-string inputs and coerces them to ``str`` before
    escaping, so callers do not need to guard against those edge cases.

    This import is intentionally placed inside the function body: ``html`` is a
    Python standard-library module with no external dependencies, making it
    statically resolvable by Nuitka during compilation.
    """
    import html as _html  # stdlib only — statically resolvable for Nuitka
    if text is None:
        return ""
    if not isinstance(text, str):
        text = str(text)
    return _html.escape(text, quote=True)
