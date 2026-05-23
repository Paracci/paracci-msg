import io
import logging

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


def build_no_download_image_preview(image_bytes: bytes, mime_type: str) -> tuple[bytes, str] | None:
    """Build a lossy, marked derivative for a restricted inline image preview."""
    if not str(mime_type or "").lower().startswith("image/"):
        return None

    try:
        with Image.open(io.BytesIO(image_bytes)) as image:
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
    """Return text unchanged; text sanitization is handled at render boundaries."""
    return text
