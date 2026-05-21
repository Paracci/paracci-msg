from PIL import Image
import io
import logging


logger = logging.getLogger(__name__)


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


def sanitize_text(text: str) -> str:
    """Return text unchanged; text sanitization is handled at render boundaries."""
    return text
