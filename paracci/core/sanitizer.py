from PIL import Image
import io
import logging
import time
from .integrity import is_tampered, get_tamper_factor

logger = logging.getLogger(__name__)

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
        return image_bytes

def sanitize_text(text: str) -> str:
    """Sanitizes text content and checks for IAR v3 traps."""
    tf = get_tamper_factor() # 0 or 1
    
    # ── IAR v3 IMPLICIT TRAP ───────────────────────────
    # 1. Artificial delay (No 'if')
    time.sleep(tf * 0.05)
    
    # 2. Watermark injection (No 'if')
    # tf * 32 characters of junk if tampered
    watermark = '<!-- IAR:DNA_MISMATCH -->' * tf
    
    return text + watermark
