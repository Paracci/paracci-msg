import io
import zipfile
import json
import base64
import random
import re
import unicodedata
from pathlib import Path
from typing import List, Dict, Tuple, NamedTuple

from .crypto import random_bytes

FALLBACK_ATTACHMENT_FILENAME = "attachment.bin"
MAX_ATTACHMENT_FILENAME_LENGTH = 180
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_UNSAFE_FILENAME_CHARS_RE = re.compile(r"[^A-Za-z0-9._ -]+")
_REPEATED_SEPARATORS_RE = re.compile(r"[\s_-]{2,}")
_REPEATED_DOTS_RE = re.compile(r"\.{2,}")


def sanitize_attachment_filename(name, fallback: str = FALLBACK_ATTACHMENT_FILENAME) -> str:
    """Return a conservative ASCII filename safe for display and download."""
    fallback = str(fallback or FALLBACK_ATTACHMENT_FILENAME)
    raw = "" if name is None else str(name)
    normalized = unicodedata.normalize("NFC", raw)
    normalized = _CONTROL_CHARS_RE.sub("", normalized)
    leaf = normalized.replace("\\", "/").split("/")[-1]
    cleaned = _UNSAFE_FILENAME_CHARS_RE.sub("_", leaf)
    cleaned = _REPEATED_SEPARATORS_RE.sub("_", cleaned)
    cleaned = _REPEATED_DOTS_RE.sub(".", cleaned)
    cleaned = cleaned.strip(" .")

    if not cleaned or cleaned in {".", ".."} or all(ch in {"_", "-"} for ch in cleaned):
        return fallback

    if len(cleaned) > MAX_ATTACHMENT_FILENAME_LENGTH:
        suffix = Path(cleaned).suffix
        if suffix and len(suffix) < MAX_ATTACHMENT_FILENAME_LENGTH:
            stem_limit = MAX_ATTACHMENT_FILENAME_LENGTH - len(suffix)
            stem = cleaned[:-len(suffix)].strip(" .")[:stem_limit].strip(" .")
            cleaned = f"{stem}{suffix}" if stem else fallback
        else:
            cleaned = cleaned[:MAX_ATTACHMENT_FILENAME_LENGTH].strip(" .") or fallback

    return cleaned


def _is_safe_attachment_path(path) -> bool:
    """Validate ZIP metadata attachment paths before reading their content."""
    if not isinstance(path, str):
        return False
    if _CONTROL_CHARS_RE.search(path) or "\\" in path:
        return False
    parts = path.split("/")
    if len(parts) != 2 or parts[0] != "attachments":
        return False
    name = parts[1]
    return bool(name and name not in {".", ".."} and ".." not in name)

class Attachment(NamedTuple):
    """Data structure representing message attachments."""
    filename: str
    content: bytes
    mime_type: str = "application/octet-stream"

class Package(NamedTuple):
    """Package structure containing message content and attachments."""
    text: str
    attachments: List[Attachment]
    allow_download: bool = False

def create_package(text: str, files: List[Tuple[str, bytes]], allow_download: bool = False) -> bytes:
    """
    Converts text and files into a ZIP package before encryption.
    TRAFFIC ANALYSIS PROTECTION: Adds random size padding (junk data) to the package.
    """
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Message text
        zf.writestr("message.md", text.encode("utf-8"))
        
        # 2. Attachments
        metadata = []
        for i, (fname, content) in enumerate(files):
            safe_fname = sanitize_attachment_filename(fname)
            internal_path = f"attachments/{i}_{safe_fname}"
            zf.writestr(internal_path, content)
            metadata.append({
                "original_name": safe_fname,
                "internal_path": internal_path,
                "size": len(content)
            })
            
        # 3. Metadata
        zf.writestr("metadata.json", json.dumps({
            "attachments": metadata,
            "allow_download": allow_download
        }).encode("utf-8"))

        # 4. RANDOM PADDING (Size Analysis Protection)
        # Add random data between 1 KB and 256 KB
        padding_size = random.randint(1024, 256 * 1024)
        zf.writestr(".padding", random_bytes(padding_size))
        
    return buffer.getvalue()

def extract_package(blob: bytes) -> Package:
    """
    Extracts the components of the decrypted package blob.
    """
    buffer = io.BytesIO(blob)
    text = ""
    attachments = []
    allow_download = False
    
    with zipfile.ZipFile(buffer, "r") as zf:
        # 1. Read message
        if "message.md" in zf.namelist():
            text = zf.read("message.md").decode("utf-8")
            
        # 2. Read Metadata and Attachments
        if "metadata.json" in zf.namelist():
            meta_obj = json.loads(zf.read("metadata.json").decode("utf-8"))
            meta_obj = meta_obj if isinstance(meta_obj, dict) else {}
            allow_download = meta_obj.get("allow_download", False)
            meta_list = meta_obj.get("attachments", [])
            meta_list = meta_list if isinstance(meta_list, list) else []
            zip_names = set(zf.namelist())
            for item in meta_list:
                if not isinstance(item, dict):
                    continue
                path = item.get("internal_path")
                if _is_safe_attachment_path(path) and path in zip_names:
                    filename = sanitize_attachment_filename(item.get("original_name"))
                    content = zf.read(path)
                    attachments.append(Attachment(
                        filename=filename,
                        content=content,
                        mime_type=_guess_mime(filename)
                    ))
                    
    return Package(text=text, attachments=attachments, allow_download=allow_download)

def _guess_mime(filename: str) -> str:
    """Guesses the MIME type based on the file extension."""
    filename = sanitize_attachment_filename(filename)
    ext = Path(filename).suffix.lower()
    mimes = {
        ".png": "image/png",
        ".jpg": "image/jpeg",
        ".jpeg": "image/jpeg",
        ".gif": "image/gif",
        ".webp": "image/webp",
        ".mp4": "video/mp4",
        ".webm": "video/webm",
        ".pdf": "application/pdf",
        ".txt": "text/plain",
    }
    return mimes.get(ext, "application/octet-stream")

def package_to_template_data(package: Package) -> Dict:
    """
    Converts the package into a format easily displayable in templates.
    Converts image/video files to base64.
    """
    processed_attachments = []
    for att in package.attachments:
        filename = sanitize_attachment_filename(att.filename)
        is_media = att.mime_type.startswith(("image/", "video/"))
        data_b64 = ""
        if is_media:
            data_b64 = base64.b64encode(att.content).decode("utf-8")
            
        processed_attachments.append({
            "filename": filename,
            "mime_type": att.mime_type,
            "is_media": is_media,
            "data_b64": data_b64,
            "size": len(att.content),
            # All files can be base64 for download or a separate route can be used
            # Base64 is sufficient for small files for now
            "full_b64": base64.b64encode(att.content).decode("utf-8") if not is_media else data_b64
        })
        
    return {
        "text": package.text,
        "attachments": processed_attachments,
        "allow_download": package.allow_download
    }
