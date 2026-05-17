import io
import zipfile
import json
import base64
import random
from pathlib import Path
from typing import List, Dict, Tuple, NamedTuple

from .crypto import random_bytes

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
            internal_path = f"attachments/{i}_{fname}"
            zf.writestr(internal_path, content)
            metadata.append({
                "original_name": fname,
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
            allow_download = meta_obj.get("allow_download", False)
            meta_list = meta_obj.get("attachments", [])
            for item in meta_list:
                path = item["internal_path"]
                if path in zf.namelist():
                    content = zf.read(path)
                    attachments.append(Attachment(
                        filename=item["original_name"],
                        content=content,
                        mime_type=_guess_mime(item["original_name"])
                    ))
                    
    return Package(text=text, attachments=attachments, allow_download=allow_download)

def _guess_mime(filename: str) -> str:
    """Guesses the MIME type based on the file extension."""
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
        is_media = att.mime_type.startswith(("image/", "video/"))
        data_b64 = ""
        if is_media:
            data_b64 = base64.b64encode(att.content).decode("utf-8")
            
        processed_attachments.append({
            "filename": att.filename,
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
