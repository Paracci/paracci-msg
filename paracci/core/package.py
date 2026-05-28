import io
import zipfile
import json
import random
import re
import unicodedata
import zlib
from pathlib import Path
from typing import List, Dict, Tuple, NamedTuple

from .crypto import random_bytes
from .burn import secure_delete

FALLBACK_ATTACHMENT_FILENAME = "attachment.bin"
MAX_ATTACHMENT_FILENAME_LENGTH = 180
MAX_PACKAGE_ATTACHMENT_COUNT = 10
MAX_PACKAGE_ZIP_ENTRY_COUNT = MAX_PACKAGE_ATTACHMENT_COUNT + 3
MAX_PACKAGE_TEXT_BYTES = 1 * 1024 * 1024
MAX_PACKAGE_METADATA_BYTES = 64 * 1024
MAX_PACKAGE_ATTACHMENT_BYTES = 50 * 1024 * 1024
MAX_PACKAGE_TOTAL_ATTACHMENT_BYTES = 50 * 1024 * 1024
MAX_PACKAGE_PADDING_BYTES = 512 * 1024
MAX_PACKAGE_ENTRY_COMPRESSED_BYTES = 60 * 1024 * 1024
MAX_PACKAGE_COMPRESSION_RATIO = 100
_ZIP_READ_CHUNK_BYTES = 64 * 1024
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_UNSAFE_FILENAME_CHARS_RE = re.compile(r"[^A-Za-z0-9._ -]+")
_REPEATED_SEPARATORS_RE = re.compile(r"[\s_-]{2,}")
_REPEATED_DOTS_RE = re.compile(r"\.{2,}")
_NATIVE_DOWNLOAD_FILENAME_RE = re.compile(
    rf"^[A-Za-z0-9._-]{{1,{MAX_ATTACHMENT_FILENAME_LENGTH}}}$"
)
_WINDOWS_RESERVED_FILENAME_STEMS = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class PackageLimitError(ValueError):
    """Raised when an incoming package fails safe extraction limits."""


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


def validate_native_download_filename(name: str) -> str:
    """Validate a filename before native code creates a Downloads file."""
    if not isinstance(name, str) or not _NATIVE_DOWNLOAD_FILENAME_RE.fullmatch(name):
        raise ValueError("Invalid download filename.")
    if name in {".", ".."} or name.endswith("."):
        raise ValueError("Invalid download filename.")
    if name.split(".", 1)[0].upper() in _WINDOWS_RESERVED_FILENAME_STEMS:
        raise ValueError("Invalid download filename.")
    return name


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


def _compression_ratio_exceeds_limit(info: zipfile.ZipInfo) -> bool:
    """Return True when ZIP metadata describes unsafe expansion."""
    if info.file_size == 0:
        return False
    if info.compress_size == 0:
        return True
    return (info.file_size / info.compress_size) > MAX_PACKAGE_COMPRESSION_RATIO


def _validate_zip_entry_info(info: zipfile.ZipInfo, max_uncompressed_bytes: int, label: str) -> None:
    """Reject ZIP entries that exceed compressed, expanded, or ratio limits."""
    if info.compress_size > MAX_PACKAGE_ENTRY_COMPRESSED_BYTES:
        raise PackageLimitError(f"{label} is too large to open safely.")
    if info.file_size > max_uncompressed_bytes:
        raise PackageLimitError(f"{label} is too large to open safely.")
    if _compression_ratio_exceeds_limit(info):
        raise PackageLimitError(f"{label} expands too much to open safely.")


def _read_zip_entry_limited(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    max_uncompressed_bytes: int,
    label: str,
) -> bytes:
    """Stream a ZIP entry into memory only after enforcing expansion limits."""
    _validate_zip_entry_info(info, max_uncompressed_bytes, label)
    total = 0
    output = io.BytesIO()
    try:
        with zf.open(info) as src:
            while True:
                chunk = src.read(_ZIP_READ_CHUNK_BYTES)
                if not chunk:
                    break
                total += len(chunk)
                if total > max_uncompressed_bytes:
                    raise PackageLimitError(f"{label} is too large to open safely.")
                output.write(chunk)
    except PackageLimitError:
        raise
    except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, zlib.error) as exc:
        raise PackageLimitError("Package is malformed and cannot be opened safely.") from exc
    return output.getvalue()


import os
import secrets
from pathlib import Path

class Attachment:
    """Tuple-compatible structure representing message attachments using disk storage."""
    def __init__(
        self,
        filename: str,
        content: bytes | str | Path | None = None,
        mime_type: str = "application/octet-stream",
        content_path: str | Path | None = None,
    ):
        self.filename = filename
        self.mime_type = mime_type

        if content_path is not None:
            self.content_path = str(content_path)
        elif isinstance(content, (str, Path)):
            self.content_path = str(content)
        elif isinstance(content, bytes):
            temp_dir = Path(os.environ.get("DATA_DIR", "data")) / "temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
            att_token = secrets.token_hex(16)
            dest_path = temp_dir / f"attachment_{att_token}.bin"
            try:
                dest_path.write_bytes(content)
            except OSError as exc:
                raise ValueError("Failed to write attachment temp file.") from exc
            self.content_path = str(dest_path)
        else:
            self.content_path = ""

    @property
    def content(self) -> bytes:
        if not self.content_path or not os.path.exists(self.content_path):
            return b""
        try:
            with open(self.content_path, "rb") as f:
                return f.read()
        except OSError:
            return b""

    @property
    def size(self) -> int:
        if self.content_path and os.path.exists(self.content_path):
            try:
                return os.path.getsize(self.content_path)
            except OSError:
                return 0
        return 0

    def __iter__(self):
        yield self.filename
        yield self.content
        yield self.mime_type

    def __getitem__(self, index):
        return [self.filename, self.content, self.mime_type][index]

    def __len__(self):
        return 3

class Package(NamedTuple):
    """Package structure containing message content and attachments."""
    text: str
    attachments: List[Attachment]
    allow_download: bool = False


def _extract_zip_entry_limited_to_file(
    zf: zipfile.ZipFile,
    info: zipfile.ZipInfo,
    max_uncompressed_bytes: int,
    dest_path: str | Path,
    label: str,
) -> int:
    """Stream a ZIP entry into a file on disk only after enforcing expansion limits."""
    _validate_zip_entry_info(info, max_uncompressed_bytes, label)
    total = 0
    with open(dest_path, "wb") as dest:
        try:
            with zf.open(info) as src:
                while True:
                    chunk = src.read(_ZIP_READ_CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > max_uncompressed_bytes:
                        raise PackageLimitError(f"{label} is too large to open safely.")
                    dest.write(chunk)
        except PackageLimitError:
            raise
        except (zipfile.BadZipFile, RuntimeError, OSError, EOFError, zlib.error) as exc:
            raise PackageLimitError("Package is malformed and cannot be opened safely.") from exc
    return total


def create_package(
    text: str,
    files: List[Tuple[str, bytes | str | Path]],
    allow_download: bool = False,
    output_path: str | Path | None = None,
) -> bytes | None:
    """
    Converts text and files into a ZIP package before encryption.
    If output_path is provided, writes the ZIP directly to disk to optimize memory.
    TRAFFIC ANALYSIS PROTECTION: Adds random size padding (junk data) to the package.
    """
    if output_path is not None:
        zf_target = output_path
    else:
        zf_target = io.BytesIO()

    with zipfile.ZipFile(zf_target, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Message text
        zf.writestr("message.md", text.encode("utf-8"))
        
        # 2. Attachments
        metadata = []
        for i, (fname, content_or_path) in enumerate(files):
            safe_fname = sanitize_attachment_filename(fname)
            internal_path = f"attachments/{i}_{safe_fname}"
            
            if isinstance(content_or_path, (str, Path)) and os.path.exists(content_or_path):
                zf.write(content_or_path, internal_path)
                file_size = os.path.getsize(content_or_path)
            elif isinstance(content_or_path, bytes):
                zf.writestr(internal_path, content_or_path)
                file_size = len(content_or_path)
            else:
                with zf.open(internal_path, "w") as dest:
                    file_size = 0
                    while True:
                        chunk = content_or_path.read(64 * 1024)
                        if not chunk:
                            break
                        dest.write(chunk)
                        file_size += len(chunk)

            metadata.append({
                "original_name": safe_fname,
                "internal_path": internal_path,
                "size": file_size
            })
            
        # 3. Metadata
        zf.writestr("metadata.json", json.dumps({
            "attachments": metadata,
            "allow_download": allow_download
        }).encode("utf-8"))

        # 4. RANDOM PADDING (Size Analysis Protection)
        padding_size = random.randint(1024, 256 * 1024)
        zf.writestr(".padding", random_bytes(padding_size))
        
    if output_path is None:
        return zf_target.getvalue()


def extract_package(
    blob: bytes | None = None,
    *,
    default_allow_download: bool = False,
    file_path: str | Path | None = None,
) -> Package:
    """
    Extracts the components of the decrypted package.
    Attachments are extracted directly to secure temp files.
    """
    text = ""
    attachments = []
    allow_download = default_allow_download
    
    if file_path is not None:
        zf_source = file_path
    else:
        if blob is None:
            raise ValueError("Either blob or file_path must be provided.")
        zf_source = io.BytesIO(blob)
    
    try:
        with zipfile.ZipFile(zf_source, "r") as zf:
            infos = zf.infolist()
            if len(infos) > MAX_PACKAGE_ZIP_ENTRY_COUNT:
                raise PackageLimitError("Package contains too many files to open safely.")

            zip_info_by_name = {}
            for info in infos:
                if info.filename in zip_info_by_name:
                    raise PackageLimitError("Package metadata is malformed.")
                zip_info_by_name[info.filename] = info

                if info.filename == "message.md":
                    max_size = MAX_PACKAGE_TEXT_BYTES
                    label = "Package message"
                elif info.filename == "metadata.json":
                    max_size = MAX_PACKAGE_METADATA_BYTES
                    label = "Package metadata"
                elif info.filename == ".padding":
                    max_size = MAX_PACKAGE_PADDING_BYTES
                    label = "Package padding"
                elif _is_safe_attachment_path(info.filename):
                    max_size = MAX_PACKAGE_ATTACHMENT_BYTES
                    label = "Package attachment"
                else:
                    max_size = MAX_PACKAGE_PADDING_BYTES
                    label = "Package entry"
                _validate_zip_entry_info(info, max_size, label)

            # 1. Read message
            message_info = zip_info_by_name.get("message.md")
            if message_info is not None:
                text = _read_zip_entry_limited(
                    zf,
                    message_info,
                    MAX_PACKAGE_TEXT_BYTES,
                    "Package message",
                ).decode("utf-8")

            # 2. Read Metadata and Attachments
            metadata_info = zip_info_by_name.get("metadata.json")
            if metadata_info is not None:
                metadata_raw = _read_zip_entry_limited(
                    zf,
                    metadata_info,
                    MAX_PACKAGE_METADATA_BYTES,
                    "Package metadata",
                )
                meta_obj = json.loads(metadata_raw.decode("utf-8"))
                if not isinstance(meta_obj, dict):
                    raise PackageLimitError("Package metadata is malformed.")
                allow_download = meta_obj.get("allow_download", default_allow_download)
                meta_list = meta_obj.get("attachments", [])
                if not isinstance(meta_list, list):
                    raise PackageLimitError("Package metadata is malformed.")
                if len(meta_list) > MAX_PACKAGE_ATTACHMENT_COUNT:
                    raise PackageLimitError("Package contains too many attachments to open safely.")

                referenced_paths = set()
                total_attachment_bytes = 0
                for item in meta_list:
                    if not isinstance(item, dict):
                        raise PackageLimitError("Package metadata is malformed.")
                    path = item.get("internal_path")
                    if not _is_safe_attachment_path(path) or path not in zip_info_by_name:
                        continue
                    if path in referenced_paths:
                        raise PackageLimitError("Package metadata is malformed.")
                    referenced_paths.add(path)

                    info = zip_info_by_name[path]
                    if total_attachment_bytes + info.file_size > MAX_PACKAGE_TOTAL_ATTACHMENT_BYTES:
                        raise PackageLimitError("Package attachments are too large to open safely.")
                    
                    # Create a secure temp file for this attachment
                    temp_dir = Path(os.environ.get("DATA_DIR", "data")) / "temp"
                    temp_dir.mkdir(parents=True, exist_ok=True)
                    att_token = secrets.token_hex(16)
                    dest_path = temp_dir / f"extracted_{att_token}.bin"
                    
                    try:
                        file_size = _extract_zip_entry_limited_to_file(
                            zf,
                            info,
                            MAX_PACKAGE_ATTACHMENT_BYTES,
                            dest_path,
                            "Package attachment",
                        )
                        total_attachment_bytes += file_size
                        if total_attachment_bytes > MAX_PACKAGE_TOTAL_ATTACHMENT_BYTES:
                            raise PackageLimitError("Package attachments are too large to open safely.")

                        filename = sanitize_attachment_filename(item.get("original_name"))
                        attachments.append(Attachment(
                            filename=filename,
                            content_path=str(dest_path),
                            mime_type=_guess_mime(filename)
                        ))
                    except Exception:
                        if dest_path.exists():
                            try:
                                secure_delete(dest_path)
                            except Exception:
                                pass
                        raise
    except Exception as exc:
        # Cleanup any temporary files created in this partial run
        for att in attachments:
            if hasattr(att, "content_path") and att.content_path:
                try:
                    secure_delete(att.content_path)
                except Exception:
                    pass
        if isinstance(exc, PackageLimitError):
            raise
        if isinstance(exc, (zipfile.BadZipFile, RuntimeError, OSError, EOFError, zlib.error, UnicodeDecodeError, json.JSONDecodeError)):
            raise PackageLimitError("Package is malformed and cannot be opened safely.") from exc
        raise
                    
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
    Attachment bytes are intentionally not base64-encoded here; callers should
    serve them through short-lived preview/download routes to avoid duplicating
    decrypted content as long-lived strings.
    """
    if len(package.attachments) > MAX_PACKAGE_ATTACHMENT_COUNT:
        raise PackageLimitError("Package contains too many attachments to open safely.")
    total_attachment_bytes = sum(att.size for att in package.attachments)
    if total_attachment_bytes > MAX_PACKAGE_TOTAL_ATTACHMENT_BYTES:
        raise PackageLimitError("Package attachments are too large to open safely.")

    processed_attachments = []
    for att in package.attachments:
        filename = sanitize_attachment_filename(att.filename)
        is_media = att.mime_type.startswith(("image/", "video/"))
            
        processed_attachments.append({
            "filename": filename,
            "mime_type": att.mime_type,
            "is_media": is_media,
            "data_b64": "",
            "size": att.size,
            "full_b64": ""
        })
        
    return {
        "text": package.text,
        "attachments": processed_attachments,
        "allow_download": package.allow_download
    }
