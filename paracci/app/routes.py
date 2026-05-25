import os
import io
import struct
import time
import uuid
import datetime
import secrets
import hmac
import mimetypes
from typing import Optional, Sequence
from pathlib import Path
import logging
import unicodedata
from urllib.parse import urljoin, urlparse

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, send_file, abort, jsonify, current_app,
    session, g, make_response, send_from_directory
)
import pyotp
import qrcode
import base64
from io import BytesIO
from werkzeug.exceptions import SecurityError

import app as ag_app
from core.config import ParacciConfig
from core.identity import get_or_create_device_identity
from core.envelope import (
    FILE_VERSION as ENVELOPE_FILE_VERSION,
    ARGON2_FILE_VERSION as ARGON2_ENVELOPE_FILE_VERSION,
    LEGACY_FILE_VERSION as LEGACY_ENVELOPE_FILE_VERSION,
    seal_envelope,
    open_envelope,
    EnvelopeError,
    EnvelopeTTLError,
)
from core.package import (
    PackageLimitError,
    create_package,
    extract_package,
    sanitize_attachment_filename,
)
from core.crypto import wipe
from core.sanitizer import (
    SanitizationError,
    build_no_download_image_preview,
    sanitize_image,
)
from core.security_utils import scan_text_for_security
from core.burn import (
    is_device_initialized, DeviceError,
    DeviceLockedError, BurnGuard, AlreadyBurnedError, TTLExpiredError
)
from desktop.device_key_binding import (
    DeviceBindingError,
    consume_device_binding_warning,
    initialize_device_with_binding,
    unlock_device_with_binding,
)
from desktop.updater import UpdateActionError
from core.session import (
    deserialize_session_meta, serialize_session_meta,
    create_initiator_session, accept_initiator_and_create_responder,
    finalize_initiator_session, apply_bond_nonce_to_y,
    serialize_initiator_file, serialize_responder_file,
    confirm_safety_code, get_session_safety_code, require_transcript_bound_session,
    LEGACY_WRAPPED_HANDSHAKE_FILE_VERSION,
    SESSION_COLORS, SESSION_STATE_UNVERIFIED, SessionError
)
from core.hybrid_kem import HybridKEMError
from core.evolution import (
    MAX_EVO_STEP,
    seconds_until_expiry,
    session_expires_at,
    validate_session_ttl,
)
from core.preview_store import PreviewEntry, preview_store
from .build_info import APP_VERSION
from .i18n_manager import i18n

logger = logging.getLogger(__name__)


def _flash_device_binding_warning():
    warning = consume_device_binding_warning()
    if warning is not None:
        flash(_(warning.i18n_key), "warning")
_ = i18n.translate


def _hybrid_error_message(exc: HybridKEMError) -> str:
    return _(getattr(exc, "i18n_key", "hybrid_kem_respond_failed"))

bp = Blueprint("main", __name__)

# ── Preview Cache (RAM only, for temporary viewing) ──
# Structure: { id: {"filename": str, "content": bytes, "mime": str, "expires": float, "allow_download": bool, "access_token": str} }
PREVIEW_CACHE = {}

# Native attachment staging is RAM-only and short-lived.
# Structure: { id: {"filename": str, "content": bytes, "expires": float} }
STAGED_ATTACHMENT_CACHE = {}

# Native file references are issued only by the pywebview Python bridge after an
# OS dialog or native drop event. Web content submits opaque IDs, never paths.
NATIVE_FILE_REF_CACHE = {}

# ── Security Configuration ──
MAX_ATTACHMENT_SIZE = 50 * 1024 * 1024  # 50MB
MAX_ATTACHMENT_COUNT = 10
DANGEROUS_EXTENSIONS = {
    '.exe', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.pif', '.scr', 
    '.reg', '.com', '.jar', '.vbe', '.jse', '.wsf', '.wsh', '.hta'
}

# Files that contain code or logic (require extra caution)
CODE_EXTENSIONS = {
    '.py', '.js', '.html', '.css', '.c', '.cpp', '.h', '.java', '.go', '.rs', '.sh', 
    '.json', '.yaml', '.md', '.sql', '.php', '.asp', '.aspx', '.jsp'
}

INLINE_PREVIEW_IMAGE_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".svg", ".ico"
}

SENSITIVE_CACHE_CLEAR_LIMIT = 100


class NativeAttachmentStagingError(Exception):
    """Raised when native-selected attachments cannot be staged safely."""


class NativeFileReferenceError(Exception):
    """Raised when a native file reference cannot be created or resolved."""


def _content_security_policy() -> str:
    """Return the app-wide CSP after inline script handlers have been removed."""
    return (
        "default-src 'self'; "
        "script-src 'self'; "
        "script-src-attr 'none'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data: blob:; "
        "media-src 'self' data:; "
        "connect-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )


def _preview_content_security_policy() -> str:
    """Return the CSP for the standalone preview window."""
    return (
        "default-src 'self'; "
        "script-src 'self'; "
        "script-src-attr 'none'; "
        "style-src 'self'; "
        "font-src 'self'; "
        "img-src 'self' data: blob:; "
        "media-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-src 'self' blob:; "
        "object-src 'self' blob:; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )


def _preview_embedded_content_security_policy() -> str:
    """Allow same-origin preview pages to embed PDF content only."""
    return (
        "default-src 'none'; "
        "frame-ancestors 'self'; "
        "base-uri 'none';"
    )


def _apply_security_headers(response):
    """Apply consistent security headers to all route responses."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    is_preview_route = request.endpoint in {"main.preview", "main.preview_content"}
    is_preview_html = request.endpoint == "main.preview" and response.mimetype == "text/html"
    is_preview_pdf = (
        request.endpoint in {"main.preview", "main.preview_content"}
        and response.mimetype == "application/pdf"
    )
    response.headers["X-Frame-Options"] = "SAMEORIGIN" if is_preview_pdf else "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "no-referrer"
    if is_preview_html:
        response.headers["Content-Security-Policy"] = _preview_content_security_policy()
    elif is_preview_pdf:
        response.headers["Content-Security-Policy"] = _preview_embedded_content_security_policy()
    else:
        response.headers["Content-Security-Policy"] = _content_security_policy()
    if request.endpoint == "main.loopback_bootstrap":
        response.headers["Cache-Control"] = "no-store"
    if request.path == "/static/js/loopback-auth-sw.js":
        response.headers["Cache-Control"] = "no-store"
        response.headers["Service-Worker-Allowed"] = "/"
    if is_preview_route:
        response.headers.pop("Set-Cookie", None)
    return response


def _mark_sensitive_no_store(response):
    """Prevent browser/proxy reuse of decrypted preview and attachment content."""
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response


@bp.after_app_request
def add_security_headers(response):
    """Add global security headers."""
    return _apply_security_headers(response)

def _drop_cached_entry(entry, byte_keys):
    """Drop Paracci-owned references to cached plaintext bytes.

    Python cannot guarantee zeroization of immutable bytes; this only shortens
    the lifetime of references controlled by this process.
    """
    if not isinstance(entry, dict):
        return
    for key in byte_keys:
        value = entry.get(key)
        if isinstance(value, (bytearray, list)):
            wipe(value)
        entry[key] = b""
    entry.clear()


def _normalize_cache_ids(raw_ids):
    """Return bounded string cache IDs, or None to mean all cache entries."""
    if raw_ids is None:
        return None
    if not isinstance(raw_ids, (list, tuple, set)):
        return []
    normalized = []
    for value in raw_ids:
        if not isinstance(value, str):
            continue
        value = value.strip()
        if value and len(value) <= 128:
            normalized.append(value)
        if len(normalized) >= SENSITIVE_CACHE_CLEAR_LIMIT:
            break
    return normalized


def _clear_preview_cache(ids=None):
    """Clear selected preview entries, or all entries when ids is None."""
    normalized_ids = _normalize_cache_ids(ids)
    targets = list(PREVIEW_CACHE.keys()) if normalized_ids is None else normalized_ids
    cleared = 0
    for cache_id in targets:
        entry = PREVIEW_CACHE.pop(cache_id, None)
        if entry is None:
            continue
        _drop_cached_entry(entry, ("content", "preview_content"))
        cleared += 1
    return cleared


def _cleanup_preview_cache():
    """Cleans expired preview files from memory."""
    now = time.time()
    expired = [k for k, v in PREVIEW_CACHE.items() if v["expires"] < now]
    return _clear_preview_cache(expired)

def _add_to_preview_cache(filename, content, mime, allow_download, ttl=600):
    """Adds a file temporarily to the preview cache."""
    _cleanup_preview_cache()
    pid = str(uuid.uuid4())
    PREVIEW_CACHE[pid] = {
        "filename": sanitize_attachment_filename(filename),
        "content": content,
        "mime": mime,
        "expires": time.time() + ttl,
        "allow_download": allow_download,
        "access_token": secrets.token_urlsafe(32),
    }
    return pid


def _can_send_original_attachment(file_data):
    """Return whether this preview entry may expose original attachment bytes."""
    return bool(file_data and file_data.get("allow_download") is True)


def _is_inline_preview_image(filename: str | None, mime_type: str | None) -> bool:
    """Return whether an attachment may be rendered as an inline image preview."""
    mime = str(mime_type or "").lower()
    suffix = Path(str(filename or "")).suffix.lower()
    return mime.startswith("image/") or suffix in INLINE_PREVIEW_IMAGE_EXTENSIONS


def _preview_url(endpoint: str, pid: str, file_data=None, **values) -> str:
    """Build a preview URL with the per-entry token needed by child windows."""
    entry = file_data if file_data is not None else PREVIEW_CACHE.get(pid)
    access_token = entry.get("access_token") if entry else None
    if access_token:
        values["preview_token"] = access_token
    return url_for(endpoint, pid=pid, **values)


def _valid_preview_access_request() -> bool:
    """Authorize token-bearing child-window requests for one cached preview item."""
    if request.method not in {"GET", "HEAD"}:
        return False
    if request.endpoint not in {"main.preview", "main.preview_download"}:
        return False
    pid = (request.view_args or {}).get("pid")
    if not pid:
        return False
    file_data = PREVIEW_CACHE.get(pid)
    expected = file_data.get("access_token") if file_data else None
    supplied = request.args.get("preview_token") or request.headers.get("X-Paracci-Preview-Token")
    return _token_matches(supplied, expected)


def _clear_staged_attachment_cache(ids=None):
    """Clear selected staged attachments, or all entries when ids is None."""
    normalized_ids = _normalize_cache_ids(ids)
    targets = list(STAGED_ATTACHMENT_CACHE.keys()) if normalized_ids is None else normalized_ids
    cleared = 0
    for cache_id in targets:
        entry = STAGED_ATTACHMENT_CACHE.pop(cache_id, None)
        if entry is None:
            continue
        _drop_cached_entry(entry, ("content",))
        cleared += 1
    return cleared


def _cleanup_staged_attachment_cache():
    """Cleans expired native staged attachments from memory."""
    now = time.time()
    expired = [k for k, v in STAGED_ATTACHMENT_CACHE.items() if v["expires"] < now]
    return _clear_staged_attachment_cache(expired)


def _add_to_staged_attachment_cache(filename, content, ttl=600):
    """Adds a native attachment temporarily until the next seal request consumes it."""
    _cleanup_staged_attachment_cache()
    attachment_id = str(uuid.uuid4())
    STAGED_ATTACHMENT_CACHE[attachment_id] = {
        "filename": sanitize_attachment_filename(filename),
        "content": content,
        "expires": time.time() + ttl,
    }
    return attachment_id


def _cleanup_native_file_ref_cache():
    """Drop expired native file references."""
    now = time.time()
    expired = [k for k, v in NATIVE_FILE_REF_CACHE.items() if v["expires"] < now]
    for ref_id in expired:
        NATIVE_FILE_REF_CACHE.pop(ref_id, None)


def register_native_file_path(path: str | Path, ttl=600) -> dict:
    """Register a native OS-selected path and return an opaque web-safe ID."""
    _cleanup_native_file_ref_cache()
    path_str = str(path or "").strip()
    if not path_str:
        raise NativeFileReferenceError("Missing native file path.")
    ref_id = str(uuid.uuid4())
    filename = sanitize_attachment_filename(Path(path_str).name)
    NATIVE_FILE_REF_CACHE[ref_id] = {
        "path": path_str,
        "filename": filename,
        "expires": time.time() + ttl,
    }
    return {"id": ref_id, "filename": filename}


def _resolve_native_file_ref(ref_id: str | None) -> dict | None:
    """Resolve an opaque native file ID to its Python-side path metadata."""
    _cleanup_native_file_ref_cache()
    if not ref_id:
        return None
    ref_id = str(ref_id).strip()
    if not ref_id:
        return None
    entry = NATIVE_FILE_REF_CACHE.get(ref_id)
    if not entry or entry["expires"] < time.time():
        NATIVE_FILE_REF_CACHE.pop(ref_id, None)
        return None
    return entry


def _import_from_native_ref(ref_id: str | None) -> tuple[bytes | None, dict | None]:
    """Read a file selected by native OS UI using its opaque reference ID."""
    entry = _resolve_native_file_ref(ref_id)
    if not entry:
        return None, None
    return _import_from_native(entry["path"]), entry


def stage_native_attachment_paths(paths: Sequence[str | Path]) -> list[dict]:
    """Stage OS-selected attachment paths without exposing paths to web content."""
    if isinstance(paths, (str, Path)):
        paths = [paths]
    selected = [str(path or "").strip() for path in (paths or [])]
    selected = [path for path in selected if path]
    if not selected:
        return []
    if len(selected) > MAX_ATTACHMENT_COUNT:
        raise NativeAttachmentStagingError(f"Maximum {MAX_ATTACHMENT_COUNT} files can be attached.")

    staged_ids = []
    staged_items = []
    total_size = 0
    try:
        for native_path in selected:
            content = _import_from_native(native_path)
            if content is None:
                raise NativeAttachmentStagingError("Could not read attachment.")
            total_size += len(content)
            if total_size > MAX_ATTACHMENT_SIZE:
                raise NativeAttachmentStagingError(
                    f"Total file size exceeds the {MAX_ATTACHMENT_SIZE // (1024*1024)}MB limit."
                )
            safe_fname = sanitize_attachment_filename(Path(native_path).name)
            try:
                content = sanitize_image(content, safe_fname)
            except SanitizationError as exc:
                raise NativeAttachmentStagingError(SanitizationError.user_message) from exc
            attachment_id = _add_to_staged_attachment_cache(safe_fname, content)
            staged_ids.append(attachment_id)
            staged_items.append({
                "id": attachment_id,
                "filename": safe_fname,
                "size": len(content),
            })
        return staged_items
    except Exception:
        _clear_staged_attachment_cache(staged_ids)
        raise


UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


def _expected_host() -> str:
    """Return the only Host header accepted by the loopback app."""
    return f"{ag_app.loopback_host}:{ag_app.loopback_port}"


def _expected_origin() -> str:
    """Return the only browser origin accepted by the loopback app."""
    return ag_app.loopback_origin


def _is_static_request() -> bool:
    """Static assets are intentionally public within the local origin."""
    static_path = current_app.static_url_path or "/static"
    return (
        request.endpoint == "static"
        or request.endpoint == "main.favicon"
        or request.path == "/favicon.ico"
        or request.path.startswith(f"{static_path}/")
    )


def _is_public_request() -> bool:
    """Return whether a route is usable before possession of the loopback bearer."""
    if _is_static_request():
        return True
    return request.method in {"GET", "HEAD"} and request.endpoint in {
        "main.unlock",
        "main.api_capabilities",
    }


def _same_origin_url(value: str | None) -> bool:
    """Validate that an absolute or relative URL resolves to the expected origin."""
    if not value:
        return False
    try:
        parsed = urlparse(urljoin(f"{_expected_origin()}/", value))
        return (
            parsed.scheme == "http"
            and parsed.hostname in {ag_app.loopback_host.lower(), "localhost"}
            and parsed.port == int(ag_app.loopback_port)
        )
    except Exception:
        return False


def _safe_local_next(value: str | None) -> str | None:
    """Allow only local redirect paths such as /settings?tab=x."""
    if not value or not value.startswith("/") or value.startswith("//"):
        return None
    parsed = urlparse(value)
    if parsed.scheme or parsed.netloc:
        return None
    return value


_FILE_ACTIVATION_NEXT_KEY = "file_activation_next"
_FILE_ACTIVATION_ERROR_ARG = "file_activation_error"


def _file_activation_continuation() -> str | None:
    """Return a narrowly scoped activation path that may survive device unlock."""
    if request.method != "GET":
        return None
    if request.endpoint == "main.index" and request.args.get(_FILE_ACTIVATION_ERROR_ARG) == "1":
        return url_for("main.index", file_activation_error="1")
    if request.endpoint != "main.session_detail":
        return None

    sid = str((request.view_args or {}).get("sid", "")).strip()
    native_file_id = request.args.get("native_file_id", "").strip()
    try:
        valid_sid = len(bytes.fromhex(sid)) == 16
    except ValueError:
        valid_sid = False
    if not valid_sid or not native_file_id or _resolve_native_file_ref(native_file_id) is None:
        return None
    return url_for("main.session_detail", sid=sid, native_file_id=native_file_id)


def _remember_file_activation_continuation() -> None:
    target = _file_activation_continuation()
    if target is not None:
        session[_FILE_ACTIVATION_NEXT_KEY] = target


def _post_unlock_target() -> str:
    target = _safe_local_next(session.pop(_FILE_ACTIVATION_NEXT_KEY, None))
    return target or url_for("main.index")


def _reject_security(reason: str):
    """Fail closed for loopback auth violations."""
    logger.warning("Loopback request rejected: %s", reason)
    try:
        logger.warning("  [DEBUG] Request URL: %s", request.url)
        logger.warning("  [DEBUG] Request Method: %s", request.method)
        logger.warning("  [DEBUG] Request Headers: %s", {k: v for k, v in request.headers.items() if k.lower() not in {"cookie", "authorization"}})
        logger.warning("  [DEBUG] Request Cookies: %s", list(request.cookies.keys()))
        logger.warning("  [DEBUG] Session Contents: %s", {k: v for k, v in session.items()})
        logger.warning("  [DEBUG] Session Permanent: %s", getattr(session, "permanent", None))
    except Exception as e:
        logger.warning("  [DEBUG] Failed to dump debug info: %s", e)

    wants_json = request.path.startswith("/api/") or request.headers.get("X-Requested-With") == "XMLHttpRequest"
    if wants_json:
        if request.path == "/api/prepare-preview" and reason in {
            "client not bootstrapped",
            "missing api bearer token",
            "missing unsafe-method bearer token",
            "missing protected bearer token",
        }:
            return jsonify({"success": False, "error": "Unauthorized."}), 401
        return jsonify({"success": False, "error": "Forbidden."}), 403
    abort(403)


def _extract_loopback_token() -> str:
    """Read bearer token from JS headers first, then form fallback."""
    token = request.headers.get("X-Paracci-Token", "")
    if token:
        return token
    return request.form.get("_paracci_token", "")


def _ensure_csrf_token() -> str:
    """Create a per-client CSRF token after loopback bootstrap."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def _extract_csrf_token() -> str:
    """Read CSRF token from JS headers first, then form fallback."""
    token = request.headers.get("X-CSRF-Token", "")
    if token:
        return token
    return request.form.get("_csrf_token", "")


def _token_matches(candidate: str | None, expected: str | None) -> bool:
    """Constant-time token comparison with missing-value protection."""
    if not candidate or not expected:
        return False
    return hmac.compare_digest(str(candidate), str(expected))


def _looks_like_preview_token(value: str | None) -> bool:
    """Return True only for PreviewStore token strings."""
    if not isinstance(value, str) or len(value) != 64:
        return False
    return all(ch in "0123456789abcdef" for ch in value)


def _preview_store_request_token() -> str | None:
    """Return a route preview token when this is a token-scoped preview request."""
    if request.method not in {"GET", "HEAD"}:
        return None
    view_args = request.view_args or {}
    if request.endpoint == "main.preview":
        token = view_args.get("pid")
    elif request.endpoint == "main.preview_content":
        token = view_args.get("preview_token")
    else:
        return None
    return token if _looks_like_preview_token(token) else None


def _validate_request_source():
    """Validate host and browser source headers before any privileged route runs."""
    # 1. Validate Host
    host_parts = request.host.lower().split(":")
    host_name = host_parts[0]
    host_port = host_parts[1] if len(host_parts) > 1 else ""
    if host_name not in {ag_app.loopback_host.lower(), "localhost"} or host_port != str(ag_app.loopback_port):
        return _reject_security("unexpected host")

    # 2. Validate Origin
    origin = request.headers.get("Origin")
    if origin and origin != "null":
        try:
            parsed = urlparse(origin)
            is_valid = (
                parsed.scheme == "http"
                and parsed.hostname in {ag_app.loopback_host.lower(), "localhost"}
                and parsed.port == int(ag_app.loopback_port)
            )
            if not is_valid:
                return _reject_security("unexpected origin")
        except Exception:
            return _reject_security("invalid origin format")

    # 3. Validate Referer
    referer = request.headers.get("Referer")
    if referer and not _same_origin_url(referer):
        return _reject_security("unexpected referer")

    # 4. Validate Fetch Site
    fetch_site = request.headers.get("Sec-Fetch-Site", "").lower()
    if fetch_site in {"cross-site", "same-site"}:
        return _reject_security("unexpected fetch site")

    # 5. OPTIONS Preflight Protection
    if request.method == "OPTIONS":
        return _reject_security("options rejected")

    return None


@bp.route("/__paracci_bootstrap")
def loopback_bootstrap():
    """Authorize the pywebview/no-GUI browser session with the launch token."""
    source_error = _validate_request_source()
    if source_error:
        return source_error

    if not _token_matches(request.args.get("token", ""), ag_app.loopback_token):
        return _reject_security("invalid bootstrap token")

    g.loopback_token_verified = True
    # Idempotency guard: if the session is already established for the
    # currently active client, reuse it rather than creating a new one.
    # This prevents spurious re-navigation to the bootstrap URL — caused by
    # pywebview 6.x firing the main window's lifecycle events when a preview
    # window is torn down — from blowing away the authenticated session and
    # producing a new paracci_client_id that no longer matches active_client_id.
    session.permanent = True
    already_valid = (
        session.get("paracci_client_ok") is True
        and ag_app.active_client_id is not None
        and session.get("paracci_client_id") == ag_app.active_client_id
    )
    if not already_valid:
        session["paracci_client_ok"] = True
        if ag_app.active_client_id is not None:
            session["paracci_client_id"] = ag_app.active_client_id
        else:
            session["paracci_client_id"] = secrets.token_urlsafe(16)
        if not session.get("csrf_token"):
            session["csrf_token"] = secrets.token_urlsafe(32)
    target = _safe_local_next(request.args.get("next")) or url_for("main.index")
    response = make_response(
        render_template(
            "bootstrap.html",
            bootstrap_token=ag_app.loopback_token,
            bootstrap_target=target,
        )
    )
    return _mark_sensitive_no_store(response)


@bp.before_app_request
def enforce_loopback_security():
    """Require bootstrap, same-origin source headers, bearer token, and CSRF."""
    if request.endpoint == "main.loopback_bootstrap":
        return _validate_request_source()

    source_error = _validate_request_source()
    if source_error:
        return source_error

    token_verified = _token_matches(_extract_loopback_token(), ag_app.loopback_token)
    if _is_public_request():
        if token_verified:
            g.loopback_token_verified = True
        return

    if not token_verified:
        return _reject_security("missing protected bearer token")
    g.loopback_token_verified = True

    if _preview_store_request_token():
        g.preview_access_ok = True
        return

    preview_access_ok = _valid_preview_access_request()
    if preview_access_ok:
        g.preview_access_ok = True

    if session.get("paracci_client_ok") is not True and not preview_access_ok:
        return _reject_security("client not bootstrapped")

    if request.method in UNSAFE_METHODS:
        if not _token_matches(_extract_csrf_token(), session.get("csrf_token")):
            return _reject_security("missing csrf token")


# ---------------------------------------------------------------------------
# Device Lock & PIN Management
# ---------------------------------------------------------------------------

@bp.before_app_request
def check_lock():
    """Checks if the application is locked; redirects to the unlock page if locked."""

    # Routes exempt from locking
    if request.endpoint in [
        "main.loopback_bootstrap",
        "main.unlock",
        "main.set_locale",
        "static",
        "main.unlock_2fa_setup",
        "main.unlock_2fa_verify",
        "main.favicon",
        "main.api_capabilities",
        "main.api_update_status",
        "main.api_update_check",
        "main.api_update_history",
        "main.api_update_dismiss",
        "main.api_update_download",
        "main.api_update_cancel",
    ]:
        return
    if _preview_store_request_token():
        return

    # 1. Device not initialized yet?
    if not is_device_initialized(ag_app.db):
        _remember_file_activation_continuation()
        _clear_preview_cache()
        _clear_staged_attachment_cache()
        return redirect(url_for("main.unlock"))

    # 2. Device key not in memory? (Locked)
    if ag_app.device_key is None:
        _remember_file_activation_continuation()
        _clear_preview_cache()
        _clear_staged_attachment_cache()
        return redirect(url_for("main.unlock"))

    client_id = session.get("paracci_client_id")
    if ag_app.active_client_id and ag_app.active_client_id != client_id and not getattr(g, "preview_access_ok", False):
        return _reject_security("unlocked client mismatch")


@bp.app_context_processor
def inject_user():
    """Injects the user profile and shell session shortcuts into all templates."""
    unverified_unlock_page = (
        request.endpoint == "main.unlock"
        and request.method in {"GET", "HEAD"}
        and not getattr(g, "loopback_token_verified", False)
    )
    if unverified_unlock_page:
        return dict(
            user_profile={"username": "", "avatar_color": ""},
            sidebar_sessions=[],
            SESSION_COLORS=SESSION_COLORS,
            csrf_token="",
            paracci_browser_token="",
        )

    cfg = ParacciConfig()
    sidebar_sessions = []
    preview_only = request.endpoint in {"main.preview", "main.preview_content"}
    try:
        if not preview_only and ag_app.device_key is not None and is_device_initialized(ag_app.db):
            db, _device_key = _get_db_and_key()
            for row in db.list_sessions():
                if row.get("state") not in {"active", "pending"}:
                    continue
                sid_hex = row["session_id"].hex()
                meta = _load_session(sid_hex)
                if meta is None:
                    continue
                sidebar_sessions.append({
                    "session_id_hex": sid_hex,
                    "label": meta.label,
                    "state": meta.state,
                    "role": meta.role,
                    "color": meta.color,
                })
                if len(sidebar_sessions) >= 6:
                    break
    except DeviceError:
        raise
    except Exception:
        sidebar_sessions = []

    browser_token = ""
    if (
        not preview_only
        and getattr(g, "loopback_token_verified", False)
        and ag_app.no_gui_mode
        and session.get("paracci_client_ok") is True
    ):
        browser_token = ag_app.loopback_token or ""

    return dict(
        user_profile={
            "username": cfg.get("username"),
            "avatar_color": cfg.get("avatar_color")
        },
        sidebar_sessions=sidebar_sessions,
        SESSION_COLORS=SESSION_COLORS,
        csrf_token="" if preview_only else _ensure_csrf_token(),
        paracci_browser_token=browser_token,
    )


def _activate_keyed_db(keyed_db) -> None:
    previous = ag_app.db
    ag_app.db = keyed_db
    if previous is not keyed_db:
        previous.release_device_key()


def _discard_pending_unlock(pending: dict | None) -> None:
    if not pending:
        return
    keyed_db = pending.get("db")
    if keyed_db is not None:
        keyed_db.release_device_key()
    pending_key = pending.get("device_key")
    if isinstance(pending_key, bytearray):
        wipe(pending_key)


@bp.route("/unlock", methods=["GET", "POST"])
def unlock():
    """Route used to initialize the device or unlock it with a passphrase."""
    initialized = is_device_initialized(ag_app.db)
    mode = "init" if not initialized else "unlock"
    lockout_seconds = ag_app.db.get_unlock_rate_limit().get("retry_after_seconds", 0) if initialized else 0
    if request.method == "GET" and (not initialized or ag_app.device_key is None):
        _clear_preview_cache()
        _clear_staged_attachment_cache()

    if request.method == "POST":
        pin = request.form.get("pin")
        if not pin:
            flash(_('auth.pin_required'), "error")
            return render_template("unlock.html", mode=mode, is_initialized=initialized, lockout_seconds=lockout_seconds)

        try:
            if mode == "init":
                # Redirect to 2FA setup after the passphrase is set during initial setup
                device_key = initialize_device_with_binding(ag_app.db, pin)
                try:
                    keyed_db = ag_app.db.with_device_key(device_key)
                except Exception:
                    wipe(device_key)
                    raise
                _activate_keyed_db(keyed_db)
                ag_app.device_key = device_key # Set globally since it's initial setup
                ag_app.active_client_id = session.get("paracci_client_id")
                session['setup_in_progress'] = True # Temporary flag
                _flash_device_binding_warning()
                return redirect(url_for("main.unlock_2fa_setup"))
            else:
                # Normal unlock: check 2FA if the passphrase is correct
                device_key = unlock_device_with_binding(ag_app.db, pin)
                _flash_device_binding_warning()
                try:
                    keyed_db = ag_app.db.with_device_key(device_key)
                    two_factor_enabled = keyed_db.is_2fa_enabled()
                except Exception:
                    if "keyed_db" in locals():
                        keyed_db.release_device_key()
                    wipe(device_key)
                    raise

                if two_factor_enabled:
                    # Keep only the pending keyed view until the second factor succeeds.
                    ag_app.db.release_device_key()
                    # Cleanup old pending unlocks (older than 10 mins)
                    now = time.time()
                    expired_ids = [k for k, v in ag_app.PENDING_UNLOCKS.items() if now - v["timestamp"] > 600]
                    for k in expired_ids:
                        _discard_pending_unlock(ag_app.PENDING_UNLOCKS.pop(k))
                    
                    # If 2FA is active, temporarily store device_key in memory
                    unlock_id = str(uuid.uuid4())
                    ag_app.PENDING_UNLOCKS[unlock_id] = {
                        "device_key": device_key,
                        "db": keyed_db,
                        "timestamp": time.time(),
                        "client_id": session.get("paracci_client_id")
                    }
                    session['unlock_id'] = unlock_id
                    return redirect(url_for("main.unlock_2fa_verify"))
                
                # If 2FA is not active, unlock directly
                _activate_keyed_db(keyed_db)
                ag_app.device_key = device_key
                ag_app.active_client_id = session.get("paracci_client_id")
                flash(_('auth.unlock_success'), "success")
                return redirect(_post_unlock_target())
                
        except DeviceLockedError as e:
            flash(str(e), "error")
            return render_template("unlock.html", mode=mode, is_initialized=initialized, lockout_seconds=e.retry_after_seconds)
        except DeviceBindingError as e:
            flash(_(e.i18n_key), "error")
            lockout_seconds = ag_app.db.get_unlock_rate_limit().get("retry_after_seconds", 0) if initialized else 0
            return render_template("unlock.html", mode=mode, is_initialized=initialized, lockout_seconds=lockout_seconds)
        except DeviceError as e:
            flash(str(e), "error")
            lockout_seconds = ag_app.db.get_unlock_rate_limit().get("retry_after_seconds", 0) if initialized else 0
            return render_template("unlock.html", mode=mode, is_initialized=initialized, lockout_seconds=lockout_seconds)

    return render_template("unlock.html", mode=mode, is_initialized=initialized, lockout_seconds=lockout_seconds)

@bp.route("/unlock/2fa/setup", methods=["GET", "POST"])
def unlock_2fa_setup():
    """Optional 2FA setup after PIN installation."""
    if not is_device_initialized(ag_app.db) or not ag_app.device_key:
        return redirect(url_for("main.unlock"))

    secret = session.get('2fa_setup_secret')
    if not secret:
        secret = pyotp.random_base32()
        session['2fa_setup_secret'] = secret

    if request.method == "POST":
        action = request.form.get("action")
        if action == "skip":
            session.pop('setup_in_progress', None)
            session.pop('2fa_setup_secret', None)
            flash(_('auth.init_success'), "success")
            return redirect(_post_unlock_target())
        
        # 2FA Activation
        code = request.form.get("code")
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            if ag_app.device_key:
                ag_app.db.set_2fa_secret(secret, ag_app.device_key)
                ag_app.db.set_2fa_enabled(True)
                session.pop('unlock_id', None)
                session.pop('2fa_setup_secret', None)
                flash(_('auth.2fa_enabled_success'), "success")
                return redirect(_post_unlock_target())
            else:
                flash("Critical Error: Device key lost during 2FA setup.", "error")
                return redirect(url_for("main.unlock"))
        else:
            flash(_('auth.invalid_2fa_code'), "error")

    # Create QR Code
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=ParacciConfig().get("username"), 
        issuer_name="Paracci"
    )
    img = qrcode.make(totp_uri)
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template("2fa_setup.html", secret=secret, qr_code=qr_base64)

@bp.route("/unlock/2fa/verify", methods=["GET", "POST"])
def unlock_2fa_verify():
    """Unlocking with 2FA verification."""
    unlock_id = session.get('unlock_id')
    pending = ag_app.PENDING_UNLOCKS.get(unlock_id) if unlock_id else None
    if not pending:
        return redirect(url_for("main.unlock"))
    try:
        if not pending["db"].is_2fa_enabled():
            _discard_pending_unlock(ag_app.PENDING_UNLOCKS.pop(unlock_id, None))
            session.pop('unlock_id', None)
            return redirect(url_for("main.unlock"))
    except DeviceError:
        _discard_pending_unlock(ag_app.PENDING_UNLOCKS.pop(unlock_id, None))
        session.pop('unlock_id', None)
        flash("Security Error: Could not decrypt device metadata.", "error")
        return redirect(url_for("main.unlock"))

    if request.method == "POST":
        code = request.form.get("code")
        
        if not unlock_id or unlock_id not in ag_app.PENDING_UNLOCKS:
            flash("Session expired or invalid.", "error")
            return redirect(url_for("main.unlock"))

        pending = ag_app.PENDING_UNLOCKS.pop(unlock_id)
        if pending.get("client_id") != session.get("paracci_client_id"):
            _discard_pending_unlock(pending)
            return _reject_security("pending unlock client mismatch")
        device_key = pending["device_key"]
        keyed_db = pending["db"]
        
        try:
            secret = keyed_db.get_2fa_secret(device_key)
        except DeviceError:
            _discard_pending_unlock(pending)
            session.pop('unlock_id', None)
            flash("Security Error: Could not decrypt 2FA secret.", "error")
            return redirect(url_for("main.unlock"))
        if not secret:
            _discard_pending_unlock(pending)
            session.pop('unlock_id', None)
            flash("2FA Secret not found.", "error")
            return redirect(url_for("main.unlock"))

        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            # 2FA correct
            _activate_keyed_db(keyed_db)
            ag_app.device_key = device_key
            ag_app.active_client_id = session.get("paracci_client_id")
            session.pop('unlock_id', None)
            flash(_('auth.unlock_success'), "success")
            return redirect(_post_unlock_target())
        else:
            # Re-insert into pending to allow retry? 
            # Better to force restart unlock for security?
            # Let's allow 3 retries? For now, force restart is safer.
            _discard_pending_unlock(pending)
            session.pop('unlock_id', None)
            flash(_('auth.invalid_2fa_code'), "error")
            return redirect(url_for("main.unlock"))

    return render_template("2fa_verify.html")

@bp.route("/settings/2fa", methods=["GET", "POST"])
def settings_2fa():
    """2FA management under settings."""
    if ag_app.device_key is None:
        return redirect(url_for("main.unlock"))

    is_enabled = ag_app.db.is_2fa_enabled()
    
    if request.method == "POST":
        action = request.form.get("action")
        if action == "disable":
            ag_app.db.set_2fa_enabled(False)
            ag_app.db.delete_2fa_secret()
            flash(_('auth.2fa_disabled_success'), "success")
            return redirect(url_for("main.settings"))
        
        # Create temp secret for Enable process
        if action == "start_setup":
            secret = pyotp.random_base32()
            session['2fa_setup_secret'] = secret
            return redirect(url_for("main.settings_2fa"))

        if action == "confirm_setup":
            secret = session.get('2fa_setup_secret')
            code = request.form.get("code")
            if secret and pyotp.TOTP(secret).verify(code):
                ag_app.db.set_2fa_secret(secret, ag_app.device_key)
                ag_app.db.set_2fa_enabled(True)
                session.pop('2fa_setup_secret', None)
                flash(_('auth.2fa_enabled_success'), "success")
                return redirect(url_for("main.settings"))
            else:
                flash(_('auth.invalid_2fa_code'), "error")

    secret = session.get('2fa_setup_secret')
    qr_base64 = None
    if secret:
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=ParacciConfig().get("username"), 
            issuer_name="Paracci"
        )
        img = qrcode.make(totp_uri)
        buffered = BytesIO()
        img.save(buffered, format="PNG")
        qr_base64 = base64.b64encode(buffered.getvalue()).decode()

    return render_template("settings_2fa.html", is_enabled=is_enabled, secret=secret, qr_code=qr_base64)


@bp.route("/set_locale/<lang>", methods=["POST"])
def set_locale(lang):
    """Changes application language (tr/en)."""
    if lang in ['tr', 'en', 'de', 'fr', 'ru', 'es']:
        session['locale'] = lang
        session.modified = True
    
    target = _safe_local_next(request.form.get("next"))
    if not target and _same_origin_url(request.referrer):
        parsed = urlparse(request.referrer)
        target = parsed.path or url_for('main.index')
        if parsed.query:
            target = f"{target}?{parsed.query}"
    return redirect(target or url_for('main.index'))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_db_and_key():
    """Returns the active database connection and device key."""
    if ag_app.device_key is None:
        raise RuntimeError(_('auth.device_locked'))
    return ag_app.db, ag_app.device_key


def _get_device_identity():
    """Returns the encrypted persistent identity keypair for this device."""
    db, device_key = _get_db_and_key()
    return get_or_create_device_identity(db, device_key)


def _load_session(session_id_hex: str):
    """Loads session data from ID in hex format."""
    db, device_key = _get_db_and_key()
    try:
        session_id = bytes.fromhex(session_id_hex)
    except ValueError:
        return None
    row = db.load_session(session_id)
    if row is None:
        return None
    _label, _state, encrypted_meta, _created_at = row
    try:
        return deserialize_session_meta(encrypted_meta, device_key)
    except Exception:
        return None


def _save_session(meta, state_override: str | None = None):
    """Encrypts and saves session data to the database."""
    db, device_key = _get_db_and_key()
    encrypted = serialize_session_meta(meta, device_key)
    state = state_override or meta.state
    db.save_session(
        session_id=meta.session_id,
        label=meta.label,
        state=state,
        encrypted_meta=encrypted,
        created_at=meta.created_at,
    )


def _fmt_time_left(expire_at: int) -> str:
    """Converts remaining time to a readable format (e.g., 5m 10s)."""
    if expire_at == 0:
        return _('time.infinite')
    remaining = expire_at - int(time.time())
    if remaining <= 0:
        return _('time.expired')
    h, r = divmod(remaining, 3600)
    m, s = divmod(r, 60)
    
    if h > 0:
        t_str = f"{h}{_('time.hours_short')} {m}{_('time.mins_short')}"
    elif m > 0:
        t_str = f"{m}{_('time.mins_short')} {s}{_('time.secs_short')}"
    else:
        t_str = f"{s}{_('time.secs_short')}"
        
    return _('time.remaining', time=t_str)


def _parse_file_header_raw(file_bytes: bytes) -> dict | None:
    """
    Paranoid Header Validation: Ensures the file structure matches 
    our protocol 100% before opening the envelope.
    """
    # 1. Minimum Length Check (Header + at least 1 byte payload)
    if len(file_bytes) < 23:
        return None
    
    # 2. Magic Bytes (PARC)
    if file_bytes[:4] != b"PARC":
        return None
    
    # 3. Protocol Version
    version = file_bytes[4]

    # 4. File Type (0x10: Init, 0x11: Resp, 0x20: Msg)
    file_type = file_bytes[5]
    if file_type not in [0x10, 0x11, 0x20]:
        return None
    if file_type == 0x20:
        if version not in (
            LEGACY_ENVELOPE_FILE_VERSION,
            ARGON2_ENVELOPE_FILE_VERSION,
            ENVELOPE_FILE_VERSION,
        ):
            return None
    elif version < LEGACY_WRAPPED_HANDSHAKE_FILE_VERSION:
        return None
        
    try:
        # Session ID (16 bytes)
        session_id = file_bytes[6:22]
        
        # 5. Type-Based Depth Check
        if file_type == 0x20: # Message File
            if len(file_bytes) < 52: # Message header must be at least 52 bytes
                return None
            
            msg_id     = file_bytes[22:38]
            direction  = file_bytes[38]
            flags      = file_bytes[39]
            evo_step   = struct.unpack(">I", file_bytes[40:44])[0]
            expire_at  = struct.unpack(">Q", file_bytes[44:52])[0]
            
            # Illogical value checks (Anti-Tamper)
            if direction not in [0x01, 0x02]: return None
            if evo_step > MAX_EVO_STEP: return None # CPU DoS protection
            
            return {
                "file_type":  file_type,
                "session_id": session_id,
                "msg_id":     msg_id,
                "direction":  direction,
                "flags":      flags,
                "evo_step":   evo_step,
                "expire_at":  expire_at,
                "single_use": bool(flags & 0x01),
            }
        
        # Handshake files (Init/Resp)
        return {
            "file_type": file_type,
            "session_id": session_id
        }
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Template Filters
# ---------------------------------------------------------------------------

@bp.app_template_filter("time_left")
def time_left_filter(expire_at):
    """Jinja2 filter: Formats remaining time."""
    return _fmt_time_left(expire_at)


@bp.app_template_filter("expires_at")
def expires_at_filter(evo_config):
    """Jinja2 filter: Returns expiry time from EvoConfig."""
    return session_expires_at(evo_config)


@bp.app_template_filter("ts_fmt")
def ts_fmt_filter(ts):
    """Jinja2 filter: Converts timestamp to date format."""
    if not ts:
        return "—"
    return datetime.datetime.fromtimestamp(ts).strftime("%d.%m.%Y %H:%M")


@bp.app_template_filter("hex")
def hex_filter(b):
    """Jinja2 filter: Converts byte data to hex string."""
    if isinstance(b, (bytes, bytearray)):
        return b.hex()
    return str(b)


# ---------------------------------------------------------------------------
# Security Checks
# ---------------------------------------------------------------------------



# ---------------------------------------------------------------------------
# GET / — Main Screen
# ---------------------------------------------------------------------------

@bp.after_request
def add_security_headers(response):
    """Adds strict security headers to every response."""
    return _apply_security_headers(response)


@bp.route("/")
def index():
    """Home page: Lists all saved sessions."""
    if request.args.get(_FILE_ACTIVATION_ERROR_ARG) == "1":
        flash(_('session.file_activation_no_match'), "error")
        return redirect(url_for("main.index"))

    db, _device_key = _get_db_and_key()
    sessions = db.list_sessions()
    detailed_sessions = []
    for s in sessions:
        sid_hex = s["session_id"].hex()
        meta = _load_session(sid_hex)
        if meta:
            detailed_sessions.append({
                "session_id_hex": sid_hex,
                "label": meta.label,
                "state": meta.state,
                "color": meta.color,
                "updated_at": s["updated_at"]
            })
    return render_template("index.html", sessions=detailed_sessions)


# ---------------------------------------------------------------------------
# GET/POST /session/new — New session (X role)
# ---------------------------------------------------------------------------

@bp.route("/session/new", methods=["GET", "POST"])
def session_new():
    """Starts a new session (Initiator / X role)."""
    if request.method == "GET":
        return render_template("setup.html", mode="new", is_import=False)

    label            = request.form.get("label", "").strip()
    session_ttl_str  = request.form.get("session_ttl", "0")
    color            = request.form.get("color")
    custom_color     = request.form.get("custom_color", "").strip()
    if custom_color:
        if not custom_color.startswith("#"):
            custom_color = "#" + custom_color
        if len(custom_color) in [4, 7]:
            color = custom_color

    if not label:
        flash(_('session.label_required'), "error")
        return render_template("setup.html", mode="new", is_import=False)

    try:
        session_ttl_sec = int(session_ttl_str)
        session_ttl_sec = validate_session_ttl(session_ttl_sec)
    except (TypeError, ValueError):
        flash(_('session.invalid_ttl'), "error")
        return render_template("setup.html", mode="new", is_import=False)

    cfg = ParacciConfig()
    try:
        identity = _get_device_identity()
        meta, file_bytes = create_initiator_session(
            label=label,
            session_ttl_sec=session_ttl_sec,
            my_username=cfg.get("username"),
            color=color,
            identity_pub=identity.public_key,
            identity_priv=identity.private_key,
        )
    except HybridKEMError as e:
        flash(_hybrid_error_message(e), "error")
        return render_template("setup.html", mode="new", is_import=False)
    except Exception as e:
        flash(_('session.create_error', error=str(e)), "error")
        return render_template("setup.html", mode="new", is_import=False)

    _save_session(meta)
    flash(_('session.init_success'), "success")
    return redirect(url_for("main.session_detail", sid=meta.session_id.hex(), auto_download="1"))


# ---------------------------------------------------------------------------
# GET/POST /session/import — File import (Y role or X finalize)
# ---------------------------------------------------------------------------

def _import_from_native(path):
    """Reads byte data from a local file."""
    logger.info(f"Importing from native path: {path}")
    try:
        with open(path, "rb") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Native read error: {e}")
        return None


@bp.route("/api/stage-attachment", methods=["POST"])
def api_stage_attachment():
    """Reject legacy web-submitted path staging."""
    if not request.is_json:
        return jsonify({"success": False, "error": "JSON body required."}), 415
    return jsonify({
        "success": False,
        "error": "Native attachment staging must use the desktop file picker.",
    }), 400


@bp.route("/api/sensitive-cache/clear", methods=["POST"])
def api_sensitive_cache_clear():
    """Clear short-lived plaintext caches owned by the current local app."""
    if not request.is_json:
        return jsonify({"success": False, "error": "JSON body required."}), 415
    payload = request.get_json(silent=True) or {}
    preview_ids = payload.get("preview_ids")
    staged_attachment_ids = payload.get("staged_attachment_ids")
    cleared_preview = _clear_preview_cache(preview_ids if preview_ids is not None else [])
    cleared_staged = _clear_staged_attachment_cache(
        staged_attachment_ids if staged_attachment_ids is not None else []
    )
    response = jsonify({
        "success": True,
        "cleared_preview": cleared_preview,
        "cleared_staged": cleared_staged,
    })
    return _mark_sensitive_no_store(response)


@bp.route("/api/capabilities", methods=["GET"])
def api_capabilities():
    """Report runtime capabilities for the current app shell."""
    response = jsonify({
        "has_native_window": not ag_app.no_gui_mode,
    })
    return _mark_sensitive_no_store(response)


def _update_manager():
    """Return the process-local update manager, if desktop startup registered one."""
    return current_app.extensions.get("paracci_updater")


def _no_update_status() -> dict:
    return {
        "state": "no_update",
        "visible": False,
        "current_version": APP_VERSION,
        "latest_version": "",
        "release_notes": "",
        "published_at": "",
        "protocol_warning": False,
        "protocol_unknown": False,
        "action": "none",
        "size_bytes": None,
        "downloaded_bytes": 0,
        "progress_percent": None,
        "verification_status": "",
        "error_code": "",
    }


@bp.route("/api/update/status", methods=["GET"])
def api_update_status():
    """Report sanitized, memory-only update notification state."""
    manager = _update_manager()
    status = manager.public_status() if manager is not None else _no_update_status()
    return _mark_sensitive_no_store(jsonify(status))


@bp.route("/api/update/check", methods=["POST"])
def api_update_check():
    """Start an explicit update check requested from the Updates page."""
    if not request.is_json:
        return _mark_sensitive_no_store(jsonify({"error_code": "json_required"})), 415
    manager = _update_manager()
    if manager is None:
        return _mark_sensitive_no_store(jsonify({"error_code": "updater_unavailable"})), 409
    if not manager.start_check(user_initiated=True):
        status = manager.public_status()
        status["error_code"] = "update_busy"
        return _mark_sensitive_no_store(jsonify(status)), 409
    return _mark_sensitive_no_store(jsonify(manager.public_status()))


@bp.route("/api/update/history", methods=["GET"])
def api_update_history():
    """Return recent stable releases for the Updates page."""
    manager = _update_manager()
    if manager is None:
        return _mark_sensitive_no_store(jsonify({"error_code": "updater_unavailable", "releases": []})), 409
    try:
        releases = manager.recent_releases()
    except Exception:
        return _mark_sensitive_no_store(jsonify({"error_code": "history_unavailable", "releases": []})), 502
    return _mark_sensitive_no_store(jsonify({"releases": releases}))


@bp.route("/api/update/dismiss", methods=["POST"])
def api_update_dismiss():
    """Dismiss the current update notification for this process only."""
    manager = _update_manager()
    status = manager.dismiss() if manager is not None else _no_update_status()
    return _mark_sensitive_no_store(jsonify(status))


@bp.route("/api/update/download", methods=["POST"])
def api_update_download():
    """Begin a user-confirmed installer download or fixed release-page action."""
    if not request.is_json:
        return _mark_sensitive_no_store(jsonify({"error_code": "json_required"})), 415
    manager = _update_manager()
    if manager is None:
        return _mark_sensitive_no_store(jsonify({"error_code": "update_not_available"})), 409
    payload = request.get_json(silent=True) or {}
    try:
        status = manager.begin_update(
            acknowledged_warning=payload.get("acknowledge_protocol_warning") is True,
        )
    except UpdateActionError as exc:
        return _mark_sensitive_no_store(jsonify({"error_code": exc.code})), 409
    return _mark_sensitive_no_store(jsonify(status))


@bp.route("/api/update/cancel", methods=["POST"])
def api_update_cancel():
    """Cancel the current installer download, if one is running."""
    manager = _update_manager()
    status = manager.cancel_download() if manager is not None else _no_update_status()
    return _mark_sensitive_no_store(jsonify(status))


@bp.route("/api/prepare-preview", methods=["POST"])
def api_prepare_preview():
    """Create a short-lived token for an already decrypted preview attachment."""
    if not request.is_json:
        return jsonify({"error": "JSON body required."}), 415
    payload = request.get_json(silent=True) or {}
    attachment_ref = payload.get("attachment_ref")
    if not isinstance(attachment_ref, str) or not attachment_ref.strip():
        return jsonify({"error": "attachment_ref is required."}), 400

    _cleanup_preview_cache()
    file_data = PREVIEW_CACHE.get(attachment_ref.strip())
    if not file_data:
        return jsonify({"error": "Attachment not found."}), 404

    filename = sanitize_attachment_filename(file_data.get("filename") or "attachment.bin")
    file_bytes = file_data.get("content", b"")
    if not isinstance(file_bytes, bytes):
        file_bytes = bytes(file_bytes or b"")
    stored_mime = str(file_data.get("mime") or "").strip()
    guessed_mime = mimetypes.guess_type(filename)[0] or "application/octet-stream"
    mime_type = stored_mime if stored_mime and stored_mime != "application/octet-stream" else guessed_mime
    allow_download = file_data.get("allow_download") is True
    token = preview_store.generate_token(file_bytes, filename, mime_type, allow_download=allow_download)
    response = jsonify({
        "preview_token": token,
        "filename": filename,
        "mime_type": mime_type,
        "file_size": len(file_bytes),
        "downloadable": allow_download,
        "allow_download": allow_download,
    })
    return _mark_sensitive_no_store(response)

def _process_initiator_import(file_bytes, local_label, native_file_id="", native_filename="", color=None):
    """Starts Y role session by processing an incoming Initiator file."""
    if not local_label:
        flash(_('session.label_required'), "error")
        return render_template(
            "setup.html",
            mode="import",
            is_import=True,
            init_native_file_id=native_file_id,
            init_path=native_filename,
        )

    try:
        logger.info("Processing initiator setup file...")
        start_t = time.time()
        cfg = ParacciConfig()
        identity = _get_device_identity()
        meta, responder_bytes = accept_initiator_and_create_responder(
            file_bytes, local_label, 
            my_username=cfg.get("username"),
            color=color,
            identity_pub=identity.public_key,
            identity_priv=identity.private_key,
        )
        logger.info(f"Bond calculated in {time.time() - start_t:.2f}s")
        _save_session(meta)
        flash(_('session.y_init_success'), "success")
        flash(_('session.safety_unverified'), "warning")
        return redirect(url_for("main.session_detail", sid=meta.session_id.hex(), auto_download="1"))
    except HybridKEMError as e:
        logger.error("Initiator hybrid KEM processing error: %s", e.__class__.__name__)
        flash(_hybrid_error_message(e), "error")
        return render_template(
            "setup.html",
            mode="import",
            is_import=True,
            init_native_file_id=native_file_id,
            init_path=native_filename,
        )
    except Exception as e:
        logger.error(f"Initiator processing error: {e}")
        flash(_('session.import_error', error=str(e)), "error")
        return render_template(
            "setup.html",
            mode="import",
            is_import=True,
            init_native_file_id=native_file_id,
            init_path=native_filename,
        )

def _process_responder_import(file_bytes, session_id):
    """Completes X role session by processing an incoming Responder file."""
    meta = _load_session(session_id.hex())
    if meta is None:
        flash(_('session.error_session_not_found_id', id=session_id.hex()[:8]), "error")
        return render_template("setup.html", mode="import", is_import=True)

    if meta.role != "X":
        flash(_('session.error_role_mismatch', role=meta.role), "error")
        return render_template("setup.html", mode="import", is_import=True)

    try:
        updated_meta = finalize_initiator_session(meta, file_bytes)
        _save_session(updated_meta)
        flash(_('session.x_finalize_success'), "success")
        flash(_('session.safety_unverified'), "warning")
        return redirect(url_for("main.session_detail", sid=updated_meta.session_id.hex()))
    except HybridKEMError as e:
        flash(_hybrid_error_message(e), "error")
        return render_template("setup.html", mode="import", is_import=True)
    except Exception as e:
        flash(_('session.import_error', error=str(e)), "error")
        return render_template("setup.html", mode="import", is_import=True)

@bp.route("/session/import", methods=["GET", "POST"])
def session_import():
    """Imports incoming session files (Init/Resp)."""
    if request.method == "GET":
        native_file_id = request.args.get("native_file_id", "").strip()
        native_ref = _resolve_native_file_ref(native_file_id)
        return render_template(
            "setup.html",
            mode="import",
            is_import=True,
            init_native_file_id=native_file_id if native_ref else "",
            init_path=native_ref["filename"] if native_ref else "",
        )

    local_label = request.form.get("label", "").strip()
    native_file_id = request.form.get("native_file_id", "").strip()
    file_bytes  = None
    native_filename = ""

    if native_file_id:
        file_bytes, native_ref = _import_from_native_ref(native_file_id)
        native_filename = native_ref["filename"] if native_ref else ""
        if not file_bytes:
            flash(f"Could not read file: {native_filename or 'selected file'}", "error")
            return render_template(
                "setup.html",
                mode="import",
                is_import=True,
                init_native_file_id=native_file_id,
                init_path=native_filename,
            )
    else:
        f = request.files.get("paracci_file")
        if f and f.filename:
            file_bytes = f.read()

    if not file_bytes:
        flash(_('session.import_file_required'), "error")
        return render_template("setup.html", mode="import")

    raw_header = _parse_file_header_raw(file_bytes)
    if not raw_header:
        flash(_('session.import_invalid'), "error")
        return render_template(
            "setup.html",
            mode="import",
            init_native_file_id=native_file_id,
            init_path=native_filename,
        )

    file_type = raw_header["file_type"]
    session_id = raw_header["session_id"]

    if file_type == 0x10:
        existing = _load_session(session_id.hex())
        if existing and existing.role == "X":
            flash(_('session.role_error'), "error")
            return redirect(url_for("main.session_detail", sid=session_id.hex()))
        
        color = request.form.get("color")
        custom_color = request.form.get("custom_color", "").strip()
        if custom_color:
            if not custom_color.startswith("#"):
                custom_color = "#" + custom_color
            if len(custom_color) in [4, 7]:
                color = custom_color
            
        return _process_initiator_import(
            file_bytes,
            local_label,
            native_file_id=native_file_id,
            native_filename=native_filename,
            color=color,
        )
    elif file_type == 0x11:
        # Responder file is now only accepted from the session page.
        flash(_('setup.error_responder_redirect'), "warning")
        existing = _load_session(session_id.hex())
        if existing:
            return redirect(url_for("main.session_detail", sid=session_id.hex()))
        return redirect(url_for("main.session_import"))
    
    flash(_('session.import_invalid'), "error")
    return render_template("setup.html", mode="import")


# ---------------------------------------------------------------------------
# GET /session/<sid> — Session details
# ---------------------------------------------------------------------------

@bp.route("/session/<sid>")
def session_detail(sid: str):
    """Shows details of the specified session (status, duration, security code, etc.)."""
    meta = _load_session(sid)
    if meta is None:
        abort(404)
    native_file_id = request.args.get("native_file_id", "").strip()
    native_ref = _resolve_native_file_ref(native_file_id)
    open_native_file_id = native_file_id if native_ref else ""
    open_native_filename = native_ref["filename"] if native_ref else ""

    safety_code = None
    if meta.peer_pub:
        try:
            safety_code = get_session_safety_code(meta)
        except Exception:
            safety_code = None

    # Evolution / bond status
    evo_info = None
    if meta.state == "active" and meta.keys is not None:
        evo_info = {
            "tx_count":       meta.tx_count,
            "bonded":         meta.is_bonded,
            "secs_remaining": seconds_until_expiry(meta.evo_config),
        }

    auto_download = request.args.get("auto_download")
    if auto_download:
        return render_template(
            "session.html",
            meta=meta, sid=sid, evo_info=evo_info,
            now=int(time.time()), auto_download=True,
            safety_code=safety_code,
            open_native_file_id=open_native_file_id,
            open_native_filename=open_native_filename,
        )

    return render_template(
        "session.html",
        meta=meta, sid=sid, evo_info=evo_info,
        now=int(time.time()),
        safety_code=safety_code,
        open_native_file_id=open_native_file_id,
        open_native_filename=open_native_filename,
    )


@bp.route("/session/<sid>/confirm-safety", methods=["POST"])
def session_confirm_safety(sid: str):
    """Confirms the out-of-band safety code before activating a session."""
    meta = _load_session(sid)
    if meta is None:
        abort(404)

    try:
        updated = confirm_safety_code(meta, request.form.get("safety_code", ""))
        _save_session(updated)
        flash(_('session.safety_code_confirmed'), "success")
    except SessionError:
        flash(_('session.safety_code_mismatch'), "error")
    except Exception as e:
        flash(_('session.import_error', error=str(e)), "error")
    return redirect(url_for("main.session_detail", sid=sid))


@bp.route("/session/<sid>/import_responder", methods=["POST"])
def session_import_responder(sid: str):
    """Imports the Responder file for a specific session."""
    meta = _load_session(sid)
    if meta is None: abort(404)

    if meta.role != "X":
        flash(_('session.error_x_only_responder'), "error")
        return redirect(url_for("main.session_detail", sid=sid))

    native_file_id = request.form.get("native_file_id", "").strip()
    file_bytes = None
    if native_file_id:
        file_bytes, native_ref = _import_from_native_ref(native_file_id)
        if not file_bytes:
            filename = native_ref["filename"] if native_ref else "selected file"
            flash(f"Could not read file: {filename}", "error")
            return redirect(url_for("main.session_detail", sid=sid))
    else:
        f = request.files.get("paracci_file")
        if f and f.filename:
            file_bytes = f.read()

    if not file_bytes:
        flash(_('session.import_file_required'), "error")
        return redirect(url_for("main.session_detail", sid=sid))

    raw_header = _parse_file_header_raw(file_bytes)
    
    if not raw_header or raw_header["file_type"] != 0x11:
        flash(_('session.error_invalid_responder'), "error")
        return redirect(url_for("main.session_detail", sid=sid))

    if raw_header["session_id"].hex() != sid:
        flash(_('session.error_mismatched_session'), "error")
        return redirect(url_for("main.session_detail", sid=sid))

    return _process_responder_import(file_bytes, raw_header["session_id"])


# ---------------------------------------------------------------------------
# POST /session/<sid>/seal — Encrypt message → download
# ---------------------------------------------------------------------------

def _parse_staged_attachment_ids(raw_ids):
    """Parses staged attachment IDs from hidden form input."""
    if not raw_ids:
        return []
    if isinstance(raw_ids, (list, tuple)):
        values = raw_ids
    else:
        values = str(raw_ids).split(",")
    return [value.strip() for value in values if value and value.strip()]


def _gather_attachments(upload_files, staged_ids=None):
    """Gathers uploaded and staged native files, checks size, and sanitizes."""
    _cleanup_staged_attachment_cache()
    files = []
    total_size = 0
    upload_files = [f for f in upload_files if f and f.filename]
    staged_id_list = _parse_staged_attachment_ids(staged_ids)

    if len(upload_files) + len(staged_id_list) > MAX_ATTACHMENT_COUNT:
        return None, f"Maximum {MAX_ATTACHMENT_COUNT} files can be attached."
        
    for f in upload_files:
        safe_fname = sanitize_attachment_filename(f.filename)
        content = f.read()
        total_size += len(content)
        if total_size > MAX_ATTACHMENT_SIZE:
            return None, f"Total file size exceeds the {MAX_ATTACHMENT_SIZE // (1024*1024)}MB limit."
        try:
            content = sanitize_image(content, safe_fname)
        except SanitizationError:
            return None, _(SanitizationError.i18n_key)
        files.append((safe_fname, content))

    for attachment_id in staged_id_list:
        staged = STAGED_ATTACHMENT_CACHE.pop(attachment_id, None)
        if not staged or staged["expires"] < time.time():
            return None, "A staged attachment expired. Please attach it again."
        content = staged.get("content", b"")
        total_size += len(content)
        if total_size > MAX_ATTACHMENT_SIZE:
            return None, f"Total file size exceeds the {MAX_ATTACHMENT_SIZE // (1024*1024)}MB limit."
        files.append((staged["filename"], content))
        _drop_cached_entry(staged, ("content",))

    return files, None

@bp.route("/session/<sid>/seal", methods=["POST"])
def session_seal(sid: str):
    """Creates a Paracci envelope by encrypting the message and attachments."""
    meta = _load_session(sid)
    if meta is None: abort(404)

    try:
        require_transcript_bound_session(meta)
    except HybridKEMError as e:
        flash(_hybrid_error_message(e), "error")
        return redirect(url_for("main.session_detail", sid=sid))

    if not meta.can_send:
        if not meta.safety_confirmed:
            msg = _('session.safety_unverified')
        elif meta.state != "active":
            msg = _('session.not_active')
        else:
            msg = _('session.bond_not_established_x' if meta.role == "X" else 'session.bond_not_established_y')
        flash(msg, "error")
        return redirect(url_for("main.session_detail", sid=sid))

    text = unicodedata.normalize('NFC', request.form.get("message", "").strip())
    allow_download = request.form.get("allow_download") == "on"
    try:
        ttl_seconds = int(request.form.get("ttl_seconds", "0"))
    except:
        ttl_seconds = 0

    files, error = _gather_attachments(
        request.files.getlist("attachments"),
        request.form.get("staged_attachment_ids", "")
    )
    if error:
        flash(error, "error")
        return redirect(url_for("main.session_detail", sid=sid))

    package_blob = b""
    try:
        package_blob = create_package(text, files, allow_download=allow_download)
        sealed = seal_envelope(
            package_blob,
            meta,
            single_use=True,
            ttl_seconds=ttl_seconds,
            allow_download=allow_download,
        )
        updated = meta._replace(tx_count=meta.tx_count + 1, send_seed=sealed.next_seed)
        _save_session(updated)
        return send_file(
            io.BytesIO(sealed.file_bytes),
            mimetype="application/octet-stream",
            as_attachment=True,
            download_name=f"msg_step_{sealed.next_step - 1:06d}_{sealed.msg_id.hex()[:12]}.paracci",
        )
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        logger.exception("Unexpected error during message seal")
        flash(_('session.unexpected_error'), "error")
        return redirect(url_for("main.session_detail", sid=sid))
    finally:
        files.clear()
        package_blob = b""


def _prepare_open_response(meta, opened, sid, is_ajax, secure_delete_warning=None):
    """Prepares opened message content for visualization."""
    if opened.bond_nonce and meta.role == "Y" and meta.bond_seed is None:
        meta = apply_bond_nonce_to_y(meta, opened.bond_nonce)
    updated_meta = meta._replace(rx_count=opened.next_step, recv_seed=opened.next_seed)
    _save_session(updated_meta)

    safety_code = None
    if updated_meta.peer_pub:
        try:
            safety_code = get_session_safety_code(updated_meta)
        except Exception:
            safety_code = None
    evo_info = {"tx_count": updated_meta.tx_count, "bonded": updated_meta.is_bonded, "secs_remaining": seconds_until_expiry(updated_meta.evo_config)} if updated_meta.keys else None

    package = extract_package(
        opened.payload,
        default_allow_download=not opened.has_download_policy,
    )
    effective_allow_download = (
        opened.allow_download
        if opened.has_download_policy
        else package.allow_download
    )
    security_report = scan_text_for_security(package.text)

    attachments = []
    for att in package.attachments:
        safe_name = sanitize_attachment_filename(att.filename)
        pid = _add_to_preview_cache(safe_name, att.content, att.mime_type, effective_allow_download)
        attachments.append({
            "pid": pid,
            "filename": safe_name,
            "mime_type": att.mime_type,
            "size": len(att.content),
            "is_media": att.mime_type.startswith(("image/", "video/")),
            "preview_url": _preview_url("main.preview", pid),
            "download_url": _preview_url("main.preview_download", pid),
        })

    opened_message = {
        "text": package.text,
        "attachments": attachments,
        "allow_download": effective_allow_download,
        "time_left": _fmt_time_left(opened.expire_at),
        "expire_at": opened.expire_at,
        "evo_step": opened.evo_step,
        "single_use": opened.single_use,
        "msg_id_hex": opened.msg_id.hex(),
        "safety_code": safety_code,
        "rx_count": updated_meta.rx_count,
        "security_report": security_report,
        "secure_delete_warning": secure_delete_warning,
    }
    if is_ajax:
        return jsonify({"success": True, **opened_message})

    if secure_delete_warning:
        flash(secure_delete_warning, "warning")
    return render_template(
        "session.html",
        meta=updated_meta,
        sid=sid,
        evo_info=evo_info,
        now=int(time.time()),
        safety_code=safety_code,
        opened_msg=opened_message,
    )

@bp.route("/session/<sid>/open", methods=["POST"])
def session_open(sid: str):
    """Opens an encrypted Paracci envelope and displays its content."""
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.args.get("ajax") == "1"
    meta = _load_session(sid)
    if meta is None: return (jsonify({"success": False, "error": "Session not found."}), 404) if is_ajax else abort(404)

    try:
        require_transcript_bound_session(meta)
    except HybridKEMError as e:
        msg = _hybrid_error_message(e)
        return jsonify({"success": False, "error": msg}) if is_ajax else (flash(msg, "error") or redirect(url_for("main.session_detail", sid=sid)))

    if not meta.can_open:
        msg = _('session.safety_unverified') if not meta.safety_confirmed else _('session.not_active')
        return jsonify({"success": False, "error": msg}) if is_ajax else (flash(msg, "error") or redirect(url_for("main.session_detail", sid=sid)))

    native_file_id = request.form.get("native_file_id", "").strip()
    uploaded = request.files.get("paracci_file")
    file_bytes = None
    native_file_path = None
    if native_file_id:
        file_bytes, native_ref = _import_from_native_ref(native_file_id)
        native_file_path = native_ref["path"] if native_ref else None
    elif uploaded and uploaded.filename != "":
        file_bytes = uploaded.read()

    if not file_bytes:
        msg = "No file selected."
        return jsonify({"success": False, "error": msg}) if is_ajax else (flash(msg, "error") or redirect(url_for("main.session_detail", sid=sid)))

    raw = _parse_file_header_raw(file_bytes)
    if raw is None:
        msg = _('session.invalid_file')
        return jsonify({"success": False, "error": msg}) if is_ajax else (flash(msg, "error") or redirect(url_for("main.session_detail", sid=sid)))

    db, _device_key = _get_db_and_key()
    guard = BurnGuard(db)
    try:
        burn_reserved = guard.pre_open_check(msg_id=raw["msg_id"], expire_at=raw["expire_at"], single_use=raw["single_use"])
        try:
            opened = open_envelope(file_bytes, meta)
        except EnvelopeError as e:
            if burn_reserved:
                guard.mark_open_failed(raw["msg_id"], str(e))
            raise
        
        if opened.bond_nonce is not None and not meta.is_bonded:
            try:
                meta = apply_bond_nonce_to_y(meta, opened.bond_nonce)
                _save_session(meta)
            except SessionError as e:
                flash(_('session.unexpected_error'), "warning")
                logger.warning("Bond nonce application failed for session=%s: %s", sid[:8], e)

        secure_delete_succeeded = guard.post_open_burn(
            msg_id=opened.msg_id,
            session_id=opened.session_id,
            direction=opened.direction,
            single_use=opened.single_use,
            file_path=native_file_path,
        )
        secure_delete_warning = (
            None if secure_delete_succeeded else _('session.secure_delete_failed')
        )
        return _prepare_open_response(
            meta,
            opened,
            sid,
            is_ajax,
            secure_delete_warning=secure_delete_warning,
        )
    except (AlreadyBurnedError, TTLExpiredError, EnvelopeTTLError) as e:
        msg = "This message was already opened or has expired."
        return jsonify({"success": False, "error": msg}) if is_ajax else _render_session_error(meta, sid, msg)
    except PackageLimitError as e:
        msg_id = raw.get("msg_id", b"").hex() if isinstance(raw, dict) else ""
        logger.warning("Rejected unsafe package expansion for session=%s msg=%s: %s", sid[:8], msg_id, e)
        stable_msg = _('session.package_limit_error')
        if is_ajax:
            return jsonify({"success": False, "error": stable_msg}), 400
        return _render_session_error(meta, sid, stable_msg)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        logger.exception("Unexpected error during session open for session=%s", sid[:8])
        stable_msg = _('session.unexpected_error')
        if is_ajax:
            return jsonify({"success": False, "error": stable_msg}), 500
        return _render_session_error(meta, sid, stable_msg)


def _render_session_error(meta, sid, msg):
    """Renders the session page with an error message."""
    evo_info = None
    if meta.keys:
        evo_info = {
            "tx_count":       meta.tx_count,
            "bonded":         meta.is_bonded,
            "secs_remaining": seconds_until_expiry(meta.evo_config),
        }
    safety_code = None
    if meta.peer_pub:
        try:
            safety_code = get_session_safety_code(meta)
        except Exception:
            safety_code = None

    return render_template(
        "session.html", meta=meta, sid=sid, evo_info=evo_info,
        now=int(time.time()), open_error=msg,
        safety_code=safety_code,
    )


@bp.route("/session/<sid>/settings", methods=["GET", "POST"])
def session_settings(sid: str):
    """Manages settings for a specific session (e.g. color)."""
    meta = _load_session(sid)
    if not meta:
        abort(404)
        
    if request.method == "POST":
        color = request.form.get("color")
        custom_color = request.form.get("custom_color", "").strip()
        if custom_color:
            if not custom_color.startswith("#"):
                custom_color = "#" + custom_color
            if len(custom_color) in [4, 7]:
                color = custom_color
            
        if color:
            updated_meta = meta._replace(color=color)
            _save_session(updated_meta)
            flash(_('session.settings_saved', default='Session settings updated.'), "success")
            return redirect(url_for("main.session_detail", sid=sid))
            
    return render_template("session_settings.html", meta=meta, sid=sid)


# ---------------------------------------------------------------------------
# GET /session/<sid>/export — Download Session file
# ---------------------------------------------------------------------------

@bp.route("/session/<sid>/export")
def session_export(sid: str):
    """Exports (downloads) the session initiation or response file."""
    meta = _load_session(sid)
    if meta is None:
        abort(404)

    identity = _get_device_identity()
    if meta.role == "X" and meta.state == "pending":
        try:
            file_bytes = serialize_initiator_file(meta, identity_priv=identity.private_key)
            filename   = f"session_init_{sid[:8]}.paracci"
        except HybridKEMError as e:
            flash(_hybrid_error_message(e), "error")
            return redirect(url_for("main.session_detail", sid=sid))
        except Exception as e:
            flash(_('session.create_error', error=str(e)), "error")
            return redirect(url_for("main.session_detail", sid=sid))

    elif meta.role == "Y":
        try:
            file_bytes = serialize_responder_file(
                session_id=meta.session_id,
                y_pub=meta.my_pub,
                evo_config=meta.evo_config,
                label=meta.label,
                x_pub=meta.peer_pub,
                x_identity_pub=meta.peer_identity_pub,
                y_identity_pub=meta.my_identity_pub,
                identity_priv=identity.private_key,
                ml_kem_ciphertext=meta.ml_kem_ciphertext,
            )
            filename = f"session_resp_{sid[:8]}.paracci"
        except HybridKEMError as e:
            flash(_hybrid_error_message(e), "error")
            return redirect(url_for("main.session_detail", sid=sid))
        except Exception as e:
            flash(_('session.create_error', error=str(e)), "error")
            return redirect(url_for("main.session_detail", sid=sid))

    else:
        flash(_('session.export_forbidden'), "error")
        return redirect(url_for("main.session_detail", sid=sid))

    return send_file(
        io.BytesIO(file_bytes),
        mimetype="application/octet-stream",
        as_attachment=True,
        download_name=filename,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------





# ---------------------------------------------------------------------------
# GET/POST /settings — Application Settings
# ---------------------------------------------------------------------------

@bp.route("/updates")
def updates():
    """Render the manual update-check and release-history page."""
    return render_template("updates.html")


@bp.route("/settings", methods=["GET", "POST"])
def settings():
    """Manages general application settings."""
    cfg = ParacciConfig()
    
    if request.method == "POST":
        # Get checkbox values
        anti_screenshot = True if request.form.get("anti_screenshot") else False
        quiet_mode      = True if request.form.get("quiet_mode") else False

        try:
            default_ttl = validate_session_ttl(int(request.form.get("default_ttl", 0)))
        except (TypeError, ValueError):
            flash(_('session.invalid_ttl'), "error")
            return redirect(url_for("main.settings"))

        cfg.set("anti_screenshot", anti_screenshot)
        cfg.set("quiet_mode", quiet_mode)
        cfg.set("default_ttl", default_ttl)
        cfg.set("auto_cleanup_hours", int(request.form.get("auto_cleanup_hours", 24)))
        
        flash(_('settings.save_success'), "success")
        return redirect(url_for("main.settings"))

    # System Info
    sys_info = {
        "data_dir": cfg.data_dir,
        "config_path": cfg.config_path,
        "db_path": os.path.join(cfg.data_dir, "paracci.db"),
        "downloads_path": cfg.full_downloads_path
    }
    
    return render_template("settings.html", settings=cfg.settings, sys_info=sys_info)


# ---------------------------------------------------------------------------
# GET/POST /profile — User Profile
# ---------------------------------------------------------------------------

@bp.route("/profile", methods=["GET", "POST"])
def profile():
    """Manages user profile information (username, color)."""
    cfg = ParacciConfig()
    
    if request.method == "POST":
        username     = request.form.get("username", "").strip()
        avatar_color = request.form.get("avatar_color", "#0a84ff")
        
        if not username:
            flash(_('profile.username_required'), "error")
            return redirect(url_for("main.profile"))
            
        cfg.set("username", username)
        cfg.set("avatar_color", avatar_color)
        
        flash(_('profile.update_success'), "success")
        return redirect(url_for("main.profile"))

    return render_template("profile.html", profile=cfg.settings)


# ---------------------------------------------------------------------------
# GET /preview/<pid> — File Preview
# ---------------------------------------------------------------------------

def _get_preview_response_data(file_data, pid):
    """Prepare metadata for the standalone preview page."""
    filename = sanitize_attachment_filename(file_data["filename"])
    mime = file_data.get("mime") or mimetypes.guess_type(filename)[0] or "application/octet-stream"
    allow_download = file_data.get("allow_download") is True
    content = file_data.get("content", b"")
    file_size = len(content) if isinstance(content, (bytes, bytearray)) else 0
    content_url = ""

    if mime.startswith("image/") and not allow_download:
        content_url = _preview_url("main.preview", pid, file_data, variant="preview")
    elif allow_download:
        content_url = _preview_url("main.preview", pid, file_data, raw=1)

    return render_template(
        "preview.html",
        token="",
        pid=pid,
        filename=filename,
        mime_type=mime,
        file_size=file_size,
        content_url=content_url,
        media_url=content_url,
        download_url=_preview_url("main.preview_download", pid, file_data) if allow_download else "",
        allow_download=allow_download,
    )

def _preview_token_not_found():
    token = (request.view_args or {}).get("pid") or ""
    preview_css = url_for("static", filename="css/standalone-preview.css")
    preview_js = url_for("static", filename="js/preview.js")
    return (
        "<!doctype html><html><head><meta charset=\"utf-8\">"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
        "<title>Preview unavailable</title>"
        f"<link rel=\"stylesheet\" href=\"{preview_css}\">"
        f"<script src=\"{preview_js}\" defer></script>"
        "</head><body>"
        "<div class=\"preview-shell\"><main class=\"preview-main\"><div class=\"content-host\">"
        "<div class=\"message-state\"><h1 class=\"state-title\">Preview unavailable</h1>"
        "<p class=\"state-copy\">This preview has expired. Please reopen the message.</p>"
        "<button class=\"btn\" id=\"closeBtn\" type=\"button\">Close</button></div>"
        "</div></main></div>"
        f"<div id=\"previewConfig\" hidden data-token=\"{token}\" data-allow-download=\"false\"></div>"
        "</body></html>"
    ), 404


def _get_preview_token_response_data(entry: PreviewEntry):
    """Render token-based preview metadata without exposing file bytes to Jinja."""
    filename = sanitize_attachment_filename(entry.filename or "attachment.bin")
    mime = entry.mime_type or "application/octet-stream"
    allow_download = entry.allow_download is True
    content_url = ""
    if allow_download or mime.lower().startswith("image/"):
        content_url = url_for("main.preview_content", preview_token=entry.token)

    return render_template(
        "preview.html",
        token=entry.token,
        filename=filename,
        mime_type=mime,
        file_size=len(entry.file_bytes),
        content_url=content_url,
        media_url=content_url,
        allow_download=allow_download,
        download_url=(
            url_for(
                "main.preview_content",
                preview_token=entry.token,
                download=1,
            )
            if allow_download
            else ""
        ),
    )


@bp.route("/preview/<pid>")
def preview(pid: str):
    """Provides a secure preview of a file inside a package."""
    if _looks_like_preview_token(pid):
        entry = preview_store.get(pid)
        if entry is None:
            return _preview_token_not_found()
        resp_html = _get_preview_token_response_data(entry)
        response = make_response(resp_html)
        response.headers["Content-Security-Policy"] = _preview_content_security_policy()
        return _mark_sensitive_no_store(response)

    file_data = PREVIEW_CACHE.get(pid)
    if not file_data: return f"<h3>{_('preview.not_found_title')}</h3><p>{_('preview.not_found_desc')}</p>", 404

    if request.args.get("raw") == "1":
        if not _can_send_original_attachment(file_data):
            abort(403)
        response = send_file(io.BytesIO(file_data["content"]), mimetype=file_data["mime"], as_attachment=False)
        return _mark_sensitive_no_store(response)

    if request.args.get("variant") == "preview":
        preview_data = build_no_download_image_preview(
            file_data.get("content", b""),
            file_data.get("mime", ""),
        )
        if not preview_data:
            abort(415)
        preview_content, preview_mime = preview_data
        response = send_file(io.BytesIO(preview_content), mimetype=preview_mime, as_attachment=False)
        return _mark_sensitive_no_store(response)

    resp_html = _get_preview_response_data(file_data, pid)
    response = make_response(resp_html)
    response.headers["Content-Security-Policy"] = _preview_content_security_policy()
    return _mark_sensitive_no_store(response)


# ---------------------------------------------------------------------------
# GET /preview/<pid>/download — Download from preview page
# ---------------------------------------------------------------------------

@bp.route("/preview/<preview_token>/content")
def preview_content(preview_token: str):
    """Serve bytes for a valid token-scoped preview session."""
    if not _looks_like_preview_token(preview_token):
        abort(404)
    entry = preview_store.get(preview_token)
    if entry is None:
        abort(404)

    download_requested = request.args.get("download") == "1"
    filename = sanitize_attachment_filename(entry.filename or "attachment.bin")
    mime_type = entry.mime_type or "application/octet-stream"
    if entry.allow_download is not True:
        if download_requested:
            abort(403)

        preview_data = build_no_download_image_preview(entry.file_bytes, mime_type)
        if not preview_data:
            abort(415)
        preview_content, preview_mime = preview_data
        response = send_file(
            io.BytesIO(preview_content),
            mimetype=preview_mime,
            as_attachment=False,
        )
        return _mark_sensitive_no_store(response)

    response = send_file(
        io.BytesIO(entry.file_bytes),
        mimetype=mime_type,
        as_attachment=download_requested,
        download_name=(
            filename
            if download_requested
            else None
        ),
    )
    return _mark_sensitive_no_store(response)


@bp.route("/preview/<pid>/download")
def preview_download(pid: str):
    """Allows downloading a previewed file."""
    file_data = PREVIEW_CACHE.get(pid)
    if not _can_send_original_attachment(file_data):
        abort(403)

    response = send_file(
        io.BytesIO(file_data["content"]),
        mimetype=file_data["mime"],
        as_attachment=True,
        download_name=sanitize_attachment_filename(file_data["filename"])
    )
    return _mark_sensitive_no_store(response)


# ---------------------------------------------------------------------------
# Security and 404 error handlers
# ---------------------------------------------------------------------------

@bp.app_errorhandler(SecurityError)
def trusted_host_rejected(e):
    """Convert Werkzeug trusted-host failures into the loopback auth status."""
    logger.warning("Loopback trusted host rejected: %s", e)
    if request.path.startswith("/api/"):
        return jsonify({"success": False, "error": "Forbidden."}), 403
    return "Forbidden", 403


@bp.route('/favicon.ico')
def favicon():
    """Serves the favicon.ico from the application/project root directory."""
    return send_from_directory(
        os.path.abspath(os.path.join(current_app.root_path, "..", "..")),
        "paracci_icon.ico",
        mimetype="image/vnd.microsoft.icon"
    )


@bp.app_errorhandler(404)
def not_found(e):
    """404 Error page: Displays a friendly error screen to the user."""
    return render_template("base.html", error_404=True), 404
