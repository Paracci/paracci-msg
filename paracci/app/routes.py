import os
import io
import struct
import time
import uuid
import datetime
import glob
from typing import Optional
from pathlib import Path
import logging
import unicodedata

from flask import (
    Blueprint, render_template, request, redirect,
    url_for, flash, send_file, abort, jsonify, current_app,
    session, g, make_response
)
import pyotp
import qrcode
import base64
from io import BytesIO
from werkzeug.utils import secure_filename

import app as ag_app
from core.config import ParacciConfig
from core.crypto import generate_keypair, get_fingerprint
from core.envelope import seal_envelope, open_envelope, EnvelopeError, EnvelopeTTLError
from core.package import create_package, extract_package, package_to_template_data
from core.sanitizer import sanitize_image
from core.security_utils import scan_text_for_security
from core.burn import (
    is_device_initialized, init_device, unlock_device, DeviceError,
    BurnGuard, AlreadyBurnedError, TTLExpiredError
)
from core.session import (
    deserialize_session_meta, serialize_session_meta,
    create_initiator_session, accept_initiator_and_create_responder,
    finalize_initiator_session, apply_bond_nonce_to_y,
    serialize_initiator_file, serialize_responder_file,
    SESSION_COLORS
)
from core.evolution import seconds_until_expiry, session_expires_at
from . import APP_DIR
from .i18n_manager import i18n

logger = logging.getLogger(__name__)
_ = i18n.translate

bp = Blueprint("main", __name__)

# ── Preview Cache (RAM only, for temporary viewing) ──
# Structure: { id: {"filename": str, "content": bytes, "mime": str, "expires": float, "allow_download": bool} }
PREVIEW_CACHE = {}

# Native attachment staging is RAM-only and short-lived.
# Structure: { id: {"filename": str, "content": bytes, "expires": float} }
STAGED_ATTACHMENT_CACHE = {}

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

@bp.after_app_request
def add_security_headers(response):
    """Add global security headers."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    
    # Content Security Policy (Hardened)
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "font-src 'self'; "
        "img-src 'self' data: blob:; "
        "connect-src 'self'; "
        "frame-src 'none'; "
        "object-src 'none';"
    )
    response.headers["Content-Security-Policy"] = csp
    return response

def _cleanup_preview_cache():
    """Cleans expired preview files from memory."""
    now = time.time()
    expired = [k for k, v in PREVIEW_CACHE.items() if v["expires"] < now]
    for k in expired:
        del PREVIEW_CACHE[k]

def _add_to_preview_cache(filename, content, mime, allow_download, ttl=600):
    """Adds a file temporarily to the preview cache."""
    _cleanup_preview_cache()
    pid = str(uuid.uuid4())
    PREVIEW_CACHE[pid] = {
        "filename": filename,
        "content": content,
        "mime": mime,
        "expires": time.time() + ttl,
        "allow_download": allow_download
    }
    return pid


def _cleanup_staged_attachment_cache():
    """Cleans expired native staged attachments from memory."""
    now = time.time()
    expired = [k for k, v in STAGED_ATTACHMENT_CACHE.items() if v["expires"] < now]
    for k in expired:
        del STAGED_ATTACHMENT_CACHE[k]


def _add_to_staged_attachment_cache(filename, content, ttl=600):
    """Adds a native attachment temporarily until the next seal request consumes it."""
    _cleanup_staged_attachment_cache()
    attachment_id = str(uuid.uuid4())
    STAGED_ATTACHMENT_CACHE[attachment_id] = {
        "filename": filename,
        "content": content,
        "expires": time.time() + ttl,
    }
    return attachment_id


# ---------------------------------------------------------------------------
# Device Lock & PIN Management
# ---------------------------------------------------------------------------

@bp.before_app_request
def check_lock():
    """Checks if the application is locked; redirects to the unlock page if locked."""

    # Routes exempt from locking
    if request.endpoint in ["main.unlock", "main.set_locale", "static", "main.unlock_2fa_setup", "main.unlock_2fa_verify"]:
        return

    # 1. Device not initialized yet?
    if not is_device_initialized(ag_app.db):
        return redirect(url_for("main.unlock"))

    # 2. Device key not in memory? (Locked)
    if ag_app.device_key is None:
        return redirect(url_for("main.unlock"))


@bp.app_context_processor
def inject_user():
    """Injects the user profile and shell session shortcuts into all templates."""
    cfg = ParacciConfig()
    sidebar_sessions = []
    try:
        if ag_app.device_key is not None and is_device_initialized(ag_app.db):
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
    except Exception:
        sidebar_sessions = []

    return dict(user_profile={
        "username": cfg.get("username"),
        "avatar_color": cfg.get("avatar_color")
    }, sidebar_sessions=sidebar_sessions, SESSION_COLORS=SESSION_COLORS)

@bp.route("/unlock", methods=["GET", "POST"])
def unlock():
    """Route used to initialize the device or unlock it with a PIN."""
    initialized = is_device_initialized(ag_app.db)
    mode = "init" if not initialized else "unlock"

    if request.method == "POST":
        pin = request.form.get("pin")
        if not pin:
            flash(_('auth.pin_required'), "error")
            return render_template("unlock.html", mode=mode, is_initialized=initialized)

        try:
            if mode == "init":
                # Redirect to 2FA setup after PIN is set during initial setup
                device_key = init_device(ag_app.db, pin)
                ag_app.device_key = device_key # Set globally since it's initial setup
                session['setup_in_progress'] = True # Temporary flag
                return redirect(url_for("main.unlock_2fa_setup"))
            else:
                # Normal unlock: check 2FA if PIN is correct
                device_key = unlock_device(ag_app.db, pin)
                
                if ag_app.db.is_2fa_enabled():
                    # Cleanup old pending unlocks (older than 10 mins)
                    now = time.time()
                    expired_ids = [k for k, v in ag_app.PENDING_UNLOCKS.items() if now - v["timestamp"] > 600]
                    for k in expired_ids: del ag_app.PENDING_UNLOCKS[k]
                    
                    # If 2FA is active, temporarily store device_key in memory
                    unlock_id = str(uuid.uuid4())
                    ag_app.PENDING_UNLOCKS[unlock_id] = {
                        "device_key": device_key,
                        "timestamp": time.time()
                    }
                    session['unlock_id'] = unlock_id
                    return redirect(url_for("main.unlock_2fa_verify"))
                
                # If 2FA is not active, unlock directly
                ag_app.device_key = device_key
                flash(_('auth.unlock_success'), "success")
                return redirect(url_for("main.index"))
                
        except DeviceError as e:
            flash(str(e), "error")
            return render_template("unlock.html", mode=mode, is_initialized=initialized)

    return render_template("unlock.html", mode=mode, is_initialized=initialized)

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
            return redirect(url_for("main.index"))
        
        # 2FA Activation
        code = request.form.get("code")
        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            # Encrypt 2FA secret with device_key before storing
            # We have device_key in memory from initial unlock (init_device)
            # during setup, init_device returns device_key directly.
            # However, we need to ensure we have it.
            if ag_app.device_key:
                from core.crypto import encrypt
                blob = encrypt(ag_app.device_key, secret.encode('utf-8'), aad=b"paracci.2fa_secret.v1")
                ag_app.db.set_2fa_secret(blob.nonce + blob.ciphertext)
                ag_app.db.set_2fa_enabled(True)
                session.pop('unlock_id', None)
                session.pop('2fa_setup_secret', None)
                flash(_('auth.2fa_enabled_success'), "success")
                return redirect(url_for("main.index"))
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
    if not ag_app.db.is_2fa_enabled() or 'unlock_id' not in session:
        return redirect(url_for("main.unlock"))

    if request.method == "POST":
        code = request.form.get("code")
        unlock_id = session.get('unlock_id')
        
        if not unlock_id or unlock_id not in ag_app.PENDING_UNLOCKS:
            flash("Session expired or invalid.", "error")
            return redirect(url_for("main.unlock"))

        pending = ag_app.PENDING_UNLOCKS.pop(unlock_id)
        device_key = pending["device_key"]
        
        # Get and Decrypt 2FA secret
        enc_secret = ag_app.db.get_2fa_secret_raw() # We'll add this helper or use get_device_meta
        if not enc_secret:
            flash("2FA Secret not found.", "error")
            return redirect(url_for("main.unlock"))
            
        try:
            from core.crypto import decrypt, EncryptedBlob
            nonce = enc_secret[:12]
            ciphertext = enc_secret[12:]
            blob = EncryptedBlob(nonce=nonce, ciphertext=ciphertext)
            secret = decrypt(device_key, blob, aad=b"paracci.2fa_secret.v1").decode('utf-8')
        except Exception:
            flash("Security Error: Could not decrypt 2FA secret.", "error")
            return redirect(url_for("main.unlock"))

        totp = pyotp.TOTP(secret)
        if totp.verify(code):
            # 2FA correct
            ag_app.device_key = device_key
            session.pop('unlock_id', None)
            flash(_('auth.unlock_success'), "success")
            return redirect(url_for("main.index"))
        else:
            # Re-insert into pending to allow retry? 
            # Better to force restart unlock for security?
            # Let's allow 3 retries? For now, force restart is safer.
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
                ag_app.db.set_2fa_secret(secret)
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


@bp.route("/set_locale/<lang>")
def set_locale(lang):
    """Changes application language (tr/en)."""
    if lang in ['tr', 'en', 'de', 'fr', 'ru', 'es']:
        session['locale'] = lang
        session.modified = True
    
    # Secure redirect
    target = request.referrer
    if not target or "set_locale" in target:
        target = url_for('main.index')
        
    return redirect(target)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_db_and_key():
    """Returns the active database connection and device key."""
    if ag_app.device_key is None:
        raise RuntimeError(_('auth.device_locked'))
    return ag_app.db, ag_app.device_key


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
    
    # 3. Protocol Version (Currently only 0x01 supported)
    version = file_bytes[4]
    if version != 0x01:
        return None
    
    # 4. File Type (0x10: Init, 0x11: Resp, 0x20: Msg)
    file_type = file_bytes[5]
    if file_type not in [0x10, 0x11, 0x20]:
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
            if evo_step > 100000: return None # 100k step limit (CPU DoS protection)
            
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
    csp = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "object-src 'none'; "
        "frame-ancestors 'none'; "
        "base-uri 'self';"
    )
    response.headers['Content-Security-Policy'] = csp
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response


@bp.route("/")
def index():
    """Home page: Lists all saved sessions."""
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
    security_profile = request.form.get("security_profile", "paranoid")
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
    except ValueError:
        flash(_('session.invalid_ttl'), "error")
        return render_template("setup.html", mode="new", is_import=False)

    custom_params = None
    if security_profile == "custom":
        try:
            t = int(request.form.get("custom_t", "256"))
            m = int(request.form.get("custom_m", "2048")) * 1024  # MB to KB
            p = int(request.form.get("custom_p", "2"))
            custom_params = {"t": t, "m": m, "p": p}
        except ValueError:
            flash(_('session.invalid_params'), "error")
            return render_template("setup.html", mode="new", is_import=False)

    cfg = ParacciConfig()
    try:
        meta, file_bytes = create_initiator_session(
            label=label,
            session_ttl_sec=session_ttl_sec,
            profile=security_profile,
            custom_params=custom_params,
            my_username=cfg.get("username"),
            color=color
        )
    except ValueError as e:
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
    """Stages a native attachment path in RAM for the next seal request."""
    payload = request.get_json(silent=True) or {}
    native_path = (payload.get("path") or "").strip()
    if not native_path:
        return jsonify({"success": False, "error": "Missing attachment path."}), 400

    content = _import_from_native(native_path)
    if content is None:
        return jsonify({"success": False, "error": "Could not read attachment."}), 400
    if len(content) > MAX_ATTACHMENT_SIZE:
        return jsonify({"success": False, "error": f"Attachment exceeds the {MAX_ATTACHMENT_SIZE // (1024 * 1024)}MB limit."}), 413

    safe_fname = secure_filename(Path(native_path).name) or "attachment.bin"
    content = sanitize_image(content, safe_fname)
    attachment_id = _add_to_staged_attachment_cache(safe_fname, content)
    return jsonify({
        "success": True,
        "id": attachment_id,
        "filename": safe_fname,
        "size": len(content),
    })

def _process_initiator_import(file_bytes, local_label, native_path, color=None):
    """Starts Y role session by processing an incoming Initiator file."""
    if not local_label:
        flash(_('session.label_required'), "error")
        return render_template("setup.html", mode="import", is_import=True)

    try:
        logger.info("Processing Initiator (Argon2id Bond starting)...")
        start_t = time.time()
        cfg = ParacciConfig()
        meta, responder_bytes = accept_initiator_and_create_responder(
            file_bytes, local_label, 
            my_username=cfg.get("username"),
            color=color
        )
        logger.info(f"Bond calculated in {time.time() - start_t:.2f}s")
        _save_session(meta)
        flash(_('session.y_init_success'), "success")
        return redirect(url_for("main.session_detail", sid=meta.session_id.hex(), auto_download="1"))
    except Exception as e:
        logger.error(f"Initiator processing error: {e}")
        flash(_('session.import_error', error=str(e)), "error")
        return render_template("setup.html", mode="import", is_import=True, init_path=native_path)

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
        return redirect(url_for("main.session_detail", sid=updated_meta.session_id.hex()))
    except Exception as e:
        flash(_('session.import_error', error=str(e)), "error")
        return render_template("setup.html", mode="import", is_import=True)

@bp.route("/session/import", methods=["GET", "POST"])
def session_import():
    """Imports incoming session files (Init/Resp)."""
    if request.method == "GET":
        init_path = request.args.get("native_path", "")
        return render_template("setup.html", mode="import", is_import=True, init_path=init_path)

    local_label = request.form.get("label", "").strip()
    native_path = request.form.get("native_path")
    file_bytes  = None

    if native_path:
        file_bytes = _import_from_native(native_path)
        if not file_bytes:
            flash(f"Could not read file: {native_path}", "error")
            return render_template("setup.html", mode="import", is_import=True, init_path=native_path)
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
        return render_template("setup.html", mode="import", init_path=native_path)

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
            
        return _process_initiator_import(file_bytes, local_label, native_path, color=color)
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

    # Fingerprint (Security Code)
    fingerprint = None
    if meta.peer_pub:
        fingerprint = get_fingerprint(meta.my_pub, meta.peer_pub)

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
            fingerprint=fingerprint,
        )

    return render_template(
        "session.html",
        meta=meta, sid=sid, evo_info=evo_info,
        now=int(time.time()),
        fingerprint=fingerprint,
    )

@bp.route("/session/<sid>/import_responder", methods=["POST"])
def session_import_responder(sid: str):
    """Imports the Responder file for a specific session."""
    meta = _load_session(sid)
    if meta is None: abort(404)

    if meta.role != "X":
        flash(_('session.error_x_only_responder'), "error")
        return redirect(url_for("main.session_detail", sid=sid))

    native_path = request.form.get("native_path", "").strip()
    file_bytes = None
    if native_path:
        file_bytes = _import_from_native(native_path)
        if not file_bytes:
            flash(f"Could not read file: {native_path}", "error")
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
        safe_fname = secure_filename(f.filename) or "attachment.bin"
        content = f.read()
        total_size += len(content)
        if total_size > MAX_ATTACHMENT_SIZE:
            return None, f"Total file size exceeds the {MAX_ATTACHMENT_SIZE // (1024*1024)}MB limit."
        content = sanitize_image(content, safe_fname)
        files.append((safe_fname, content))

    for attachment_id in staged_id_list:
        staged = STAGED_ATTACHMENT_CACHE.pop(attachment_id, None)
        if not staged or staged["expires"] < time.time():
            return None, "A staged attachment expired. Please attach it again."
        total_size += len(staged["content"])
        if total_size > MAX_ATTACHMENT_SIZE:
            return None, f"Total file size exceeds the {MAX_ATTACHMENT_SIZE // (1024*1024)}MB limit."
        files.append((staged["filename"], staged["content"]))

    return files, None

@bp.route("/session/<sid>/seal", methods=["POST"])
def session_seal(sid: str):
    """Creates a Paracci envelope by encrypting the message and attachments."""
    meta = _load_session(sid)
    if meta is None: abort(404)

    if meta.state != "active" or not meta.is_bonded:
        flash(_('session.not_active' if meta.state != "active" else ('session.bond_not_established_x' if meta.role == "X" else 'session.bond_not_established_y')), "error")
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

    package_blob = create_package(text, files, allow_download=allow_download)
    try:
        sealed = seal_envelope(package_blob, meta, single_use=True, ttl_seconds=ttl_seconds)
        updated = meta._replace(tx_count=meta.tx_count + 1, send_seed=sealed.next_seed)
        _save_session(updated)
        return send_file(io.BytesIO(sealed.file_bytes), mimetype="application/octet-stream", as_attachment=True, download_name=f"msg_{sealed.msg_id.hex()[:12]}.paracci")
    except Exception as e:
        logger.exception("Message could not be encrypted")
        flash(f"Message could not be encrypted: {e}", "error")
        return redirect(url_for("main.session_detail", sid=sid))


def _prepare_open_response(meta, opened, sid, is_ajax):
    """Prepares opened message content for visualization."""
    if opened.bond_nonce and meta.role == "Y" and meta.bond_seed is None:
        meta = apply_bond_nonce_to_y(meta, opened.bond_nonce)
    updated_meta = meta._replace(rx_count=opened.next_step, recv_seed=opened.next_seed)
    _save_session(updated_meta)

    fingerprint = get_fingerprint(updated_meta.my_pub, updated_meta.peer_pub) if updated_meta.peer_pub else None
    evo_info = {"tx_count": updated_meta.tx_count, "bonded": updated_meta.is_bonded, "secs_remaining": seconds_until_expiry(updated_meta.evo_config)} if updated_meta.keys else None

    package = extract_package(opened.payload)
    display_data = package_to_template_data(package)
    security_report = scan_text_for_security(display_data["text"])

    attachments = []
    for att in package.attachments:
        pid = _add_to_preview_cache(att.filename, att.content, att.mime_type, display_data["allow_download"])
        attachments.append({"pid": pid, "filename": att.filename, "mime_type": att.mime_type, "size": len(att.content), "is_media": att.mime_type.startswith(("image/", "video/"))})

    if is_ajax:
        return jsonify({"success": True, "text": display_data["text"], "attachments": attachments, "allow_download": display_data["allow_download"], "time_left": _fmt_time_left(opened.expire_at), "expire_at": opened.expire_at, "evo_step": opened.evo_step, "single_use": opened.single_use, "msg_id_hex": opened.msg_id.hex(), "fingerprint": fingerprint, "rx_count": updated_meta.rx_count, "security_report": security_report})

    return render_template("session.html", meta=updated_meta, sid=sid, evo_info=evo_info, now=int(time.time()), fingerprint=fingerprint, opened_msg={"text": display_data["text"], "attachments": attachments, "allow_download": display_data["allow_download"], "time_left": _fmt_time_left(opened.expire_at), "expire_at": opened.expire_at, "evo_step": opened.evo_step, "single_use": opened.single_use, "msg_id_hex": opened.msg_id.hex(), "security_report": security_report})

@bp.route("/session/<sid>/open", methods=["POST"])
def session_open(sid: str):
    """Opens an encrypted Paracci envelope and displays its content."""
    is_ajax = request.headers.get("X-Requested-With") == "XMLHttpRequest" or request.args.get("ajax") == "1"
    meta = _load_session(sid)
    if meta is None: return (jsonify({"success": False, "error": "Session not found."}), 404) if is_ajax else abort(404)

    if meta.state != "active":
        msg = _('session.not_active')
        return jsonify({"success": False, "error": msg}) if is_ajax else (flash(msg, "error") or redirect(url_for("main.session_detail", sid=sid)))

    native_path = request.form.get("native_path", "").strip()
    uploaded = request.files.get("paracci_file")
    file_bytes = None
    if native_path:
        file_bytes = _import_from_native(native_path)
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
        guard.pre_open_check(msg_id=raw["msg_id"], expire_at=raw["expire_at"], single_use=raw["single_use"])
        opened = open_envelope(file_bytes, meta)
        
        if opened.bond_nonce is not None and not meta.is_bonded:
            try:
                meta = apply_bond_nonce_to_y(meta, opened.bond_nonce)
                _save_session(meta)
            except Exception as e: flash(f"Error while establishing bond: {e}", "warning")

        guard.post_open_burn(msg_id=opened.msg_id, session_id=opened.session_id, direction=opened.direction, single_use=opened.single_use, file_path=native_path)
        return _prepare_open_response(meta, opened, sid, is_ajax)
    except (AlreadyBurnedError, TTLExpiredError) as e:
        msg = "This message was already opened or has expired."
        return jsonify({"success": False, "error": msg}) if is_ajax else _render_session_error(meta, sid, msg)
    except Exception as e:
        if is_ajax: return jsonify({"success": False, "error": str(e)})
        return _render_session_error(meta, sid, str(e))


def _render_session_error(meta, sid, msg):
    """Renders the session page with an error message."""
    evo_info = None
    if meta.keys:
        evo_info = {
            "tx_count":       meta.tx_count,
            "bonded":         meta.is_bonded,
            "secs_remaining": seconds_until_expiry(meta.evo_config),
        }
    # Fingerprint (Security Code)
    fingerprint = None
    if meta.peer_pub:
        fingerprint = get_fingerprint(meta.my_pub, meta.peer_pub)

    return render_template(
        "session.html", meta=meta, sid=sid, evo_info=evo_info,
        now=int(time.time()), open_error=msg,
        fingerprint=fingerprint,
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

    if meta.role == "X" and meta.state == "pending":
        try:
            file_bytes = serialize_initiator_file(meta)
            filename   = f"session_init_{sid[:8]}.paracci"
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
                y_qseed=meta.my_qseed
            )
            filename = f"session_resp_{sid[:8]}.paracci"
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

@bp.route("/settings", methods=["GET", "POST"])
def settings():
    """Manages general application settings."""
    cfg = ParacciConfig()
    
    if request.method == "POST":
        # Get checkbox values
        anti_screenshot = True if request.form.get("anti_screenshot") else False
        quiet_mode      = True if request.form.get("quiet_mode") else False
        
        cfg.set("anti_screenshot", anti_screenshot)
        cfg.set("quiet_mode", quiet_mode)
        cfg.set("default_ttl", int(request.form.get("default_ttl", 0)))
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
    """Prepares necessary data and mode for the preview page."""
    filename = file_data["filename"]
    mime = file_data["mime"]
    ext = Path(filename).suffix.lower()
    is_dangerous = ext in DANGEROUS_EXTENSIONS
    is_code = ext in CODE_EXTENSIONS
    mode = "image" if mime.startswith("image/") else ("video" if mime.startswith("video/") else ("text" if mime == "text/plain" else ("pdf" if mime == "application/pdf" else "default")))

    if is_code or is_dangerous:
        try:
            return render_template("preview.html", pid=pid, filename=filename, mode="code", code_content=file_data["content"].decode("utf-8", errors="replace"), lang=ext[1:] if ext else "txt", is_dangerous=is_dangerous, allow_download=file_data["allow_download"])
        except:
            return render_template("preview.html", pid=pid, filename=filename, mode="default", mime=mime, is_dangerous=True, allow_download=file_data["allow_download"])
    if mode == "text":
        return render_template("preview.html", pid=pid, filename=filename, mode=mode, mime=mime, code_content=file_data["content"].decode("utf-8", errors="replace"), is_dangerous=False, allow_download=file_data["allow_download"])
    return render_template("preview.html", pid=pid, filename=filename, mode=mode, mime=mime, is_dangerous=False, allow_download=file_data["allow_download"])

@bp.route("/preview/<pid>")
def preview(pid: str):
    """Provides a secure preview of a file inside a package."""
    file_data = PREVIEW_CACHE.get(pid)
    if not file_data: return f"<h3>{_('preview.not_found_title')}</h3><p>{_('preview.not_found_desc')}</p>", 404

    if request.args.get("raw") == "1":
        return send_file(io.BytesIO(file_data["content"]), mimetype=file_data["mime"], as_attachment=False)

    resp_html = _get_preview_response_data(file_data, pid)
    response = make_response(resp_html)
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; media-src 'self' data:; object-src 'none'; base-uri 'none';"
    return response


# ---------------------------------------------------------------------------
# GET /preview/<pid>/download — Download from preview page
# ---------------------------------------------------------------------------

@bp.route("/preview/<pid>/download")
def preview_download(pid: str):
    """Allows downloading a previewed file."""
    file_data = PREVIEW_CACHE.get(pid)
    if not file_data or not file_data["allow_download"]:
        abort(403)

    return send_file(
        io.BytesIO(file_data["content"]),
        mimetype=file_data["mime"],
        as_attachment=True,
        download_name=file_data["filename"]
    )


# ---------------------------------------------------------------------------
# GET /armor-report — Armor Calibration Report
# ---------------------------------------------------------------------------

@bp.route("/armor-report")
def armor_report():
    """Displays the most recent armor report based on the user's language."""
    lang = session.get('locale', 'tr')
    reports_dir = APP_DIR / "reports"
    
    # Find reports: armor_report_*_{lang}.md
    report_files = list(reports_dir.glob(f"armor_report_*_{lang}.md"))
    
    if not report_files:
        # If no language-specific report, try default (tr)
        report_files = list(reports_dir.glob("armor_report_*_tr.md"))
        
    if not report_files:
        abort(404, description="Report file not found.")
        
    # Get the latest one (sort by name)
    latest_report = sorted(report_files)[-1]
    
    try:
        with open(latest_report, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception as e:
        abort(500, description=f"Report read error: {e}")
        
    return render_template("report_viewer.html", content=content, title=_('nav.armor_report'))


# ---------------------------------------------------------------------------
# API: Get Latest Hardware Benchmark Report
# ---------------------------------------------------------------------------

@bp.route("/api/benchmark-report")
def api_benchmark_report():
    """Returns the system verification (benchmark) report in JSON format."""
    lang = session.get('locale', 'tr')
    reports_dir = APP_DIR / "reports"
    
    report_files = list(reports_dir.glob(f"armor_report_*_{lang}.md"))
    if not report_files:
        report_files = list(reports_dir.glob("armor_report_*_tr.md"))
    
    if not report_files:
        return jsonify({"success": False, "message": _('benchmark.not_found')}), 404
        
    try:
        latest_report = sorted(report_files)[-1]
        with open(latest_report, "r", encoding="utf-8") as f:
            content = f.read()
        return jsonify({"success": True, "report": content})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

    return jsonify({"success": False, "message": "Unknown error"}), 500


# ---------------------------------------------------------------------------
# 404
# ---------------------------------------------------------------------------

@bp.app_errorhandler(404)
def not_found(e):
    """404 Error page: Displays a friendly error screen to the user."""
    return render_template("base.html", error_404=True), 404
