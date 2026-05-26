"""
Paracci — app/__init__.py
Flask application factory.
"""

import os
import sys
import threading
import datetime
import logging
from pathlib import Path
from flask import Flask
from .i18n_manager import i18n
from core.burn import BurnDB
from core.crypto import wipe

logger = logging.getLogger(__name__)

# Project root directory: paracci/
# _MEIPASS check for PyInstaller compatibility
if hasattr(sys, '_MEIPASS'):
    ROOT_DIR = Path(sys._MEIPASS)
    # When packaged, check directory next to the executable
    EXE_DIR = Path(sys.executable).parent
else:
    ROOT_DIR = Path(__file__).parent.parent
    EXE_DIR = ROOT_DIR

# Application directory (templates and static are located here)
APP_DIR = Path(__file__).parent
if hasattr(sys, '_MEIPASS'):
    # When packaged, APP_DIR is the paracci/app folder within _MEIPASS
    APP_DIR = ROOT_DIR / "paracci" / "app"

# Smart Persistent DATA_DIR Selection:
# 1. Environment Variable check (Override)
# 2. Portable Mod check: if a folder named "data" already exists next to the EXE, go portable!
# 3. Standard Mod check (Default): Use the safe, hidden, non-deletable OS AppData directory to prevent accidental deletions
env_data_dir = os.environ.get("DATA_DIR")
local_data_dir = EXE_DIR / "data"

if env_data_dir:
    DATA_DIR = Path(env_data_dir).absolute()
    DATA_MODE = "override"
elif local_data_dir.exists() and local_data_dir.is_dir():
    DATA_DIR = local_data_dir
    DATA_MODE = "portable"
else:
    DATA_MODE = "standard"
    # OS AppData
    if sys.platform == "win32":
        appdata_root = os.environ.get("LOCALAPPDATA")
        if appdata_root:
            DATA_DIR = Path(appdata_root) / "Paracci"
        else:
            DATA_DIR = Path.home() / "AppData" / "Local" / "Paracci"
    elif sys.platform == "darwin":
        DATA_DIR = Path.home() / "Library" / "Application Support" / "Paracci"
    else:
        xdg_data_root = os.environ.get("XDG_DATA_HOME")
        if xdg_data_root:
            DATA_DIR = Path(xdg_data_root) / "paracci"
        else:
            DATA_DIR = Path.home() / ".local" / "share" / "paracci"

# Set in os.environ so all other core modules automatically use the same persistent path
os.environ["DATA_DIR"] = str(DATA_DIR)

DATA_DIR.mkdir(parents=True, exist_ok=True)

# Global shared objects (imported in routes.py)
db = None
device_key = None
PENDING_UNLOCKS = {} # Memory-only store for device_key during 2FA (prevents double Argon2)
loopback_token = None
loopback_host = "127.0.0.1"
loopback_port = None
loopback_origin = None
no_gui_mode = False
active_client_id = None

# ---------------------------------------------------------------------------
# Inactivity timer
# ---------------------------------------------------------------------------

_inactivity_timer: threading.Timer | None = None
_inactivity_timer_lock = threading.Lock()


class InactivityTimer:
    """Background auto-lock timer driven by threading.Timer.

    Call reset() on every authenticated request to restart the countdown.
    A timeout_seconds of 0 disables the timer entirely.  Pass
    flask_testing=True when running under pytest to keep tests deterministic.
    """

    def __init__(self, timeout_seconds: int) -> None:
        self._timeout = max(0, int(timeout_seconds))
        self._lock = threading.Lock()
        self._timer: threading.Timer | None = None

    @property
    def timeout_seconds(self) -> int:
        return self._timeout

    def reset(self, flask_testing: bool = False) -> None:
        """Cancel any running timer and start a fresh one (unless disabled)."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None
            if self._timeout == 0 or flask_testing:
                return
            t = threading.Timer(self._timeout, lock_device)
            t.daemon = True
            t.start()
            self._timer = t

    # Alias used at unlock time for clarity at call sites.
    def start(self, flask_testing: bool = False) -> None:
        self.reset(flask_testing=flask_testing)

    def cancel(self) -> None:
        """Cancel the running timer without locking the device."""
        with self._lock:
            if self._timer is not None:
                self._timer.cancel()
                self._timer = None


# Module-level singleton — replaced by init_inactivity_timer() after create_app().
inactivity_timer: InactivityTimer = InactivityTimer(0)  # disabled until configured


def init_inactivity_timer(timeout_seconds: int) -> None:
    """Create (or replace) the module-level inactivity timer.

    Called once from run.py after create_app() so the timeout value from
    ParacciConfig is available.  Must not be called during module import.
    """
    global inactivity_timer
    inactivity_timer = InactivityTimer(timeout_seconds)


# ---------------------------------------------------------------------------
# Explicit lock action
# ---------------------------------------------------------------------------

def lock_device() -> None:
    """Wipe device_key, demote BurnDB to bootstrap-only, and set locked state.

    Safe to call from any thread (the inactivity timer fires from a daemon
    thread).  Idempotent — calling when already locked is a no-op for the
    sensitive operations.

    Memory hygiene note:
        device_key SHOULD be a bytearray as set by the unlock paths in
        routes.py (initialize_device_with_binding / unlock_device_with_binding
        both return bytearray).  wipe() handles immutable bytes gracefully by
        logging a security event rather than raising — see core/crypto.py.
    """
    global db, device_key, active_client_id

    # 1. Stop the inactivity timer so it does not fire again redundantly.
    inactivity_timer.cancel()

    # 2. Wipe and discard any pending 2FA unlock keys.
    for pending in list(PENDING_UNLOCKS.values()):
        pending_db = pending.get("db")
        if pending_db is not None:
            pending_db.release_device_key()
        pending_key = pending.get("device_key")
        if isinstance(pending_key, (bytearray, bytes)):
            wipe(pending_key)
    PENDING_UNLOCKS.clear()

    # 3. Wipe the live device key.
    if device_key is not None:
        wipe(device_key)
    device_key = None

    # 4. Clear the active client binding so re-bootstrap is required after unlock.
    active_client_id = None

    # 5. Demote BurnDB back to bootstrap-only (unkeyed) mode.
    #    This matches the keyed/unkeyed promotion pattern used in create_app().
    if db is not None:
        db.release_device_key()
    db = BurnDB(DATA_DIR / "sessions.db")

    # 6. Clear system clipboard if it contains Paracci-owned text
    try:
        from core.shields import shield
        shield.clear_owned_clipboard()
    except Exception as exc:
        logger.error("Failed to clear clipboard on lock: %s", exc)


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(*, loopback_auth_token: str) -> Flask:
    """Initializes and configures the Paracci Flask application factory."""
    global db, device_key, loopback_token, loopback_host, loopback_port, loopback_origin, no_gui_mode, active_client_id

    os.environ.pop("PARACCI_LOOPBACK_TOKEN", None)
    if not isinstance(loopback_auth_token, str) or not loopback_auth_token:
        raise RuntimeError("Paracci loopback security token must be supplied directly before app initialization.")
    loopback_token = loopback_auth_token

    app = Flask(__name__, 
                template_folder=str(APP_DIR / "templates"), 
                static_folder=str(APP_DIR / "static"))

    loopback_host = os.environ.get("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    loopback_port = os.environ.get("PARACCI_LOOPBACK_PORT")
    no_gui_mode = os.environ.get("PARACCI_NO_GUI") == "1"
    if not loopback_port:
        raise RuntimeError("Paracci loopback port must be set before app initialization.")
    loopback_origin = f"http://{loopback_host}:{loopback_port}"
    if db is not None:
        db.release_device_key()
    for pending in PENDING_UNLOCKS.values():
        pending_db = pending.get("db")
        if pending_db is not None:
            pending_db.release_device_key()
        pending_key = pending.get("device_key")
        if isinstance(pending_key, bytearray):
            wipe(pending_key)
    PENDING_UNLOCKS.clear()
    if isinstance(device_key, bytearray):
        wipe(device_key)
    device_key = None
    active_client_id = None

    app.config.update(
        TRUSTED_HOSTS=[f"{loopback_host}:{loopback_port}"],
        SESSION_COOKIE_NAME="paracci_session",
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,
        SESSION_REFRESH_EACH_REQUEST=False,
        SESSION_PERMANENT=True,
        PERMANENT_SESSION_LIFETIME=datetime.timedelta(days=1),
    )

    # Persistent secret key for Flask session
    secret_path = DATA_DIR / ".flask_secret"
    if secret_path.exists():
        app.secret_key = secret_path.read_bytes()
    else:
        sk = os.urandom(32)
        secret_path.write_bytes(sk)
        app.secret_key = sk

    # Database (Device key will remain None until PIN is entered)
    db = BurnDB(DATA_DIR / "sessions.db")

    # Blueprint registration
    # NOTE: Imported inside the function to prevent circular dependency.
    from .routes import bp
    app.register_blueprint(bp)

    # Initialize i18n
    i18n.init_app(app)

    # Prevent session cookie from being saved/updated on preview routes
    original_save_session = app.session_interface.save_session

    def custom_save_session(*args, **kwargs):
        from flask import request
        if request.endpoint in {"main.preview", "main.preview_content", "main.preview_download"}:
            return
        return original_save_session(*args, **kwargs)

    app.session_interface.save_session = custom_save_session

    return app
