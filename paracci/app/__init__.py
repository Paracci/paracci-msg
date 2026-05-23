"""
Paracci — app/__init__.py
Flask application factory.
"""

import os
import sys
import datetime
from pathlib import Path
from flask import Flask
from .i18n_manager import i18n
from core.burn import BurnDB

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


def create_app() -> Flask:
    """Initializes and configures the Paracci Flask application factory."""
    global db, device_key, loopback_token, loopback_host, loopback_port, loopback_origin, no_gui_mode, active_client_id

    app = Flask(__name__, 
                template_folder=str(APP_DIR / "templates"), 
                static_folder=str(APP_DIR / "static"))

    loopback_token = os.environ.get("PARACCI_LOOPBACK_TOKEN")
    loopback_host = os.environ.get("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    loopback_port = os.environ.get("PARACCI_LOOPBACK_PORT")
    no_gui_mode = os.environ.get("PARACCI_NO_GUI") == "1"
    if not loopback_token or not loopback_port:
        raise RuntimeError("Paracci loopback security token and port must be set before app initialization.")
    loopback_origin = f"http://{loopback_host}:{loopback_port}"
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
