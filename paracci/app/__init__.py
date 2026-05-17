"""
Paracci — app/__init__.py
Flask application factory.
"""

import os
import sys
from pathlib import Path
from flask import Flask
from .i18n_manager import i18n
from core.burn import BurnDB

# Project root directory: paracci/
# _MEIPASS check for PyInstaller compatibility
if hasattr(sys, '_MEIPASS'):
    ROOT_DIR = Path(sys._MEIPASS)
else:
    ROOT_DIR = Path(__file__).parent.parent

# Application directory (templates and static are located here)
APP_DIR = Path(__file__).parent
if hasattr(sys, '_MEIPASS'):
    # When packaged, APP_DIR is the paracci/app folder within _MEIPASS
    APP_DIR = ROOT_DIR / "paracci" / "app"
# Use DATA_DIR environment variable if it exists, otherwise default to "data"
env_data_dir = os.environ.get("DATA_DIR")
if env_data_dir:
    DATA_DIR = Path(env_data_dir).absolute()
else:
    DATA_DIR = ROOT_DIR / "data"

DATA_DIR.mkdir(parents=True, exist_ok=True)

# Global shared objects (imported in routes.py)
db = None
device_key = None
PENDING_UNLOCKS = {} # Memory-only store for device_key during 2FA (prevents double Argon2)


def create_app() -> Flask:
    """Initializes and configures the Paracci Flask application factory."""
    global db, device_key

    app = Flask(__name__, 
                template_folder=str(APP_DIR / "templates"), 
                static_folder=str(APP_DIR / "static"))

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

    return app
