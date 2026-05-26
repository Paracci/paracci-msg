import importlib
import os
import sys
import time
from pathlib import Path
import pytest

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

TOKEN = "test-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"


def make_flask_app(tmp_path, monkeypatch, no_gui=True):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "1" if no_gui else "0")

    import app as ag_app

    ag_app = importlib.reload(ag_app)
    flask_app = ag_app.create_app(loopback_auth_token=TOKEN)
    flask_app.config["TESTING"] = True
    return ag_app, flask_app


def bootstrap(client):
    return client.get(
        f"/__paracci_bootstrap?token={TOKEN}&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )


def csrf_from(client):
    with client.session_transaction(base_url=ORIGIN) as sess:
        return sess["csrf_token"]


def auth_headers(client, **extra):
    headers = {
        "Host": HOST,
        "X-Paracci-Token": TOKEN,
        "X-CSRF-Token": csrf_from(client),
        "Origin": ORIGIN,
    }
    headers.update(extra)
    return headers


def _unlock_test_client(ag_app, client):
    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "Correct-Horse-95175328")
    ag_app.db = ag_app.db.with_device_key(ag_app.device_key)
    with client.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]


def test_lock_device_wipes_device_key(tmp_path, monkeypatch):
    """Verify lock_device() clears ag_app.device_key and zeroizes the key bytes."""
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    key_bytes = bytearray(b"0" * 32)
    ag_app.device_key = key_bytes

    ag_app.lock_device()

    assert ag_app.device_key is None
    # Original bytearray must be zeroed
    assert key_bytes == bytearray(32)


def test_lock_device_demotes_db(tmp_path, monkeypatch):
    """Verify lock_device() transitions BurnDB back to unkeyed state."""
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    from core.burn import init_device

    init_device(ag_app.db, "Correct-Horse-95175328")
    ag_app.device_key = bytearray(b"0" * 32)
    ag_app.db = ag_app.db.with_device_key(ag_app.device_key)
    assert ag_app.db.has_device_key is True

    ag_app.lock_device()

    assert ag_app.db.has_device_key is False


def test_inactivity_timer_fires_and_locks(tmp_path, monkeypatch):
    """Verify that the inactivity timer automatically locks the app when it expires."""
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    ag_app.device_key = bytearray(b"0" * 32)
    ag_app.db = ag_app.db.with_device_key(ag_app.device_key)

    ag_app.init_inactivity_timer(1)
    ag_app.inactivity_timer._timeout = 0.05

    ag_app.inactivity_timer.start(flask_testing=False)
    assert ag_app.device_key is not None

    time.sleep(0.15)
    assert ag_app.device_key is None
    assert ag_app.db.has_device_key is False


def test_authenticated_request_resets_timer(tmp_path, monkeypatch):
    """Verify that authenticated loopback requests reset the inactivity timer."""
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    # Disable TESTING mode temporarily so the request reset hook is active
    flask_app.config["TESTING"] = False

    ag_app.inactivity_timer._timeout = 0.15
    ag_app.inactivity_timer.start(flask_testing=False)

    time.sleep(0.08)
    assert ag_app.device_key is not None

    # Authenticated request resets the timer
    response = client.get("/", base_url=ORIGIN, headers=auth_headers(client))
    assert response.status_code != 403

    # Wait another 0.1 seconds (0.18s since start). If not reset, it would have locked by now.
    time.sleep(0.1)
    assert ag_app.device_key is not None

    # Wait another 0.1 seconds (0.28s since start, 0.2s since reset). Now it should lock.
    time.sleep(0.1)
    assert ag_app.device_key is None


def test_timeout_zero_disables_autolock(tmp_path, monkeypatch):
    """Verify that a timeout of 0 disables the inactivity timer."""
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    ag_app.device_key = bytearray(b"0" * 32)

    ag_app.init_inactivity_timer(0)
    ag_app.inactivity_timer.start(flask_testing=False)

    time.sleep(0.1)
    assert ag_app.device_key is not None


def test_flask_testing_disables_timer(tmp_path, monkeypatch):
    """Verify that passing flask_testing=True disables the timer."""
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    ag_app.device_key = bytearray(b"0" * 32)

    ag_app.init_inactivity_timer(0.05)
    ag_app.inactivity_timer.start(flask_testing=True)

    time.sleep(0.1)
    assert ag_app.device_key is not None


def test_api_lock_route_locks_device(tmp_path, monkeypatch):
    """Verify that POST /api/lock explicitly locks the device."""
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    assert ag_app.device_key is not None

    response = client.post(
        "/api/lock",
        base_url=ORIGIN,
        headers=auth_headers(client),
    )
    assert response.status_code == 200
    assert response.get_json() == {"locked": True}
    assert ag_app.device_key is None


def test_locked_device_redirects_to_unlock(tmp_path, monkeypatch):
    """Verify that requests to protected routes redirect to /unlock if device is locked."""
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    ag_app.lock_device()

    response = client.get("/session/new", base_url=ORIGIN, headers=auth_headers(client))
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/unlock")


def test_lock_device_clears_clipboard(tmp_path, monkeypatch):
    """Verify that lock_device() clears the clipboard via shield."""
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    from core.shields import shield
    called_clear = False

    def mock_clear():
        nonlocal called_clear
        called_clear = True
        return True

    monkeypatch.setattr(shield, "clear_owned_clipboard", mock_clear)

    ag_app.lock_device()

    assert called_clear is True
