import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

TOKEN = "test-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"


def make_flask_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "1")

    import app as ag_app

    ag_app = importlib.reload(ag_app)
    flask_app = ag_app.create_app(loopback_auth_token=TOKEN)
    flask_app.config["TESTING"] = True
    return ag_app, flask_app


def test_session_cookie_samesite_is_lax(tmp_path, monkeypatch):
    """
    Verifies that the session cookie SameSite policy is set to 'Lax'.
    This ensures that when a new preview window is opened, the session cookie is shared
    correctly with it, preventing pywebview/WebView2 from overwriting/clearing
    the main window's session cookies upon closing the preview window.
    """
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    
    # 1. Assert the Flask configuration is set to 'Lax'
    assert flask_app.config["SESSION_COOKIE_SAMESITE"] == "Lax"

    # 2. Check the actual Set-Cookie header returned upon bootstrap
    client = flask_app.test_client()
    response = client.get(
        f"/__paracci_bootstrap?token={TOKEN}&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert response.status_code == 200
    
    cookies = response.headers.getlist("Set-Cookie")
    assert len(cookies) > 0

    session_cookie_found = False
    for cookie in cookies:
        if "paracci_session=" in cookie:
            session_cookie_found = True
            cookie_lower = cookie.lower()
            assert "samesite=lax" in cookie_lower
            assert "samesite=strict" not in cookie_lower
            assert ("expires=" in cookie_lower) or ("max-age=" in cookie_lower), "Session cookie is not persistent (missing expires or max-age)"

    assert session_cookie_found, "paracci_session cookie was not set in the response headers"


def test_preview_routes_do_not_save_session(tmp_path, monkeypatch):
    """
    Verifies that requests to preview routes do not send a Set-Cookie header for the session,
    thereby protecting the main window's session cookie from being overwritten or cleared.
    """
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()

    # 1. Bootstrap to establish a session
    client.get(
        f"/__paracci_bootstrap?token={TOKEN}&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    # 2. Make a request to a preview route. It should not save the session.
    dummy_token = "a" * 32
    response = client.get(
        f"/preview/{dummy_token}",
        base_url=ORIGIN,
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    # Verify that Set-Cookie is not present in the response headers for the preview route
    cookies = response.headers.getlist("Set-Cookie")
    for cookie in cookies:
        assert "paracci_session=" not in cookie, "Session cookie was sent/saved on a preview route!"
