import sys
from pathlib import Path
import pytest
from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from test_loopback_security import (
    HOST,
    ORIGIN,
    _make_active_handshake,
    _save_meta,
    _unlock_test_client,
    auth_headers,
    bootstrap,
    make_flask_app,
)

def multipart_file(payload: bytes, filename="message.paracci"):
    import io
    return io.BytesIO(payload), filename

@oqs_required
def test_session_open_ingestion_limit_error_returns_generic_message(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module
    from core.ingest_limits import IngestionLimitError

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_y)

    def raise_ingestion_limit(*args, **kwargs):
        raise IngestionLimitError("internal limit details 123")

    monkeypatch.setattr(routes_module, "copy_stream_limited", raise_ingestion_limit)
    monkeypatch.setattr(routes_module, "ensure_path_within_limit", raise_ingestion_limit)

    # Test AJAX response
    ajax_opened = client.post(
        f"/session/{meta_y.session_id.hex()}/open?ajax=1",
        base_url=ORIGIN,
        data={"paracci_file": multipart_file(b"payload data")},
        headers=auth_headers(client, **{"X-Requested-With": "XMLHttpRequest"}),
        content_type="multipart/form-data",
    )

    assert ajax_opened.status_code == 400
    ajax_json = ajax_opened.get_json()
    assert ajax_json["success"] is False
    assert ajax_json["error"] == "The selected message file is too large or could not be processed safely."
    assert "internal limit details 123" not in ajax_opened.get_data(as_text=True)

    # Test Non-AJAX response (Flash)
    non_ajax_opened = client.post(
        f"/session/{meta_y.session_id.hex()}/open",
        base_url=ORIGIN,
        data={"paracci_file": multipart_file(b"payload data")},
        headers=auth_headers(client),
        content_type="multipart/form-data",
    )

    assert non_ajax_opened.status_code == 302
    assert "internal limit details 123" not in non_ajax_opened.get_data(as_text=True)

    with client.session_transaction(base_url=ORIGIN) as sess:
        flashes = dict(sess.get("_flashes", []))
        assert flashes.get("error") == "The selected message file is too large or could not be processed safely."
        assert "internal limit details 123" not in str(flashes)

@oqs_required
def test_session_open_native_file_ingestion_limit_error_returns_generic_message(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module
    from core.ingest_limits import IngestionLimitError

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_y)

    def raise_ingestion_limit(*args, **kwargs):
        raise IngestionLimitError("native limit details 456")

    monkeypatch.setattr(routes_module, "ensure_path_within_limit", raise_ingestion_limit)
    monkeypatch.setattr(routes_module, "_resolve_native_file_ref", lambda ref_id: {"path": "/fake/native/path.paracci"})

    # Test AJAX response
    ajax_opened = client.post(
        f"/session/{meta_y.session_id.hex()}/open?ajax=1",
        base_url=ORIGIN,
        data={"native_file_id": "fake_ref_id"},
        headers=auth_headers(client, **{"X-Requested-With": "XMLHttpRequest"}),
    )

    assert ajax_opened.status_code == 400
    ajax_json = ajax_opened.get_json()
    assert ajax_json["success"] is False
    assert ajax_json["error"] == "The selected message file is too large or could not be processed safely."
    assert "native limit details 456" not in ajax_opened.get_data(as_text=True)

    # Test Non-AJAX response (Flash)
    non_ajax_opened = client.post(
        f"/session/{meta_y.session_id.hex()}/open",
        base_url=ORIGIN,
        data={"native_file_id": "fake_ref_id"},
        headers=auth_headers(client),
    )

    assert non_ajax_opened.status_code == 302
    assert "native limit details 456" not in non_ajax_opened.get_data(as_text=True)

    with client.session_transaction(base_url=ORIGIN) as sess:
        flashes = dict(sess.get("_flashes", []))
        assert flashes.get("error") == "The selected message file is too large or could not be processed safely."
        assert "native limit details 456" not in str(flashes)
