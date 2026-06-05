import importlib
import io
import sys
from pathlib import Path

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.burn import BurnDB, unlock_device
from core.crypto import wipe
from core.envelope import seal_envelope
from core.package import create_package
from core.session import deserialize_session_meta
from paracci.tools import dev_setup


TOKEN = "test-dev-setup-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"


def _load_generated_session(data_dir: Path):
    bootstrap_db = BurnDB(data_dir / "sessions.db")
    device_key = unlock_device(bootstrap_db, dev_setup.DEFAULT_PIN)
    keyed_db = bootstrap_db.with_device_key(device_key)
    try:
        sessions = keyed_db.list_sessions()
        assert len(sessions) == 1
        row = keyed_db.load_session(sessions[0]["session_id"])
        assert row is not None
        return device_key, deserialize_session_meta(row[2], device_key)
    finally:
        keyed_db.release_device_key()
        bootstrap_db.close()


def _bootstrap(client):
    return client.get(
        f"/__paracci_bootstrap?token={TOKEN}&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )


def _auth_headers(client):
    with client.session_transaction(base_url=ORIGIN) as sess:
        csrf_token = sess["csrf_token"]
    return {
        "Host": HOST,
        "X-Paracci-Token": TOKEN,
        "X-CSRF-Token": csrf_token,
        "X-Requested-With": "XMLHttpRequest",
        "Origin": ORIGIN,
    }


def _load_app_session(ag_app, session_id: bytes):
    row = ag_app.db.load_session(session_id)
    assert row is not None
    return deserialize_session_meta(row[2], ag_app.device_key)


@oqs_required
def test_generated_profiles_unlock_cleanly_and_first_message_bonds_y(
    tmp_path,
    monkeypatch,
):
    dev_setup.create_dev_profiles(tmp_path)
    data_x = tmp_path / "data_x"
    data_y = tmp_path / "data_y"

    for data_dir in (data_x, data_y):
        db = BurnDB(data_dir / "sessions.db")
        try:
            rate_limit = db.get_unlock_rate_limit()
            assert rate_limit["failed_attempts"] == 0
            assert rate_limit["locked_until"] == 0
            assert rate_limit["retry_after_seconds"] == 0
        finally:
            db.close()

    monkeypatch.setenv("DATA_DIR", str(data_x))
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "1")

    import app as ag_app

    ag_app = importlib.reload(ag_app)
    for data_dir in (data_x, data_y):
        flask_app = ag_app.create_app(loopback_auth_token=TOKEN, data_dir=data_dir)
        flask_app.config["TESTING"] = True
        client = flask_app.test_client()
        _bootstrap(client)
        unlock_page = client.get("/unlock", base_url=ORIGIN, headers={"Host": HOST})
        assert unlock_page.status_code == 200
        assert b'data-lockout-seconds="0"' in unlock_page.data
        assert b'id="lockoutAlert"' not in unlock_page.data

    key_x, meta_x = _load_generated_session(data_x)
    key_y, meta_y = _load_generated_session(data_y)
    assert meta_x.session_id == meta_y.session_id
    assert meta_x.role == "X"
    assert meta_x.tx_count == 0
    assert meta_x.rx_count == 0
    assert meta_x.bond_nonce is not None
    assert meta_x.is_bonded
    assert meta_x.can_send

    assert meta_y.role == "Y"
    assert meta_y.tx_count == 0
    assert meta_y.rx_count == 0
    assert meta_y.state == "active"
    assert not meta_y.is_bonded
    assert meta_y.bond_seed is None
    assert meta_y.send_seed is None
    assert meta_y.recv_seed is None
    assert meta_y.bond_nonce is None
    assert meta_y.can_open
    assert not meta_y.can_send

    corrupt_sealed = seal_envelope(
        create_package("corrupt dev setup candidate", [], allow_download=False),
        meta_x,
    )
    corrupt_bytes = bytearray(corrupt_sealed.file_bytes)
    corrupt_bytes[-1] ^= 0x01
    valid_sealed = seal_envelope(
        create_package("dev setup first message", [], allow_download=False),
        meta_x,
    )

    flask_app = ag_app.create_app(loopback_auth_token=TOKEN, data_dir=data_y)
    flask_app.config["TESTING"] = True
    client = flask_app.test_client()
    _bootstrap(client)

    ag_app.device_key = key_y
    ag_app.db = ag_app.db.with_device_key(key_y)
    with client.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]

    try:
        rejected = client.post(
            f"/session/{meta_y.session_id.hex()}/open?ajax=1",
            base_url=ORIGIN,
            data={
                "paracci_file": (
                    io.BytesIO(bytes(corrupt_bytes)),
                    "corrupt.paracci",
                )
            },
            headers=_auth_headers(client),
            content_type="multipart/form-data",
        )
        assert rejected.status_code == 400
        assert rejected.get_json() == {
            "success": False,
            "error": "Invalid or corrupt file.",
        }
        after_rejection = _load_app_session(ag_app, meta_y.session_id)
        assert after_rejection.rx_count == 0
        assert after_rejection.recv_seed is None
        assert not after_rejection.is_bonded

        opened = client.post(
            f"/session/{meta_y.session_id.hex()}/open?ajax=1",
            base_url=ORIGIN,
            data={
                "paracci_file": (
                    io.BytesIO(valid_sealed.file_bytes),
                    "first-message.paracci",
                )
            },
            headers=_auth_headers(client),
            content_type="multipart/form-data",
        )
        assert opened.status_code == 200
        assert opened.get_json()["success"] is True
        assert opened.get_json()["text"] == "dev setup first message"

        bonded_y = _load_app_session(ag_app, meta_y.session_id)
        assert bonded_y.is_bonded
        assert bonded_y.rx_count == 1
        assert bonded_y.recv_seed is not None
        assert bonded_y.can_send
    finally:
        ag_app.lock_device()
        wipe(key_x)
