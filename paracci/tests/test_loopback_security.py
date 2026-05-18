import importlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


TOKEN = "test-loopback-token"
HOST = "127.0.0.1:18080"
ORIGIN = f"http://{HOST}"


def make_flask_app(tmp_path, monkeypatch):
    monkeypatch.setenv("DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("PARACCI_LOOPBACK_TOKEN", TOKEN)
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "18080")
    monkeypatch.setenv("PARACCI_NO_GUI", "1")

    import app as ag_app

    ag_app = importlib.reload(ag_app)
    flask_app = ag_app.create_app()
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


def test_root_requires_bootstrap(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    response = flask_app.test_client().get("/", base_url=ORIGIN, headers={"Host": HOST})

    assert response.status_code == 403


def test_bootstrap_rejects_bad_token(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    response = flask_app.test_client().get(
        "/__paracci_bootstrap?token=bad&next=/",
        base_url=ORIGIN,
        headers={"Host": HOST},
    )

    assert response.status_code == 403


def test_bootstrap_sets_authorized_client_session(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()

    response = bootstrap(client)

    assert response.status_code == 302
    assert response.headers["Location"] == "/"
    with client.session_transaction(base_url=ORIGIN) as sess:
        assert sess["paracci_client_ok"] is True
        assert sess["paracci_client_id"]
        assert sess["csrf_token"]


def test_api_rejects_missing_bearer_after_bootstrap(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    response = client.post(
        "/api/stage-attachment",
        base_url=ORIGIN,
        json={"path": str(tmp_path / "missing.txt")},
        headers={"Host": HOST},
    )

    assert response.status_code == 403


def test_api_rejects_missing_csrf_after_bootstrap(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    response = client.post(
        "/api/stage-attachment",
        base_url=ORIGIN,
        json={"path": str(tmp_path / "missing.txt")},
        headers={"Host": HOST, "X-Paracci-Token": TOKEN},
    )

    assert response.status_code == 403


def test_api_rejects_cross_site_source_headers(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    bad_origin = client.post(
        "/api/stage-attachment",
        base_url=ORIGIN,
        json={"path": str(tmp_path / "missing.txt")},
        headers=auth_headers(client, Origin="http://evil.test"),
    )
    bad_fetch_site = client.post(
        "/api/stage-attachment",
        base_url=ORIGIN,
        json={"path": str(tmp_path / "missing.txt")},
        headers=auth_headers(client, **{"Sec-Fetch-Site": "cross-site"}),
    )

    assert bad_origin.status_code == 403
    assert bad_fetch_site.status_code == 403


def test_api_with_valid_tokens_reaches_route_validation(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "95175328")
    with client.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]

    response = client.post(
        "/api/stage-attachment",
        base_url=ORIGIN,
        json={"path": str(tmp_path / "missing.txt")},
        headers=auth_headers(client),
    )

    assert response.status_code == 400
    assert response.get_json()["error"] == "Could not read attachment."


def test_unexpected_host_is_rejected(tmp_path, monkeypatch):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)

    response = flask_app.test_client().get(
        "/",
        base_url="http://attacker.test:18080",
        headers={"Host": "attacker.test:18080"},
    )

    assert response.status_code == 403


def test_second_bootstrapped_client_cannot_reuse_unlocked_device_key(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client_one = flask_app.test_client()
    client_two = flask_app.test_client()
    bootstrap(client_one)
    bootstrap(client_two)

    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "95175328")
    with client_one.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]

    response = client_two.get("/", base_url=ORIGIN, headers={"Host": HOST})

    assert response.status_code == 403


def _unlock_test_client(ag_app, client):
    from core.burn import init_device

    ag_app.device_key = init_device(ag_app.db, "95175328")
    with client.session_transaction(base_url=ORIGIN) as sess:
        ag_app.active_client_id = sess["paracci_client_id"]


def _save_meta(ag_app, meta):
    from core.session import serialize_session_meta

    ag_app.db.save_session(
        session_id=meta.session_id,
        label=meta.label,
        state=meta.state,
        encrypted_meta=serialize_session_meta(meta, ag_app.device_key),
        created_at=meta.created_at,
    )


def _load_meta(ag_app, meta):
    from core.session import deserialize_session_meta

    row = ag_app.db.load_session(meta.session_id)
    return deserialize_session_meta(row[2], ag_app.device_key)


def _make_unverified_handshake():
    from core.crypto import generate_identity_keypair
    from core.session import (
        accept_initiator_and_create_responder,
        create_initiator_session,
        finalize_initiator_session,
        get_session_safety_code,
    )

    x_identity_priv, x_identity_pub = generate_identity_keypair()
    y_identity_priv, y_identity_pub = generate_identity_keypair()
    meta_x, init_file = create_initiator_session(
        "X",
        profile="standard",
        identity_pub=x_identity_pub,
        identity_priv=x_identity_priv,
    )
    meta_y, resp_file = accept_initiator_and_create_responder(
        init_file,
        "Y",
        identity_pub=y_identity_pub,
        identity_priv=y_identity_priv,
    )
    meta_x = finalize_initiator_session(meta_x, resp_file)
    return meta_x, meta_y, get_session_safety_code(meta_x)


def test_flask_seal_rejects_unconfirmed_safety_code(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, _meta_y, _safety_code = _make_unverified_handshake()
    _save_meta(ag_app, meta_x)

    response = client.post(
        f"/session/{meta_x.session_id.hex()}/seal",
        base_url=ORIGIN,
        data={"message": "blocked", "ttl_seconds": "0"},
        headers=auth_headers(client),
    )

    assert response.status_code == 302
    restored = _load_meta(ag_app, meta_x)
    assert restored.safety_confirmed is False
    assert restored.state == "unverified"


def test_flask_safety_confirmation_route_rejects_wrong_and_accepts_correct_code(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, _meta_y, safety_code = _make_unverified_handshake()
    _save_meta(ag_app, meta_x)

    bad = client.post(
        f"/session/{meta_x.session_id.hex()}/confirm-safety",
        base_url=ORIGIN,
        data={"safety_code": "0000-0000-0000-0000-0000-0000"},
        headers=auth_headers(client),
    )
    assert bad.status_code == 302
    assert _load_meta(ag_app, meta_x).safety_confirmed is False

    good = client.post(
        f"/session/{meta_x.session_id.hex()}/confirm-safety",
        base_url=ORIGIN,
        data={"safety_code": safety_code},
        headers=auth_headers(client),
    )

    assert good.status_code == 302
    restored = _load_meta(ag_app, meta_x)
    assert restored.safety_confirmed is True
    assert restored.state == "active"
