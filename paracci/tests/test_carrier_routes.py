import io
import sys
from pathlib import Path

import pytest
from PIL import Image

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.carrier import CARRIER_PUBLIC_ERROR, PNG_LOSSLESS_V1, QR_MATRIX_V1  # noqa: E402
from core.carrier import registry as carrier_registry  # noqa: E402
from test_loopback_security import (  # noqa: E402
    HOST,
    ORIGIN,
    TOKEN,
    _load_meta,
    _make_active_handshake,
    _save_meta,
    _unlock_test_client,
    auth_headers,
    bootstrap,
    make_flask_app,
)


PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def png_cover_bytes(size=(1024, 1024)):
    output = io.BytesIO()
    Image.new("RGB", size, (32, 96, 160)).save(output, format="PNG")
    return output.getvalue()


def carrier_for(payload: bytes, *, payload_kind="message", size=(1024, 1024)) -> bytes:
    return carrier_registry.embed_envelope(
        PNG_LOSSLESS_V1,
        payload,
        carrier_bytes=png_cover_bytes(size),
        payload_kind=payload_kind,
    ).carrier_bytes


def multipart_file(payload: bytes, filename="carrier.png"):
    return io.BytesIO(payload), filename


def assert_generic_carrier_response(response, *sentinels, status=400):
    assert response.status_code == status
    assert response.headers["Cache-Control"].startswith("no-store")
    body = response.get_data(as_text=True)
    assert CARRIER_PUBLIC_ERROR in body
    for sentinel in sentinels:
        if isinstance(sentinel, bytes):
            assert sentinel not in response.data
        else:
            assert str(sentinel) not in body


@pytest.mark.parametrize(
    "path",
    [
        "/session/import/carrier",
        "/session/00112233445566778899aabbccddeeff/carrier/import_responder",
        "/session/00112233445566778899aabbccddeeff/carrier/open",
        "/session/00112233445566778899aabbccddeeff/carrier/seal",
        "/session/00112233445566778899aabbccddeeff/carrier/export",
    ],
)
def test_carrier_routes_require_bearer_csrf_and_same_origin(tmp_path, monkeypatch, path):
    _ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)

    missing_bearer = client.post(
        path,
        base_url=ORIGIN,
        data={},
        headers={"Host": HOST, "Origin": ORIGIN},
    )
    assert missing_bearer.status_code == 403

    missing_csrf = client.post(
        path,
        base_url=ORIGIN,
        data={},
        headers={"Host": HOST, "Origin": ORIGIN, "X-Paracci-Token": TOKEN},
    )
    assert missing_csrf.status_code == 403

    bad_origin = client.post(
        path,
        base_url=ORIGIN,
        data={},
        headers=auth_headers(client, Origin="http://evil.test"),
    )
    assert bad_origin.status_code == 403


def test_carrier_raw_path_fields_rejected_before_file_helpers(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    monkeypatch.setattr(
        routes_module,
        "_carrier_bytes_from_request",
        lambda *_args, **_kwargs: pytest.fail("raw path reached carrier file helper"),
    )
    sentinel_path = "<local-user-path>/carrier-redaction.png"
    sentinel_name = "filename-redaction-sentinel.png"

    response = client.post(
        "/session/import/carrier",
        base_url=ORIGIN,
        data={
            "label": "Y",
            "nested[path]": sentinel_path,
            "carrier_png": multipart_file(b"not used", sentinel_name),
        },
        headers=auth_headers(client),
        content_type="multipart/form-data",
    )

    assert_generic_carrier_response(response, sentinel_path, sentinel_name)


def test_carrier_upload_cap_rejects_before_decode(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    monkeypatch.setattr(routes_module, "MAX_CARRIER_FILE_BYTES", 32)
    monkeypatch.setattr(
        routes_module,
        "extract_envelope",
        lambda *_args, **_kwargs: pytest.fail("oversized carrier reached decoder"),
    )
    sentinel = b"payload-redaction-sentinel"

    response = client.post(
        "/session/import/carrier",
        base_url=ORIGIN,
        data={
            "label": "Y",
            "carrier_png": multipart_file(sentinel + b"x" * 64, "carrier-redaction.png"),
        },
        headers=auth_headers(client),
        content_type="multipart/form-data",
    )

    assert_generic_carrier_response(response, sentinel, "carrier-redaction.png")


@oqs_required
def test_carrier_setup_import_keeps_normal_responder_export_primary(tmp_path, monkeypatch):
    from core.crypto import generate_identity_keypair
    from core.session import create_initiator_session

    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    x_identity_priv, x_identity_pub = generate_identity_keypair()
    _meta_x, init_file = create_initiator_session(
        "X",
        identity_pub=x_identity_pub,
        identity_priv=x_identity_priv,
    )
    init_carrier = carrier_for(init_file, payload_kind="setup")

    imported = client.post(
        "/session/import/carrier",
        base_url=ORIGIN,
        data={
            "label": "Y",
            "carrier_png": multipart_file(init_carrier, "carrier.png"),
        },
        headers=auth_headers(client),
        content_type="multipart/form-data",
    )

    assert imported.status_code == 302
    assert "auto_download=1" in imported.headers["Location"]
    sid = imported.headers["Location"].split("/session/", 1)[1].split("?", 1)[0]

    exported = client.get(
        f"/session/{sid}/export",
        base_url=ORIGIN,
        headers=auth_headers(client),
    )

    assert exported.status_code == 200
    assert exported.data.startswith(b"PARC")
    assert not exported.data.startswith(PNG_SIGNATURE)


@oqs_required
def test_normal_setup_import_route_still_accepts_paracci_bytes(tmp_path, monkeypatch):
    from core.crypto import generate_identity_keypair
    from core.session import create_initiator_session

    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)

    x_identity_priv, x_identity_pub = generate_identity_keypair()
    _meta_x, init_file = create_initiator_session(
        "X",
        identity_pub=x_identity_pub,
        identity_priv=x_identity_priv,
    )

    imported = client.post(
        "/session/import",
        base_url=ORIGIN,
        data={
            "label": "Y",
            "paracci_file": multipart_file(init_file, "setup.paracci"),
        },
        headers=auth_headers(client),
        content_type="multipart/form-data",
    )

    assert imported.status_code == 302
    sid = imported.headers["Location"].split("/session/", 1)[1].split("?", 1)[0]
    exported = client.get(
        f"/session/{sid}/export",
        base_url=ORIGIN,
        headers=auth_headers(client),
    )
    assert exported.status_code == 200
    assert exported.data.startswith(b"PARC")
    assert not exported.data.startswith(PNG_SIGNATURE)


@oqs_required
def test_normal_paracci_seal_and_export_routes_remain_unchanged(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_x)

    sealed = client.post(
        f"/session/{meta_x.session_id.hex()}/seal",
        base_url=ORIGIN,
        data={"message": "normal route", "ttl_seconds": "0"},
        headers=auth_headers(client),
    )
    assert sealed.status_code == 200
    assert sealed.data.startswith(b"PARC")
    assert not sealed.data.startswith(PNG_SIGNATURE)

    _save_meta(ag_app, meta_y)
    opened = client.post(
        f"/session/{meta_y.session_id.hex()}/open?ajax=1",
        base_url=ORIGIN,
        data={"paracci_file": multipart_file(sealed.data, "message.paracci")},
        headers=auth_headers(client, **{"X-Requested-With": "XMLHttpRequest"}),
        content_type="multipart/form-data",
    )
    assert opened.status_code == 200
    assert opened.get_json()["success"] is True
    assert opened.get_json()["text"] == "normal route"

    exported = client.get(
        f"/session/{meta_y.session_id.hex()}/export",
        base_url=ORIGIN,
        headers=auth_headers(client),
    )
    assert exported.status_code == 200
    assert exported.data.startswith(b"PARC")
    assert not exported.data.startswith(PNG_SIGNATURE)


@oqs_required
def test_carrier_export_uses_purpose_scoped_ref_and_native_grant(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch, no_gui=False)
    import app.routes as routes_module
    from core.preview_store import NativeSaveGrantStore

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    grants = NativeSaveGrantStore()
    monkeypatch.setattr(routes_module, "native_save_grants", grants)
    _meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_y)

    normal_ref_file = tmp_path / "normal-ref.paracci"
    normal_ref_file.write_bytes(b"PARC normal ref")
    normal_ref = routes_module.register_native_file_path(normal_ref_file)
    assert routes_module._resolve_native_file_ref(normal_ref["id"]) is not None
    assert routes_module._resolve_native_file_ref(normal_ref["id"]) is not None

    cover_path = tmp_path / "cover.png"
    cover_path.write_bytes(png_cover_bytes())
    cover_ref = routes_module.register_native_file_path(
        cover_path,
        purpose=routes_module.NATIVE_FILE_REF_PURPOSE_CARRIER_COVER,
    )

    response = client.post(
        f"/session/{meta_y.session_id.hex()}/carrier/export",
        base_url=ORIGIN,
        data={"cover_native_file_id": cover_ref["id"]},
        headers=auth_headers(client, **{"X-Paracci-Native-Save": "1"}),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["filename"] == "carrier.png"
    grant = grants.consume(payload["native_save_token"])
    assert grant is not None
    assert grant.filename == "carrier.png"
    assert grant.file_bytes.startswith(PNG_SIGNATURE)
    assert grants.consume(payload["native_save_token"]) is None
    assert cover_path.exists()

    reused = client.post(
        f"/session/{meta_y.session_id.hex()}/carrier/export",
        base_url=ORIGIN,
        data={"cover_native_file_id": cover_ref["id"]},
        headers=auth_headers(client),
    )
    assert_generic_carrier_response(reused)
    assert cover_path.exists()


@oqs_required
def test_carrier_seal_returns_png_bytes_and_keeps_qr_unsupported(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, _meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_x)

    sealed = client.post(
        f"/session/{meta_x.session_id.hex()}/carrier/seal",
        base_url=ORIGIN,
        data={
            "message": "carrier sealed",
            "ttl_seconds": "0",
            "cover_png": multipart_file(png_cover_bytes(), "cover.png"),
        },
        headers=auth_headers(client),
        content_type="multipart/form-data",
    )

    assert sealed.status_code == 200
    assert sealed.data.startswith(PNG_SIGNATURE)
    extracted = carrier_registry.extract_envelope(PNG_LOSSLESS_V1, sealed.data).envelope_bytes
    assert extracted.startswith(b"PARC")
    assert extracted[5] == 0x20
    meta_after = _load_meta(ag_app, meta_x)
    assert meta_after.tx_count == meta_x.tx_count + 1

    unsupported = client.post(
        f"/session/{meta_x.session_id.hex()}/carrier/seal",
        base_url=ORIGIN,
        data={
            "message": "unsupported kind",
            "ttl_seconds": "0",
            "carrier_kind": QR_MATRIX_V1,
            "cover_png": multipart_file(png_cover_bytes(), "cover.png"),
        },
        headers=auth_headers(client),
        content_type="multipart/form-data",
    )

    assert_generic_carrier_response(unsupported, QR_MATRIX_V1)
    assert _load_meta(ag_app, meta_x).tx_count == meta_after.tx_count


@oqs_required
def test_carrier_open_uses_existing_validation_and_generic_failures(tmp_path, monkeypatch):
    ag_app, flask_app = make_flask_app(tmp_path, monkeypatch)
    import app.routes as routes_module

    client = flask_app.test_client()
    bootstrap(client)
    _unlock_test_client(ag_app, client)
    meta_x, meta_y = _make_active_handshake()
    _save_meta(ag_app, meta_x)

    sealed = client.post(
        f"/session/{meta_x.session_id.hex()}/seal",
        base_url=ORIGIN,
        data={"message": "opened through carrier route", "ttl_seconds": "0"},
        headers=auth_headers(client),
    )
    assert sealed.status_code == 200
    message_bytes = sealed.data
    tampered_message = bytearray(message_bytes)
    tampered_message[-1] ^= 0x01
    _save_meta(ag_app, meta_y)

    tampered = client.post(
        f"/session/{meta_y.session_id.hex()}/carrier/open",
        base_url=ORIGIN,
        data={
            "carrier_png": multipart_file(
                carrier_for(bytes(tampered_message)),
                "decrypt-redaction-sentinel.png",
            )
        },
        headers=auth_headers(client),
        content_type="multipart/form-data",
    )
    assert_generic_carrier_response(
        tampered,
        "decrypt",
        "role",
        "replay",
        "decrypt-redaction-sentinel.png",
    )

    carrier_path = tmp_path / "message-carrier.png"
    carrier_path.write_bytes(carrier_for(message_bytes))
    message_ref = routes_module.register_native_file_path(
        carrier_path,
        purpose=routes_module.NATIVE_FILE_REF_PURPOSE_CARRIER_MESSAGE_OPEN,
    )
    opened = client.post(
        f"/session/{meta_y.session_id.hex()}/carrier/open",
        base_url=ORIGIN,
        data={"carrier_native_file_id": message_ref["id"]},
        headers=auth_headers(client),
    )

    assert opened.status_code == 200
    assert opened.get_json()["success"] is True
    assert opened.get_json()["text"] == "opened through carrier route"
    assert carrier_path.exists()

    replay_ref = routes_module.register_native_file_path(
        carrier_path,
        purpose=routes_module.NATIVE_FILE_REF_PURPOSE_CARRIER_MESSAGE_OPEN,
    )
    replayed = client.post(
        f"/session/{meta_y.session_id.hex()}/carrier/open",
        base_url=ORIGIN,
        data={"carrier_native_file_id": replay_ref["id"]},
        headers=auth_headers(client),
    )
    assert_generic_carrier_response(replayed, "already", "expired", "replay")
    assert carrier_path.exists()
