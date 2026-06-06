import io
import json
import os
import sys
from pathlib import Path

import pytest
from PIL import Image

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.carrier import CARRIER_PUBLIC_ERROR, PNG_LOSSLESS_V1  # noqa: E402
from core.carrier import base as carrier_base  # noqa: E402
from core.carrier import registry as carrier_registry  # noqa: E402
from desktop import services as service_module  # noqa: E402
from desktop.services import NativeServices  # noqa: E402
from ui_api import UIApi, UIApiError  # noqa: E402


PIN = "Correct-Horse-95175328"


def make_services(path: Path) -> NativeServices:
    path.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(path)
    svc = NativeServices(path, "en")
    svc.device.initialize(
        PIN,
        allow_linux_passphrase_fallback=sys.platform.startswith("linux"),
    )
    return svc


def make_active_services_pair(tmp_path):
    x = make_services(tmp_path / "x")
    y = make_services(tmp_path / "y")

    created = x.sessions.create_initiator("X to Y")
    imported = y.sessions.import_handshake(created.auto_export_bytes, "Y to X")
    finalized = x.sessions.import_handshake(imported.auto_export_bytes, "unused")
    x.sessions.confirm_safety(finalized.session_id_hex, finalized.safety_code)
    y.sessions.confirm_safety(imported.session_id_hex, imported.safety_code)
    return x, y, finalized.session_id_hex, imported.session_id_hex


def make_api(path: Path) -> UIApi:
    svc = make_services(path)
    return UIApi(svc)


def png_cover_bytes(size=(192, 192)):
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


def assert_generic_service_error(exc_info, *sentinels):
    message = str(exc_info.value)
    assert message == CARRIER_PUBLIC_ERROR
    for sentinel in sentinels:
        assert sentinel not in message


@oqs_required
def test_session_import_from_png_carrier_uses_existing_setup_path(tmp_path):
    x = make_services(tmp_path / "x")
    y = make_services(tmp_path / "y")

    created = x.sessions.create_initiator("X to Y")
    init_carrier = carrier_for(created.auto_export_bytes, payload_kind="setup")
    imported = y.sessions.import_handshake_from_carrier(
        PNG_LOSSLESS_V1,
        "Y to X",
        carrier_bytes=init_carrier,
    )

    resp_carrier = carrier_for(imported.auto_export_bytes, payload_kind="setup")
    finalized = x.sessions.import_handshake_from_carrier(
        PNG_LOSSLESS_V1,
        "unused",
        carrier_bytes=resp_carrier,
    )

    assert created.session_id_hex == imported.session_id_hex == finalized.session_id_hex
    assert imported.auto_export_bytes is not None
    assert imported.requires_confirmation is True
    assert finalized.requires_confirmation is True


@oqs_required
def test_message_open_from_png_carrier_uses_existing_message_path(tmp_path):
    x, y, x_session_id, y_session_id = make_active_services_pair(tmp_path)
    msg_bytes, _filename = x.messages.seal_message(
        x_session_id,
        "Hello from carrier",
        [],
        False,
        0,
    )
    msg_carrier = carrier_for(msg_bytes)

    opened = y.messages.open_message_from_carrier(
        y_session_id,
        PNG_LOSSLESS_V1,
        carrier_bytes=msg_carrier,
    )

    assert opened.text == "Hello from carrier"
    assert opened.single_use is True
    assert opened.allow_download is False


@oqs_required
def test_message_open_from_internal_carrier_path_does_not_delete_source(tmp_path):
    x, y, x_session_id, y_session_id = make_active_services_pair(tmp_path)
    msg_bytes, _filename = x.messages.seal_message(
        x_session_id,
        "Carrier path source remains",
        [],
        False,
        0,
    )
    source_path = tmp_path / "trusted-carrier.png"
    source_path.write_bytes(carrier_for(msg_bytes))

    opened = y.messages.open_message_from_carrier(
        y_session_id,
        PNG_LOSSLESS_V1,
        carrier_path=source_path,
    )

    assert opened.text == "Carrier path source remains"
    assert source_path.exists()


@oqs_required
def test_non_paracci_payload_from_carrier_fails_downstream_generically(tmp_path):
    svc = make_services(tmp_path / "device")
    sentinel = "payload-secret-sentinel"
    setup_carrier = carrier_for(
        f"not a setup {sentinel}".encode("ascii"),
        payload_kind="setup",
    )

    with pytest.raises(service_module.SessionServiceError) as setup_exc:
        svc.sessions.import_handshake_from_carrier(
            PNG_LOSSLESS_V1,
            "Y",
            carrier_bytes=setup_carrier,
        )

    assert_generic_service_error(setup_exc, sentinel, "Invalid Paracci file")

    x, y, _x_session_id, y_session_id = make_active_services_pair(tmp_path / "message")
    del x
    message_carrier = carrier_for(f"not a message {sentinel}".encode("ascii"))

    with pytest.raises(service_module.MessageServiceError) as message_exc:
        y.messages.open_message_from_carrier(
            y_session_id,
            PNG_LOSSLESS_V1,
            carrier_bytes=message_carrier,
        )

    assert_generic_service_error(message_exc, sentinel, "Invalid Paracci message")


@oqs_required
def test_wrong_role_and_wrong_session_carriers_fail_generically_without_state_change(tmp_path):
    x, y, x_session_id, y_session_id = make_active_services_pair(tmp_path / "role")
    del x_session_id
    responder_bytes = y.sessions.export_handshake(y_session_id)[0]
    responder_carrier = carrier_for(responder_bytes, payload_kind="setup")
    before_role = y.sessions.load(y_session_id)

    with pytest.raises(service_module.SessionServiceError) as role_exc:
        y.sessions.import_handshake_from_carrier(
            PNG_LOSSLESS_V1,
            "unused",
            carrier_bytes=responder_carrier,
        )

    after_role = y.sessions.load(y_session_id)
    assert after_role.role == before_role.role
    assert after_role.state == before_role.state
    assert_generic_service_error(role_exc, "Responder", "finalize", "X sessions")

    x1, _y1, x1_session_id, _y1_session_id = make_active_services_pair(tmp_path / "a")
    _x2, y2, _x2_session_id, y2_session_id = make_active_services_pair(tmp_path / "b")
    msg_bytes, _filename = x1.messages.seal_message(
        x1_session_id,
        "Wrong session",
        [],
        False,
        0,
    )
    wrong_session_carrier = carrier_for(msg_bytes)
    before_session = y2.sessions.load(y2_session_id)

    with pytest.raises(service_module.MessageServiceError) as session_exc:
        y2.messages.open_message_from_carrier(
            y2_session_id,
            PNG_LOSSLESS_V1,
            carrier_bytes=wrong_session_carrier,
        )

    after_session = y2.sessions.load(y2_session_id)
    assert after_session.rx_count == before_session.rx_count
    assert after_session.recv_seed == before_session.recv_seed
    assert_generic_service_error(session_exc, "session", "mismatch", "decrypt")


@oqs_required
def test_message_replay_from_carrier_uses_existing_burndb_generically(tmp_path):
    x, y, x_session_id, y_session_id = make_active_services_pair(tmp_path)
    msg_bytes, _filename = x.messages.seal_message(
        x_session_id,
        "Replay once",
        [],
        False,
        0,
    )
    msg_carrier = carrier_for(msg_bytes)

    opened = y.messages.open_message_from_carrier(
        y_session_id,
        PNG_LOSSLESS_V1,
        carrier_bytes=msg_carrier,
    )
    assert opened.text == "Replay once"

    with pytest.raises(service_module.MessageServiceError) as replay_exc:
        y.messages.open_message_from_carrier(
            y_session_id,
            PNG_LOSSLESS_V1,
            carrier_bytes=msg_carrier,
        )

    assert_generic_service_error(replay_exc, "already", "opened", "expired", "replay")


def test_oversized_extracted_carrier_payload_rejected_before_import_or_open(
    tmp_path,
    monkeypatch,
):
    svc = make_services(tmp_path / "device")
    payload = b"payload-secret-sentinel"

    setup_carrier = carrier_for(payload, payload_kind="message")
    monkeypatch.setattr(carrier_base, "MAX_EXTRACTED_SETUP_BYTES", len(payload) - 1)
    monkeypatch.setattr(
        service_module.SessionService,
        "import_handshake",
        lambda *_args, **_kwargs: pytest.fail("oversized setup reached import"),
    )
    with pytest.raises(service_module.SessionServiceError) as setup_exc:
        svc.sessions.import_handshake_from_carrier(
            PNG_LOSSLESS_V1,
            "Y",
            carrier_bytes=setup_carrier,
        )
    assert_generic_service_error(setup_exc, payload.decode("ascii"), "too large")

    monkeypatch.setattr(carrier_base, "MAX_EXTRACTED_SETUP_BYTES", 1024)
    message_carrier = carrier_for(payload, payload_kind="setup")
    monkeypatch.setattr(carrier_base, "MAX_EXTRACTED_MESSAGE_BYTES", len(payload) - 1)
    monkeypatch.setattr(
        service_module.MessageService,
        "open_message",
        lambda *_args, **_kwargs: pytest.fail("oversized message reached open"),
    )
    with pytest.raises(service_module.MessageServiceError) as message_exc:
        svc.messages.open_message_from_carrier(
            "00" * 16,
            PNG_LOSSLESS_V1,
            carrier_bytes=message_carrier,
        )
    assert_generic_service_error(message_exc, payload.decode("ascii"), "too large")


def test_carrier_decode_failures_are_generic_for_bytes_and_paths(tmp_path):
    svc = make_services(tmp_path / "device")
    sentinel = "path-token-payload-secret-sentinel"
    bad_path = tmp_path / "path-secret-sentinel.png"
    bad_path.write_bytes(f"not a carrier {sentinel}".encode("ascii"))

    with pytest.raises(service_module.SessionServiceError) as bytes_exc:
        svc.sessions.import_handshake_from_carrier(
            PNG_LOSSLESS_V1,
            "Y",
            carrier_bytes=f"not a carrier {sentinel}".encode("ascii"),
        )
    assert_generic_service_error(bytes_exc, sentinel, "magic", "checksum", "length")

    with pytest.raises(service_module.MessageServiceError) as path_exc:
        svc.messages.open_message_from_carrier(
            "00" * 16,
            PNG_LOSSLESS_V1,
            carrier_path=bad_path,
        )
    assert bad_path.exists()
    assert_generic_service_error(path_exc, sentinel, str(bad_path), "magic", "checksum", "length")


def test_ui_api_exposes_no_carrier_commands_or_raw_path_surface(tmp_path):
    api = make_api(tmp_path / "api")
    sentinel = "C:/private/path-secret-sentinel.png"

    assert not hasattr(api, "cmd_session_import_carrier")
    assert not hasattr(api, "cmd_message_open_carrier")

    with pytest.raises(UIApiError) as raw_path_exc:
        api.dispatch(
            "message_open",
            {
                "session_id_hex": "00",
                "message_path": sentinel,
            },
        )
    serialized = json.dumps(raw_path_exc.value.to_dict())
    assert raw_path_exc.value.code == "raw_path_rejected"
    assert sentinel not in serialized

    with pytest.raises(UIApiError) as carrier_method_exc:
        api.dispatch("message_open_carrier", {"carrier_path": sentinel})
    serialized = json.dumps(carrier_method_exc.value.to_dict())
    assert carrier_method_exc.value.code == "method_not_found"
    assert sentinel not in serialized
