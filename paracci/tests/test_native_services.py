import io
import json
import os
import sqlite3
import sys
import zipfile
from pathlib import Path
import pytest

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from desktop import services as service_module
from desktop.services import NativeServices, configure_data_dir
import core.burn as burn_module
from core import envelope as envelope_module
from core.burn import BurnDB
from core.package import create_package


def make_services(path: Path) -> NativeServices:
    path.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(path)
    svc = NativeServices(path, "en")
    svc.device.initialize("Correct-Horse-95175328")
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


def legacy_package(text: str, allow_download):
    metadata = {"attachments": []}
    if allow_download is not None:
        metadata["allow_download"] = allow_download
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("message.md", text.encode("utf-8"))
        zf.writestr("metadata.json", json.dumps(metadata).encode("utf-8"))
    return buffer.getvalue()


@oqs_required
def test_native_services_full_message_roundtrip(tmp_path):
    x, y, x_session_id, y_session_id = make_active_services_pair(tmp_path)

    msg_bytes, filename = x.messages.seal_message(x_session_id, "Hello **Y**", [], False, 0)
    opened = y.messages.open_message(y_session_id, msg_bytes)

    assert opened.text == "Hello **Y**"
    assert opened.single_use is True
    assert opened.allow_download is False
    assert opened.secure_delete_failed is False
    assert filename.startswith("msg_step_000000_")


@oqs_required
def test_native_services_surfaces_failed_source_secure_delete(tmp_path, monkeypatch):
    x, y, x_session_id, y_session_id = make_active_services_pair(tmp_path)
    msg_bytes, _ = x.messages.seal_message(x_session_id, "Sensitive message", [], False, 0)
    source_path = tmp_path / "incoming.paracci"
    source_path.write_bytes(msg_bytes)
    monkeypatch.setattr(burn_module.shield, "secure_delete", lambda _path: False)

    opened = y.messages.open_message(y_session_id, source_path.read_bytes(), source_path)

    assert opened.text == "Sensitive message"
    assert opened.secure_delete_failed is True
    assert source_path.exists()


@oqs_required
def test_native_bound_header_policy_overrides_package_metadata(tmp_path, monkeypatch):
    x, y, x_session_id, y_session_id = make_active_services_pair(tmp_path)
    attachment_path = tmp_path / "secret.txt"
    attachment_path.write_bytes(b"original bytes")

    monkeypatch.setattr(
        service_module,
        "create_package",
        lambda text, files, allow_download: create_package(text, files, allow_download=True),
    )
    msg_bytes, _ = x.messages.seal_message(
        x_session_id,
        "Header policy wins",
        [attachment_path],
        False,
        0,
    )
    opened = y.messages.open_message(y_session_id, msg_bytes)

    assert opened.allow_download is False
    assert len(opened.attachments) == 1
    assert opened.attachments[0].allow_download is False


@pytest.mark.parametrize("metadata_allow_download", [False, True, None])
@oqs_required
def test_native_marker_free_current_envelope_uses_package_policy(
    tmp_path,
    monkeypatch,
    metadata_allow_download,
):
    x, y, x_session_id, y_session_id = make_active_services_pair(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(envelope_module, "FLAG_HAS_DOWNLOAD_POLICY", 0)
        patch.setattr(
            service_module,
            "create_package",
            lambda text, files, allow_download: legacy_package(text, metadata_allow_download),
        )
        msg_bytes, _ = x.messages.seal_message(x_session_id, "Legacy policy", [], False, 0)

    opened = y.messages.open_message(y_session_id, msg_bytes)
    expected = True if metadata_allow_download is None else metadata_allow_download

    assert opened.allow_download is expected


def test_2fa_secret_is_upgraded_to_encrypted_metadata(tmp_path):
    svc = make_services(tmp_path / "device")

    svc.device.set_2fa_secret("JBSWY3DPEHPK3PXP")
    svc.device.set_2fa_enabled(True)

    assert svc.device.db.get_device_meta("2fa_secret") is None
    assert svc.device.db.get_device_meta("2fa_secret_enc_v1") is not None
    assert svc.device.get_2fa_secret() == "JBSWY3DPEHPK3PXP"


def test_configure_data_dir_copies_legacy_data_once(tmp_path, monkeypatch):
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    with sqlite3.connect(legacy / "sessions.db") as conn:
        conn.execute("CREATE TABLE burned_messages (fingerprint BLOB PRIMARY KEY)")
        conn.execute("CREATE TABLE sessions (session_id BLOB PRIMARY KEY)")
        conn.execute("CREATE TABLE device_meta (key TEXT PRIMARY KEY, value BLOB)")
    (legacy / "config.json").write_text('{"language": "en"}', encoding="utf-8")

    target = tmp_path / "native"
    monkeypatch.setattr(service_module, "LEGACY_DATA_DIR", legacy)

    configured = configure_data_dir(str(target))
    assert configured == target.resolve()

    # Explicit data dirs are trusted and do not trigger legacy copy.
    assert not (target / "sessions.db").exists()

    target2 = tmp_path / "native-default"
    monkeypatch.setattr(service_module.shield, "get_default_data_dir", lambda app_name: str(target2))
    configured2 = configure_data_dir()
    assert configured2 == target2.resolve()
    assert (target2 / "sessions.db").exists()
    marker = json.loads((target2 / service_module.MIGRATION_MARKER).read_text(encoding="utf-8"))
    assert marker["validation"]["db_integrity"] == "ok"
    assert marker["validation"]["config_json"] == "ok"
    assert marker["validation"]["decryptability"] == "deferred_until_unlock"
