import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from desktop import services as service_module
from desktop.services import NativeServices, configure_data_dir
from core.burn import BurnDB


def make_services(path: Path) -> NativeServices:
    path.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(path)
    svc = NativeServices(path, "en")
    svc.device.initialize("95175328")
    return svc


def test_native_services_full_message_roundtrip(tmp_path):
    x = make_services(tmp_path / "x")
    y = make_services(tmp_path / "y")

    created = x.sessions.create_initiator("X to Y", profile="standard")
    imported = y.sessions.import_handshake(created.auto_export_bytes, "Y to X")
    finalized = x.sessions.import_handshake(imported.auto_export_bytes, "unused")

    msg_bytes, _ = x.messages.seal_message(finalized.session_id_hex, "Hello **Y**", [], False, 0)
    opened = y.messages.open_message(imported.session_id_hex, msg_bytes)

    assert opened.text == "Hello **Y**"
    assert opened.single_use is True
    assert opened.allow_download is False


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
    BurnDB(legacy / "sessions.db")
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
