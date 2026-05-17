import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from desktop.services import NativeServices
from ui_api import UIApi, UIApiError


def make_api(path: Path) -> UIApi:
    path.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(path)
    svc = NativeServices(path, "en")
    return UIApi(svc)


def test_ui_api_device_settings_and_profile(tmp_path):
    api = make_api(tmp_path / "device")

    status = api.dispatch("device_status")
    assert status["initialized"] is False
    assert status["unlocked"] is False

    initialized = api.dispatch("device_init", {"pin": "95175328"})
    assert initialized["initialized"] is True
    assert initialized["unlocked"] is True

    settings = api.dispatch("settings_update", {"values": {"theme_mode": "light", "language": "en"}})
    assert settings["settings"]["theme_mode"] == "light"

    profile = api.dispatch("profile_update", {"username": "Paracci Operator", "avatar_color": "#0a84ff"})
    assert profile["settings"]["username"] == "Paracci Operator"


def test_ui_api_session_roundtrip_and_attachment_cache(tmp_path):
    x = make_api(tmp_path / "x")
    y = make_api(tmp_path / "y")
    x.dispatch("device_init", {"pin": "95175328"})
    y.dispatch("device_init", {"pin": "95175328"})

    init_path = tmp_path / "init.paracci"
    resp_path = tmp_path / "resp.paracci"
    msg_path = tmp_path / "msg.paracci"
    attachment_path = tmp_path / "note.txt"
    attachment_path.write_text("attachment text", encoding="utf-8")

    created = x.dispatch(
        "session_create",
        {"label": "X", "export_path": str(init_path), "profile": "standard"},
    )
    imported = y.dispatch(
        "session_import",
        {"import_path": str(init_path), "local_label": "Y", "auto_export_path": str(resp_path)},
    )
    finalized = x.dispatch("session_import", {"import_path": str(resp_path), "local_label": "unused"})

    assert init_path.exists()
    assert resp_path.exists()
    assert created["session_id_hex"] == imported["session_id_hex"] == finalized["session_id_hex"]

    sealed = x.dispatch(
        "message_seal",
        {
            "session_id_hex": finalized["session_id_hex"],
            "text": "Hello **Y**",
            "output_path": str(msg_path),
            "attachment_paths": [str(attachment_path)],
            "allow_download": True,
        },
    )
    assert msg_path.exists()
    assert sealed["filename"].endswith(".paracci")

    opened = y.dispatch(
        "message_open",
        {"session_id_hex": imported["session_id_hex"], "message_path": str(msg_path), "burn_source": False},
    )
    assert opened["text"] == "Hello **Y**"
    assert opened["attachments"][0]["filename"] == "note.txt"

    preview = y.dispatch(
        "attachment_preview",
        {"open_id": opened["open_id"], "attachment_id": opened["attachments"][0]["attachment_id"]},
    )
    assert preview["preview_kind"] == "text"
    assert "attachment text" in preview["text"]

    saved_path = tmp_path / "saved-note.txt"
    saved = y.dispatch(
        "attachment_save",
        {"open_id": opened["open_id"], "attachment_id": "0", "output_path": str(saved_path)},
    )
    assert Path(saved["output_path"]).read_text(encoding="utf-8") == "attachment text"

    y.dispatch("open_clear", {"open_id": opened["open_id"]})
    try:
        y.dispatch("attachment_preview", {"open_id": opened["open_id"], "attachment_id": "0"})
        assert False, "cleared attachment cache remained accessible"
    except UIApiError as exc:
        assert exc.code == "open_not_found"


def test_worker_json_rpc_success_and_error(tmp_path):
    worker = Path(__file__).parent.parent / "bridge" / "worker.py"
    request = {"id": "1", "method": "device_status", "params": {}}
    bad_request = {"id": "2", "method": "missing_method", "params": {}}
    proc = subprocess.run(
        [
            sys.executable,
            str(worker),
            "--data-dir",
            str(tmp_path / "worker"),
            "--locale",
            "en",
        ],
        input=json.dumps(request) + "\n" + json.dumps(bad_request) + "\n",
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
    )
    assert proc.returncode == 0
    lines = [json.loads(line) for line in proc.stdout.splitlines()]
    assert lines[0]["id"] == "1"
    assert lines[0]["ok"] is True
    assert "initialized" in lines[0]["result"]
    assert lines[1]["id"] == "2"
    assert lines[1]["ok"] is False
    assert lines[1]["error"]["code"] == "method_not_found"
