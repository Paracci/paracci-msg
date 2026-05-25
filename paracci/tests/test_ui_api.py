import base64
import io
import json
import os
import subprocess
import sys
import time
from pathlib import Path
import pytest
from PIL import Image

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from desktop.device_key_binding import (
    DPAPI_DIFFERENT_ACCOUNT_CODE,
    DPAPI_DIFFERENT_ACCOUNT_I18N,
    DPAPI_DIFFERENT_ACCOUNT_MESSAGE,
    DeviceBindingError,
)
from desktop.services import AttachmentPayload, NativeServices, OpenedMessage
from ui_api import UIApi, UIApiError
from ui_api.facade import CachedOpenMessage


def make_api(path: Path) -> UIApi:
    path.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(path)
    svc = NativeServices(path, "en")
    return UIApi(svc)


def cache_open_attachment(api: UIApi, attachment: AttachmentPayload, open_id: str = "open-id") -> str:
    api._opened[open_id] = CachedOpenMessage(
        message=OpenedMessage(
            text="secret",
            attachments=[attachment],
            allow_download=attachment.allow_download,
            msg_id_hex="00",
            evo_step=1,
            expire_at=0,
            single_use=True,
            security_report={"is_safe": True, "risks": []},
        ),
        opened_at=int(time.time()),
    )
    return open_id


def png_bytes(size=(1400, 900), color=(14, 80, 130, 255)):
    image = Image.new("RGBA", size, color)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def test_ui_api_device_settings_and_profile(tmp_path):
    api = make_api(tmp_path / "device")

    status = api.dispatch("device_status")
    assert status["initialized"] is False
    assert status["unlocked"] is False
    assert status["two_factor_enabled"] is None

    initialized = api.dispatch("device_init", {"pin": "Correct-Horse-95175328"})
    assert initialized["initialized"] is True
    assert initialized["unlocked"] is True

    settings = api.dispatch("settings_update", {"values": {"theme_mode": "light", "language": "en"}})
    assert settings["settings"]["theme_mode"] == "light"

    profile = api.dispatch("profile_update", {"username": "Paracci Operator", "avatar_color": "#0a84ff"})
    assert profile["settings"]["username"] == "Paracci Operator"


@oqs_required
def test_ui_api_session_roundtrip_and_attachment_cache(tmp_path):
    x = make_api(tmp_path / "x")
    y = make_api(tmp_path / "y")
    x.dispatch("device_init", {"pin": "Correct-Horse-95175328"})
    y.dispatch("device_init", {"pin": "Correct-Horse-95175328"})

    init_path = tmp_path / "init.paracci"
    resp_path = tmp_path / "resp.paracci"
    msg_path = tmp_path / "msg.paracci"
    attachment_path = tmp_path / "note.txt"
    attachment_path.write_text("attachment text", encoding="utf-8")

    created = x.dispatch(
        "session_create",
        {"label": "X", "export_path": str(init_path)},
    )
    imported = y.dispatch(
        "session_import",
        {"import_path": str(init_path), "local_label": "Y", "auto_export_path": str(resp_path)},
    )
    finalized = x.dispatch("session_import", {"import_path": str(resp_path), "local_label": "unused"})
    x.dispatch("session_confirm_safety", {
        "session_id_hex": finalized["session_id_hex"],
        "safety_code": finalized["safety_code"],
    })
    y.dispatch("session_confirm_safety", {
        "session_id_hex": imported["session_id_hex"],
        "safety_code": imported["safety_code"],
    })

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
    assert sealed["filename"].startswith("msg_step_000000_")
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
    assert opened["open_id"] not in y._opened
    try:
        y.dispatch("attachment_preview", {"open_id": opened["open_id"], "attachment_id": "0"})
        assert False, "cleared attachment cache remained accessible"
    except UIApiError as exc:
        assert exc.code == "open_not_found"


def test_ui_api_device_lock_drops_open_cache_and_windows_status_is_best_effort(tmp_path):
    api = make_api(tmp_path / "device-lock")
    api.dispatch("device_init", {"pin": "Correct-Horse-95175328"})
    retained_device_key = api.services.device.device_key
    assert isinstance(retained_device_key, bytearray)
    api.services.shield.get_os_name = lambda: "Windows"

    status = api.dispatch("device_status")
    assert status["shield"] == {"state": "best_effort", "label": "Best effort"}

    api._opened["open-id"] = CachedOpenMessage(
        message=OpenedMessage(
            text="secret",
            attachments=[
                AttachmentPayload(
                    filename="secret.txt",
                    content=b"attachment plaintext",
                    mime_type="text/plain",
                    allow_download=True,
                )
            ],
            allow_download=True,
            msg_id_hex="00",
            evo_step=1,
            expire_at=0,
            single_use=True,
            security_report={"is_safe": True, "risks": []},
        ),
        opened_at=int(time.time()),
    )

    locked = api.dispatch("device_lock")

    assert locked["unlocked"] is False
    assert locked["two_factor_enabled"] is None
    assert api._opened == {}
    assert retained_device_key == bytearray(len(retained_device_key))


def test_ui_api_non_downloadable_text_preview_returns_policy_message(tmp_path):
    api = make_api(tmp_path / "native-preview-text")
    open_id = cache_open_attachment(
        api,
        AttachmentPayload(
            filename="secret.txt",
            content=b"attachment plaintext",
            mime_type="text/plain",
            allow_download=False,
        ),
    )

    preview = api.dispatch(
        "attachment_preview",
        {"open_id": open_id, "attachment_id": "0"},
    )

    assert preview["preview_kind"] == "unsupported"
    assert preview["message"] == "This file cannot be previewed here."
    assert "text" not in preview
    assert "content_base64" not in preview


def test_ui_api_non_downloadable_binary_preview_returns_policy_message(tmp_path):
    api = make_api(tmp_path / "native-preview-binary")
    open_id = cache_open_attachment(
        api,
        AttachmentPayload(
            filename="secret.pdf",
            content=b"%PDF-private",
            mime_type="application/pdf",
            allow_download=False,
        ),
    )

    preview = api.dispatch(
        "attachment_preview",
        {"open_id": open_id, "attachment_id": "0"},
    )

    assert preview["preview_kind"] == "unsupported"
    assert preview["message"] == "Preview not available for this file type when downloading is disabled."
    assert "text" not in preview
    assert "content_base64" not in preview


def test_ui_api_non_downloadable_image_preview_remains_available(tmp_path):
    api = make_api(tmp_path / "native-preview-image")
    image_bytes = png_bytes()
    open_id = cache_open_attachment(
        api,
        AttachmentPayload(
            filename="preview.png",
            content=image_bytes,
            mime_type="image/png",
            allow_download=False,
        ),
    )

    preview = api.dispatch(
        "attachment_preview",
        {"open_id": open_id, "attachment_id": "0"},
    )

    assert preview["preview_kind"] == "image_base64"
    assert preview["mime_type"] == "image/jpeg"
    preview_bytes = base64.b64decode(preview["content_base64"])
    assert preview_bytes != image_bytes
    rendered = Image.open(io.BytesIO(preview_bytes))
    assert rendered.width <= 1024
    assert rendered.height <= 1024


def test_ui_api_non_downloadable_invalid_image_preview_exposes_no_bytes(tmp_path):
    api = make_api(tmp_path / "native-preview-invalid-image")
    open_id = cache_open_attachment(
        api,
        AttachmentPayload(
            filename="preview.png",
            content=b"\x89PNG\r\nnot-a-real-image",
            mime_type="image/png",
            allow_download=False,
        ),
    )

    preview = api.dispatch(
        "attachment_preview",
        {"open_id": open_id, "attachment_id": "0"},
    )

    assert preview["preview_kind"] == "unsupported"
    assert preview["message"] == "Preview not available for this file type when downloading is disabled."
    assert "content_base64" not in preview


def test_ui_api_downloadable_image_preview_returns_original_bytes(tmp_path):
    api = make_api(tmp_path / "native-preview-downloadable-image")
    image_bytes = png_bytes()
    open_id = cache_open_attachment(
        api,
        AttachmentPayload(
            filename="preview.png",
            content=image_bytes,
            mime_type="image/png",
            allow_download=True,
        ),
    )

    preview = api.dispatch(
        "attachment_preview",
        {"open_id": open_id, "attachment_id": "0"},
    )

    assert preview["preview_kind"] == "image_base64"
    assert preview["mime_type"] == "image/png"
    assert base64.b64decode(preview["content_base64"]) == image_bytes


def test_ui_api_maps_device_binding_error(tmp_path):
    api = make_api(tmp_path / "device-binding-error")

    def fail_unlock(_pin: str):
        raise DeviceBindingError(
            DPAPI_DIFFERENT_ACCOUNT_CODE,
            DPAPI_DIFFERENT_ACCOUNT_I18N,
            DPAPI_DIFFERENT_ACCOUNT_MESSAGE,
        )

    api.services.device.unlock = fail_unlock

    try:
        api.dispatch("device_unlock", {"pin": "Correct-Horse-95175328"})
        assert False, "device binding error was not mapped"
    except UIApiError as exc:
        assert exc.code == DPAPI_DIFFERENT_ACCOUNT_CODE
        assert exc.message == DPAPI_DIFFERENT_ACCOUNT_MESSAGE


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
