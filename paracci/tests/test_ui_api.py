import base64
import io
import json
import logging
import os
import subprocess
import sys
import time
from pathlib import Path
import pytest
import pyotp
from PIL import Image

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from desktop.device_key_binding import (
    DPAPI_DIFFERENT_ACCOUNT_CODE,
    DPAPI_DIFFERENT_ACCOUNT_I18N,
    DPAPI_DIFFERENT_ACCOUNT_MESSAGE,
    DeviceBindingError,
)
from desktop.services import (
    PENDING_UNLOCK_TTL_SECONDS,
    AttachmentPayload,
    NativeServices,
    OpenedMessage,
)
from ui_api import UIApi, UIApiError
from ui_api import facade as facade_module
from ui_api.facade import CachedOpenMessage


PIN = "Correct-Horse-95175328"
TOTP_SECRET = "JBSWY3DPEHPK3PXP"


def make_api(path: Path) -> UIApi:
    path.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(path)
    svc = NativeServices(path, "en")
    downloads = path / "downloads"
    downloads.mkdir(parents=True, exist_ok=True)
    svc.settings.config.full_downloads_path = str(downloads)
    return UIApi(svc)


def enable_2fa_and_lock(api: UIApi, pin: str = PIN, secret: str = TOTP_SECRET) -> str:
    api.dispatch("device_init", {"pin": pin})
    api.dispatch(
        "2fa_enable",
        {"secret": secret, "code": pyotp.TOTP(secret).now()},
    )
    api.dispatch("device_lock")
    return secret


def assert_sensitive_absent(label: str, sensitive_value: str, text: str) -> None:
    if sensitive_value and sensitive_value in text:
        raise AssertionError(f"{label} leaked")


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


def save_grant(api: UIApi, result: dict) -> Path:
    saved = api.dispatch(
        "save_grant_to_downloads",
        {"native_save_token": result["native_save_token"]},
    )
    return Path(saved["output_path"])


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

    attachment_path = tmp_path / "note.txt"
    attachment_path.write_text("attachment text", encoding="utf-8")

    created = x.dispatch(
        "session_create",
        {"label": "X"},
    )
    init_path = save_grant(x, created)
    init_ref = y.register_trusted_file_path(init_path, "session_import")
    imported = y.dispatch(
        "session_import",
        {"import_ref": init_ref["id"], "local_label": "Y"},
    )
    resp_path = save_grant(y, imported)
    resp_ref = x.register_trusted_file_path(resp_path, "session_import")
    finalized = x.dispatch("session_import", {"import_ref": resp_ref["id"], "local_label": "unused"})
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

    staged = x.stage_trusted_attachment_paths([attachment_path])
    sealed = x.dispatch(
        "message_seal",
        {
            "session_id_hex": finalized["session_id_hex"],
            "text": "Hello **Y**",
            "attachment_ids": [staged[0]["id"]],
            "allow_download": True,
        },
    )
    msg_path = save_grant(x, sealed)
    assert msg_path.exists()
    assert sealed["filename"].startswith("msg_step_000000_")
    assert sealed["filename"].endswith(".paracci")

    msg_ref = y.register_trusted_file_path(msg_path, "message_open")
    opened = y.dispatch(
        "message_open",
        {"session_id_hex": imported["session_id_hex"], "message_ref": msg_ref["id"], "burn_source": False},
    )
    assert opened["text"] == "Hello **Y**"
    assert opened["attachments"][0]["filename"] == "note.txt"
    assert opened["secure_delete_warning"] is None

    preview = y.dispatch(
        "attachment_preview",
        {"open_id": opened["open_id"], "attachment_id": opened["attachments"][0]["attachment_id"]},
    )
    assert preview["preview_kind"] == "text"
    assert "attachment text" in preview["text"]

    saved = y.dispatch(
        "attachment_save",
        {"open_id": opened["open_id"], "attachment_id": "0"},
    )
    saved_path = save_grant(y, saved)
    assert saved_path.read_text(encoding="utf-8") == "attachment text"

    y.dispatch("open_clear", {"open_id": opened["open_id"]})
    assert opened["open_id"] not in y._opened
    try:
        y.dispatch("attachment_preview", {"open_id": opened["open_id"], "attachment_id": "0"})
        assert False, "cleared attachment cache remained accessible"
    except UIApiError as exc:
        assert exc.code == "open_not_found"


def test_ui_api_surfaces_secure_delete_warning(tmp_path):
    api = make_api(tmp_path / "secure-delete-warning")
    message = OpenedMessage(
        text="secret",
        attachments=[],
        allow_download=False,
        msg_id_hex="00",
        evo_step=1,
        expire_at=0,
        single_use=True,
        security_report={"is_safe": True, "risks": []},
        secure_delete_failed=True,
    )

    opened = api._opened_message_to_dict("open-id", message)

    assert opened["secure_delete_warning"] == api.services.i18n.translate(
        "session.secure_delete_failed"
    )


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


def test_ui_api_session_import_rejects_oversized_path_before_service_import(tmp_path, monkeypatch):
    api = make_api(tmp_path / "oversized-import")
    setup_path = tmp_path / "oversized-setup.paracci"
    sentinel = "ui-setup-secret"
    setup_path.write_bytes(sentinel.encode("ascii") + b"x" * 64)
    monkeypatch.setattr(facade_module, "MAX_SETUP_FILE_BYTES", 32)
    monkeypatch.setattr(
        api.services.sessions,
        "import_handshake",
        lambda *_args, **_kwargs: pytest.fail("oversized setup reached service import"),
    )

    import_ref = api.register_trusted_file_path(setup_path, "session_import")

    with pytest.raises(UIApiError) as exc_info:
        api.dispatch("session_import", {"import_ref": import_ref["id"], "local_label": "Y"})

    assert exc_info.value.code == "session_service_error"
    assert "too large" in exc_info.value.message
    assert sentinel not in exc_info.value.message
    assert str(setup_path) not in exc_info.value.message


@pytest.mark.parametrize(
    "method,params",
    [
        ("session_create", {"label": "X", "export_path": "C:/private/init.paracci"}),
        ("session_import", {"import_ref": "opaque", "import_path": "C:/private/init.paracci"}),
        ("session_import", {"import_ref": "opaque", "auto_export_path": "C:/private/resp.paracci"}),
        ("session_export", {"session_id_hex": "00", "export_path": "C:/private/export.paracci"}),
        (
            "message_seal",
            {
                "session_id_hex": "00",
                "text": "secret",
                "output_path": "C:/private/msg.paracci",
            },
        ),
        (
            "message_seal",
            {
                "session_id_hex": "00",
                "text": "secret",
                "attachment_paths": ["C:/private/secret.txt"],
            },
        ),
        ("message_open", {"session_id_hex": "00", "message_path": "C:/private/msg.paracci"}),
        ("attachment_save", {"open_id": "open-id", "attachment_id": "0", "output_path": "C:/private/out.txt"}),
    ],
)
def test_ui_api_rejects_raw_path_params_before_handler(tmp_path, monkeypatch, caplog, method, params):
    api = make_api(tmp_path / "raw-path-reject")
    sentinel = "C:/private/path-secret-sentinel.paracci"
    params = {
        key: (
            sentinel
            if isinstance(value, str) and value.startswith("C:/private")
            else [sentinel] if isinstance(value, list) else value
        )
        for key, value in params.items()
    }

    monkeypatch.setattr(
        api,
        f"cmd_{method}",
        lambda **_kwargs: pytest.fail("raw path reached command handler"),
    )

    caplog.clear()
    with caplog.at_level(logging.DEBUG), pytest.raises(UIApiError) as exc_info:
        api.dispatch(method, params)

    serialized_error = json.dumps(exc_info.value.to_dict())
    assert exc_info.value.code == "raw_path_rejected"
    assert sentinel not in serialized_error
    assert sentinel not in caplog.text


def test_ui_api_rejects_raw_attachment_paths_before_service_call(tmp_path, monkeypatch):
    api = make_api(tmp_path / "raw-attachment-path")
    secret_path = tmp_path / "private-secret.txt"
    secret_path.write_text("secret attachment", encoding="utf-8")
    monkeypatch.setattr(
        api.services.messages,
        "seal_message",
        lambda *_args, **_kwargs: pytest.fail("raw attachment path reached message service"),
    )

    with pytest.raises(UIApiError) as exc_info:
        api.dispatch(
            "message_seal",
            {
                "session_id_hex": "00",
                "text": "secret",
                "attachment_paths": [str(secret_path)],
            },
        )

    serialized_error = json.dumps(exc_info.value.to_dict())
    assert exc_info.value.code == "raw_path_rejected"
    assert str(secret_path) not in serialized_error


def test_ui_api_file_refs_are_purpose_scoped_one_shot_and_sanitized(tmp_path):
    api = make_api(tmp_path / "file-refs")
    selected = tmp_path / "selected-secret-name.paracci"
    selected.write_bytes(b"not a real paracci file")
    ref = api.register_trusted_file_path(selected, "session_import")

    with pytest.raises(UIApiError) as wrong_purpose:
        api.dispatch(
            "message_open",
            {"session_id_hex": "00", "message_ref": ref["id"], "burn_source": False},
        )
    assert wrong_purpose.value.code == "file_ref_invalid"
    assert str(selected) not in json.dumps(wrong_purpose.value.to_dict())

    with pytest.raises(UIApiError) as consumed:
        api.dispatch("session_import", {"import_ref": ref["id"], "local_label": "Y"})
    assert consumed.value.code == "file_ref_invalid"

    stale_ref = api.register_trusted_file_path(selected, "session_import")
    api._file_refs[stale_ref["id"]] = facade_module.TrustedFileRef(
        path=selected,
        purpose="session_import",
        expires_at=time.time() - 1,
    )
    with pytest.raises(UIApiError) as expired:
        api.dispatch("session_import", {"import_ref": stale_ref["id"], "local_label": "Y"})
    assert expired.value.code == "file_ref_invalid"
    assert str(selected) not in json.dumps(expired.value.to_dict())


def test_ui_api_save_grant_to_downloads_is_one_shot_and_no_clobber(tmp_path):
    api = make_api(tmp_path / "save-grant-no-clobber")
    downloads = Path(api.services.settings.downloads_dir)
    existing = downloads / "payload.bin"
    existing.write_bytes(b"existing")
    open_id = cache_open_attachment(
        api,
        AttachmentPayload(
            filename="payload.bin",
            content=b"payload",
            mime_type="application/octet-stream",
            allow_download=True,
        ),
    )

    grant = api.dispatch("attachment_save", {"open_id": open_id, "attachment_id": "0"})
    saved = api.dispatch(
        "save_grant_to_downloads",
        {"native_save_token": grant["native_save_token"]},
    )

    saved_path = Path(saved["output_path"])
    assert saved_path == downloads / "payload_1.bin"
    assert saved_path.read_bytes() == b"payload"
    assert existing.read_bytes() == b"existing"

    with pytest.raises(UIApiError) as reused:
        api.dispatch(
            "save_grant_to_downloads",
            {"native_save_token": grant["native_save_token"]},
        )
    assert reused.value.code == "save_grant_invalid"


def test_ui_api_save_grant_to_downloads_does_not_follow_existing_symlink(tmp_path):
    api = make_api(tmp_path / "save-grant-symlink")
    downloads = Path(api.services.settings.downloads_dir)
    outside = tmp_path / "outside.bin"
    outside.write_bytes(b"outside")
    symlink = downloads / "payload.bin"
    try:
        symlink.symlink_to(outside)
    except OSError:
        pytest.skip("Symlink creation is not available on this platform.")
    open_id = cache_open_attachment(
        api,
        AttachmentPayload(
            filename="payload.bin",
            content=b"payload",
            mime_type="application/octet-stream",
            allow_download=True,
        ),
    )

    grant = api.dispatch("attachment_save", {"open_id": open_id, "attachment_id": "0"})
    saved = api.dispatch(
        "save_grant_to_downloads",
        {"native_save_token": grant["native_save_token"]},
    )

    saved_path = Path(saved["output_path"])
    assert saved_path == downloads / "payload_1.bin"
    assert saved_path.read_bytes() == b"payload"
    assert outside.read_bytes() == b"outside"


def test_ui_api_attachment_save_rejects_unsafe_filename_without_parent_creation(tmp_path):
    api = make_api(tmp_path / "save-grant-unsafe-name")
    downloads = Path(api.services.settings.downloads_dir)
    open_id = cache_open_attachment(
        api,
        AttachmentPayload(
            filename="../payload.bin",
            content=b"payload",
            mime_type="application/octet-stream",
            allow_download=True,
        ),
    )

    with pytest.raises(UIApiError) as exc_info:
        api.dispatch("attachment_save", {"open_id": open_id, "attachment_id": "0"})

    serialized_error = json.dumps(exc_info.value.to_dict())
    assert exc_info.value.code == "save_failed"
    assert "../payload.bin" not in serialized_error
    assert not (downloads / "payload.bin").exists()
    assert not (downloads / "nested").exists()


def test_ui_api_staged_attachment_count_and_size_limits_remain_enforced(tmp_path, monkeypatch):
    api = make_api(tmp_path / "staged-limits")
    too_many = []
    for index in range(facade_module.MAX_ATTACHMENT_COUNT + 1):
        candidate = tmp_path / f"note-{index}.txt"
        candidate.write_text("x", encoding="utf-8")
        too_many.append(candidate)

    with pytest.raises(UIApiError) as count_error:
        api.stage_trusted_attachment_paths(too_many)
    assert count_error.value.code == "attachment_limit"

    oversized = tmp_path / "oversized.txt"
    oversized.write_bytes(b"x" * 16)
    monkeypatch.setattr(facade_module, "MAX_ATTACHMENT_SIZE", 8)

    with pytest.raises(UIApiError) as size_error:
        api.stage_trusted_attachment_paths([oversized])
    assert size_error.value.code == "attachment_limit"
    assert api._staged_attachments == {}


def test_worker_unexpected_errors_are_sanitized():
    from bridge.worker import handle_line

    class FailingApi:
        def dispatch(self, _method, _params):
            raise RuntimeError("C:/private/path-secret-sentinel.paracci")

    response = handle_line(FailingApi(), json.dumps({"id": "1", "method": "boom", "params": {}}))

    serialized = json.dumps(response)
    assert response["ok"] is False
    assert response["error"]["code"] == "unexpected_error"
    assert response["error"]["message"] == "Unexpected error."
    assert "path-secret-sentinel" not in serialized


def test_ui_api_2fa_unlock_stays_pending_until_totp_verification(tmp_path):
    api = make_api(tmp_path / "native-2fa-pending")
    secret = enable_2fa_and_lock(api)

    pending_status = api.dispatch("device_unlock", {"pin": PIN})

    assert pending_status["unlocked"] is False
    assert pending_status["two_factor_enabled"] is True
    assert pending_status["unlock_state"] == "pending_2fa"
    assert pending_status["two_factor_required"] is True
    assert api.services.device.device_key is None
    assert api.services.device.db.has_device_key is False
    assert api.services.device._pending_unlock is not None

    unlocked_status = api.dispatch("2fa_verify", {"code": pyotp.TOTP(secret).now()})

    assert unlocked_status["verified"] is True
    assert unlocked_status["unlocked"] is True
    assert unlocked_status["two_factor_enabled"] is True
    assert unlocked_status["unlock_state"] == "unlocked"
    assert unlocked_status["two_factor_required"] is False
    assert api.services.device.device_key is not None
    assert api.services.device.db.has_device_key is True
    assert api.services.device._pending_unlock is None


def test_ui_api_invalid_totp_clears_pending_unlock_material(tmp_path):
    api = make_api(tmp_path / "native-2fa-invalid")
    secret = enable_2fa_and_lock(api)
    api.dispatch("device_unlock", {"pin": PIN})
    pending = api.services.device._pending_unlock
    assert pending is not None
    pending_key = pending.device_key
    pending_db = pending.db

    with pytest.raises(UIApiError) as invalid:
        api.dispatch("2fa_verify", {"code": "invalid-code"})

    assert invalid.value.code == "invalid_2fa"
    assert api.services.device.device_key is None
    assert api.services.device.db.has_device_key is False
    assert api.services.device._pending_unlock is None
    assert pending_db.has_device_key is False
    assert pending_key == bytearray(len(pending_key))

    with pytest.raises(UIApiError) as missing:
        api.dispatch("2fa_verify", {"code": pyotp.TOTP(secret).now()})

    assert missing.value.code == "2fa_not_pending"


def test_ui_api_lock_and_expiry_clear_pending_unlock_material(tmp_path):
    api = make_api(tmp_path / "native-2fa-cleanup")
    enable_2fa_and_lock(api)
    api.dispatch("device_unlock", {"pin": PIN})
    locked_pending = api.services.device._pending_unlock
    assert locked_pending is not None

    locked_status = api.dispatch("device_lock")

    assert locked_status["unlock_state"] == "locked"
    assert locked_status["two_factor_required"] is False
    assert locked_pending.db.has_device_key is False
    assert locked_pending.device_key == bytearray(len(locked_pending.device_key))

    api.dispatch("device_unlock", {"pin": PIN})
    expired_pending = api.services.device._pending_unlock
    assert expired_pending is not None
    expired_pending.created_at -= PENDING_UNLOCK_TTL_SECONDS + 1

    expired_status = api.dispatch("device_status")

    assert expired_status["unlocked"] is False
    assert expired_status["unlock_state"] == "locked"
    assert expired_status["two_factor_required"] is False
    assert expired_pending.db.has_device_key is False
    assert expired_pending.device_key == bytearray(len(expired_pending.device_key))


def test_ui_api_non_2fa_unlock_still_activates_device(tmp_path):
    api = make_api(tmp_path / "native-non-2fa-unlock")
    api.dispatch("device_init", {"pin": PIN})
    api.dispatch("device_lock")

    unlocked_status = api.dispatch("device_unlock", {"pin": PIN})

    assert unlocked_status["unlocked"] is True
    assert unlocked_status["two_factor_enabled"] is False
    assert unlocked_status["unlock_state"] == "unlocked"
    assert unlocked_status["two_factor_required"] is False
    assert api.services.device.db.has_device_key is True


def test_ui_api_2fa_reunlock_while_active_does_not_create_pending_state(tmp_path):
    api = make_api(tmp_path / "native-2fa-active-reunlock")
    api.dispatch("device_init", {"pin": PIN})
    api.dispatch(
        "2fa_enable",
        {"secret": TOTP_SECRET, "code": pyotp.TOTP(TOTP_SECRET).now()},
    )

    unlocked_status = api.dispatch("device_unlock", {"pin": PIN})

    assert unlocked_status["unlocked"] is True
    assert unlocked_status["two_factor_enabled"] is True
    assert unlocked_status["unlock_state"] == "unlocked"
    assert unlocked_status["two_factor_required"] is False
    assert api.services.device.db.has_device_key is True
    assert api.services.device._pending_unlock is None


def test_ui_api_2fa_unlock_does_not_log_sensitive_values(tmp_path, caplog):
    api = make_api(tmp_path / "native-2fa-log-hygiene")
    pin = "Correct-Horse-Log-Sentinel-95175328"
    secret = TOTP_SECRET
    token_sentinel = "session-token-log-sentinel"

    with caplog.at_level(logging.DEBUG):
        api.dispatch("device_init", {"pin": pin})
        active_device_key_hex = bytes(api.services.device.device_key or b"").hex()
        valid_code = pyotp.TOTP(secret).now()
        api.dispatch("2fa_enable", {"secret": secret, "code": valid_code})
        api.dispatch("device_lock")
        api.dispatch("device_unlock", {"pin": pin})
        pending = api.services.device._pending_unlock
        assert pending is not None
        pending_key_hex = bytes(pending.device_key).hex()
        pending_db_key_hex = bytes(pending.db._device_key or b"").hex()
        pending_repr = repr(pending)
        with pytest.raises(UIApiError):
            api.dispatch("2fa_verify", {"code": token_sentinel})

    for label, value in [
        ("passphrase", pin),
        ("TOTP secret", secret),
        ("valid TOTP", valid_code),
        ("session token", token_sentinel),
        ("device key", active_device_key_hex),
        ("pending key", pending_key_hex),
        ("pending DB key", pending_db_key_hex),
    ]:
        assert_sensitive_absent(label, value, caplog.text)
    assert_sensitive_absent("pending key repr", pending_key_hex, pending_repr)
    assert_sensitive_absent("pending DB key repr", pending_db_key_hex, pending_repr)


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


def test_ui_api_non_downloadable_svg_preview_does_not_use_raster_decoder(tmp_path, monkeypatch):
    api = make_api(tmp_path / "native-preview-svg")
    svg_bytes = b"<svg><script>secretPreviewToken()</script></svg>"
    open_id = cache_open_attachment(
        api,
        AttachmentPayload(
            filename="vector.svg",
            content=svg_bytes,
            mime_type="image/svg+xml",
            allow_download=False,
        ),
    )

    monkeypatch.setattr(
        facade_module,
        "build_no_download_image_preview",
        lambda *_args, **_kwargs: pytest.fail("SVG reached raster preview builder"),
    )

    preview = api.dispatch(
        "attachment_preview",
        {"open_id": open_id, "attachment_id": "0"},
    )

    assert preview["preview_kind"] == "unsupported"
    assert preview["message"] == "Preview not available for this file type when downloading is disabled."
    assert "content_base64" not in preview
    assert svg_bytes.decode("utf-8") not in str(preview)


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
