"""JSON-safe UI API shared by QML and macOS JSON-RPC frontends."""

from __future__ import annotations

import base64
import logging
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from desktop.device_key_binding import DeviceBindingError
from desktop.services import AttachmentPayload, MessageServiceError, NativeServices, OpenedMessage, SessionServiceError
from core.sanitizer import build_no_download_image_preview

logger = logging.getLogger(__name__)


OPEN_CACHE_TTL_SECONDS = 600
NO_DOWNLOAD_TEXT_PREVIEW_MESSAGE = "This file cannot be previewed here."
NO_DOWNLOAD_BINARY_PREVIEW_MESSAGE = "Preview not available for this file type when downloading is disabled."


class UIApiError(Exception):
    """Frontend-safe UI API failure."""

    def __init__(self, code: str, message: str, details: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.details = details

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, "details": self.details}


@dataclass
class CachedOpenMessage:
    """Short-lived opened message cache entry."""

    message: OpenedMessage | None
    opened_at: int


class UIApi:
    """Stable command surface for native frontends.

    The API only returns JSON-safe values. Binary message and attachment data is
    written to explicit paths, except previews which return base64 or text.
    """

    def __init__(self, services: NativeServices):
        self.services = services
        self._opened: dict[str, CachedOpenMessage] = {}

    # ------------------------------------------------------------------
    # Command dispatcher
    # ------------------------------------------------------------------

    def dispatch(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        handler = getattr(self, f"cmd_{method}", None)
        if handler is None:
            raise UIApiError("method_not_found", f"Unknown UI API method: {method}")
        try:
            result = handler(**params)
            return result if isinstance(result, dict) else {"value": result}
        except UIApiError:
            raise
        except DeviceBindingError as exc:
            message = self.services.i18n.translate(exc.i18n_key)
            raise UIApiError(exc.code, message) from exc
        except SessionServiceError as exc:
            message = str(exc)
            if message.startswith("hybrid_kem_") or message.startswith("session."):
                raise UIApiError(message, self.services.i18n.translate(message)) from exc
            raise UIApiError("session_service_error", message) from exc
        except MessageServiceError as exc:
            message = str(exc)
            if message.startswith("hybrid_kem_") or message.startswith("session."):
                raise UIApiError(message, self.services.i18n.translate(message)) from exc
            raise UIApiError("message_service_error", message) from exc
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            logger.exception(
                "Unexpected error in UIApi.dispatch method=%s", method
            )
            raise UIApiError("unexpected_error", "Unexpected error.") from exc

    # ------------------------------------------------------------------
    # Device and settings
    # ------------------------------------------------------------------

    def cmd_device_status(self) -> dict[str, Any]:
        return {
            "initialized": self.services.device.is_initialized(),
            "unlocked": self.services.device.is_unlocked,
            "two_factor_enabled": self.services.device.is_2fa_enabled(),
            "data_dir": str(self.services.data_dir),
            "platform": self.services.shield.get_os_name(),
            "shield": self._shield_status(),
        }

    def cmd_device_init(self, pin: str) -> dict[str, Any]:
        self.services.device.initialize(pin)
        result = self.cmd_device_status()
        self._attach_device_binding_warning(result)
        return result

    def cmd_device_unlock(self, pin: str) -> dict[str, Any]:
        self.services.device.unlock(pin)
        result = self.cmd_device_status()
        self._attach_device_binding_warning(result)
        return result

    def cmd_device_lock(self) -> dict[str, Any]:
        self.clear_open_cache()
        self.services.device.lock()
        return self.cmd_device_status()

    def _attach_device_binding_warning(self, result: dict[str, Any]) -> None:
        warning = self.services.device.device_binding_warning
        if warning is None:
            return
        result["device_binding_warning"] = {
            "code": warning.code,
            "message": self.services.i18n.translate(warning.i18n_key),
        }
        self.services.device.device_binding_warning = None

    def cmd_2fa_new_secret(self) -> dict[str, Any]:
        secret = self.services.device.new_2fa_secret()
        username = str(self.services.settings.get("username") or "Paracci User")
        return {
            "secret": secret,
            "provisioning_uri": self.services.device.provisioning_uri(secret, username),
        }

    def cmd_2fa_enable(self, secret: str, code: str) -> dict[str, Any]:
        if not self.services.device.verify_2fa_code(secret, code):
            raise UIApiError("invalid_2fa", "Invalid two-factor authentication code.")
        self.services.device.set_2fa_secret(secret)
        self.services.device.set_2fa_enabled(True)
        return self.cmd_device_status()

    def cmd_2fa_verify(self, code: str) -> dict[str, Any]:
        secret = self.services.device.get_2fa_secret()
        if not secret or not self.services.device.verify_2fa_code(secret, code):
            raise UIApiError("invalid_2fa", "Invalid two-factor authentication code.")
        return {"verified": True}

    def cmd_2fa_disable(self) -> dict[str, Any]:
        self.services.device.set_2fa_enabled(False)
        return self.cmd_device_status()

    def cmd_settings_get(self) -> dict[str, Any]:
        return {"settings": self.services.settings.refresh()}

    def cmd_settings_update(self, values: dict[str, Any]) -> dict[str, Any]:
        self.services.settings.set_many(values)
        if "language" in values:
            self.services.i18n.set_locale(str(values["language"]))
        return self.cmd_settings_get()

    def cmd_profile_update(self, username: str, avatar_color: str = "#0a84ff") -> dict[str, Any]:
        if not username.strip():
            raise UIApiError("invalid_profile", "Username is required.")
        self.services.settings.set_many(
            {"username": username.strip(), "avatar_color": avatar_color.strip() or "#0a84ff"}
        )
        return self.cmd_settings_get()

    # ------------------------------------------------------------------
    # Sessions
    # ------------------------------------------------------------------

    def cmd_sessions_list(self) -> dict[str, Any]:
        sessions = []
        for session in self.services.sessions.list_sessions():
            item = asdict(session)
            item["updated_text"] = time.strftime("%Y-%m-%d %H:%M", time.localtime(session.updated_at))
            sessions.append(item)
        return {"sessions": sessions}

    def cmd_session_load(self, session_id_hex: str) -> dict[str, Any]:
        meta = self.services.sessions.load(session_id_hex)
        safety_code = self.services.sessions.safety_code(meta)
        evo = self.services.sessions.evo_info(meta)
        return {
            "session": {
                "session_id_hex": session_id_hex,
                "label": meta.label,
                "role": meta.role,
                "state": meta.state,
                "bonded": meta.is_bonded,
                "safety_code": safety_code,
                "fingerprint": safety_code,
                "safety_confirmed": meta.safety_confirmed,
                "handshake_version": meta.handshake_version,
                "requires_confirmation": bool(safety_code and not meta.safety_confirmed),
                "tx_count": meta.tx_count,
                "rx_count": meta.rx_count,
                "evolution": evo,
                "active_and_bonded": meta.can_send,
            }
        }

    def cmd_session_confirm_safety(self, session_id_hex: str, safety_code: str) -> dict[str, Any]:
        self.services.sessions.confirm_safety(session_id_hex, safety_code)
        return self.cmd_session_load(session_id_hex)

    def cmd_session_create(
        self,
        label: str,
        export_path: str,
        session_ttl_sec: int = 0,
    ) -> dict[str, Any]:
        result = self.services.sessions.create_initiator(
            label=label,
            session_ttl_sec=int(session_ttl_sec),
        )
        self._write_bytes(export_path, result.auto_export_bytes or b"")
        return {
            "session_id_hex": result.session_id_hex,
            "message": result.message,
            "export_path": str(Path(export_path)),
            "filename": result.auto_export_filename,
        }

    def cmd_session_import(
        self,
        import_path: str,
        local_label: str = "",
        auto_export_path: str | None = None,
    ) -> dict[str, Any]:
        path = Path(import_path)
        result = self.services.sessions.import_handshake(path.read_bytes(), local_label or path.stem)
        response = {
            "session_id_hex": result.session_id_hex,
            "message": result.message,
            "auto_exported": False,
            "auto_export_path": None,
            "filename": result.auto_export_filename,
            "state": result.state,
            "safety_code": result.safety_code,
            "requires_confirmation": result.requires_confirmation,
        }
        if result.auto_export_bytes and auto_export_path:
            self._write_bytes(auto_export_path, result.auto_export_bytes)
            response["auto_exported"] = True
            response["auto_export_path"] = str(Path(auto_export_path))
        return response

    def cmd_session_export(self, session_id_hex: str, export_path: str) -> dict[str, Any]:
        data, filename = self.services.sessions.export_handshake(session_id_hex)
        self._write_bytes(export_path, data)
        return {"session_id_hex": session_id_hex, "export_path": str(Path(export_path)), "filename": filename}

    # ------------------------------------------------------------------
    # Messages and attachments
    # ------------------------------------------------------------------

    def cmd_message_seal(
        self,
        session_id_hex: str,
        text: str,
        output_path: str,
        attachment_paths: list[str] | None = None,
        allow_download: bool = False,
        ttl_seconds: int = 0,
    ) -> dict[str, Any]:
        data, filename = self.services.messages.seal_message(
            session_id_hex=session_id_hex,
            text=text,
            attachment_paths=[Path(p) for p in attachment_paths or []],
            allow_download=bool(allow_download),
            ttl_seconds=int(ttl_seconds),
        )
        self._write_bytes(output_path, data)
        return {"session_id_hex": session_id_hex, "output_path": str(Path(output_path)), "filename": filename}

    def cmd_message_open(self, session_id_hex: str, message_path: str, burn_source: bool = True) -> dict[str, Any]:
        self._cleanup_open_cache()
        path = Path(message_path)
        source_path = path if burn_source else None
        opened = self.services.messages.open_message(session_id_hex, path.read_bytes(), source_path)
        open_id = uuid.uuid4().hex
        self._opened[open_id] = CachedOpenMessage(
            message=opened,
            opened_at=int(time.time()),
        )
        return self._opened_message_to_dict(open_id, opened)

    def cmd_attachment_preview(self, open_id: str, attachment_id: str) -> dict[str, Any]:
        attachment = self._get_attachment(open_id, attachment_id)
        response = self._attachment_meta(attachment, attachment_id)
        if not attachment.allow_download:
            if attachment.is_image:
                preview_data = build_no_download_image_preview(
                    attachment.content,
                    attachment.mime_type,
                )
                if preview_data:
                    preview_content, preview_mime = preview_data
                    response["preview_kind"] = "image_base64"
                    response["mime_type"] = preview_mime
                    response["content_base64"] = base64.b64encode(preview_content).decode("ascii")
                else:
                    response["preview_kind"] = "unsupported"
                    response["message"] = NO_DOWNLOAD_BINARY_PREVIEW_MESSAGE
            else:
                response["preview_kind"] = "unsupported"
                response["message"] = (
                    NO_DOWNLOAD_TEXT_PREVIEW_MESSAGE
                    if attachment.is_text_like or attachment.is_dangerous
                    else NO_DOWNLOAD_BINARY_PREVIEW_MESSAGE
                )
            return response

        if attachment.is_text_like or attachment.is_dangerous:
            response["preview_kind"] = "text"
            response["text"] = attachment.content.decode("utf-8", errors="replace")
        elif attachment.is_image:
            response["preview_kind"] = "image_base64"
            response["content_base64"] = base64.b64encode(attachment.content).decode("ascii")
        else:
            response["preview_kind"] = "unsupported"
            response["message"] = "Native preview is not available for this file type."
        return response

    def cmd_attachment_save(self, open_id: str, attachment_id: str, output_path: str) -> dict[str, Any]:
        attachment = self._get_attachment(open_id, attachment_id)
        if not attachment.allow_download:
            raise UIApiError("download_blocked", "The sender did not allow saving this attachment.")
        self._write_bytes(output_path, attachment.content)
        return {"open_id": open_id, "attachment_id": attachment_id, "output_path": str(Path(output_path))}

    def cmd_open_clear(self, open_id: str | None = None) -> dict[str, Any]:
        if open_id:
            self._drop_open_cache_entry(self._opened.pop(open_id, None))
        else:
            self.clear_open_cache()
        return {"cleared": True}

    def clear_open_cache(self) -> None:
        for open_id in list(self._opened.keys()):
            self._drop_open_cache_entry(self._opened.pop(open_id, None))

    def _cleanup_open_cache(self) -> None:
        now = int(time.time())
        expired = [
            open_id
            for open_id, cached in self._opened.items()
            if now - cached.opened_at > OPEN_CACHE_TTL_SECONDS
        ]
        for open_id in expired:
            self._drop_open_cache_entry(self._opened.pop(open_id, None))

    def _drop_open_cache_entry(self, cached: CachedOpenMessage | None) -> None:
        if cached is None or cached.message is None:
            return
        cached.message.attachments.clear()
        cached.message = None

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _opened_message_to_dict(self, open_id: str, message: OpenedMessage) -> dict[str, Any]:
        return {
            "open_id": open_id,
            "text": message.text,
            "allow_download": message.allow_download,
            "msg_id_hex": message.msg_id_hex,
            "evo_step": message.evo_step,
            "expire_at": message.expire_at,
            "single_use": message.single_use,
            "security_report": message.security_report,
            "attachments": [
                self._attachment_meta(attachment, str(index))
                for index, attachment in enumerate(message.attachments)
            ],
        }

    def _attachment_meta(self, attachment: AttachmentPayload, attachment_id: str) -> dict[str, Any]:
        return {
            "attachment_id": attachment_id,
            "filename": attachment.filename,
            "size": attachment.size,
            "mime_type": attachment.mime_type,
            "allow_download": attachment.allow_download,
            "is_image": attachment.is_image,
            "is_video": attachment.is_video,
            "is_text_like": attachment.is_text_like,
            "is_dangerous": attachment.is_dangerous,
        }

    def _get_attachment(self, open_id: str, attachment_id: str) -> AttachmentPayload:
        self._cleanup_open_cache()
        cached = self._opened.get(open_id)
        if cached is None or cached.message is None:
            raise UIApiError("open_not_found", "Opened message is no longer available.")
        try:
            index = int(attachment_id)
            return cached.message.attachments[index]
        except (ValueError, IndexError) as exc:
            raise UIApiError("attachment_not_found", "Attachment is no longer available.") from exc

    def _write_bytes(self, output_path: str, data: bytes) -> None:
        path = Path(output_path).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)

    def _shield_status(self) -> dict[str, str]:
        enabled = bool(self.services.settings.get("anti_screenshot"))
        os_name = self.services.shield.get_os_name()
        if not enabled:
            return {"state": "disabled", "label": "Disabled"}
        if os_name == "Windows":
            return {"state": "best_effort", "label": "Best effort"}
        if os_name == "macOS":
            return {"state": "best_effort", "label": "Best effort"}
        if os_name == "Linux":
            return {"state": "limited", "label": "Limited"}
        return {"state": "unavailable", "label": "Unavailable"}
