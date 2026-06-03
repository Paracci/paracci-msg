"""JSON-safe UI API shared by QML and macOS JSON-RPC frontends."""

from __future__ import annotations

import base64
import logging
import os
import secrets
import time
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from core.burn import _secure_dir_permissions, secure_delete
from desktop.device_key_binding import DeviceBindingError
from desktop.services import (
    MAX_ATTACHMENT_COUNT,
    MAX_ATTACHMENT_SIZE,
    AttachmentPayload,
    MessageServiceError,
    NativeServices,
    OpenedMessage,
    SessionServiceError,
)
from core.ingest_limits import MAX_SETUP_FILE_BYTES, IngestionLimitError, read_path_limited
from core.package import (
    MAX_ATTACHMENT_FILENAME_LENGTH,
    sanitize_attachment_filename,
    validate_native_download_filename,
)
from core.preview_store import MAX_NATIVE_SAVE_BYTES, NativeSaveGrantStore
from core.sanitizer import (
    SanitizationError,
    build_no_download_image_preview,
    is_safe_raster_image_mime,
    sanitize_image,
)

logger = logging.getLogger(__name__)


OPEN_CACHE_TTL_SECONDS = 600
FILE_REF_TTL_SECONDS = 600
STAGED_ATTACHMENT_TTL_SECONDS = 600
NO_DOWNLOAD_TEXT_PREVIEW_MESSAGE = "This file cannot be previewed here."
NO_DOWNLOAD_BINARY_PREVIEW_MESSAGE = "Preview not available for this file type when downloading is disabled."
RAW_PATH_REJECTED_MESSAGE = (
    "Raw filesystem paths are not accepted by this UI API method. "
    "Use a trusted file reference or save grant."
)
FILE_REF_INVALID_MESSAGE = "Selected file is no longer available."
SAVE_GRANT_INVALID_MESSAGE = "Save grant is invalid or expired."
TRUSTED_FILE_REF_PURPOSES = {"session_import", "message_open"}
RAW_PATH_PARAMS_BY_METHOD = {
    "session_create": {"export_path"},
    "session_import": {"import_path", "auto_export_path"},
    "session_export": {"export_path"},
    "message_seal": {"output_path", "attachment_paths"},
    "message_open": {"message_path"},
    "attachment_save": {"output_path"},
}


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


@dataclass(frozen=True)
class TrustedFileRef:
    """Short-lived trusted file reference created by native picker code."""

    path: Path
    purpose: str
    expires_at: float


@dataclass(frozen=True)
class StagedAttachmentRef:
    """Short-lived attachment copy created from trusted picker results."""

    filename: str
    content_path: Path
    size: int
    expires_at: float


class UIApi:
    """Stable command surface for native frontends.

    The API only returns JSON-safe values. Binary message and attachment data is
    exposed through one-shot save grants, except previews which return base64 or text.
    """

    def __init__(self, services: NativeServices):
        self.services = services
        self._opened: dict[str, CachedOpenMessage] = {}
        self._file_refs: dict[str, TrustedFileRef] = {}
        self._staged_attachments: dict[str, StagedAttachmentRef] = {}
        self._save_grants = NativeSaveGrantStore()

    # ------------------------------------------------------------------
    # Command dispatcher
    # ------------------------------------------------------------------

    def dispatch(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        params = params or {}
        handler = getattr(self, f"cmd_{method}", None)
        if handler is None:
            raise UIApiError("method_not_found", f"Unknown UI API method: {method}")
        self._reject_raw_path_params(method, params)
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
            "unlock_state": self.services.device.unlock_state,
            "two_factor_required": self.services.device.has_pending_unlock,
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
        if self.services.device.has_pending_unlock:
            if not self.services.device.complete_pending_unlock(code):
                raise UIApiError("invalid_2fa", "Invalid two-factor authentication code.")
            result = self.cmd_device_status()
            result["verified"] = True
            return result
        if not self.services.device.is_unlocked:
            raise UIApiError("2fa_not_pending", "Two-factor unlock is not pending.")
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
        export_path: str | None = None,
        session_ttl_sec: int = 0,
    ) -> dict[str, Any]:
        self._reject_raw_path_param("export_path", export_path)
        result = self.services.sessions.create_initiator(
            label=label,
            session_ttl_sec=int(session_ttl_sec),
        )
        native_save_token = self._issue_save_grant(
            result.auto_export_bytes or b"",
            result.auto_export_filename or "session.paracci",
        )
        return {
            "session_id_hex": result.session_id_hex,
            "message": result.message,
            "native_save_token": native_save_token,
            "filename": result.auto_export_filename,
        }

    def cmd_session_import(
        self,
        import_ref: str | None = None,
        local_label: str = "",
        import_path: str | None = None,
        auto_export_path: str | None = None,
    ) -> dict[str, Any]:
        self._reject_raw_path_param("import_path", import_path)
        self._reject_raw_path_param("auto_export_path", auto_export_path)
        if not import_ref:
            raise UIApiError("file_ref_required", "A trusted file reference is required.")
        path = self._consume_file_ref(import_ref, "session_import")
        try:
            file_bytes = read_path_limited(path, MAX_SETUP_FILE_BYTES, "Setup file")
        except IngestionLimitError as exc:
            raise SessionServiceError(str(exc)) from exc
        except OSError as exc:
            raise SessionServiceError("Could not read selected setup file.") from exc
        result = self.services.sessions.import_handshake(file_bytes, local_label or path.stem)
        response = {
            "session_id_hex": result.session_id_hex,
            "message": result.message,
            "auto_exported": False,
            "auto_export_path": None,
            "native_save_token": None,
            "filename": result.auto_export_filename,
            "state": result.state,
            "safety_code": result.safety_code,
            "requires_confirmation": result.requires_confirmation,
        }
        if result.auto_export_bytes:
            response["native_save_token"] = self._issue_save_grant(
                result.auto_export_bytes,
                result.auto_export_filename or "session.paracci",
            )
            response["auto_exported"] = True
        return response

    def cmd_session_export(self, session_id_hex: str, export_path: str | None = None) -> dict[str, Any]:
        self._reject_raw_path_param("export_path", export_path)
        data, filename = self.services.sessions.export_handshake(session_id_hex)
        native_save_token = self._issue_save_grant(data, filename)
        return {
            "session_id_hex": session_id_hex,
            "native_save_token": native_save_token,
            "filename": filename,
        }

    # ------------------------------------------------------------------
    # Messages and attachments
    # ------------------------------------------------------------------

    def cmd_message_seal(
        self,
        session_id_hex: str,
        text: str,
        output_path: str | None = None,
        attachment_paths: list[str] | None = None,
        attachment_ids: list[str] | None = None,
        allow_download: bool = False,
        ttl_seconds: int = 0,
    ) -> dict[str, Any]:
        self._reject_raw_path_param("output_path", output_path)
        self._reject_raw_path_param("attachment_paths", attachment_paths)
        staged_attachments = self._consume_staged_attachment_ids(attachment_ids or [])
        try:
            data, filename = self.services.messages.seal_message(
                session_id_hex=session_id_hex,
                text=text,
                attachment_paths=[],
                staged_attachments=staged_attachments,
                allow_download=bool(allow_download),
                ttl_seconds=int(ttl_seconds),
                output_path=None,
            )
        except Exception:
            self._drop_staged_files(staged_attachments)
            raise
        native_save_token = self._issue_save_grant(data or b"", filename)
        return {
            "session_id_hex": session_id_hex,
            "native_save_token": native_save_token,
            "filename": filename,
        }

    def cmd_message_open(
        self,
        session_id_hex: str,
        message_ref: str | None = None,
        message_path: str | None = None,
        burn_source: bool = True,
    ) -> dict[str, Any]:
        self._reject_raw_path_param("message_path", message_path)
        if not message_ref:
            raise UIApiError("file_ref_required", "A trusted file reference is required.")
        self._cleanup_open_cache()
        path = self._consume_file_ref(message_ref, "message_open")
        opened = self.services.messages.open_message(session_id_hex, file_bytes=None, source_path=path, burn_source=burn_source)
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
            if attachment.is_image and is_safe_raster_image_mime(attachment.mime_type):
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

    def cmd_attachment_save(
        self,
        open_id: str,
        attachment_id: str,
        output_path: str | None = None,
    ) -> dict[str, Any]:
        self._reject_raw_path_param("output_path", output_path)
        attachment = self._get_attachment(open_id, attachment_id)
        if not attachment.allow_download:
            raise UIApiError("download_blocked", "The sender did not allow saving this attachment.")
        try:
            native_save_token = self._issue_save_grant(
                file_bytes=None,
                filename=attachment.filename,
                file_path=attachment.content_path,
            )
        except ValueError as exc:
            raise UIApiError("save_failed", "Failed to prepare attachment save.") from exc
        return {
            "open_id": open_id,
            "attachment_id": attachment_id,
            "native_save_token": native_save_token,
            "filename": validate_native_download_filename(attachment.filename),
        }

    def cmd_open_clear(self, open_id: str | None = None) -> dict[str, Any]:
        if open_id:
            self._drop_open_cache_entry(self._opened.pop(open_id, None))
        else:
            self.clear_open_cache()
        return {"cleared": True}

    def cmd_save_grant_to_downloads(self, native_save_token: str) -> dict[str, Any]:
        grant = self._save_grants.consume(str(native_save_token or ""))
        if grant is None:
            raise UIApiError("save_grant_invalid", SAVE_GRANT_INVALID_MESSAGE)
        try:
            path = self._write_managed_download(grant.filename, grant.file_bytes)
        except ValueError as exc:
            raise UIApiError("save_failed", "Failed to save file.") from exc
        return {"output_path": str(path), "filename": path.name}

    def register_trusted_file_path(self, path: str | Path, purpose: str) -> dict[str, str]:
        """Register an OS-picker-selected file without exposing its path to JSON callers."""
        normalized_purpose = self._normalize_file_ref_purpose(purpose)
        candidate = Path(path)
        try:
            if not candidate.is_file():
                raise OSError
        except OSError as exc:
            raise UIApiError("file_ref_invalid", "Selected file is unavailable.") from exc
        self._cleanup_file_refs()
        ref_id = secrets.token_hex(32)
        self._file_refs[ref_id] = TrustedFileRef(
            path=candidate,
            purpose=normalized_purpose,
            expires_at=time.time() + FILE_REF_TTL_SECONDS,
        )
        return {
            "id": ref_id,
            "filename": sanitize_attachment_filename(candidate.name),
        }

    def stage_trusted_attachment_paths(self, paths: list[str | Path] | str | Path) -> list[dict[str, Any]]:
        """Stage OS-picker-selected attachments as opaque IDs for message sealing."""
        if isinstance(paths, (str, Path)):
            paths = [paths]
        selected = [Path(path) for path in (paths or [])]
        selected = [path for path in selected if str(path).strip()]
        if len(selected) > MAX_ATTACHMENT_COUNT:
            raise UIApiError("attachment_limit", f"Maximum {MAX_ATTACHMENT_COUNT} files can be attached.")

        self._cleanup_staged_attachments()
        staged_ids: list[str] = []
        staged_items: list[dict[str, Any]] = []
        total_size = 0
        temp_dir = self._temp_dir()

        try:
            for selected_path in selected:
                try:
                    if not selected_path.is_file():
                        raise OSError
                except OSError as exc:
                    raise UIApiError("attachment_unavailable", "Selected attachment could not be read.") from exc

                safe_filename = sanitize_attachment_filename(selected_path.name)
                staged_path = temp_dir / f"ui_attachment_{secrets.token_hex(16)}.bin"
                written_size = 0
                try:
                    with open(selected_path, "rb") as src, open(staged_path, "wb") as dest:
                        while True:
                            chunk = src.read(64 * 1024)
                            if not chunk:
                                break
                            written_size += len(chunk)
                            if total_size + written_size > MAX_ATTACHMENT_SIZE:
                                raise UIApiError(
                                    "attachment_limit",
                                    f"Total attachment size exceeds {MAX_ATTACHMENT_SIZE // (1024 * 1024)}MB.",
                                )
                            dest.write(chunk)
                except UIApiError:
                    self._secure_delete_quietly(staged_path)
                    raise
                except OSError as exc:
                    self._secure_delete_quietly(staged_path)
                    raise UIApiError("attachment_unavailable", "Selected attachment could not be read.") from exc

                file_size = written_size
                try:
                    if Path(safe_filename).suffix.lower() in {".jpg", ".jpeg", ".png", ".webp"}:
                        sanitized = sanitize_image(staged_path.read_bytes(), safe_filename)
                        staged_path.write_bytes(sanitized)
                        file_size = len(sanitized)
                except SanitizationError as exc:
                    self._secure_delete_quietly(staged_path)
                    raise UIApiError("attachment_rejected", SanitizationError.user_message) from exc
                except OSError as exc:
                    self._secure_delete_quietly(staged_path)
                    raise UIApiError("attachment_unavailable", "Selected attachment could not be read.") from exc

                total_size += file_size
                attachment_id = secrets.token_hex(32)
                self._staged_attachments[attachment_id] = StagedAttachmentRef(
                    filename=safe_filename,
                    content_path=staged_path,
                    size=file_size,
                    expires_at=time.time() + STAGED_ATTACHMENT_TTL_SECONDS,
                )
                staged_ids.append(attachment_id)
                staged_items.append({
                    "id": attachment_id,
                    "filename": safe_filename,
                    "size": file_size,
                })
            return staged_items
        except Exception:
            for staged_id in staged_ids:
                self._drop_staged_attachment(staged_id)
            raise

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

    def _reject_raw_path_params(self, method: str, params: dict[str, Any]) -> None:
        for field in RAW_PATH_PARAMS_BY_METHOD.get(method, set()):
            if field in params:
                raise UIApiError("raw_path_rejected", RAW_PATH_REJECTED_MESSAGE)

    def _reject_raw_path_param(self, field: str, value: Any) -> None:
        if value is not None:
            raise UIApiError("raw_path_rejected", RAW_PATH_REJECTED_MESSAGE)

    def _normalize_file_ref_purpose(self, purpose: str) -> str:
        normalized = str(purpose or "").strip()
        if normalized not in TRUSTED_FILE_REF_PURPOSES:
            raise UIApiError("file_ref_invalid", FILE_REF_INVALID_MESSAGE)
        return normalized

    def _cleanup_file_refs(self) -> None:
        now = time.time()
        for ref_id, entry in list(self._file_refs.items()):
            if entry.expires_at < now:
                self._file_refs.pop(ref_id, None)

    def _consume_file_ref(self, ref_id: str, purpose: str) -> Path:
        normalized_purpose = self._normalize_file_ref_purpose(purpose)
        self._cleanup_file_refs()
        entry = self._file_refs.pop(str(ref_id or "").strip(), None)
        if (
            entry is None
            or entry.purpose != normalized_purpose
            or entry.expires_at < time.time()
        ):
            raise UIApiError("file_ref_invalid", FILE_REF_INVALID_MESSAGE)
        return entry.path

    def _cleanup_staged_attachments(self) -> None:
        now = time.time()
        for attachment_id, entry in list(self._staged_attachments.items()):
            if entry.expires_at < now:
                self._staged_attachments.pop(attachment_id, None)
                self._secure_delete_quietly(entry.content_path)

    def _drop_staged_attachment(self, attachment_id: str) -> None:
        entry = self._staged_attachments.pop(attachment_id, None)
        if entry is not None:
            self._secure_delete_quietly(entry.content_path)

    def _drop_staged_files(self, files: list[tuple[str, Path]]) -> None:
        for _name, path in files:
            self._secure_delete_quietly(path)

    def _consume_staged_attachment_ids(self, attachment_ids: list[str]) -> list[tuple[str, Path]]:
        self._cleanup_staged_attachments()
        if not isinstance(attachment_ids, list):
            raise UIApiError("invalid_attachment_ids", "Attachment IDs must be a list.")
        if len(attachment_ids) > MAX_ATTACHMENT_COUNT:
            raise UIApiError("attachment_limit", f"Maximum {MAX_ATTACHMENT_COUNT} files can be attached.")

        files: list[tuple[str, Path]] = []
        for raw_id in attachment_ids:
            attachment_id = str(raw_id or "").strip()
            entry = self._staged_attachments.pop(attachment_id, None)
            if entry is None or entry.expires_at < time.time():
                self._drop_staged_files(files)
                raise UIApiError("attachment_ref_invalid", "A staged attachment is no longer available.")
            files.append((entry.filename, entry.content_path))
        return files

    def _temp_dir(self) -> Path:
        temp_dir = self.services.data_dir / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        _secure_dir_permissions(temp_dir)
        return temp_dir

    def _issue_save_grant(
        self,
        file_bytes: bytes | None,
        filename: str,
        *,
        file_path: str | Path | None = None,
    ) -> str:
        try:
            return self._save_grants.issue(
                file_bytes,
                validate_native_download_filename(filename),
                file_path=file_path,
            )
        except ValueError:
            raise

    def _is_link_or_junction(self, path: Path) -> bool:
        if path.is_symlink():
            return True
        is_junction = getattr(path, "is_junction", None)
        return bool(is_junction and is_junction())

    def _managed_downloads_root(self) -> Path:
        configured = self.services.settings.downloads_dir
        if self._is_link_or_junction(configured):
            raise ValueError("Downloads directory is unavailable.")
        try:
            resolved = configured.resolve(strict=True)
        except OSError as exc:
            raise ValueError("Downloads directory is unavailable.") from exc
        if not resolved.is_dir():
            raise ValueError("Downloads directory is unavailable.")
        return resolved

    def _collision_filename(self, filename: str, counter: int) -> str:
        if counter == 0:
            return filename
        suffix = Path(filename).suffix
        stem = filename[:-len(suffix)] if suffix else filename
        marker = f"_{counter}"
        stem_limit = MAX_ATTACHMENT_FILENAME_LENGTH - len(marker) - len(suffix)
        if stem_limit < 1:
            raise ValueError("Invalid download filename.")
        return validate_native_download_filename(f"{stem[:stem_limit]}{marker}{suffix}")

    def _write_managed_download(self, filename: str, file_bytes: bytes) -> Path:
        if not isinstance(file_bytes, bytes) or len(file_bytes) > MAX_NATIVE_SAVE_BYTES:
            raise ValueError("Native download exceeds the size limit.")
        validated_filename = validate_native_download_filename(filename)
        downloads_root = self._managed_downloads_root()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)

        for counter in range(10000):
            candidate = downloads_root / self._collision_filename(validated_filename, counter)
            candidate.relative_to(downloads_root)
            try:
                descriptor = os.open(candidate, flags, 0o600)
            except FileExistsError:
                continue
            except OSError as exc:
                raise ValueError("Native download path is unavailable.") from exc
            try:
                with os.fdopen(descriptor, "wb") as output:
                    output.write(file_bytes)
            except Exception:
                try:
                    candidate.unlink()
                except OSError:
                    pass
                raise
            return candidate
        raise ValueError("Native download destination is unavailable.")

    def _secure_delete_quietly(self, path: str | Path) -> None:
        try:
            if path and Path(path).exists():
                secure_delete(path)
        except Exception:
            pass

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
            "secure_delete_warning": (
                self.services.i18n.translate("session.secure_delete_failed")
                if message.secure_delete_failed
                else None
            ),
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
