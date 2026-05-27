"""Native service layer for the Qt desktop application.

These services replace the Flask route layer as the UI-facing API. They keep
the existing core protocol and persistence formats intact.
"""

from __future__ import annotations

import json
import logging
import os
import secrets

logger = logging.getLogger(__name__)
import shutil
import sqlite3
import struct
import time
import unicodedata
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import pyotp

from core.burn import (
    AlreadyBurnedError,
    BurnDB,
    BurnGuard,
    DeviceError,
    TTLExpiredError,
    is_device_initialized,
)
from core.config import ParacciConfig
from core.crypto import EncryptedBlob, decrypt, encrypt, wipe
from core.envelope import (
    FILE_VERSION as ENVELOPE_FILE_VERSION,
    ARGON2_FILE_VERSION as ARGON2_ENVELOPE_FILE_VERSION,
    LEGACY_FILE_VERSION as LEGACY_ENVELOPE_FILE_VERSION,
    EnvelopeError,
    EnvelopeTTLError,
    open_envelope,
    seal_envelope,
)
from core.evolution import EVO_UNLIMITED, seconds_until_expiry, session_expires_at
from core.identity import get_or_create_device_identity
from core.package import Attachment, PackageLimitError, create_package, extract_package
from core.sanitizer import SanitizationError, sanitize_image
from core.security_utils import scan_text_for_security
from core.session import (
    LEGACY_WRAPPED_HANDSHAKE_FILE_VERSION,
    TYPE_INITIATOR,
    TYPE_MESSAGE,
    TYPE_RESPONDER,
    SessionMeta,
    accept_initiator_and_create_responder,
    apply_bond_nonce_to_y,
    create_initiator_session,
    confirm_safety_code,
    deserialize_session_meta,
    finalize_initiator_session,
    get_session_safety_code,
    require_transcript_bound_session,
    serialize_initiator_file,
    serialize_responder_file,
    serialize_session_meta,
)
from core.hybrid_kem import HybridKEMError
from desktop.device_key_binding import (
    DeviceBindingWarning,
    consume_device_binding_warning,
    initialize_device_with_binding,
    unlock_device_with_binding,
)
from core.shields import shield

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = Path(__file__).resolve().parents[1]
LEGACY_DATA_DIR = PACKAGE_ROOT / "data"
MIGRATION_MARKER = ".native_migration.json"

MAX_ATTACHMENT_SIZE = 50 * 1024 * 1024
MAX_ATTACHMENT_COUNT = 10

DANGEROUS_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".pif",
    ".scr",
    ".reg",
    ".com",
    ".jar",
    ".vbe",
    ".jse",
    ".wsf",
    ".wsh",
    ".hta",
}

TEXT_EXTENSIONS = {
    ".txt",
    ".md",
    ".json",
    ".yaml",
    ".yml",
    ".py",
    ".js",
    ".html",
    ".css",
    ".sql",
    ".sh",
    ".rs",
    ".go",
    ".java",
    ".c",
    ".cpp",
    ".h",
}


@dataclass(frozen=True)
class SessionSummary:
    """Lightweight session row for the UI."""

    session_id_hex: str
    label: str
    state: str
    created_at: int
    updated_at: int


@dataclass(frozen=True)
class ImportResult:
    """Result of importing a handshake file."""

    session_id_hex: str
    message: str
    auto_export_bytes: Optional[bytes] = None
    auto_export_filename: Optional[str] = None
    state: str | None = None
    safety_code: str | None = None
    requires_confirmation: bool = False


@dataclass(frozen=True)
class AttachmentPayload:
    """Opened attachment held on disk."""

    filename: str
    content_path: str
    mime_type: str
    allow_download: bool

    def __init__(
        self,
        filename: str,
        content_path: str | None = None,
        mime_type: str = "application/octet-stream",
        allow_download: bool = True,
        content: bytes | None = None,
    ):
        object.__setattr__(self, "filename", filename)
        object.__setattr__(self, "mime_type", mime_type)
        object.__setattr__(self, "allow_download", allow_download)
        if content_path is not None:
            object.__setattr__(self, "content_path", str(content_path))
        elif content is not None:
            temp_dir = Path(os.environ.get("DATA_DIR", "data")) / "temp"
            temp_dir.mkdir(parents=True, exist_ok=True)
            token = secrets.token_hex(16)
            temp_file_path = temp_dir / f"test_payload_{token}.bin"
            try:
                temp_file_path.write_bytes(content)
            except OSError:
                pass
            object.__setattr__(self, "content_path", str(temp_file_path))
        else:
            object.__setattr__(self, "content_path", "")

    @property
    def content(self) -> bytes:
        if not self.content_path or not os.path.exists(self.content_path):
            return b""
        try:
            with open(self.content_path, "rb") as f:
                return f.read()
        except OSError:
            return b""

    @property
    def size(self) -> int:
        if self.content_path and os.path.exists(self.content_path):
            try:
                return os.path.getsize(self.content_path)
            except OSError:
                return 0
        return 0

    @property
    def is_image(self) -> bool:
        return self.mime_type.startswith("image/")

    @property
    def is_video(self) -> bool:
        return self.mime_type.startswith("video/")

    @property
    def is_text_like(self) -> bool:
        return self.mime_type == "text/plain" or Path(self.filename).suffix.lower() in TEXT_EXTENSIONS

    @property
    def is_dangerous(self) -> bool:
        return Path(self.filename).suffix.lower() in DANGEROUS_EXTENSIONS


@dataclass(frozen=True)
class OpenedMessage:
    """Message content after a successful open operation."""

    text: str
    attachments: list[AttachmentPayload]
    allow_download: bool
    msg_id_hex: str
    evo_step: int
    expire_at: int
    single_use: bool
    security_report: dict
    secure_delete_failed: bool = False


def configure_data_dir(explicit: str | None = None, user_profile: str | None = None) -> Path:
    """Selects DATA_DIR and performs the native first-launch copy if needed."""
    if explicit:
        data_dir = Path(explicit).expanduser().resolve()
    elif user_profile:
        root_profile = (REPO_ROOT / f"data_{user_profile}").resolve()
        package_profile = (PACKAGE_ROOT / f"data_{user_profile}").resolve()
        data_dir = root_profile if root_profile.exists() else package_profile
    else:
        data_dir = Path(shield.get_default_data_dir("Paracci")).expanduser().resolve()
        _copy_legacy_data_if_needed(data_dir)

    data_dir.mkdir(parents=True, exist_ok=True)
    os.environ["DATA_DIR"] = str(data_dir)
    return data_dir


def _copy_legacy_data_if_needed(target_dir: Path) -> None:
    """Copies legacy packaged data once without modifying the original."""
    marker = target_dir / MIGRATION_MARKER
    if marker.exists():
        return
    if not LEGACY_DATA_DIR.exists():
        return
    if any((target_dir / name).exists() for name in ("sessions.db", "config.json")):
        return

    target_dir.mkdir(parents=True, exist_ok=True)
    for item in LEGACY_DATA_DIR.iterdir():
        dest = target_dir / item.name
        if item.is_dir():
            shutil.copytree(item, dest, dirs_exist_ok=True)
        else:
            shutil.copy2(item, dest)

    validation = _validate_migrated_data(target_dir)
    marker.write_text(
        json.dumps(
            {
                "from": str(LEGACY_DATA_DIR),
                "to": str(target_dir),
                "migrated_at": int(time.time()),
                "mode": "copy",
                "validation": validation,
            },
            indent=2,
        ),
        encoding="utf-8",
    )


def _validate_migrated_data(data_dir: Path) -> dict:
    """Validates copied legacy data without requiring the user's PIN."""
    report: dict[str, object] = {
        "db_integrity": "not_present",
        "session_rows": 0,
        "device_initialized": False,
        "config_json": "not_present",
        "decryptability": "deferred_until_unlock",
    }

    db_path = data_dir / "sessions.db"
    if db_path.exists():
        try:
            conn = sqlite3.connect(str(db_path))
            try:
                integrity = conn.execute("PRAGMA integrity_check").fetchone()
                result = integrity[0] if integrity else "missing_result"
                if result != "ok":
                    raise MigrationError(f"SQLite integrity check failed: {result}")
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                    ).fetchall()
                }
                required = {"burned_messages", "sessions", "device_meta"}
                missing = required - tables
                if missing:
                    raise MigrationError(f"SQLite schema is missing: {', '.join(sorted(missing))}")
                report["db_integrity"] = "ok"
                report["session_rows"] = conn.execute("SELECT COUNT(*) FROM sessions").fetchone()[0]
                report["device_initialized"] = (
                    conn.execute(
                        # 'pin_salt' key is kept in SQLite for database compatibility
                        "SELECT 1 FROM device_meta WHERE key='pin_salt' LIMIT 1"
                    ).fetchone()
                    is not None
                )
            finally:
                conn.close()
        except sqlite3.DatabaseError as exc:
            raise MigrationError("Copied sessions.db is not a readable SQLite database.") from exc

    config_path = data_dir / "config.json"
    if config_path.exists():
        try:
            json.loads(config_path.read_text(encoding="utf-8"))
            report["config_json"] = "ok"
        except Exception as exc:
            raise MigrationError("Copied config.json is not valid JSON.") from exc

    return report


def parse_file_header(file_bytes: bytes) -> dict | None:
    """Fast protocol header check used before expensive cryptographic work."""
    if len(file_bytes) < 23 or file_bytes[:4] != b"PARC":
        return None

    file_version = file_bytes[4]
    file_type = file_bytes[5]
    if file_type not in (TYPE_INITIATOR, TYPE_RESPONDER, TYPE_MESSAGE):
        return None
    if file_type == TYPE_MESSAGE:
        if file_version not in (
            LEGACY_ENVELOPE_FILE_VERSION,
            ARGON2_ENVELOPE_FILE_VERSION,
            ENVELOPE_FILE_VERSION,
        ):
            return None
    elif file_version < LEGACY_WRAPPED_HANDSHAKE_FILE_VERSION:
        return None

    session_id = file_bytes[6:22]
    if file_type != TYPE_MESSAGE:
        return {"file_type": file_type, "session_id": session_id}

    if len(file_bytes) < 52:
        return None
    direction = file_bytes[38]
    flags = file_bytes[39]
    evo_step = struct.unpack(">I", file_bytes[40:44])[0]
    expire_at = struct.unpack(">Q", file_bytes[44:52])[0]
    if direction not in (0x01, 0x02) or evo_step > 100000:
        return None

    return {
        "file_type": file_type,
        "session_id": session_id,
        "msg_id": file_bytes[22:38],
        "direction": direction,
        "flags": flags,
        "evo_step": evo_step,
        "expire_at": expire_at,
        "single_use": bool(flags & 0x01),
    }


class DeviceService:
    """Owns device unlock state and device-bound metadata."""

    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self.db = BurnDB(data_dir / "sessions.db")
        self.device_key: bytearray | None = None
        self.device_binding_warning: DeviceBindingWarning | None = None

    @property
    def is_unlocked(self) -> bool:
        return self.device_key is not None

    def is_initialized(self) -> bool:
        return is_device_initialized(self.db)

    def initialize(self, passphrase: str) -> bytearray:
        self.device_binding_warning = None
        device_key = initialize_device_with_binding(self.db, passphrase)
        try:
            self._activate_keyed_db(device_key)
        except Exception:
            wipe(device_key)
            raise
        self.device_key = device_key
        self.device_binding_warning = consume_device_binding_warning()
        return self.device_key

    def unlock(self, passphrase: str) -> bytearray:
        self.device_binding_warning = None
        device_key = unlock_device_with_binding(self.db, passphrase)
        try:
            self._activate_keyed_db(device_key)
        except Exception:
            wipe(device_key)
            raise
        self.device_key = device_key
        self.device_binding_warning = consume_device_binding_warning()
        self._verify_stored_sessions_decryptable()
        return self.device_key

    def lock(self) -> None:
        if self.device_key is not None:
            wipe(self.device_key)
        self.device_key = None
        self.db.release_device_key()
        self.db = BurnDB(self.data_dir / "sessions.db")
        self.device_binding_warning = None
        try:
            self.db.retry_pending_deletions()
        except Exception as exc:
            logger.error("Failed to run desktop lock pending deletions cleanup: %s", exc)

    def _activate_keyed_db(self, device_key: bytes | bytearray) -> None:
        keyed_db = self.db.with_device_key(device_key)
        self.db.release_device_key()
        self.db = keyed_db

    def ensure_unlocked(self) -> bytearray:
        if self.device_key is None:
            raise DeviceError("Device is locked.")
        return self.device_key

    def identity(self):
        device_key = self.ensure_unlocked()
        return get_or_create_device_identity(self.db, device_key)

    def is_2fa_enabled(self) -> bool | None:
        if not self.is_unlocked:
            return None
        return self.db.is_2fa_enabled()

    def new_2fa_secret(self) -> str:
        return pyotp.random_base32()

    def provisioning_uri(self, secret: str, username: str) -> str:
        return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Paracci")

    def verify_2fa_code(self, secret: str, code: str) -> bool:
        return pyotp.TOTP(secret).verify((code or "").strip())

    def get_2fa_secret(self) -> str | None:
        device_key = self.ensure_unlocked()
        encrypted = self.db.get_device_meta("2fa_secret_enc_v1")
        if encrypted:
            blob = EncryptedBlob(nonce=encrypted[:12], ciphertext=encrypted[12:])
            return decrypt(device_key, blob, aad=b"paracci.device.2fa.v1").decode("utf-8")

        legacy = self.db.get_2fa_secret(device_key)
        if legacy:
            self.set_2fa_secret(legacy)
            self.db.delete_2fa_secret()
        return legacy

    def set_2fa_secret(self, secret: str) -> None:
        device_key = self.ensure_unlocked()
        blob = encrypt(device_key, secret.encode("utf-8"), aad=b"paracci.device.2fa.v1")
        self.db.set_device_meta("2fa_secret_enc_v1", blob.nonce + blob.ciphertext)
        self.db.delete_2fa_secret()

    def set_2fa_enabled(self, enabled: bool) -> None:
        self.db.set_2fa_enabled(enabled)

    def _verify_stored_sessions_decryptable(self) -> None:
        """Confirms encrypted session metadata can be opened after migration."""
        if self.device_key is None:
            return
        try:
            for row in self.db.list_sessions():
                stored = self.db.load_session(row["session_id"])
                if stored is None:
                    continue
                deserialize_session_meta(stored[2], self.device_key)
        except Exception as exc:
            self.lock()
            raise DeviceError(
                "Device unlocked, but stored session metadata could not be decrypted."
            ) from exc


class SettingsService:
    """Typed wrapper around the existing JSON settings file."""

    def __init__(self):
        self.config = ParacciConfig()

    def refresh(self) -> dict:
        self.config.load()
        return self.config.settings.copy()

    def get(self, key: str):
        return self.config.get(key)

    def set_many(self, values: dict) -> None:
        for key, value in values.items():
            self.config.settings[key] = value
        self.config.save()
        self.config.load()

    @property
    def downloads_dir(self) -> Path:
        return Path(self.config.full_downloads_path)


class SessionService:
    """Session lifecycle operations."""

    def __init__(self, device: DeviceService):
        self.device = device

    def list_sessions(self) -> list[SessionSummary]:
        rows = self.device.db.list_sessions()
        return [
            SessionSummary(
                session_id_hex=row["session_id"].hex(),
                label=row["label"],
                state=row["state"],
                created_at=row["created_at"],
                updated_at=row["updated_at"],
            )
            for row in rows
        ]

    def _import_result(self, meta: SessionMeta, message: str, auto_export_bytes: bytes | None = None, auto_export_filename: str | None = None) -> ImportResult:
        safety_code = self.safety_code(meta)
        return ImportResult(
            session_id_hex=meta.session_id.hex(),
            message=message,
            auto_export_bytes=auto_export_bytes,
            auto_export_filename=auto_export_filename,
            state=meta.state,
            safety_code=safety_code,
            requires_confirmation=bool(safety_code and not meta.safety_confirmed),
        )

    def load(self, session_id_hex: str) -> SessionMeta:
        device_key = self.device.ensure_unlocked()
        session_id = bytes.fromhex(session_id_hex)
        row = self.device.db.load_session(session_id)
        if row is None:
            raise SessionServiceError("Session not found.")
        return deserialize_session_meta(row[2], device_key)

    def save(self, meta: SessionMeta, state_override: str | None = None) -> None:
        device_key = self.device.ensure_unlocked()
        self.device.db.save_session(
            session_id=meta.session_id,
            label=meta.label,
            state=state_override or meta.state,
            encrypted_meta=serialize_session_meta(meta, device_key),
            created_at=meta.created_at,
        )

    def create_initiator(
        self,
        label: str,
        session_ttl_sec: int = EVO_UNLIMITED,
    ) -> ImportResult:
        identity = self.device.identity()
        try:
            meta, init_bytes = create_initiator_session(
                label=label.strip(),
                session_ttl_sec=session_ttl_sec,
                identity_pub=identity.public_key,
                identity_priv=identity.private_key,
            )
        except HybridKEMError as exc:
            raise SessionServiceError(exc.i18n_key) from exc
        self.save(meta)
        return self._import_result(
            meta,
            "Initiator session created.",
            auto_export_bytes=init_bytes,
            auto_export_filename=f"session_init_{meta.session_id.hex()[:8]}.paracci",
        )

    def import_handshake(self, file_bytes: bytes, local_label: str) -> ImportResult:
        header = parse_file_header(file_bytes)
        if not header:
            raise SessionServiceError("Invalid Paracci file.")

        file_type = header["file_type"]
        session_id_hex = header["session_id"].hex()

        if file_type == TYPE_INITIATOR:
            identity = self.device.identity()
            try:
                meta, responder_bytes = accept_initiator_and_create_responder(
                    file_bytes,
                    local_label.strip(),
                    identity_pub=identity.public_key,
                    identity_priv=identity.private_key,
                )
            except HybridKEMError as exc:
                raise SessionServiceError(exc.i18n_key) from exc
            self.save(meta)
            return self._import_result(
                meta,
                "Responder session created.",
                auto_export_bytes=responder_bytes,
                auto_export_filename=f"session_resp_{meta.session_id.hex()[:8]}.paracci",
            )

        if file_type == TYPE_RESPONDER:
            meta = self.load(session_id_hex)
            if meta.role != "X":
                raise SessionServiceError("Responder files can only finalize X sessions.")
            try:
                updated = finalize_initiator_session(meta, file_bytes)
            except HybridKEMError as exc:
                raise SessionServiceError(exc.i18n_key) from exc
            self.save(updated)
            return self._import_result(updated, "Initiator session finalized.")

        raise SessionServiceError("Message files must be opened inside an active session.")

    def export_handshake(self, session_id_hex: str) -> tuple[bytes, str]:
        meta = self.load(session_id_hex)
        identity = self.device.identity()
        if meta.role == "X" and meta.state == "pending":
            try:
                return (
                    serialize_initiator_file(meta, identity_priv=identity.private_key),
                    f"session_init_{session_id_hex[:8]}.paracci",
                )
            except HybridKEMError as exc:
                raise SessionServiceError(exc.i18n_key) from exc
        if meta.role == "Y":
            try:
                return (
                    serialize_responder_file(
                        session_id=meta.session_id,
                        y_pub=meta.my_pub,
                        evo_config=meta.evo_config,
                        label=meta.label,
                        x_pub=meta.peer_pub,
                        x_identity_pub=meta.peer_identity_pub,
                        y_identity_pub=meta.my_identity_pub,
                        identity_priv=identity.private_key,
                        ml_kem_ciphertext=meta.ml_kem_ciphertext,
                    ),
                    f"session_resp_{session_id_hex[:8]}.paracci",
                )
            except HybridKEMError as exc:
                raise SessionServiceError(exc.i18n_key) from exc
        raise SessionServiceError("No handshake export is available for this session.")

    def safety_code(self, meta: SessionMeta) -> str | None:
        if not meta.peer_pub:
            return None
        try:
            return get_session_safety_code(meta)
        except Exception:
            return None

    def confirm_safety(self, session_id_hex: str, safety_code: str) -> SessionMeta:
        meta = self.load(session_id_hex)
        updated = confirm_safety_code(meta, safety_code)
        self.save(updated)
        return updated

    def evo_info(self, meta: SessionMeta) -> dict | None:
        if meta.keys is None:
            return None
        return {
            "tx_count": meta.tx_count,
            "rx_count": meta.rx_count,
            "bonded": meta.is_bonded,
            "expires_at": session_expires_at(meta.evo_config),
            "secs_remaining": seconds_until_expiry(meta.evo_config),
        }


class MessageService:
    """Message packaging, sealing, opening, and burn handling."""

    def __init__(self, sessions: SessionService, settings: SettingsService):
        self.sessions = sessions
        self.settings = settings

    def seal_message(
        self,
        session_id_hex: str,
        text: str,
        attachment_paths: list[Path],
        allow_download: bool,
        ttl_seconds: int = 0,
        output_path: str | Path | None = None,
    ) -> tuple[bytes | None, str]:
        meta = self.sessions.load(session_id_hex)
        try:
            require_transcript_bound_session(meta)
        except HybridKEMError as exc:
            raise MessageServiceError(exc.i18n_key) from exc
        if not meta.can_send:
            raise MessageServiceError("Session safety code has not been confirmed.")

        normalized_text = unicodedata.normalize("NFC", text.strip())
        files = self._read_attachments(attachment_paths)
        
        # Write ZIP directly to disk to minimize memory usage
        temp_dir = Path(os.environ.get("DATA_DIR", "data")) / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        token = secrets.token_hex(16)
        temp_zip_path = temp_dir / f"package_{token}.zip"
        
        try:
            import inspect
            sig = inspect.signature(create_package)
            if "output_path" in sig.parameters:
                create_package(normalized_text, files, allow_download=allow_download, output_path=temp_zip_path)
            else:
                pkg_bytes = create_package(normalized_text, files, allow_download)
                with open(temp_zip_path, "wb") as f:
                    f.write(pkg_bytes)
            
            sealed = seal_envelope(
                temp_zip_path,
                meta,
                single_use=True,
                ttl_seconds=ttl_seconds,
                allow_download=allow_download,
                output_path=output_path,
            )
        finally:
            if temp_zip_path.exists():
                try:
                    os.remove(temp_zip_path)
                except OSError:
                    pass
            for name, temp_file_path in files:
                if isinstance(temp_file_path, (str, Path)) and os.path.exists(temp_file_path):
                    try:
                        os.remove(temp_file_path)
                    except OSError:
                        pass
        
        self.sessions.save(meta._replace(tx_count=meta.tx_count + 1, send_seed=sealed.next_seed))
        return sealed.file_bytes if output_path is None else None, f"msg_step_{sealed.next_step - 1:06d}_{sealed.msg_id.hex()[:12]}.paracci"

    def open_message(
        self,
        session_id_hex: str,
        file_bytes: bytes | None = None,
        source_path: Path | None = None,
        burn_source: bool = True,
    ) -> OpenedMessage:
        meta = self.sessions.load(session_id_hex)
        try:
            require_transcript_bound_session(meta)
        except HybridKEMError as exc:
            raise MessageServiceError(exc.i18n_key) from exc
        if not meta.can_open:
            raise MessageServiceError("Session safety code has not been confirmed.")

        if source_path is not None:
            try:
                with open(source_path, "rb") as f:
                    header_bytes_prefix = f.read(100)
            except OSError as exc:
                raise MessageServiceError("Could not read message file.") from exc
            header = parse_file_header(header_bytes_prefix)
        else:
            if file_bytes is None:
                raise ValueError("Either file_bytes or source_path must be provided.")
            header = parse_file_header(file_bytes)
            
        if not header or header["file_type"] != TYPE_MESSAGE:
            raise MessageServiceError("Invalid Paracci message file.")

        guard = BurnGuard(self.sessions.device.db)
        try:
            burn_reserved = guard.pre_open_check(
                msg_id=header["msg_id"],
                expire_at=header["expire_at"],
                single_use=header["single_use"],
            )
            try:
                if source_path is not None:
                    opened = open_envelope(session=meta, file_path=source_path)
                else:
                    opened = open_envelope(file_bytes, meta)
            except EnvelopeError as exc:
                if burn_reserved:
                    guard.mark_open_failed(header["msg_id"], str(exc))
                raise
            if opened.bond_nonce is not None and not meta.is_bonded:
                meta = apply_bond_nonce_to_y(meta, opened.bond_nonce)
            updated = meta._replace(rx_count=opened.next_step, recv_seed=opened.next_seed)
            self.sessions.save(updated)
            secure_delete_succeeded = guard.post_open_burn(
                msg_id=opened.msg_id,
                session_id=opened.session_id,
                direction=opened.direction,
                single_use=opened.single_use,
                file_path=source_path if burn_source else None,
            )
        except (AlreadyBurnedError, TTLExpiredError, EnvelopeTTLError) as exc:
            raise MessageServiceError("This message was already opened or has expired.") from exc
        except EnvelopeError as exc:
            raise MessageServiceError(str(exc)) from exc

        # Decrypt payload directly to a temp file
        temp_dir = Path(os.environ.get("DATA_DIR", "data")) / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        token = secrets.token_hex(16)
        temp_zip_path = temp_dir / f"decrypted_{token}.zip"
        
        try:
            temp_zip_path.write_bytes(opened.payload)
            package = extract_package(
                default_allow_download=not opened.has_download_policy,
                file_path=temp_zip_path,
            )
        except PackageLimitError as exc:
            raise MessageServiceError(str(exc)) from exc
        finally:
            if temp_zip_path.exists():
                try:
                    os.remove(temp_zip_path)
                except OSError:
                    pass
                    
        effective_allow_download = (
            opened.allow_download
            if opened.has_download_policy
            else package.allow_download
        )
        attachments = [
            AttachmentPayload(
                filename=att.filename,
                content_path=att.content_path,
                mime_type=att.mime_type,
                allow_download=effective_allow_download,
            )
            for att in package.attachments
        ]
        return OpenedMessage(
            text=package.text,
            attachments=attachments,
            allow_download=effective_allow_download,
            msg_id_hex=opened.msg_id.hex(),
            evo_step=opened.evo_step,
            expire_at=opened.expire_at,
            single_use=opened.single_use,
            security_report=scan_text_for_security(package.text),
            secure_delete_failed=not secure_delete_succeeded,
        )

    def _read_attachments(self, paths: list[Path]) -> list[tuple[str, Path]]:
        if len(paths) > MAX_ATTACHMENT_COUNT:
            raise MessageServiceError(f"Maximum {MAX_ATTACHMENT_COUNT} files can be attached.")

        files: list[tuple[str, Path]] = []
        total_size = 0
        temp_dir = Path(os.environ.get("DATA_DIR", "data")) / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            for path in paths:
                if not path:
                    continue
                p = Path(path)
                if not p.is_file():
                    raise MessageServiceError(f"Attachment not found: {p}")
                    
                token = secrets.token_hex(16)
                temp_file_path = temp_dir / f"staged_desk_{token}.bin"
                
                written_size = 0
                try:
                    with open(p, "rb") as src, open(temp_file_path, "wb") as dest:
                        while True:
                            chunk = src.read(64 * 1024)
                            if not chunk:
                                break
                            written_size += len(chunk)
                            if total_size + written_size > MAX_ATTACHMENT_SIZE:
                                raise MessageServiceError(
                                    f"Total attachment size exceeds {MAX_ATTACHMENT_SIZE // (1024 * 1024)}MB."
                                )
                            dest.write(chunk)
                except Exception:
                    if temp_file_path.exists():
                        try:
                            os.remove(temp_file_path)
                        except OSError:
                            pass
                    raise
                    
                file_size = written_size
                try:
                    ext = p.name.split('.')[-1].lower()
                    if ext in ['jpg', 'jpeg', 'png', 'webp']:
                        with open(temp_file_path, "rb") as f:
                            image_bytes = f.read()
                        sanitized = sanitize_image(image_bytes, p.name)
                        temp_file_path.write_bytes(sanitized)
                        file_size = len(sanitized)
                except Exception as exc:
                    if temp_file_path.exists():
                        try:
                            os.remove(temp_file_path)
                        except OSError:
                            pass
                    if isinstance(exc, SanitizationError):
                        raise MessageServiceError(SanitizationError.user_message) from exc
                    raise
                    
                total_size += file_size
                files.append((p.name, temp_file_path))
            return files
        except Exception:
            for name, tf in files:
                if isinstance(tf, (str, Path)) and os.path.exists(tf):
                    try:
                        os.remove(tf)
                    except OSError:
                        pass
            raise


class I18nService:
    """Flask-free translation loader for native UI strings."""

    def __init__(self, locale: str = "tr"):
        self.locale = locale
        self.translations: dict[str, dict[str, str]] = {}
        self.load()

    def load(self) -> None:
        i18n_dir = PACKAGE_ROOT / "app" / "i18n"
        for path in i18n_dir.glob("*.json"):
            self.translations[path.stem] = self._flatten(json.loads(path.read_text(encoding="utf-8")))

    def set_locale(self, locale: str) -> None:
        if locale in self.translations:
            self.locale = locale

    def translate(self, key: str, **kwargs) -> str:
        bundle = self.translations.get(self.locale) or self.translations.get("tr") or {}
        text = bundle.get(key, key)
        return text.format(**kwargs) if kwargs else text

    def _flatten(self, obj: dict, prefix: str = "") -> dict[str, str]:
        result: dict[str, str] = {}
        for key, value in obj.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                result.update(self._flatten(value, full_key))
            else:
                result[full_key] = str(value)
        return result


class ShieldService:
    """Thin wrapper for OS-specific shield operations."""

    def apply_anti_screenshot(self, window, enabled: bool) -> bool:
        return shield.apply_anti_screenshot(window, enabled)

    def clear_recent_documents(self) -> bool:
        return shield.clear_recent_documents()

    def copy_to_clipboard(self, text: str, clear_delay: int = 30) -> bool:
        return shield.copy_to_clipboard(text, clear_delay)

    def get_os_name(self) -> str:
        return shield.get_os_name()

    def get_system_info(self) -> dict:
        return shield.get_system_info()


class NativeServices:
    """Composition root used by the Qt application."""

    def __init__(self, data_dir: Path, locale: str = "tr"):
        self.data_dir = data_dir
        self.device = DeviceService(data_dir)
        self.settings = SettingsService()
        self.sessions = SessionService(self.device)
        self.messages = MessageService(self.sessions, self.settings)
        self.i18n = I18nService(locale)
        self.shield = ShieldService()
        try:
            self.device.db.retry_pending_deletions()
        except Exception as exc:
            logger.error("Failed to run desktop startup pending deletions cleanup: %s", exc)


class SessionServiceError(Exception):
    """Session service failure."""


class MessageServiceError(Exception):
    """Message service failure."""


class MigrationError(Exception):
    """Native data migration failed validation."""
