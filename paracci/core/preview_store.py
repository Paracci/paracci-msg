from __future__ import annotations

import os
from pathlib import Path
from dataclasses import dataclass
import secrets
import threading
import time
from typing import Callable

from .package import validate_native_download_filename
from .burn import secure_delete


MAX_NATIVE_SAVE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class PreviewEntry:
    token: str
    file_path: str
    filename: str
    mime_type: str
    allow_download: bool
    created_at: float
    expires_at: float

    @property
    def file_size(self) -> int:
        if self.file_path and os.path.exists(self.file_path):
            try:
                return os.path.getsize(self.file_path)
            except OSError:
                return 0
        return 0


@dataclass(frozen=True)
class NativeSaveGrant:
    token: str
    file_path: str
    filename: str
    created_at: float
    expires_at: float


class PreviewStore:
    """Thread-safe, in-memory store for short-lived preview tokens."""

    def __init__(
        self,
        ttl_seconds: float = 300,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self._clock = clock or time.time
        self._entries: dict[str, PreviewEntry] = {}
        self._lock = threading.RLock()

    def generate_token(
        self,
        file_bytes: bytes | None = None,
        filename: str = "",
        mime_type: str = "",
        allow_download: bool = True,
        file_path: str | Path | None = None,
    ) -> str:
        self.cleanup_expired()
        now = self._clock()
        token = secrets.token_hex(32)

        # Write to secure temp file
        temp_dir = Path(os.environ.get("DATA_DIR", "data")) / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        dest_path = temp_dir / f"preview_{token}.bin"
        try:
            if file_path is not None:
                import shutil
                shutil.copy2(file_path, dest_path)
            else:
                if file_bytes is None:
                    raise ValueError("Either file_bytes or file_path must be provided.")
                dest_path.write_bytes(file_bytes)
        except OSError as exc:
            raise ValueError("Failed to write preview temp file.") from exc

        entry = PreviewEntry(
            token=token,
            file_path=str(dest_path),
            filename=filename,
            mime_type=mime_type,
            allow_download=bool(allow_download),
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            self._entries[token] = entry
        return token

    def get(self, token: str) -> PreviewEntry | None:
        if not token:
            return None
        now = self._clock()
        with self._lock:
            entry = self._entries.get(token)
            if entry is None or entry.expires_at < now:
                return None
            return entry

    def revoke(self, token: str) -> None:
        with self._lock:
            entry = self._entries.pop(token, None)
        if entry is not None:
            try:
                secure_delete(entry.file_path)
            except Exception:
                pass

    def cleanup_expired(self) -> None:
        now = self._clock()
        with self._lock:
            expired = [
                token
                for token, entry in self._entries.items()
                if entry.expires_at < now
            ]
            for token in expired:
                entry = self._entries.pop(token, None)
                if entry is not None:
                    try:
                        secure_delete(entry.file_path)
                    except Exception:
                        pass

    def clear(self) -> None:
        with self._lock:
            for token, entry in list(self._entries.items()):
                self._entries.pop(token, None)
                if entry is not None:
                    try:
                        secure_delete(entry.file_path)
                    except Exception:
                        pass


class NativeSaveGrantStore:
    """Thread-safe, one-shot storage for server-authorized native downloads."""

    def __init__(
        self,
        ttl_seconds: float = 60,
        clock: Callable[[], float] | None = None,
    ) -> None:
        self.ttl_seconds = ttl_seconds
        self._clock = clock or time.time
        self._entries: dict[str, NativeSaveGrant] = {}
        self._lock = threading.RLock()

    def issue(
        self,
        file_bytes: bytes | None = None,
        filename: str = "",
        *,
        file_path: str | Path | None = None,
    ) -> str:
        if file_bytes is not None:
            if not isinstance(file_bytes, bytes) or len(file_bytes) > MAX_NATIVE_SAVE_BYTES:
                raise ValueError("Native download exceeds the size limit.")
        elif file_path is not None:
            try:
                f_size = os.path.getsize(file_path)
            except OSError as exc:
                raise ValueError("Could not read source file for save grant.") from exc
            if f_size > MAX_NATIVE_SAVE_BYTES:
                raise ValueError("Native download exceeds the size limit.")
        else:
            raise ValueError("Either file_bytes or file_path must be provided.")

        validated_filename = validate_native_download_filename(filename)
        self.cleanup_expired()
        now = self._clock()
        token = secrets.token_hex(32)

        # Write to secure temp file
        temp_dir = Path(os.environ.get("DATA_DIR", "data")) / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        dest_path = temp_dir / f"save_{token}.bin"
        try:
            if file_path is not None:
                import shutil
                shutil.copy2(file_path, dest_path)
            else:
                dest_path.write_bytes(file_bytes)
        except OSError as exc:
            raise ValueError("Failed to write native save temp file.") from exc

        entry = NativeSaveGrant(
            token=token,
            file_path=str(dest_path),
            filename=validated_filename,
            created_at=now,
            expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            self._entries[token] = entry
        return token

    def consume(self, token: str) -> NativeSaveGrant | None:
        if not token:
            return None
        now = self._clock()
        with self._lock:
            entry = self._entries.pop(str(token), None)
        if entry is None or entry.expires_at < now:
            if entry is not None:
                try:
                    secure_delete(entry.file_path)
                except Exception:
                    pass
            return None

        # Return entry without reading file into memory or deleting it.
        # The consumer is responsible for deleting the file at entry.file_path.
        return NativeSaveGrant(
            token=entry.token,
            file_path=entry.file_path,
            filename=entry.filename,
            created_at=entry.created_at,
            expires_at=entry.expires_at,
        )

    def cleanup_expired(self) -> None:
        now = self._clock()
        with self._lock:
            expired = [
                token
                for token, entry in self._entries.items()
                if entry.expires_at < now
            ]
            for token in expired:
                entry = self._entries.pop(token, None)
                if entry is not None:
                    try:
                        secure_delete(entry.file_path)
                    except Exception:
                        pass

    def clear(self) -> None:
        with self._lock:
            for token, entry in list(self._entries.items()):
                self._entries.pop(token, None)
                if entry is not None:
                    try:
                        secure_delete(entry.file_path)
                    except Exception:
                        pass


preview_store = PreviewStore()
native_save_grants = NativeSaveGrantStore()
