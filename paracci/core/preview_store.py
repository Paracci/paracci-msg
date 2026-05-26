from __future__ import annotations

from dataclasses import dataclass
import secrets
import threading
import time
from typing import Callable

from .package import validate_native_download_filename


MAX_NATIVE_SAVE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class PreviewEntry:
    token: str
    file_bytes: bytes
    filename: str
    mime_type: str
    allow_download: bool
    created_at: float
    expires_at: float


@dataclass(frozen=True)
class NativeSaveGrant:
    token: str
    file_bytes: bytes
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
        file_bytes: bytes,
        filename: str,
        mime_type: str,
        allow_download: bool = True,
    ) -> str:
        self.cleanup_expired()
        now = self._clock()
        token = secrets.token_hex(32)
        entry = PreviewEntry(
            token=token,
            file_bytes=file_bytes,
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
            self._entries.pop(token, None)

    def cleanup_expired(self) -> None:
        now = self._clock()
        with self._lock:
            expired = [
                token
                for token, entry in self._entries.items()
                if entry.expires_at < now
            ]
            for token in expired:
                self._entries.pop(token, None)


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

    def issue(self, file_bytes: bytes, filename: str) -> str:
        if not isinstance(file_bytes, bytes) or len(file_bytes) > MAX_NATIVE_SAVE_BYTES:
            raise ValueError("Native download exceeds the size limit.")
        validated_filename = validate_native_download_filename(filename)
        self.cleanup_expired()
        now = self._clock()
        token = secrets.token_hex(32)
        entry = NativeSaveGrant(
            token=token,
            file_bytes=file_bytes,
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
            return None
        return entry

    def cleanup_expired(self) -> None:
        now = self._clock()
        with self._lock:
            expired = [
                token
                for token, entry in self._entries.items()
                if entry.expires_at < now
            ]
            for token in expired:
                self._entries.pop(token, None)


preview_store = PreviewStore()
native_save_grants = NativeSaveGrantStore()
