"""Shared size limits for attacker-supplied Paracci file ingestion."""

from __future__ import annotations

import os
from pathlib import Path
from typing import BinaryIO

MAX_SETUP_FILE_BYTES = 1 * 1024 * 1024
MAX_MESSAGE_ENVELOPE_BYTES = 64 * 1024 * 1024
INGEST_READ_CHUNK_BYTES = 64 * 1024


class IngestionLimitError(ValueError):
    """Raised when an incoming file exceeds a pre-read safety limit."""


def _limit_message(label: str) -> str:
    return f"{label} is too large to open safely."


def ensure_buffer_within_limit(data: bytes | bytearray | memoryview, max_bytes: int, label: str) -> None:
    if len(data) > max_bytes:
        raise IngestionLimitError(_limit_message(label))


def ensure_path_within_limit(path: str | Path, max_bytes: int, label: str) -> int:
    try:
        size = os.path.getsize(path)
    except OSError as exc:
        raise OSError("Could not read selected file.") from exc
    if size > max_bytes:
        raise IngestionLimitError(_limit_message(label))
    return size


def read_path_limited(path: str | Path, max_bytes: int, label: str) -> bytes:
    ensure_path_within_limit(path, max_bytes, label)
    chunks: list[bytes] = []
    total = 0
    try:
        with open(path, "rb") as src:
            while True:
                remaining_probe = max_bytes - total + 1
                if remaining_probe <= 0:
                    raise IngestionLimitError(_limit_message(label))
                chunk = src.read(min(INGEST_READ_CHUNK_BYTES, remaining_probe))
                if not chunk:
                    break
                total += len(chunk)
                if total > max_bytes:
                    raise IngestionLimitError(_limit_message(label))
                chunks.append(chunk)
    except IngestionLimitError:
        raise
    except OSError as exc:
        raise OSError("Could not read selected file.") from exc
    return b"".join(chunks)


def copy_stream_limited(src: BinaryIO, dest: BinaryIO, max_bytes: int, label: str) -> int:
    total = 0
    while True:
        remaining_probe = max_bytes - total + 1
        if remaining_probe <= 0:
            raise IngestionLimitError(_limit_message(label))
        chunk = src.read(min(INGEST_READ_CHUNK_BYTES, remaining_probe))
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise IngestionLimitError(_limit_message(label))
        dest.write(chunk)
    return total
