"""Application and compatibility metadata."""

from __future__ import annotations

import re
import sys
from pathlib import Path


_VERSION_RE = re.compile(r"\d+\.\d+\.\d+")


def _read_app_version() -> str:
    root = Path(sys._MEIPASS) if hasattr(sys, "_MEIPASS") else Path(__file__).resolve().parents[2]
    path = root / "VERSION"
    try:
        version = path.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise RuntimeError(f"Application version file is unavailable: {path}") from exc
    if not _VERSION_RE.fullmatch(version):
        raise RuntimeError(f"Invalid application version in {path}: {version!r}")
    return version


APP_VERSION = _read_app_version()

# Keep this synchronized with core.session.HANDSHAKE_VERSION.
SESSION_PROTOCOL_VERSION = 3
