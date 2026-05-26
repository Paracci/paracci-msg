import os
import ctypes
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
from .base import BaseShield

FALLOC_FL_KEEP_SIZE = 0x01
FALLOC_FL_PUNCH_HOLE = 0x02


@dataclass(frozen=True)
class _LinuxClipboardOwner:
    payload: bytes
    backend: str


class LinuxShield(BaseShield):
    def __init__(self):
        super().__init__()

    def get_os_name(self) -> str:
        """Returns the human-readable OS name."""
        return "Linux"

    def apply_anti_screenshot(self, window, enabled: bool) -> bool:
        """Explicit stub: Linux capture controls are compositor-specific and unimplemented."""
        logging.warning("[LinuxShield] Capture-reduction is unimplemented on Linux/X11/Wayland.")
        return False

    def get_default_data_dir(self, app_name: str) -> str:
        """Returns the XDG standard data directory."""
        base = os.getenv('XDG_DATA_HOME') or os.path.expanduser('~/.local/share')
        return str(Path(base) / app_name.lower())

    def _try_fdatasync(self, fd: int) -> None:
        """Flush data changes when available without making deletion fail."""
        try:
            os.fdatasync(fd)
        except Exception as e:
            logging.debug("[LinuxShield] fdatasync unavailable or failed: %s", e)

    def _try_punch_hole(self, fd: int, size: int) -> bool:
        """Deallocate this regular file's extents when the filesystem supports it."""
        if size <= 0:
            return False
        try:
            libc = ctypes.CDLL(None, use_errno=True)
            fallocate = libc.fallocate
            fallocate.argtypes = [
                ctypes.c_int,
                ctypes.c_int,
                ctypes.c_longlong,
                ctypes.c_longlong,
            ]
            fallocate.restype = ctypes.c_int
            result = fallocate(
                fd,
                FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
                0,
                size,
            )
            if result != 0:
                err = ctypes.get_errno()
                logging.debug(
                    "[LinuxShield] FALLOC_FL_PUNCH_HOLE unavailable or failed: %s",
                    os.strerror(err) if err else "unknown error",
                )
                return False
            return True
        except Exception as e:
            logging.debug(
                "[LinuxShield] FALLOC_FL_PUNCH_HOLE unavailable or failed: %s", e
            )
            return False

    def secure_delete(self, file_path: str) -> bool:
        """
        Best-effort hygiene: overwrite in place, fdatasync, optionally request
        per-file FALLOC_FL_PUNCH_HOLE deallocation, and unlink the file. SSD
        wear leveling, journaling/COW filesystems, snapshots, backups, and sync
        layers mean physical erasure cannot be guaranteed from userspace. For
        encrypted .paracci content, encryption key protection or destruction is
        the stronger security boundary.
        """
        try:
            with open(file_path, "r+b") as f:
                size = os.fstat(f.fileno()).st_size
                f.write(os.urandom(size))
                f.flush()
                self._try_fdatasync(f.fileno())
                if self._try_punch_hole(f.fileno(), size):
                    self._try_fdatasync(f.fileno())
            os.remove(file_path)
            return True
        except Exception:
            return False

    def clear_recent_documents(self) -> bool:
        """Attempts to clear known GNOME/KDE recent-file state."""
        try:
            # Typical path for GNOME
            recent = Path.home() / ".local/share/recently-used.xbel"
            if recent.exists():
                with open(recent, 'w') as f: f.write("")
            return True
        except: return False

    def _write_clipboard(self, payload: bytes, backend: str | None = None) -> str | None:
        """Write clipboard bytes through an available Linux clipboard backend."""
        backends = (backend,) if backend is not None else ("xclip", "wl-copy")
        for candidate in backends:
            command = (
                ["xclip", "-selection", "clipboard"]
                if candidate == "xclip"
                else ["wl-copy"]
            )
            try:
                subprocess.run(command, input=payload, check=True)
                return candidate
            except (OSError, subprocess.SubprocessError):
                continue
        logging.warning("[LinuxShield] Clipboard write failed through available backends.")
        return None

    def _read_clipboard(self, backend: str) -> bytes | None:
        """Read clipboard bytes through the backend used for the owned write."""
        command = (
            ["xclip", "-selection", "clipboard", "-out"]
            if backend == "xclip"
            else ["wl-paste", "--no-newline"]
        )
        try:
            result = subprocess.run(command, capture_output=True, check=True)
            return result.stdout
        except (OSError, subprocess.SubprocessError) as exc:
            logging.warning("[LinuxShield] Clipboard read failed: %s", exc)
            return None

    def clear_owned_clipboard(self, owner=None) -> bool:
        """Clear only text still matching the active Paracci clipboard write."""
        with self._clipboard_lock:
            active_owner = getattr(self, "_clipboard_owner", None)
            if active_owner is None or (owner is not None and owner is not active_owner):
                return True
            current = self._read_clipboard(active_owner.backend)
            if current is None:
                return False
            if current != active_owner.payload:
                self._clipboard_owner = None
                return True
            if self._write_clipboard(b"", active_owner.backend) is None:
                return False
            self._clipboard_owner = None
            logging.info("[LinuxShield] Owned clipboard content cleared.")
            return True

    def copy_to_clipboard(self, text: str, clear_delay: int = 30) -> bool:
        """Copy text and clear it later only if it remains Paracci-owned."""
        if not text:
            return self.clear_owned_clipboard()

        payload = str(text).encode("utf-8")
        with self._clipboard_lock:
            backend = self._write_clipboard(payload)
            if backend is None:
                return False
            owner = _LinuxClipboardOwner(payload, backend)
            self._clipboard_owner = owner

        self._schedule_owned_clipboard_clear(owner, clear_delay)
        return True
