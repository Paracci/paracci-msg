import os
import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path
import ctypes.util
from .base import BaseShield

try:
    import fcntl
except ImportError:  # pragma: no cover - imported eagerly on Windows.
    fcntl = None


@dataclass(frozen=True)
class _MacOSClipboardOwner:
    payload: bytes


class MacOSShield(BaseShield):
    def __init__(self):
        super().__init__()

    def get_os_name(self) -> str:
        """Returns the human-readable OS name."""
        return "macOS"

    def apply_anti_screenshot(self, window, enabled: bool) -> bool:
        """
        Best-effort macOS window sharing restriction.
        Sets NSWindow sharingType to NSWindowSharingNone (0) when possible;
        this does not block every screenshot, recording, or privileged capture path.
        """
        if not enabled:
            logging.info("[MacOSShield] Capture-reduction disabled by user config")
            return False

        # Detect headless/CI or offscreen QPA to avoid segfaults on invalid handles
        is_ci = os.environ.get("GITHUB_ACTIONS") == "true"
        is_offscreen = os.environ.get("QT_QPA_PLATFORM") == "offscreen"
        
        if is_ci or is_offscreen:
            logging.info("[MacOSShield] Capture-reduction skipped in CI/offscreen environment")
            return False

        try:
            libobjc_path = ctypes.util.find_library('objc')
            if not libobjc_path:
                logging.error("[MacOSShield] Could not find objc library")
                return False
                
            libobjc = ctypes.CDLL(libobjc_path)
            
            # On macOS ARM64, objc_msgSend requires proper prototyping to avoid ABI-related segfaults.
            # We use ctypes.CFUNCTYPE to create a typed function pointer.
            msg_send_type = ctypes.CFUNCTYPE(ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long)
            objc_msgSend = msg_send_type(libobjc.objc_msgSend)
            
            sel_registerName = libobjc.sel_registerName
            sel_registerName.restype = ctypes.c_void_p
            sel_registerName.argtypes = [ctypes.c_char_p]

            # NSWindowSharingNone = 0
            setSharingType = sel_registerName(b"setSharingType:")
            
            # Acquire native handle
            ptr = 0
            if hasattr(window, "winId"):
                ptr = int(window.winId())
            elif hasattr(window, 'native') and window.native:
                ptr = window.native

            if ptr:
                objc_msgSend(ptr, setSharingType, 0)
                logging.info(f"[MacOSShield] Capture-reduction requested (handle: {hex(ptr)})")
                return True
            
            logging.warning("[MacOSShield] Could not acquire native NSWindow pointer")
            return False
        except Exception as e:
            logging.error(f"[MacOSShield] Anti-screenshot implementation error: {e}")
            return False

    def get_default_data_dir(self, app_name: str) -> str:
        """Returns the standard macOS Application Support path."""
        base = Path('~/Library/Application Support').expanduser()
        return str(base / app_name)

    def _flush_overwrite(self, fd: int) -> None:
        """Attempt macOS full persistence, falling back to an ordinary flush."""
        if fcntl is not None and hasattr(fcntl, "F_FULLFSYNC"):
            try:
                fcntl.fcntl(fd, fcntl.F_FULLFSYNC)
                return
            except Exception as e:
                logging.debug(
                    "[MacOSShield] F_FULLFSYNC failed; falling back to fsync: %s", e
                )
        else:
            logging.debug("[MacOSShield] F_FULLFSYNC unavailable; falling back to fsync.")
        try:
            os.fsync(fd)
        except Exception as e:
            logging.debug("[MacOSShield] fsync fallback failed: %s", e)

    def secure_delete(self, file_path: str) -> bool:
        """
        Best-effort hygiene: overwrite in place, request F_FULLFSYNC with an
        fsync fallback, and unlink the file. SSD wear leveling, journaling/COW
        filesystems, snapshots, backups, and sync layers mean physical erasure
        cannot be guaranteed from userspace. For encrypted .paracci content,
        encryption key protection or destruction is the stronger security boundary.
        """
        try:
            p = Path(file_path)
            if p.is_symlink():
                p.unlink()
                return True
            if not p.exists(): return True

            flags = os.O_RDWR
            if hasattr(os, "O_NOFOLLOW"):
                flags |= getattr(os, "O_NOFOLLOW")

            try:
                fd = os.open(file_path, flags)
            except OSError:
                os.remove(file_path)
                return True

            with os.fdopen(fd, "r+b") as f:
                size = os.fstat(f.fileno()).st_size
                f.write(os.urandom(size))
                f.flush()
                self._flush_overwrite(f.fileno())
            os.remove(file_path)
            return True
        except Exception:
            return False

    def clear_recent_documents(self) -> bool:
        """Clears macOS recent items."""
        try:
            subprocess.run(["osascript", "-e", 'tell application "System Events" to clear recent items'], check=True)
            return True
        except: return False

    def _write_clipboard(self, payload: bytes) -> bool:
        """Write bytes to the macOS clipboard and report failure."""
        try:
            subprocess.run(["pbcopy"], input=payload, check=True)
            return True
        except (OSError, subprocess.SubprocessError) as exc:
            logging.warning("[MacOSShield] Clipboard write failed: %s", exc)
            return False

    def _read_clipboard(self) -> bytes | None:
        """Read current macOS clipboard bytes for ownership verification."""
        try:
            result = subprocess.run(["pbpaste"], capture_output=True, check=True)
            return result.stdout
        except (OSError, subprocess.SubprocessError) as exc:
            logging.warning("[MacOSShield] Clipboard read failed: %s", exc)
            return None

    def clear_owned_clipboard(self, owner=None) -> bool:
        """Clear only text still matching the active Paracci clipboard write."""
        with self._clipboard_lock:
            active_owner = getattr(self, "_clipboard_owner", None)
            if active_owner is None or (owner is not None and owner is not active_owner):
                return True
            current = self._read_clipboard()
            if current is None:
                return False
            if current != active_owner.payload:
                self._clipboard_owner = None
                return True
            if not self._write_clipboard(b""):
                return False
            self._clipboard_owner = None
            logging.info("[MacOSShield] Owned clipboard content cleared.")
            return True

    def copy_to_clipboard(self, text: str, clear_delay: int = 30) -> bool:
        """Copy text and clear it later only if it remains Paracci-owned."""
        if not text:
            return self.clear_owned_clipboard()

        payload = str(text).encode("utf-8")
        owner = _MacOSClipboardOwner(payload)
        with self._clipboard_lock:
            if not self._write_clipboard(payload):
                return False
            self._clipboard_owner = owner

        self._schedule_owned_clipboard_clear(owner, clear_delay)
        return True
