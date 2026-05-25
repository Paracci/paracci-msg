import os
import ctypes
import logging
import threading
import time
import subprocess
from pathlib import Path
from .base import BaseShield

FALLOC_FL_KEEP_SIZE = 0x01
FALLOC_FL_PUNCH_HOLE = 0x02

class LinuxShield(BaseShield):
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

    def copy_to_clipboard(self, text: str, clear_delay: int = 30) -> bool:
        """Copies to clipboard and auto-clears after delay; local processes can read it meanwhile."""
        def _set_clipboard(content):
            """Internal Linux clipboard setter."""
            try:
                # Try xclip (X11)
                process = subprocess.Popen(['xclip', '-selection', 'clipboard'], stdin=subprocess.PIPE)
                process.communicate(input=content.encode('utf-8'))
            except:
                try:
                    # Try wl-copy (Wayland)
                    process = subprocess.Popen(['wl-copy'], stdin=subprocess.PIPE)
                    process.communicate(input=content.encode('utf-8'))
                except: pass

        def _delayed_clear():
            """Delayed task to clear the clipboard."""
            time.sleep(clear_delay)
            _set_clipboard("")

        try:
            _set_clipboard(text)
            if clear_delay > 0 and text:
                threading.Thread(target=_delayed_clear, daemon=True).start()
            return True
        except: return False
