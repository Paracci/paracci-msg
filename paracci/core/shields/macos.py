import os
import logging
import threading
import time
import subprocess
from pathlib import Path
import ctypes.util
from .base import BaseShield

try:
    import fcntl
except ImportError:  # pragma: no cover - imported eagerly on Windows.
    fcntl = None

class MacOSShield(BaseShield):
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
            with open(file_path, "r+b") as f:
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

    def copy_to_clipboard(self, text: str, clear_delay: int = 30) -> bool:
        """Copies to clipboard and auto-clears after delay; local processes can read it meanwhile."""
        def _set_clipboard(content):
            """Internal macOS clipboard setter."""
            try:
                process = subprocess.Popen(['pbcopy'], stdin=subprocess.PIPE)
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
