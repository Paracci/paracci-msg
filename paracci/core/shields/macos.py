import os
import logging
import threading
import time
import subprocess
from pathlib import Path
import ctypes.util
from .base import BaseShield

class MacOSShield(BaseShield):
    def get_os_name(self) -> str:
        """Returns the human-readable OS name."""
        return "macOS"

    def apply_anti_screenshot(self, window, enabled: bool) -> bool:
        """
        Theoretical implementation for macOS anti-screenshot.
        Sets NSWindow sharingType to NSWindowSharingNone (0).
        """
        if not enabled:
            logging.info("[MacOSShield] Anti-Screenshot DISABLED by user config")
            return False

        # Detect headless/CI or offscreen QPA to avoid segfaults on invalid handles
        is_ci = os.environ.get("GITHUB_ACTIONS") == "true"
        is_offscreen = os.environ.get("QT_QPA_PLATFORM") == "offscreen"
        
        if is_ci or is_offscreen:
            logging.info("[MacOSShield] Anti-Screenshot skipped in CI/offscreen environment")
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
                logging.info(f"[MacOSShield] Anti-Screenshot ENABLED (handle: {hex(ptr)})")
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

    def secure_delete(self, file_path: str) -> bool:
        """Overwrites file with random bytes before deletion on macOS."""
        try:
            p = Path(file_path)
            size = p.stat().st_size
            with open(file_path, "wb") as f: f.write(os.urandom(size))
            os.remove(file_path)
            return True
        except: return False

    def clear_recent_documents(self) -> bool:
        """Clears macOS recent items."""
        try:
            subprocess.run(["osascript", "-e", 'tell application "System Events" to clear recent items'], check=True)
            return True
        except: return False

    def copy_to_clipboard(self, text: str, clear_delay: int = 30) -> bool:
        """Securely copies to clipboard using pbcopy on macOS."""
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
