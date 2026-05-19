import os
import logging
import threading
import time
import subprocess
from pathlib import Path
from .base import BaseShield

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

    def secure_delete(self, file_path: str) -> bool:
        """Best-effort shred/overwrite; SSDs, journals, snapshots, and sync may retain data."""
        try:
            subprocess.run(["shred", "-u", "-z", "-n", "1", file_path], check=True)
            return True
        except:
            try:
                p = Path(file_path)
                size = p.stat().st_size
                with open(file_path, "wb") as f: f.write(os.urandom(size))
                os.remove(file_path)
                return True
            except: return False

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
