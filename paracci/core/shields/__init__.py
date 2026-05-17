import platform
import logging
import os

from .windows import WindowsShield
from .linux import LinuxShield
from .macos import MacOSShield
from .base import BaseShield

def get_shield():
    """
    Factory function that detects the current OS 
    and returns the appropriate Shield instance.
    """
    system = platform.system()
    
    if system == "Windows":
        return WindowsShield()
    elif system == "Linux":
        return LinuxShield()
    elif system == "Darwin": # macOS
        return MacOSShield()
    else:
        logging.warning(f"Unsupported OS detected: {system}. Falling back to BaseShield (No protection).")
        
        class DummyShield(BaseShield):
            """Fallback shield for unsupported operating systems."""
            def get_os_name(self): 
                """Returns Unknown OS name."""
                return "Unknown"
            def apply_anti_screenshot(self, h, e): 
                """Dummy implementation."""
                return False
            def get_default_data_dir(self, n): 
                """Returns current directory as fallback."""
                return "./data"
            def secure_delete(self, p): 
                """Standard deletion as fallback."""
                try: os.remove(p); return True
                except: return False
            def clear_recent_documents(self):
                """No-op fallback."""
                return False
            def copy_to_clipboard(self, text, clear_delay=30):
                """No-op fallback."""
                return False
        return DummyShield()

# Global Shield instance for the application
shield = get_shield()
