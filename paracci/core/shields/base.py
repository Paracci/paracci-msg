import os
import platform
import logging
import threading
import time
from abc import ABC, abstractmethod

class BaseShield(ABC):
    """
    Abstract Base Class for OS-Specific Security Adapters.
    Defines the best-effort contract that every OS shield must fulfill.
    These helpers reduce exposure where the platform allows it; they are not
    guarantees against capture, forensic recovery, or local process access.
    """

    _clipboard_lock = threading.Lock()

    def __init__(self):
        self._clipboard_owner = None

    def _schedule_owned_clipboard_clear(self, owner, clear_delay: int) -> None:
        """Schedule a best-effort clear for one immutable clipboard owner record."""
        if clear_delay <= 0:
            return

        def _delayed_clear():
            try:
                time.sleep(clear_delay)
                self.clear_owned_clipboard(owner)
            except Exception as exc:
                logging.error("[Shield] Delayed clipboard clear failed: %s", exc)

        threading.Thread(target=_delayed_clear, daemon=True).start()

    def clear_owned_clipboard(self, owner=None) -> bool:
        """Clear an active Paracci-owned clipboard value when a platform can verify it."""
        return True
    
    @abstractmethod
    def get_os_name(self) -> str:
        """Returns the name of the operating system."""
        pass

    @abstractmethod
    def apply_anti_screenshot(self, window, enabled: bool) -> bool:
        """Attempts platform-specific capture reduction for the app window."""
        pass

    @abstractmethod
    def get_default_data_dir(self, app_name: str) -> str:
        """Returns the OS-recommended data storage path."""
        pass

    @abstractmethod
    def secure_delete(self, file_path: str) -> bool:
        """Attempts best-effort deletion hygiene; physical erasure is not guaranteed."""
        pass

    @abstractmethod
    def clear_recent_documents(self) -> bool:
        """Attempts to clear known recent-file locations for the current OS."""
        pass

    @abstractmethod
    def copy_to_clipboard(self, text: str, clear_delay: int = 30) -> bool:
        """Copies text and schedules clearing; local processes may read it first."""
        pass

    def start_window_resize(self, window, direction: int) -> bool:
        """Triggers a native window resize operation. (Optional)"""
        return False

    def start_window_drag(self, window) -> bool:
        """Triggers a native window drag operation. (Optional)"""
        return False

    def get_system_info(self):
        """Common system info retrieval."""
        return {
            "os": platform.system(),
            "version": platform.version(),
            "machine": platform.machine(),
            "processor": platform.processor()
        }
