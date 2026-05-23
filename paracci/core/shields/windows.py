import os
import ctypes
import ctypes.wintypes
import logging
import threading
import time
from pathlib import Path
from .base import BaseShield

class WindowsShield(BaseShield):
    """
    Windows implementation of Paracci's best-effort platform shield.
    Uses private WinDLL instances and explicit 64-bit signatures to prevent crashes.
    SetWindowDisplayAffinity can reduce common captures, but it does not cover
    external cameras, privileged capture paths, all screen-sharing tools, or
    unsupported Windows/window configurations.
    """
    
    def __init__(self):
        super().__init__()
        self._init_win32_api()

    def _init_win32_api(self):
        """Initialize private Win32 DLLs and function signatures."""
        try:
            self._user32 = ctypes.WinDLL('user32', use_last_error=True)
            self._kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
            self._shell32 = ctypes.WinDLL('shell32', use_last_error=True)

            # --- User32 Signatures ---
            # BOOL SetWindowDisplayAffinity(HWND hWnd, DWORD dwAffinity)
            self._user32.SetWindowDisplayAffinity.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.DWORD]
            self._user32.SetWindowDisplayAffinity.restype = ctypes.wintypes.BOOL

            # BOOL OpenClipboard(HWND hWndNewOwner)
            self._user32.OpenClipboard.argtypes = [ctypes.wintypes.HWND]
            self._user32.OpenClipboard.restype = ctypes.wintypes.BOOL

            # BOOL EmptyClipboard()
            self._user32.EmptyClipboard.argtypes = []
            self._user32.EmptyClipboard.restype = ctypes.wintypes.BOOL

            # HANDLE SetClipboardData(UINT uFormat, HANDLE hMem)
            self._user32.SetClipboardData.argtypes = [ctypes.wintypes.UINT, ctypes.wintypes.HANDLE]
            self._user32.SetClipboardData.restype = ctypes.wintypes.HANDLE

            # BOOL CloseClipboard()
            self._user32.CloseClipboard.argtypes = []
            self._user32.CloseClipboard.restype = ctypes.wintypes.BOOL

            # --- Kernel32 Signatures ---
            # HGLOBAL GlobalAlloc(UINT uFlags, SIZE_T dwBytes)
            self._kernel32.GlobalAlloc.argtypes = [ctypes.wintypes.UINT, ctypes.c_size_t]
            self._kernel32.GlobalAlloc.restype = ctypes.wintypes.HGLOBAL

            # LPVOID GlobalLock(HGLOBAL hMem)
            self._kernel32.GlobalLock.argtypes = [ctypes.wintypes.HGLOBAL]
            self._kernel32.GlobalLock.restype = ctypes.wintypes.LPVOID

            # BOOL GlobalUnlock(HGLOBAL hMem)
            self._kernel32.GlobalUnlock.argtypes = [ctypes.wintypes.HGLOBAL]
            self._kernel32.GlobalUnlock.restype = ctypes.wintypes.BOOL

            # HGLOBAL GlobalFree(HGLOBAL hMem)
            self._kernel32.GlobalFree.argtypes = [ctypes.wintypes.HGLOBAL]
            self._kernel32.GlobalFree.restype = ctypes.wintypes.HGLOBAL

            # --- Shell32 Signatures ---
            # void SHAddToRecentDocs(UINT uFlags, LPCVOID pv)
            self._shell32.SHAddToRecentDocs.argtypes = [ctypes.wintypes.UINT, ctypes.c_void_p]
            self._shell32.SHAddToRecentDocs.restype = None

            # --- Window Management Signatures ---
            # BOOL ReleaseCapture()
            self._user32.ReleaseCapture.argtypes = []
            self._user32.ReleaseCapture.restype = ctypes.wintypes.BOOL

            # LRESULT SendMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
            self._user32.SendMessageW.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM]
            self._user32.SendMessageW.restype = ctypes.wintypes.LPARAM

            # BOOL PostMessageW(HWND hWnd, UINT Msg, WPARAM wParam, LPARAM lParam)
            self._user32.PostMessageW.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.UINT, ctypes.wintypes.WPARAM, ctypes.wintypes.LPARAM]
            self._user32.PostMessageW.restype = ctypes.wintypes.BOOL

            # HWND GetAncestor(HWND hWnd, UINT gaFlags)
            self._user32.GetAncestor.argtypes = [ctypes.wintypes.HWND, ctypes.wintypes.UINT]
            self._user32.GetAncestor.restype = ctypes.wintypes.HWND

            logging.info("[WindowsArmor] Win32 API initialized successfully")
        except Exception as e:
            logging.error(f"[WindowsArmor] Failed to initialize Win32 API: {e}")

    def get_os_name(self) -> str:
        return "Windows"

    def _get_hwnd(self, window):
        """Extracts the root HWND from a window object (supports pywebview and Qt)."""
        try:
            hwnd = None
            
            # Qt Support (from Remote HEAD)
            if hasattr(window, "winId"):
                try:
                    hwnd = int(window.winId())
                except:
                    pass

            # pywebview Support (Legacy/Fallback)
            if not hwnd:
                if hasattr(window, 'native') and window.native:
                    if hasattr(window.native, 'hwnd'):
                        hwnd = window.native.hwnd
                    elif hasattr(window.native, 'Handle'):
                        hwnd = window.native.Handle
            
            if not hwnd: return None

            # Normalize HWND to a pointer-sized integer
            h_val = None
            if hasattr(hwnd, 'value'): h_val = int(hwnd.value)
            elif hasattr(hwnd, 'ToInt64'): h_val = hwnd.ToInt64()
            else: h_val = int(hwnd)

            # Ensure we have the ROOT window (GA_ROOT = 2)
            if h_val:
                root_h = self._user32.GetAncestor(h_val, 2)
                return root_h if root_h else h_val
            return h_val
        except Exception as e:
            logging.error(f"[WindowsArmor] HWND acquisition failed: {e}")
            return None


    def apply_anti_screenshot(self, window, enabled: bool) -> bool:
        """
        Attempts best-effort OS-specific screen capture reduction.
        WDA_MONITOR = 0x1, WDA_EXCLUDEFROMCAPTURE = 0x11 (Windows 10+)
        """
        h_val = self._get_hwnd(window)
        if not h_val: 
            # In Qt, it might take a moment for the window to be ready
            for _ in range(5):
                time.sleep(0.2)
                h_val = self._get_hwnd(window)
                if h_val: break
            
            if not h_val:
                logging.warning("[WindowsArmor] Could not obtain HWND for capture-reduction")
                return False

        try:
            if not enabled:
                self._user32.SetWindowDisplayAffinity(h_val, 0)
                logging.info("[WindowsArmor] Capture-reduction disabled")
                return True

            # Try modern best-effort exclusion first (transparent in many screenshots).
            if self._user32.SetWindowDisplayAffinity(h_val, 0x00000011):
                logging.info("[WindowsArmor] Capture-reduction requested (exclude from capture)")
                return True
            else:
                # Fallback to legacy monitor mode for older Windows capture APIs.
                self._user32.SetWindowDisplayAffinity(h_val, 0x00000001)
                logging.info("[WindowsArmor] Capture-reduction requested (legacy monitor mode)")
                return True
        except Exception as e:
            logging.error(f"[WindowsArmor] Capture-reduction error: {e}")
            return False

    def get_default_data_dir(self, app_name: str) -> str:
        base = os.getenv('LOCALAPPDATA')
        if base:
            return str(Path(base) / app_name)
        return str(Path.home() / "AppData" / "Local" / app_name)

    def secure_delete(self, file_path: str) -> bool:
        """Best-effort overwrite/delete; SSDs, journals, snapshots, and sync may retain data."""
        try:
            p = Path(file_path)
            if not p.exists(): return True
            size = p.stat().st_size
            with open(file_path, "wb") as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())
            os.remove(file_path)
            return True
        except Exception as e:
            logging.error(f"[WindowsArmor] Secure delete failed: {e}")
            return False

    def clear_recent_documents(self) -> bool:
        try:
            # SHARD_PATHW = 0x00000003
            self._shell32.SHAddToRecentDocs(0x00000003, None)
            return True
        except Exception as e:
            logging.error(f"[WindowsArmor] Failed to clear recent docs: {e}")
            return False

    def copy_to_clipboard(self, text: str, clear_delay: int = 30) -> bool:
        """Copies to clipboard and auto-clears after delay; local processes can read it meanwhile."""
        def _set_clipboard(content):
            CF_UNICODETEXT = 13
            GHND = 0x0042 # GMEM_MOVEABLE (0x02) | GMEM_ZEROINIT (0x40)
            
            # Retry loop for OpenClipboard (it can fail if another app is using it)
            opened = False
            for i in range(10):
                if self._user32.OpenClipboard(None):
                    opened = True
                    break
                logging.warning(f"[WindowsArmor] OpenClipboard attempt {i+1} failed. Retrying...")
                time.sleep(0.1)

            if not opened:
                logging.error(f"[WindowsArmor] Failed to open clipboard after 10 attempts.")
                return False
                
            try:
                if not self._user32.EmptyClipboard():
                    return False

                if not content:
                    return True
                
                content_bytes = str(content).encode('utf-16le')
                msize = len(content_bytes) + 2
                
                hGlobalMem = self._kernel32.GlobalAlloc(GHND, msize)
                if not hGlobalMem:
                    return False
                    
                lpGlobalMem = self._kernel32.GlobalLock(hGlobalMem)
                if not lpGlobalMem:
                    self._kernel32.GlobalFree(hGlobalMem)
                    return False
                
                try:
                    ctypes.memmove(lpGlobalMem, content_bytes, len(content_bytes))
                finally:
                    self._kernel32.GlobalUnlock(hGlobalMem)
                    
                if not self._user32.SetClipboardData(CF_UNICODETEXT, hGlobalMem):
                    self._kernel32.GlobalFree(hGlobalMem)
                    return False
                    
                return True
            except Exception as e:
                logging.error(f"[WindowsArmor] Internal clipboard error: {e}")
                return False
            finally:
                self._user32.CloseClipboard()

        def _delayed_clear():
            try:
                time.sleep(clear_delay)
                if _set_clipboard(""):
                    logging.info(f"[WindowsArmor] Clipboard auto-cleared after {clear_delay}s")
            except Exception as e:
                logging.error(f"[WindowsArmor] Error in delayed clear: {e}")

        try:
            if _set_clipboard(text):
                if clear_delay > 0:
                    threading.Thread(target=_delayed_clear, daemon=True).start()
                return True
            return False
        except Exception as e:
            logging.error(f"[WindowsArmor] Clipboard error: {e}")
            return False
