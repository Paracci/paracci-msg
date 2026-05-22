"""
Paracci — run.py
Starts the application: python run.py

Execution directory: paracci/
    cd paracci
    python run.py
"""

from __future__ import annotations

import sys
import os
import argparse
import secrets
import json
from pathlib import Path
from urllib.parse import quote

# Add paracci/ directory to import path (for core.xxx imports)
# This makes core/ and app/ folders appear as root.
sys.path.insert(0, str(Path(__file__).parent / "paracci"))

# core.shields import
from core.shields import shield
from core.preview_store import preview_store

import threading
import socket
import webview


_preview_windows: dict[str, webview.Window] = {}
_preview_windows_lock = threading.Lock()
_preview_loopback_host = "127.0.0.1"
_preview_loopback_port: int | None = None

# ── Preview-close guard ────────────────────────────────────────────────────
# pywebview 6.x has a known multi-window event propagation bug: destroying
# a secondary (preview) window spuriously fires the MAIN window's lifecycle
# events (before_load, loaded) and can trigger a full page
# reload that blows away the authenticated Flask session.
#
# The guard counter is raised BEFORE destroy() is called and stays elevated
# for _PREVIEW_CLOSING_LINGER_S seconds after cleanup completes.  This
# linger window covers the async GUI-thread delay between calling destroy()
# and pywebview actually firing the spurious events.  Loaded-event handlers
# bail out immediately while the counter is non-zero.
_preview_closing_count: int = 0
_preview_closing_lock = threading.Lock()
_PREVIEW_CLOSING_LINGER_S: float = 1.5  # seconds to keep guard after teardown


def _begin_preview_close_guard() -> None:
    """Raise the preview-close guard counter (call before window teardown)."""
    global _preview_closing_count
    with _preview_closing_lock:
        _preview_closing_count += 1


def _end_preview_close_guard() -> None:
    """Schedule a delayed decrement so the guard outlives async pywebview events."""
    def _decrement():
        import time
        time.sleep(_PREVIEW_CLOSING_LINGER_S)
        global _preview_closing_count
        with _preview_closing_lock:
            _preview_closing_count = max(0, _preview_closing_count - 1)
    threading.Thread(target=_decrement, daemon=True).start()


def _preview_close_guard_active() -> bool:
    """Return True if any preview teardown is in progress or recently completed."""
    with _preview_closing_lock:
        return _preview_closing_count > 0


class PreviewWindowApi:
    """Token-scoped API exposed only to a dedicated preview window."""

    def __init__(self, token: str):
        self.token = str(token)

    def close_preview_window(self, token):
        if not _preview_token_matches(token, self.token):
            return {"success": False, "error": "Invalid preview token."}
        return {"success": close_preview_window(self.token)}

    def download_preview_file(self, token):
        if not _preview_token_matches(token, self.token):
            return {"success": False, "error": "Invalid preview token."}
        return download_preview_file(self.token)


def _preview_token_matches(candidate: str | None, expected: str | None) -> bool:
    return bool(candidate and expected and secrets.compare_digest(str(candidate), str(expected)))

def get_free_port():
    """Requests a free port from the OS."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _configure_preview_window_context(host: str, port: int) -> None:
    """Set the loopback address used by native preview windows."""
    global _preview_loopback_host, _preview_loopback_port
    _preview_loopback_host = host
    _preview_loopback_port = int(port)


def _preview_window_title(filename: str) -> str:
    title = str(filename or "Paracci Secure Preview").strip() or "Paracci Secure Preview"
    return title if len(title) <= 60 else f"{title[:57]}..."


def _preview_window_size(filename: str, mime_type: str) -> tuple[int, int]:
    mime = str(mime_type or "").lower()
    suffix = Path(str(filename or "")).suffix.lower()
    text_suffixes = {
        ".txt", ".log", ".csv", ".md", ".json", ".xml", ".html",
        ".py", ".js", ".css", ".sql", ".sh", ".rs", ".go", ".java",
        ".c", ".cpp", ".h", ".yaml", ".yml",
    }

    if mime.startswith("image/"):
        return 900, 700
    if mime.startswith("video/"):
        return 1024, 640
    if mime.startswith("audio/"):
        return 500, 200
    if mime == "application/pdf" or suffix == ".pdf":
        return 900, 800
    if mime.startswith("text/") or suffix in text_suffixes or "json" in mime or "xml" in mime:
        return 900, 700
    return 800, 600


def open_preview_window(token: str, filename: str, mime_type: str, file_size: int) -> None:
    """Open a dedicated native preview window for a PreviewStore token."""
    if not token:
        raise ValueError("preview token is required")
    if _preview_loopback_port is None:
        raise RuntimeError("Preview window context is not configured.")

    token = str(token)
    width, height = _preview_window_size(filename, mime_type)
    url = f"http://{_preview_loopback_host}:{_preview_loopback_port}/preview/{quote(token, safe='')}"

    print(f"  [>] open_preview_window requested: {filename} ({file_size} bytes)")
    preview_win = webview.create_window(
        title=_preview_window_title(filename),
        url=url,
        width=width,
        height=height,
        resizable=True,
        on_top=False,
        background_color='#121212',
        text_select=True,
        js_api=PreviewWindowApi(token),
    )

    with _preview_windows_lock:
        _preview_windows[token] = preview_win

    try:
        if hasattr(preview_win.events, 'closed'):
            preview_win.events.closed += lambda *_args, _token=token: _on_preview_window_closed(_token)
    except Exception as e:
        print(f"  [!] Preview close event binding error: {e}")


def _on_preview_window_closed(token: str) -> None:
    # Raise the guard so that any spurious pywebview lifecycle events that
    # fire on the main window during / after this teardown are suppressed.
    # The linger keeps it raised past the async GUI-thread event delay.
    _begin_preview_close_guard()
    try:
        with _preview_windows_lock:
            _preview_windows.pop(str(token), None)
        preview_store.revoke(str(token))
    finally:
        _end_preview_close_guard()


def close_preview_window(token: str) -> bool:
    token = str(token)
    with _preview_windows_lock:
        preview_win = _preview_windows.pop(token, None)

    if preview_win is None:
        preview_store.revoke(token)
        return False

    # Raise the guard BEFORE destroy() so the GUI-thread's spurious events
    # are blocked from the moment the window is torn down.  The closed-event
    # callback (_on_preview_window_closed) will also raise the guard when it
    # fires — the counter handles the double-increment correctly.
    _begin_preview_close_guard()
    try:
        preview_win.destroy()
        return True
    finally:
        preview_store.revoke(token)
        _end_preview_close_guard()


def _preview_download_destination(downloads_dir: Path, filename: str) -> Path:
    downloads_dir.mkdir(parents=True, exist_ok=True)
    dest = downloads_dir / filename
    if not dest.exists():
        return dest

    stem = dest.stem
    suffix = dest.suffix
    counter = 1
    while dest.exists():
        dest = downloads_dir / f"{stem} ({counter}){suffix}"
        counter += 1
    return dest


def download_preview_file(token: str) -> dict:
    token = str(token)
    entry = preview_store.get(token)
    if entry is None:
        return {"success": False, "error": "Preview unavailable."}
    if entry.allow_download is not True:
        return {"success": False, "error": "Download not permitted."}

    with _preview_windows_lock:
        preview_win = _preview_windows.get(token)
    if preview_win is None:
        return {"success": False, "error": "Preview window unavailable."}

    try:
        from core.package import sanitize_attachment_filename
        from core.config import ParacciConfig

        filename = sanitize_attachment_filename(entry.filename or "attachment.bin")
        cfg = ParacciConfig()
        downloads_dir = Path(cfg.full_downloads_path)
        out_path = _preview_download_destination(downloads_dir, filename)
        out_path.write_bytes(entry.file_bytes)
        preview_win.evaluate_js(
            f"window.showDownloadSuccess({json.dumps(out_path.name)});"
        )
        return {"success": True, "path": str(out_path), "filename": out_path.name}
    except Exception as e:
        print(f"  [!] Preview download error: {e}")
        return {"success": False, "error": str(e)}


def _safe_native_download_filename(filename) -> str:
    from core.package import sanitize_attachment_filename

    leaf = Path(str(filename or "").replace("\\", "/")).name
    return sanitize_attachment_filename(leaf, fallback="attachment")


class ProApi:
    """Privileged API exposed only to the trusted main pywebview window."""

    def __init__(self):
        self._window = None

    def bind_window(self, window):
        self._window = window
        return self

    def _require_window(self):
        if self._window is None:
            raise RuntimeError("ProApi window is not bound.")
        return self._window

    def close(self):
        window = self._require_window()
        _close_all_preview_windows()
        window.destroy()

    def minimize(self):
        self._require_window().minimize()

    def select_file(self):
        window = self._require_window()
        result = window.create_file_dialog(
            webview.FileDialog.OPEN,
            allow_multiple=False,
            file_types=('Paracci Message (*.paracci)', 'All Files (*.*)')
        )
        if result:
            return result[0] if isinstance(result, (list, tuple)) else result
        return None

    def select_attachments(self):
        window = self._require_window()
        result = window.create_file_dialog(
            webview.FileDialog.OPEN,
            allow_multiple=True,
            file_types=('All Files (*.*)',)
        )
        if not result:
            return {"success": True, "attachments": []}
        paths = list(result) if isinstance(result, (list, tuple)) else [result]
        try:
            from app.routes import stage_native_attachment_paths
            return {
                "success": True,
                "attachments": stage_native_attachment_paths(paths),
            }
        except Exception as e:
            print(f"  [!] Attachment staging error: {e}")
            return {"success": False, "error": str(e)}

    def save_file(self, content_b64, filename):
        import base64
        from core.config import ParacciConfig

        window = self._require_window()
        cfg = ParacciConfig()

        print(f"  [>] save_file requested: {filename}")

        path = window.create_file_dialog(
            webview.FileDialog.SAVE,
            directory=cfg.full_downloads_path,
            save_filename=filename,
            file_types=('Paracci Message (*.paracci)', 'All Files (*.*)')
        )

        if path:
            if isinstance(path, (list, tuple)):
                path = path[0]

            try:
                file_data = base64.b64decode(content_b64)
                with open(path, "wb") as f:
                    f.write(file_data)
                print(f"  [+] Saved to: {path}")
                return path
            except Exception as e:
                print(f"  [!] Save error: {e}")
        return None

    def save_file_silent(self, content_b64, filename):
        """Saves directly to the downloads folder without asking the user."""
        import base64
        from core.config import ParacciConfig

        cfg = ParacciConfig()
        safe_filename = _safe_native_download_filename(filename)
        path = Path(cfg.full_downloads_path) / safe_filename
        try:
            file_data = base64.b64decode(content_b64)
            with open(path, "wb") as f:
                f.write(file_data)
            print(f"  [+] Silent Save: {path}")
            return str(path)
        except Exception as e:
            print(f"  [!] Silent save error: {e}")
        return None

    def open_file_location(self, path):
        """Opens the folder containing the file in Windows Explorer."""
        import subprocess

        if os.path.exists(path):
            print(f"  [>] Opening location: {path}")
            subprocess.Popen(f'explorer /select,"{os.path.normpath(path)}"')

    def copy_and_clear(self, text, delay=30):
        """Copies text to the clipboard and clears it after X seconds."""
        if shield.copy_to_clipboard(text, delay):
            print(f"  [>] Text copied to clipboard. Cleanup: {delay}s ({shield.get_os_name()})")
            return True
        return False

    def open_preview_window(self, token, filename, mime_type, file_size):
        open_preview_window(token, filename, mime_type, file_size)


def _build_main_navigation_guard_script(loopback_host: str, port: int) -> str:
    return f"""
    (function() {{
        if (window.__PARACCI_NAVIGATION_GUARD_INSTALLED__) {{
            return;
        }}
        window.__PARACCI_NAVIGATION_GUARD_INSTALLED__ = true;

        const allowedHost = {json.dumps(loopback_host)};
        const allowedPort = {json.dumps(str(port))};

        function isAllowedHref(href) {{
            if (!href || href.charAt(0) === '#') {{
                return true;
            }}

            let target;
            try {{
                target = new URL(href, window.location.href);
            }} catch (e) {{
                return false;
            }}

            return target.protocol === 'http:' &&
                target.hostname === allowedHost &&
                target.port === allowedPort &&
                target.username === '' &&
                target.password === '';
        }}

        function blockIfExternal(event, href) {{
            if (isAllowedHref(href)) {{
                return false;
            }}
            event.preventDefault();
            event.stopImmediatePropagation();
            console.warn('Paracci blocked external navigation:', href);
            return true;
        }}

        function handleLinkEvent(event) {{
            const link = event.target && event.target.closest
                ? event.target.closest('a[href]')
                : null;
            if (link) {{
                blockIfExternal(event, link.getAttribute('href'));
            }}
        }}

        document.addEventListener('click', handleLinkEvent, true);
        document.addEventListener('auxclick', handleLinkEvent, true);
        document.addEventListener('submit', function(event) {{
            const form = event.target;
            if (form && form.tagName === 'FORM') {{
                blockIfExternal(event, form.getAttribute('action') || form.action);
            }}
        }}, true);

        const originalOpen = window.open;
        window.open = function(url) {{
            if (url && !isAllowedHref(String(url))) {{
                console.warn('Paracci blocked external window.open:', url);
                return null;
            }}
            return originalOpen.apply(window, arguments);
        }};
    }})();
    """


def _install_navigation_guard_or_exit(window, script) -> None:
    def inject_navigation_guard(*_args):
        if _preview_close_guard_active():
            return
        try:
            window.evaluate_js(script)
        except Exception as exc:
            print(f"  [!] Navigation guard injection failed: {exc}")

    try:
        window.events.loaded += inject_navigation_guard
    except Exception as exc:
        print(f"  [!] Navigation guard event binding failed: {exc}")


def _close_all_preview_windows() -> None:
    with _preview_windows_lock:
        windows = list(_preview_windows.items())
        _preview_windows.clear()

    for token, preview_win in windows:
        try:
            preview_win.destroy()
        except Exception as e:
            print(f"  [!] Preview window close error: {e}")
        preview_store.revoke(token)


def _on_main_window_closed(*_args) -> None:
    _close_all_preview_windows()

def clear_recent_docs():
    """Clears the system 'Recent Documents' list (Anti-Forensics)."""
    if shield.clear_recent_documents():
        print(f"  [SHIELD] Anti-Forensics: {shield.get_os_name()} traces cleared.")

def run_auto_cleanup():
    """Cleans message files older than the specified duration."""
    import time
    from core.config import ParacciConfig
    
    try:
        cfg = ParacciConfig()
        cleanup_hours = cfg.get("auto_cleanup_hours")
        if not cleanup_hours: return
        
        target_dir = cfg.full_downloads_path
        if not os.path.exists(target_dir): return
        
        now = time.time()
        max_age = cleanup_hours * 3600
        count = 0
        
        for fname in os.listdir(target_dir):
            if fname.endswith(".paracci"):
                path = os.path.join(target_dir, fname)
                if os.path.isfile(path):
                    f_age = now - os.path.getmtime(path)
                    if f_age > max_age:
                        os.remove(path)
                        count += 1
        
        if count > 0:
            print(f"  [BURN] Auto-Cleanup: {count} old message files destroyed.")
            
    except Exception as e:
        print(f"  [!] Auto-Cleanup error: {e}")

if __name__ == "__main__":
    clear_recent_docs() # Clear Windows traces on startup
    run_auto_cleanup()  # Clean up old files
    
    # Start hourly cleanup loop in the background
    def cleanup_loop():
        import time
        while True:
            time.sleep(3600) # Check every hour
            run_auto_cleanup()
    
    cleaner_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleaner_thread.start()

    parser = argparse.ArgumentParser(description="Paracci Desktop App")
    parser.add_argument("--port", type=int, help="Fixed port (default: random)")
    parser.add_argument("--user", type=str, choices=['x', 'y'], help="Quick profile select")
    parser.add_argument("--no-gui", action="store_true", help="Run only as web server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode and inspector")
    args = parser.parse_args()

    # Automatically set DATA_DIR if a user profile is selected
    if args.user:
        os.environ['DATA_DIR'] = f"data_{args.user}"
        # Default ports for X and Y (if not specified)
        if not args.port:
            args.port = 5000 if args.user == 'x' else 5001

    port = args.port if args.port else get_free_port()
    loopback_host = "127.0.0.1"
    _configure_preview_window_context(loopback_host, port)
    webview_token = getattr(webview, "token", None) if not args.no_gui else None
    using_webview_token = bool(webview_token)
    loopback_token = (
        os.environ.get("PARACCI_LOOPBACK_TOKEN")
        if args.no_gui
        else webview_token
    ) or secrets.token_urlsafe(32)

    os.environ["PARACCI_LOOPBACK_TOKEN"] = loopback_token
    os.environ["PARACCI_LOOPBACK_HOST"] = loopback_host
    os.environ["PARACCI_LOOPBACK_PORT"] = str(port)
    os.environ["PARACCI_NO_GUI"] = "1" if args.no_gui else "0"

    bootstrap_url = (
        f"http://{loopback_host}:{port}/__paracci_bootstrap"
        f"?token={quote(loopback_token, safe='')}&next=/"
    )

    # App initialization (must be imported after DATA_DIR and loopback security are set)
    from app import create_app
    app = create_app()
    data_dir = os.environ.get('DATA_DIR', 'data (default)')

    print("\n  [o] Paracci Desktop")
    print("  -----------------------------")
    print(f"  Internal: http://{loopback_host}:{port}")
    print(f"  DATA_DIR: {data_dir}")
    
    if args.no_gui:
        print("  Mode: Server Only")
        print("  Authenticated entrypoint:")
        print(f"  {bootstrap_url}")
        print("  Bare loopback URLs reject protected requests without bootstrap auth.")
        print("  Stop with: Ctrl+C\n")
        app.run(host=loopback_host, port=port, debug=False)
    else:
        print("  Mode: Desktop App")
        
        # Start Flask in the background (Thread)
        def start_flask():
            # reloader conflicts with GUI, disabling it.
            app.run(host=loopback_host, port=port, debug=False, use_reloader=False)

        server_thread = threading.Thread(target=start_flask)
        server_thread.daemon = True
        server_thread.start()

        # Main Window (WebView)
        pro_api = ProApi()
        window = webview.create_window(
            title="Paracci Secure Messaging",
            url=bootstrap_url,
            width=1100,
            height=850,
            min_size=(900, 700),
            background_color='#121212',
            frameless=False,
            easy_drag=False, # Disable window dragging trick (title bar only)
            js_api=pro_api
        )
        pro_api.bind_window(window)
        
        # ── Security Shield (Chromium Hardening) ───────────────
        navigation_guard_script = _build_main_navigation_guard_script(loopback_host, port)
        _install_navigation_guard_or_exit(window, navigation_guard_script)

        try:
            if hasattr(window.events, 'closed'):
                window.events.closed += _on_main_window_closed
        except Exception as e:
            print(f"  [!] Main close event binding error: {e}")

        def inject_fallback_loopback_token(*_args):
            # Guard: skip this handler entirely when a preview window is
            # closing.  pywebview 6.x spuriously fires the main window's
            # `loaded` event whenever any secondary window closes.  Running
            # evaluate_js here during that spurious event can interact badly
            # with the concurrent teardown and is never needed — the main
            # window's token was already injected at initial load.
            if _preview_close_guard_active():
                return
            if using_webview_token:
                return
            try:
                window.evaluate_js(f"window.__PARACCI_NATIVE_TOKEN = {json.dumps(loopback_token)};")
            except Exception as e:
                print(f"  [!] Loopback token injection failed: {e}")

        try:
            if hasattr(window.events, 'loaded'):
                window.events.loaded += inject_fallback_loopback_token
        except Exception as e:
            print(f"  [!] Token event binding error: {e}")

        
        # Drag-and-Drop Handler (Global)
        def on_files_dropped(files):
            # Clear traces as soon as the file hits the system (Anti-Forensics)
            clear_recent_docs()
            
            if files and isinstance(files, (list, tuple)):
                file_path = files[0]
                # Global drop should only work for .paracci files and if we are not on the import page
                if file_path.lower().endswith('.paracci'):
                    print(f"  [>] Global file drop detected: {file_path}")
                    try:
                        from app.routes import register_native_file_path
                        file_ref = register_native_file_path(file_path)
                    except Exception as e:
                        print(f"  [!] Native file reference error: {e}")
                        return
                    ref_json = json.dumps(file_ref)
                    # If we are already on the import page, update the UI directly
                    # Otherwise, redirect with parameter
                    js_code = f"""
                    const nativeRef = {ref_json};
                    if (window.location.href.includes('/session/import')) {{
                        if (typeof updateNativeUI === 'function') {{
                            updateNativeUI(nativeRef);
                        }}
                    }} else {{
                        window.location.href = '/session/import?native_file_id=' + encodeURIComponent(nativeRef.id);
                    }}
                    """
                    window.evaluate_js(js_code)

        # Bind events (Error-protected)
        try:
            if hasattr(window.events, 'files_dropped'):
                window.events.files_dropped += on_files_dropped
            elif hasattr(window.events, 'dropped'):
                window.events.dropped += on_files_dropped
            else:
                # If no drag-and-drop support, continue silently
                pass
        except Exception as e:
            print(f"  [!] Event binding error: {e}")

        # Start GUI
        from core.config import ParacciConfig
        cfg = ParacciConfig()
        anti_screenshot_enabled = cfg.get("anti_screenshot")
        
        # Locate application icon relative to run.py
        ICON_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "paracci_icon.ico")
        if not os.path.exists(ICON_PATH):
            ICON_PATH = None

        # Ensure a persistent WebView storage path to prevent session cookie loss when preview windows are closed
        storage_path = os.path.join(os.environ.get("DATA_DIR", "data"), "webview")

        if ICON_PATH:
            webview.start(
                shield.apply_anti_screenshot,
                (window, anti_screenshot_enabled),
                debug=args.debug,
                icon=ICON_PATH,
                private_mode=False,
                storage_path=storage_path
            )
        else:
            webview.start(
                shield.apply_anti_screenshot,
                (window, anti_screenshot_enabled),
                debug=args.debug,
                private_mode=False,
                storage_path=storage_path
            )
        
        # Forcefully close Flask thread and the entire process when the app closes
        _close_all_preview_windows()
        print("\n  [o] Paracci closed. Cleaning up processes...")
        os._exit(0)
