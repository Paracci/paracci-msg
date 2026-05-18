"""
Paracci — run.py
Starts the application: python run.py

Execution directory: paracci/
    cd paracci
    python run.py
"""

import sys
import os
import argparse
import secrets
import json
from pathlib import Path
from urllib.parse import quote, urlparse

# Add paracci/ directory to import path (for core.xxx imports)
# This makes core/ and app/ folders appear as root.
sys.path.insert(0, str(Path(__file__).parent / "paracci"))

# core.shields import
from core.shields import shield

import threading
import socket
import webview

def get_free_port():
    """Requests a free port from the OS."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

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

        # Window Control API (JS -> Python)
        class ProApi:
            def close(self):
                window.destroy()
            def minimize(self):
                window.minimize()
            def select_file(self):
                # Native Windows File Selection Dialog
                result = window.create_file_dialog(
                    webview.FileDialog.OPEN, 
                    allow_multiple=False, 
                    file_types=('Paracci Message (*.paracci)', 'All Files (*.*)')
                )
                if result:
                    # Pywebview returns a list in some versions
                    return result[0] if isinstance(result, (list, tuple)) else result
                return None

            def save_file(self, content_b64, filename):
                # Native Windows Save As Dialog
                import base64
                from core.config import ParacciConfig
                cfg = ParacciConfig()
                
                print(f"  [>] save_file requested: {filename}")
                
                path = window.create_file_dialog(
                    webview.FileDialog.SAVE,
                    directory=cfg.full_downloads_path, # Default folder
                    save_filename=filename,
                    file_types=('Paracci Message (*.paracci)', 'All Files (*.*)')
                )
                
                if path:
                    # Some pywebview versions may return a list/tuple
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
                import os
                from core.config import ParacciConfig
                cfg = ParacciConfig()
                
                path = os.path.join(cfg.full_downloads_path, filename)
                try:
                    file_data = base64.b64decode(content_b64)
                    with open(path, "wb") as f:
                        f.write(file_data)
                    print(f"  [+] Silent Save: {path}")
                    return path
                except Exception as e:
                    print(f"  [!] Silent save error: {e}")
                return None

            def open_file_location(self, path):
                """Opens the folder containing the file in Windows Explorer."""
                import os
                import subprocess
                if os.path.exists(path):
                    print(f"  [>] Opening location: {path}")
                    # Open the folder and select the file (Windows-specific command)
                    subprocess.Popen(f'explorer /select,"{os.path.normpath(path)}"')

            def copy_and_clear(self, text, delay=30):
                """Copies text to the clipboard and clears it after X seconds (Shielded)."""
                if shield.copy_to_clipboard(text, delay):
                    print(f"  [>] Text copied to clipboard. Cleanup: {delay}s ({shield.get_os_name()})")
                    return True
                return False

        # Main Window (WebView)
        window = webview.create_window(
            title="Paracci Secure Messaging",
            url=bootstrap_url,
            width=1100,
            height=850,
            min_size=(900, 700),
            background_color='#121212',
            frameless=False,
            easy_drag=False, # Disable window dragging trick (title bar only)
            js_api=ProApi()
        )
        
        # ── Security Shield (Chromium Hardening) ───────────────
        def on_navigating(url):
            """Blocks all links leading to the outside world."""
            try:
                parsed = urlparse(url)
                allowed = (
                    parsed.scheme == "http"
                    and parsed.hostname == loopback_host
                    and parsed.port == port
                    and parsed.username is None
                    and parsed.password is None
                )
            except Exception:
                allowed = False

            if not allowed:
                print(f"  [!] Security: Access to external address blocked: {url}")
                return False # Cancel navigation
            return True

        try:
            window.events.navigating += on_navigating
        except:
            pass # This event may not exist in some older versions

        def inject_fallback_loopback_token(*_args):
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
                    safe_path = file_path.replace('\\', '/')
                    # If we are already on the import page, update the UI directly
                    # Otherwise, redirect with parameter
                    js_code = f"""
                    if (window.location.href.includes('/session/import')) {{
                        if (typeof updateNativeUI === 'function') {{
                            updateNativeUI('{safe_path}');
                        }}
                    }} else {{
                        window.location.href = '/session/import?native_path={safe_path}';
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
        
        webview.start(shield.apply_anti_screenshot, (window, anti_screenshot_enabled), debug=args.debug)
        
        # Forcefully close Flask thread and the entire process when the app closes
        print("\n  [o] Paracci closed. Cleaning up processes...")
        os._exit(0)
