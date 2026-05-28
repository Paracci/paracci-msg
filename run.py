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
import base64
import binascii
import logging
import secrets
import json
import subprocess
from pathlib import Path
from urllib.parse import quote

# Check dependencies and auto-re-execute in virtual environment if available
try:
    import yoyo
except ImportError:
    ROOT_DIR = Path(__file__).parent
    if os.environ.get("PARACCI_VENV_BOOTSTRAPPED"):
        print("[ERROR] Running inside virtual environment but dependencies are still missing.", file=sys.stderr)
        print("[ERROR] Please install dependencies by running: pip install -r requirements.lock", file=sys.stderr)
        sys.exit(1)

    # Look for local workspace virtual environment (.venv)
    venv_dir = ROOT_DIR / ".venv"
    appdata_local = os.environ.get("LOCALAPPDATA")
    appdata_venv = Path(appdata_local) / "Paracci" / ".venv" if appdata_local else None

    target_python = None
    if venv_dir.exists():
        py_exe = venv_dir / "Scripts" / "python.exe" if sys.platform == "win32" else venv_dir / "bin" / "python"
        if py_exe.exists():
            target_python = py_exe
    elif appdata_venv and appdata_venv.exists():
        py_exe = appdata_venv / "Scripts" / "python.exe" if sys.platform == "win32" else appdata_venv / "bin" / "python"
        if py_exe.exists():
            target_python = py_exe

    # If no virtual environment is found, automatically create one in the workspace
    if not target_python:
        print("[*] Virtual environment (.venv) not found. Creating a new virtual environment...", flush=True)
        try:
            subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
            
            # Locate python in the new venv
            if sys.platform == "win32":
                py_exe = venv_dir / "Scripts" / "python.exe"
            else:
                py_exe = venv_dir / "bin" / "python"

            if py_exe.exists():
                print("[*] Installing dependencies into the virtual environment...", flush=True)
                
                # Install lock files using python -m pip to prevent lock errors when upgrading pip
                req_args = [str(py_exe), "-m", "pip", "install", "--require-hashes", "-r", str(ROOT_DIR / "requirements.lock")]
                if (ROOT_DIR / "requirements-dev.lock").exists():
                    req_args.extend(["-r", str(ROOT_DIR / "requirements-dev.lock")])
                subprocess.run(req_args, check=True)

                # If on Windows, also install sqlcipher3-wheels to prevent build failures/DatabaseErrors
                if sys.platform == "win32":
                    print("[*] Installing sqlcipher3-wheels for Windows SQLCipher support...", flush=True)
                    subprocess.run([str(py_exe), "-m", "pip", "install", "sqlcipher3-wheels"], check=True)
                
                target_python = py_exe
        except Exception as e:
            print(f"[ERROR] Failed to automatically create virtual environment and install dependencies: {e}", file=sys.stderr)
            print("[ERROR] Please create a virtual environment manually:", file=sys.stderr)
            if sys.platform == "win32":
                print("    python -m venv .venv\n    .\\.venv\\Scripts\\activate\n    pip install -r requirements.lock", file=sys.stderr)
            else:
                print("    python -m venv .venv\n    source .venv/bin/activate\n    pip install -r requirements.lock", file=sys.stderr)
            sys.exit(1)

    if target_python:
        print(f"[*] Re-running script inside virtual environment: {target_python}", flush=True)
        env = os.environ.copy()
        env["PARACCI_VENV_BOOTSTRAPPED"] = "1"
        try:
            result = subprocess.run([str(target_python), str(Path(__file__).resolve())] + sys.argv[1:], env=env)
            sys.exit(result.returncode)
        except Exception as e:
            print(f"[ERROR] Failed to execute script within virtual environment: {e}", file=sys.stderr)
            sys.exit(1)

# Add paracci/ directory to import path (for core.xxx imports)
# This makes core/ and app/ folders appear as root.
sys.path.insert(0, str(Path(__file__).parent / "paracci"))

# core.shields import
from core.shields import shield
from core.burn import secure_delete
from core.package import MAX_ATTACHMENT_FILENAME_LENGTH, validate_native_download_filename
from core.preview_store import MAX_NATIVE_SAVE_BYTES, native_save_grants, preview_store
from desktop.file_activation import (
    FileActivationBroker,
    LaunchFileCandidate,
    inspect_launch_file,
    install_macos_file_open_handler,
)

import threading
import socket
import webview
from werkzeug.serving import make_server

logger = logging.getLogger(__name__)


_preview_windows: dict[str, webview.Window] = {}
_preview_windows_lock = threading.Lock()
_preview_loopback_host = "127.0.0.1"
_preview_loopback_port: int | None = None
_FILE_ACTIVATION_ERROR_TARGET = "/?file_activation_error=1"

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


def _open_download_file_location(path, *, preview_window: bool = False) -> dict:
    """Reveal only an existing application-managed download in Explorer."""
    from core.config import ParacciConfig

    try:
        raw_path = os.fspath(path)
        if not isinstance(raw_path, str) or "\x00" in raw_path:
            raise ValueError("Invalid path.")
        candidate = Path(raw_path)
        if not candidate.is_absolute():
            raise ValueError("Path must be absolute.")

        downloads_root = Path(ParacciConfig().full_downloads_path).resolve()
        resolved_path = candidate.resolve(strict=True)
        resolved_path.relative_to(downloads_root)
    except (OSError, RuntimeError, TypeError, ValueError):
        return {"success": False, "error": "File location is unavailable."}

    label = " (Preview window)" if preview_window else ""
    print(f"  [>] Opening location{label}: {resolved_path}")
    subprocess.Popen(["explorer", f"/select,{os.path.normpath(str(resolved_path))}"])
    return {"success": True}


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

    def open_file_location(self, path):
        """Opens the folder containing the file in Windows Explorer."""
        return _open_download_file_location(path, preview_window=True)


def _preview_token_matches(candidate: str | None, expected: str | None) -> bool:
    return bool(candidate and expected and secrets.compare_digest(str(candidate), str(expected)))




def _file_activation_target(candidate: LaunchFileCandidate | None, db) -> str:
    """Return a local route for a validated message activation."""
    if candidate is None:
        return "/"
    if not db.session_exists(candidate.session_id):
        return _FILE_ACTIVATION_ERROR_TARGET

    from app.routes import register_native_file_path

    file_ref = register_native_file_path(candidate.path)
    return (
        f"/session/{candidate.session_id.hex()}"
        f"?native_file_id={quote(file_ref['id'], safe='')}"
    )


def _bootstrap_url(loopback_host: str, port: int, loopback_token: str, target: str = "/") -> str:
    """Create the one-time authorized entrypoint for an internal local target."""
    return (
        f"http://{loopback_host}:{port}/__paracci_bootstrap"
        f"?token={quote(loopback_token, safe='')}&next={quote(target, safe='/')}"
    )


def _foreground_main_window(window) -> None:
    """Restore and reveal an existing application window."""
    for operation in ("restore", "show"):
        try:
            getattr(window, operation)()
        except (AttributeError, RuntimeError) as exc:
            logger.warning("Main-window foreground error (%s): %s", operation, exc)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            logger.exception("Unexpected main-window foreground error (%s): %s", operation, exc)


def _activate_main_window(
    window,
    raw_path: str | None,
    db,
    loopback_host: str,
    port: int,
    loopback_token: str,
) -> str | None:
    """Handle one authenticated activation request in the primary process."""
    _foreground_main_window(window)
    if raw_path is None:
        return None

    candidate = inspect_launch_file(raw_path)
    if candidate is None:
        return None

    target = _file_activation_target(candidate, db)
    window.load_url(_bootstrap_url(loopback_host, port, loopback_token, target))
    return target


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
    except AttributeError as exc:
        logger.warning("Preview close event binding error (attribute): %s", exc)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        logger.exception("Unexpected preview close event binding error: %s", exc)


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


def _is_link_or_junction(path: Path) -> bool:
    """Return whether a filesystem path is a symlink or Windows junction."""
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction and is_junction())


def _native_downloads_root() -> Path:
    """Return a canonical, non-linked Downloads directory owned by Paracci."""
    from core.config import ParacciConfig

    configured = Path(ParacciConfig().full_downloads_path)
    if _is_link_or_junction(configured):
        raise ValueError("Downloads directory is unavailable.")
    try:
        resolved = configured.resolve(strict=True)
    except OSError as exc:
        raise ValueError("Downloads directory is unavailable.") from exc
    if not resolved.is_dir():
        raise ValueError("Downloads directory is unavailable.")
    return resolved


def _collision_filename(filename: str, counter: int) -> str:
    if counter == 0:
        return filename
    suffix = Path(filename).suffix
    stem = filename[:-len(suffix)] if suffix else filename
    marker = f"_{counter}"
    stem_limit = MAX_ATTACHMENT_FILENAME_LENGTH - len(marker) - len(suffix)
    if stem_limit < 1:
        raise ValueError("Invalid download filename.")
    return validate_native_download_filename(f"{stem[:stem_limit]}{marker}{suffix}")


import shutil

def _write_native_download(filename: str, source_path: Path | None = None, file_bytes: bytes | None = None) -> Path:
    """Atomically create a validated file under the managed Downloads root."""
    if source_path is not None:
        try:
            if os.path.getsize(source_path) > MAX_NATIVE_SAVE_BYTES:
                raise ValueError("Native download exceeds the size limit.")
        except OSError:
            raise ValueError("Native download size check failed.")
    else:
        if not isinstance(file_bytes, bytes) or len(file_bytes) > MAX_NATIVE_SAVE_BYTES:
            raise ValueError("Native download exceeds the size limit.")
            
    validated_filename = validate_native_download_filename(filename)
    downloads_root = _native_downloads_root()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)

    for counter in range(10000):
        candidate = downloads_root / _collision_filename(validated_filename, counter)
        candidate.relative_to(downloads_root)
        try:
            descriptor = os.open(candidate, flags, 0o600)
        except FileExistsError:
            continue
        except OSError as exc:
            raise ValueError("Native download path is unavailable.") from exc
        try:
            with os.fdopen(descriptor, "wb") as output:
                if source_path is not None:
                    with open(source_path, "rb") as f:
                        shutil.copyfileobj(f, output)
                else:
                    output.write(file_bytes)
        except Exception:
            try:
                candidate.unlink()
            except OSError:
                pass
            raise
        return candidate
    raise ValueError("Native download destination is unavailable.")


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
        filename = validate_native_download_filename(entry.filename or "attachment.bin")
        if not preview_win.create_confirmation_dialog(
            "Confirm download",
            f"Save {filename} to Paracci Downloads?",
        ):
            return {"success": False, "cancelled": True}
        out_path = _write_native_download(filename, source_path=Path(entry.file_path))
        preview_win.evaluate_js(
            f"window.showDownloadSuccess({json.dumps(out_path.name)});"
        )
        return {"success": True, "path": str(out_path), "filename": out_path.name}
    except Exception as e:
        print(f"  [!] Preview download error: {e}")
        return {"success": False, "error": str(e)}


def _decode_native_base64(content_b64: str) -> bytes:
    max_encoded_length = 4 * ((MAX_NATIVE_SAVE_BYTES + 2) // 3)
    if not isinstance(content_b64, str) or len(content_b64) > max_encoded_length:
        raise ValueError("Native download exceeds the size limit.")
    try:
        file_data = base64.b64decode(content_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise ValueError("Native download payload is invalid.") from exc
    if len(file_data) > MAX_NATIVE_SAVE_BYTES:
        raise ValueError("Native download exceeds the size limit.")
    return file_data


class ProApi:
    """Privileged API exposed only to the trusted main pywebview window."""

    def __init__(self, loopback_token=None, update_manager=None):
        self._window = None
        self._loopback_token = str(loopback_token) if loopback_token else None
        self._update_manager = update_manager
        self.installer_to_launch: Path | None = None

    def bind_window(self, window):
        self._window = window
        return self

    def _require_window(self):
        if self._window is None:
            raise RuntimeError("ProApi window is not bound.")
        return self._window

    def _require_native_write_token(self, candidate):
        if not (
            candidate
            and self._loopback_token
            and secrets.compare_digest(str(candidate), self._loopback_token)
        ):
            raise PermissionError("Native save authorization failed.")

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

    def save_file(self, content_b64, filename, loopback_token):
        from core.config import ParacciConfig

        self._require_native_write_token(loopback_token)
        safe_filename = validate_native_download_filename(filename)
        file_data = _decode_native_base64(content_b64)
        window = self._require_window()
        cfg = ParacciConfig()

        print(f"  [>] save_file requested: {safe_filename}")

        path = window.create_file_dialog(
            webview.FileDialog.SAVE,
            directory=cfg.full_downloads_path,
            save_filename=safe_filename,
            file_types=('Paracci Message (*.paracci)', 'All Files (*.*)')
        )

        if path:
            if isinstance(path, (list, tuple)):
                path = path[0]

            try:
                resolved_downloads = Path(cfg.full_downloads_path).resolve()
                resolved_path = Path(path).resolve()
                try:
                    resolved_path.relative_to(resolved_downloads)
                except ValueError:
                    raise ValueError("Destination path must be inside the managed Downloads directory.")

                if _is_link_or_junction(resolved_path) or _is_link_or_junction(resolved_path.parent):
                    raise ValueError("Junctions or symbolic links are not permitted.")

                with open(path, "wb") as f:
                    f.write(file_data)
                print(f"  [+] Saved to: {path}")
                return path
            except Exception as e:
                print(f"  [!] Save error: {e}")
        return None

    def save_file_silent(self, native_save_token, loopback_token):
        """Save a one-shot server-authorized download after native confirmation."""
        self._require_native_write_token(loopback_token)
        grant = native_save_grants.consume(str(native_save_token or ""))
        if grant is None:
            raise PermissionError("Native save grant is invalid or expired.")
        filename = validate_native_download_filename(grant.filename)
        try:
            if os.path.getsize(grant.file_path) > MAX_NATIVE_SAVE_BYTES:
                raise ValueError("Native download exceeds the size limit.")
        except OSError:
            pass
            
        window = self._require_window()
        if not window.create_confirmation_dialog(
            "Confirm download",
            f"Save {filename} to Paracci Downloads?",
        ):
            return None
            
        try:
            path = _write_native_download(filename, source_path=Path(grant.file_path))
            print(f"  [+] Confirmed Save: {path}")
            return str(path)
        finally:
            try:
                secure_delete(grant.file_path)
            except Exception:
                pass

    def open_file_location(self, path):
        """Opens the folder containing the file in Windows Explorer."""
        return _open_download_file_location(path)

    def copy_and_clear(self, text, delay=30):
        """Copies text to the clipboard and clears it after X seconds."""
        if shield.copy_to_clipboard(text, delay):
            print(f"  [>] Text copied to clipboard. Cleanup: {delay}s ({shield.get_os_name()})")
            return True
        return False

    def open_preview_window(self, token, filename, mime_type, file_size):
        open_preview_window(token, filename, mime_type, file_size)

    def install_verified_update(self):
        """Close the application only for a verified updater-owned installer."""
        if self._update_manager is None:
            return {"success": False, "error": "Update installer is unavailable."}
        installer = self._update_manager.prepare_installer_launch()
        if installer is None:
            return {"success": False, "error": "Update installer is not verified."}
        self.installer_to_launch = installer
        self.close()
        return {"success": True}


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
            if (!href || typeof href !== 'string') return true;
            if (href.charAt(0) === '#') {{
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
    except AttributeError as exc:
        logger.warning("Navigation guard event binding failed (attribute): %s", exc)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception as exc:
        logger.exception("Unexpected navigation guard event binding error: %s", exc)


def _close_all_preview_windows() -> None:
    with _preview_windows_lock:
        windows = list(_preview_windows.items())
        _preview_windows.clear()

    for token, preview_win in windows:
        try:
            preview_win.destroy()
        except AttributeError as exc:
            logger.warning("Preview window close error (attribute): %s", exc)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            logger.exception("Unexpected preview window close error: %s", exc)
        preview_store.revoke(token)


def _on_main_window_closed(*_args) -> None:
    _close_all_preview_windows()


def _shutdown_desktop_runtime(
    server,
    server_thread,
    activation_broker,
    update_manager,
    installer_path: Path | None,
) -> None:
    """Close background resources, then hand a verified installer to the OS."""
    import app as ag_app
    ag_app.lock_device()
    _close_all_preview_windows()
    if update_manager is not None:
        update_manager.close(preserve_handoff=installer_path is not None)
    server.shutdown()
    server_thread.join(timeout=2.0)
    server.server_close()
    if activation_broker is not None:
        activation_broker.close()
    if installer_path is not None:
        subprocess.Popen([str(installer_path)], close_fds=True)


def clear_recent_docs():
    """Clears the system 'Recent Documents' list (Anti-Forensics)."""
    if shield.clear_recent_documents():
        print(f"  [SHIELD] Anti-Forensics: {shield.get_os_name()} traces cleared.")

def run_auto_cleanup(protected_path: Path | None = None):
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
        failed_count = 0
        
        for fname in os.listdir(target_dir):
            if fname.endswith(".paracci"):
                path = os.path.join(target_dir, fname)
                if os.path.isfile(path):
                    if protected_path is not None:
                        current = os.path.normcase(os.path.abspath(path))
                        protected = os.path.normcase(os.path.abspath(str(protected_path)))
                        if current == protected:
                            continue
                    f_age = now - os.path.getmtime(path)
                    if f_age > max_age:
                        if secure_delete(path):
                            count += 1
                        else:
                            failed_count += 1
        
        if count > 0:
            print(f"  [BURN] Auto-Cleanup: {count} old message files destroyed.")
        if failed_count > 0:
            logger.error(
                "Auto-cleanup could not securely delete %d expired message file(s).",
                failed_count,
            )
            print(
                f"  [!] Auto-Cleanup: {failed_count} old message file(s) "
                "could not be securely destroyed."
            )
            
    except Exception as e:
        print(f"  [!] Auto-Cleanup error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Paracci Desktop App")
    parser.add_argument("--port", type=int, help="Fixed port (default: random)")
    parser.add_argument("--user", type=str, choices=['x', 'y'], help="Quick profile select")
    parser.add_argument("--no-gui", action="store_true", help="Run only as web server")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode and inspector")
    parser.add_argument("open_file", nargs="?", help="Associated .paracci message file to open")
    args = parser.parse_args()
    launch_candidate = inspect_launch_file(args.open_file) if not args.no_gui else None

    clear_recent_docs() # Clear Windows traces on startup
    run_auto_cleanup(launch_candidate.path if launch_candidate is not None else None)  # Clean up old files
    
    # Start hourly cleanup loop in the background
    def cleanup_loop():
        import time
        while True:
            time.sleep(3600) # Check every hour
            run_auto_cleanup()
    
    cleaner_thread = threading.Thread(target=cleanup_loop, daemon=True)
    cleaner_thread.start()

    user_data_dir = None
    # Automatically set DATA_DIR if a user profile is selected
    if args.user:
        user_data_dir = f"data_{args.user}"
        # Default ports for X and Y (if not specified)
        if not args.port:
            args.port = 5000 if args.user == 'x' else 5001

    import werkzeug.serving
    _original_server_bind = werkzeug.serving.BaseWSGIServer.server_bind
    def _hardened_server_bind(self):
        self.allow_reuse_address = False
        if os.name == 'nt':
            import socket
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_EXCLUSIVEADDRUSE', -5), 1)
            except Exception:
                pass
        _original_server_bind(self)
    werkzeug.serving.BaseWSGIServer.server_bind = _hardened_server_bind

    class AppProxy:
        def __init__(self):
            self.app = None
        def __call__(self, environ, start_response):
            if self.app is None:
                raise RuntimeError("App is not initialized yet")
            return self.app(environ, start_response)
    
    app_proxy = AppProxy()
    
    loopback_host = "127.0.0.1"
    desired_port = args.port if args.port else 0
    server = make_server(loopback_host, desired_port, app_proxy, threaded=True)
    port = server.socket.getsockname()[1]

    _configure_preview_window_context(loopback_host, port)
    webview_token = getattr(webview, "token", None) if not args.no_gui else None
    using_webview_token = bool(webview_token)
    loopback_token = (
        webview_token if not args.no_gui else None
    ) or secrets.token_urlsafe(32)

    # App initialization
    import app as ag_app

    activation_state = {
        "window": None,
        "ready": False,
        "pending": [],
    }
    activation_state_lock = threading.Lock()

    def on_external_activation(raw_path):
        with activation_state_lock:
            if not activation_state["ready"] or activation_state["window"] is None:
                activation_state["pending"].append(raw_path)
                return
            main_window = activation_state["window"]
        _activate_main_window(main_window, raw_path, ag_app.db, loopback_host, port, loopback_token)

    activation_broker = None
    if not args.no_gui:
        install_macos_file_open_handler(on_external_activation)
        activation_path = str(launch_candidate.path) if launch_candidate is not None else None
        activation_broker, forwarded = FileActivationBroker.claim_or_forward(
            ag_app.DATA_DIR,
            activation_path,
            on_external_activation,
        )
        if forwarded:
            sys.exit(0)

    app = ag_app.create_app(
        loopback_auth_token=loopback_token,
        data_dir=user_data_dir,
        loopback_host=loopback_host,
        loopback_port=port,
        no_gui_mode=args.no_gui,
    )
    
    app_proxy.app = app

    from core.config import ParacciConfig
    _timeout_minutes = ParacciConfig().get("inactivity_timeout_minutes")
    _timeout_seconds = max(0, int(_timeout_minutes or 0)) * 60
    ag_app.init_inactivity_timer(_timeout_seconds)

    update_manager = None
    if not args.no_gui:
        from desktop.updater import UpdateManager

        update_manager = UpdateManager(distribution_mode=ag_app.DATA_MODE)
        app.extensions["paracci_updater"] = update_manager
    if not args.no_gui:
        with activation_state_lock:
            queued_before_start = activation_state["pending"]
            activation_state["pending"] = []
        for queued_path in queued_before_start:
            queued_candidate = inspect_launch_file(queued_path) if queued_path is not None else None
            if queued_candidate is not None:
                launch_candidate = queued_candidate
        initial_target = _file_activation_target(launch_candidate, ag_app.db)
    else:
        initial_target = "/"
    bootstrap_url = _bootstrap_url(loopback_host, port, loopback_token, initial_target)
    data_dir = os.environ.get('DATA_DIR', 'data (default)')

    print("\n  [o] Paracci Desktop")
    print("  -----------------------------")
    print(f"  Internal: http://{loopback_host}:{port}")
    print(f"  DATA_DIR: {data_dir}")
    
    if args.no_gui:
        import atexit
        atexit.register(ag_app.lock_device)
        print("  Mode: Server Only")
        print("  Authenticated entrypoint:")
        print(f"  {bootstrap_url}", flush=True)
        print("  Bare loopback URLs reject protected requests without bootstrap auth.")
        print("  Stop with: Ctrl+C\n")
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()
        try:
            while True:
                import time
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        _shutdown_desktop_runtime(server, server_thread, activation_broker, update_manager, None)
        sys.exit(0)
    else:
        print("  Mode: Desktop App")
        
        # Retain a stoppable loopback server so installer handoff can be clean.
        server_thread = threading.Thread(target=server.serve_forever)
        server_thread.daemon = True
        server_thread.start()

        # Main Window (WebView)
        pro_api = ProApi(loopback_token=loopback_token, update_manager=update_manager)
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
        update_manager.start_check()
        with activation_state_lock:
            activation_state["window"] = window

        def activate_when_loaded(*_args):
            with activation_state_lock:
                activation_state["ready"] = True
                pending = activation_state["pending"]
                activation_state["pending"] = []
            for pending_path in pending:
                _activate_main_window(window, pending_path, ag_app.db, loopback_host, port, loopback_token)

        try:
            if hasattr(window.events, 'loaded'):
                window.events.loaded += activate_when_loaded
            else:
                activate_when_loaded()
        except AttributeError as exc:
            logger.warning("Activation event binding error (attribute): %s", exc)
            activate_when_loaded()
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            logger.exception("Unexpected activation event binding error: %s", exc)
            activate_when_loaded()
        
        # ── Security Shield (Chromium Hardening) ───────────────
        navigation_guard_script = _build_main_navigation_guard_script(loopback_host, port)
        _install_navigation_guard_or_exit(window, navigation_guard_script)

        try:
            if hasattr(window.events, 'closed'):
                window.events.closed += _on_main_window_closed
        except AttributeError as exc:
            logger.warning("Main close event binding error (attribute): %s", exc)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            logger.exception("Unexpected main close event binding error: %s", exc)

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
                window.evaluate_js(
                    f"window.__PARACCI_NATIVE_TOKEN = {json.dumps(loopback_token)}; "
                    "window.dispatchEvent(new CustomEvent('paracci:loopback-token-ready'));"
                )
            except (RuntimeError, AttributeError) as exc:
                logger.warning("Loopback token injection error (expected): %s", exc)
            except (MemoryError, KeyboardInterrupt, SystemExit):
                raise
            except Exception as exc:
                logger.exception("Unexpected loopback token injection failure")

        try:
            if hasattr(window.events, 'loaded'):
                window.events.loaded += inject_fallback_loopback_token
        except AttributeError as exc:
            logger.warning("Token event binding error (attribute): %s", exc)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            logger.exception("Unexpected token event binding error: %s", exc)

        
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
                    except (ValueError, OSError) as exc:
                        logger.warning("Native file reference error (expected): %s", exc)
                        return
                    except (MemoryError, KeyboardInterrupt, SystemExit):
                        raise
                    except Exception as exc:
                        logger.exception("Unexpected native file reference error")
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
                        const target = '/session/import?native_file_id=' + encodeURIComponent(nativeRef.id);
                        if (window.ParacciSecurity && typeof window.ParacciSecurity.navigateAuthorized === 'function') {{
                            window.ParacciSecurity.navigateAuthorized(target);
                        }}
                    }}
                    """
                    try:
                        window.evaluate_js(js_code)
                    except (RuntimeError, AttributeError) as exc:
                        logger.warning("File drop JS injection error (expected): %s", exc)
                    except (MemoryError, KeyboardInterrupt, SystemExit):
                        raise
                    except Exception as exc:
                        logger.exception("Unexpected file drop JS injection error")

        # Bind events (Error-protected)
        try:
            if hasattr(window.events, 'files_dropped'):
                window.events.files_dropped += on_files_dropped
            elif hasattr(window.events, 'dropped'):
                window.events.dropped += on_files_dropped
            else:
                # If no drag-and-drop support, continue silently
                pass
        except AttributeError as exc:
            logger.warning("Event binding error (attribute): %s", exc)
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception as exc:
            logger.exception("Unexpected event binding error: %s", exc)

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
        
        _shutdown_desktop_runtime(
            server,
            server_thread,
            activation_broker,
            update_manager,
            pro_api.installer_to_launch,
        )
        print("\n  [o] Paracci closed. Cleaning up processes...")
