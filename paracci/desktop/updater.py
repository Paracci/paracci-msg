"""In-memory GitHub Release update checking and verified installer download."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import tempfile
import threading
import urllib.request
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

from packaging.version import InvalidVersion, Version

from app.build_info import APP_VERSION, SESSION_PROTOCOL_VERSION


LATEST_RELEASE_URL = "https://api.github.com/repos/Paracci/paracci-msg/releases/latest"
RECENT_RELEASES_URL = "https://api.github.com/repos/Paracci/paracci-msg/releases?per_page=10"
RELEASES_PAGE_URL = "https://github.com/Paracci/paracci-msg/releases"
CHECKSUM_FILENAME = "SHA256SUMS.txt"
REQUEST_TIMEOUT_SECONDS = 5.0
MAX_RELEASE_BYTES = 512 * 1024
MAX_RELEASE_HISTORY_BYTES = 2 * 1024 * 1024
MAX_CHECKSUM_BYTES = 128 * 1024
DOWNLOAD_CHUNK_SIZE = 64 * 1024
_PROTOCOL_MARKER_RE = re.compile(
    r"<!--\s*paracci-update:\s*(\{.*?\})\s*-->",
    re.IGNORECASE | re.DOTALL,
)
_STABLE_TAG_RE = re.compile(r"^v(\d+\.\d+\.\d+)$")
_CHECKSUM_RE = re.compile(r"^([0-9a-fA-F]{64})\s+[* ]?(.+?)\s*$")


class UpdateActionError(RuntimeError):
    """Raised when an update action is not allowed in the current state."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class _DownloadCancelled(Exception):
    pass


@dataclass(frozen=True)
class ReleaseAsset:
    name: str
    download_url: str
    size: int


@dataclass(frozen=True)
class ReleaseInfo:
    version: str
    release_notes: str
    published_at: str
    protocol_version: int | None
    protocol_warning: bool
    protocol_unknown: bool
    installer_asset: ReleaseAsset | None
    checksum_asset: ReleaseAsset | None


def is_newer_version(current: str, latest: str) -> bool:
    """Return whether a normalized release version is newer than the build."""
    try:
        return Version(latest) > Version(current)
    except InvalidVersion:
        return False


def extract_protocol_version(body: str) -> int | None:
    """Read the updater compatibility marker from untrusted release notes."""
    if not isinstance(body, str):
        return None
    match = _PROTOCOL_MARKER_RE.search(body)
    if not match:
        return None
    try:
        payload = json.loads(match.group(1))
    except (TypeError, ValueError):
        return None
    value = payload.get("protocol_version") if isinstance(payload, dict) else None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def expected_checksum(checksum_text: str, filename: str) -> str | None:
    """Return the SHA-256 listed for exactly one named release asset."""
    found: str | None = None
    for raw_line in checksum_text.lstrip("\ufeff").splitlines():
        match = _CHECKSUM_RE.match(raw_line)
        if not match or match.group(2) != filename:
            continue
        if found is not None:
            return None
        found = match.group(1).lower()
    return found


def _https_url(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    parsed = urlparse(value)
    if parsed.scheme != "https" or not parsed.netloc:
        return None
    return value


def _release_notes(body: str) -> str:
    return _PROTOCOL_MARKER_RE.sub("", body if isinstance(body, str) else "").strip()


class UpdateManager:
    """Own update state for a single running desktop process."""

    def __init__(
        self,
        *,
        current_version: str = APP_VERSION,
        protocol_version: int = SESSION_PROTOCOL_VERSION,
        platform_id: str = sys.platform,
        distribution_mode: str = "standard",
        urlopen: Callable[..., object] = urllib.request.urlopen,
        browser_open: Callable[[str], bool] = webbrowser.open,
        temp_root: Path | None = None,
    ) -> None:
        self.current_version = current_version
        self.protocol_version = protocol_version
        self.platform_id = platform_id
        self.distribution_mode = distribution_mode
        self._urlopen = urlopen
        self._browser_open = browser_open
        self._temp_root = Path(temp_root) if temp_root is not None else None
        self._lock = threading.RLock()
        self._cancel_event = threading.Event()
        self._worker: threading.Thread | None = None
        self._release: ReleaseInfo | None = None
        self._state = "no_update"
        self._visible = False
        self._action = "none"
        self._downloaded_bytes = 0
        self._size_bytes: int | None = None
        self._verification_status = ""
        self._error_code = ""
        self._temp_dir: Path | None = None
        self._verified_installer: Path | None = None
        self._handoff_installer: Path | None = None

    def start_check(self, *, user_initiated: bool = False) -> bool:
        """Start an update check without blocking the GUI thread."""
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return False
            if self._state in {"downloading", "verifying", "ready", "installing"}:
                return False
            self._state = "checking"
            self._visible = False
            self._error_code = ""
            self._worker = threading.Thread(
                target=self._check_worker,
                args=(user_initiated,),
                daemon=True,
                name="paracci-update-check",
            )
            self._worker.start()
            return True

    def check_now(self, *, user_initiated: bool = False) -> None:
        """Synchronous check entrypoint used by focused tests."""
        with self._lock:
            self._state = "checking"
            self._visible = False
            self._error_code = ""
        self._check_worker(user_initiated)

    def public_status(self) -> dict:
        """Expose UI-safe state only; remote URLs and local paths stay private."""
        with self._lock:
            release = self._release
            percent = None
            if self._size_bytes and self._downloaded_bytes >= 0:
                percent = min(100, int(self._downloaded_bytes * 100 / self._size_bytes))
            return {
                "state": self._state,
                "visible": self._visible,
                "current_version": self.current_version,
                "latest_version": release.version if release else "",
                "release_notes": release.release_notes if release else "",
                "published_at": release.published_at if release else "",
                "protocol_warning": release.protocol_warning if release else False,
                "protocol_unknown": release.protocol_unknown if release else False,
                "action": self._action,
                "size_bytes": self._size_bytes,
                "downloaded_bytes": self._downloaded_bytes,
                "progress_percent": percent,
                "verification_status": self._verification_status,
                "error_code": self._error_code,
            }

    def recent_releases(self) -> list[dict]:
        """Fetch recent stable GitHub releases for the updates page."""
        payload = json.loads(
            self._read_bounded_url(RECENT_RELEASES_URL, MAX_RELEASE_HISTORY_BYTES).decode("utf-8")
        )
        if not isinstance(payload, list):
            raise ValueError("invalid release history response")
        history = []
        for item in payload:
            if not isinstance(item, dict) or item.get("draft") is True or item.get("prerelease") is True:
                continue
            release = self._parse_release(item)
            if release is None:
                continue
            history.append(
                {
                    "version": release.version,
                    "published_at": release.published_at,
                    "release_notes": release.release_notes,
                }
            )
            if len(history) == 5:
                break
        return history

    def dismiss(self) -> dict:
        """Hide update state only for this application process."""
        cleanup_path = None
        with self._lock:
            self._cancel_event.set()
            self._state = "dismissed"
            self._visible = False
            if self._verified_installer is not None:
                cleanup_path = self._temp_dir
                self._verified_installer = None
                self._temp_dir = None
        self._remove_temp_dir(cleanup_path)
        return self.public_status()

    def begin_update(self, *, acknowledged_warning: bool = False) -> dict:
        """Start an explicit update action selected by the user."""
        with self._lock:
            release = self._release
            if release is None or self._state not in {"available", "failed", "cancelled"}:
                raise UpdateActionError("update_not_available")
            if release.protocol_warning and not acknowledged_warning:
                raise UpdateActionError("protocol_ack_required")
            action = self._action
            if action == "browser":
                self._state = "dismissed"
                self._visible = False
            elif action == "download":
                if self._worker is not None and self._worker.is_alive():
                    raise UpdateActionError("download_in_progress")
                self._cancel_event = threading.Event()
                self._state = "downloading"
                self._visible = True
                self._downloaded_bytes = 0
                self._size_bytes = release.installer_asset.size if release.installer_asset else None
                self._verification_status = ""
                self._error_code = ""
                self._worker = threading.Thread(
                    target=self._download_worker,
                    daemon=True,
                    name="paracci-update-download",
                )
                self._worker.start()
                return self.public_status()
            else:
                raise UpdateActionError("update_not_available")

        try:
            opened = bool(self._browser_open(RELEASES_PAGE_URL))
        except Exception:
            opened = False
        if not opened:
            with self._lock:
                self._state = "failed"
                self._visible = True
                self._error_code = "browser_open_failed"
        return self.public_status()

    def cancel_download(self) -> dict:
        """Cancel an active installer transfer and expose cancelled state."""
        with self._lock:
            if self._state not in {"downloading", "verifying"}:
                return self.public_status()
            self._cancel_event.set()
            self._state = "cancelled"
            self._visible = True
            self._verification_status = ""
            self._error_code = ""
        return self.public_status()

    def prepare_installer_launch(self) -> Path | None:
        """Consume a verified installer for the trusted native launch bridge."""
        with self._lock:
            if self._state != "ready" or self._verified_installer is None:
                return None
            if not self._verified_installer.is_file():
                self._state = "failed"
                self._error_code = "installer_missing"
                self._verification_status = ""
                return None
            self._handoff_installer = self._verified_installer
            self._verified_installer = None
            self._state = "installing"
            self._visible = True
            return self._handoff_installer

    def close(self, *, preserve_handoff: bool = False) -> None:
        """Cancel work and remove temporary content not handed to an installer."""
        with self._lock:
            self._cancel_event.set()
            worker = self._worker
        if worker is not None and worker.is_alive() and worker is not threading.current_thread():
            worker.join(timeout=1.0)
        cleanup_path = None
        with self._lock:
            if not preserve_handoff or self._handoff_installer is None:
                cleanup_path = self._temp_dir
                self._temp_dir = None
                self._verified_installer = None
                self._handoff_installer = None
        self._remove_temp_dir(cleanup_path)

    def _check_worker(self, user_initiated: bool = False) -> None:
        try:
            payload = json.loads(
                self._read_bounded_url(LATEST_RELEASE_URL, MAX_RELEASE_BYTES).decode("utf-8")
            )
            release = self._parse_release(payload)
            if release is None or not is_newer_version(self.current_version, release.version):
                self._hide_no_update()
                return
            action = self._select_action(release)
            with self._lock:
                self._release = release
                self._state = "available"
                self._visible = True
                self._action = action
                self._size_bytes = (
                    release.installer_asset.size if action == "download" and release.installer_asset else None
                )
                self._downloaded_bytes = 0
                self._verification_status = ""
                self._error_code = ""
        except Exception:
            if user_initiated:
                self._set_check_failed()
            else:
                self._hide_no_update()

    def _parse_release(self, payload: object) -> ReleaseInfo | None:
        if not isinstance(payload, dict):
            return None
        tag_name = payload.get("tag_name")
        tag_match = _STABLE_TAG_RE.match(tag_name) if isinstance(tag_name, str) else None
        if not tag_match:
            return None
        version = tag_match.group(1)
        body = payload.get("body") if isinstance(payload.get("body"), str) else ""
        published_at = payload.get("published_at") if isinstance(payload.get("published_at"), str) else ""
        protocol_version = extract_protocol_version(body)
        protocol_unknown = protocol_version is None
        protocol_warning = protocol_unknown or protocol_version != self.protocol_version
        assets = payload.get("assets") if isinstance(payload.get("assets"), list) else []
        installer_name = f"Paracci-Setup-v{version}.exe"
        return ReleaseInfo(
            version=version,
            release_notes=_release_notes(body),
            published_at=published_at,
            protocol_version=protocol_version,
            protocol_warning=protocol_warning,
            protocol_unknown=protocol_unknown,
            installer_asset=self._find_asset(assets, installer_name),
            checksum_asset=self._find_asset(assets, CHECKSUM_FILENAME),
        )

    def _find_asset(self, assets: list, expected_name: str) -> ReleaseAsset | None:
        matching = [asset for asset in assets if isinstance(asset, dict) and asset.get("name") == expected_name]
        if len(matching) != 1:
            return None
        item = matching[0]
        url = _https_url(item.get("browser_download_url"))
        size = item.get("size")
        if url is None or isinstance(size, bool) or not isinstance(size, int) or size <= 0:
            return None
        return ReleaseAsset(name=expected_name, download_url=url, size=size)

    def _select_action(self, release: ReleaseInfo) -> str:
        if self.platform_id != "win32" or self.distribution_mode != "standard":
            return "browser"
        if release.installer_asset is None or release.checksum_asset is None:
            return "browser"
        return "download"

    def _download_worker(self) -> None:
        temp_dir: Path | None = None
        try:
            with self._lock:
                release = self._release
            if release is None or release.installer_asset is None or release.checksum_asset is None:
                raise UpdateActionError("asset_missing")
            checksum_bytes = self._read_bounded_url(
                release.checksum_asset.download_url,
                MAX_CHECKSUM_BYTES,
            )
            checksum = expected_checksum(checksum_bytes.decode("utf-8-sig"), release.installer_asset.name)
            if checksum is None:
                raise UpdateActionError("checksum_missing")
            if self._cancel_event.is_set():
                raise _DownloadCancelled()

            temp_dir = Path(
                tempfile.mkdtemp(
                    prefix="paracci-update-",
                    dir=str(self._temp_root) if self._temp_root is not None else None,
                )
            )
            target = temp_dir / release.installer_asset.name
            digest = hashlib.sha256()
            downloaded = 0
            with self._open_url(release.installer_asset.download_url) as response, target.open("wb") as output:
                while True:
                    if self._cancel_event.is_set():
                        raise _DownloadCancelled()
                    chunk = response.read(DOWNLOAD_CHUNK_SIZE)
                    if not chunk:
                        break
                    if downloaded + len(chunk) > release.installer_asset.size:
                        raise UpdateActionError("size_mismatch")
                    output.write(chunk)
                    digest.update(chunk)
                    downloaded += len(chunk)
                    with self._lock:
                        self._downloaded_bytes = downloaded
            if downloaded != release.installer_asset.size:
                raise UpdateActionError("size_mismatch")
            with self._lock:
                self._state = "verifying"
                self._verification_status = "verifying"
            if self._cancel_event.is_set():
                raise _DownloadCancelled()
            if digest.hexdigest().lower() != checksum:
                raise UpdateActionError("checksum_failed")
            with self._lock:
                if self._cancel_event.is_set() or self._state == "dismissed":
                    raise _DownloadCancelled()
                self._temp_dir = temp_dir
                self._verified_installer = target
                self._state = "ready"
                self._visible = True
                self._verification_status = "verified"
                self._error_code = ""
        except _DownloadCancelled:
            self._remove_temp_dir(temp_dir)
            with self._lock:
                if self._state != "dismissed":
                    self._state = "cancelled"
                    self._visible = True
                    self._verification_status = ""
                    self._error_code = ""
        except UpdateActionError as exc:
            self._remove_temp_dir(temp_dir)
            with self._lock:
                self._state = "failed"
                self._visible = True
                self._verification_status = ""
                self._error_code = exc.code
        except Exception:
            self._remove_temp_dir(temp_dir)
            with self._lock:
                self._state = "failed"
                self._visible = True
                self._verification_status = ""
                self._error_code = "download_failed"

    def _read_bounded_url(self, url: str, limit: int) -> bytes:
        with self._open_url(url) as response:
            data = response.read(limit + 1)
        if len(data) > limit:
            raise ValueError("remote response too large")
        return data

    def _open_url(self, url: str):
        if _https_url(url) is None:
            raise ValueError("non-HTTPS updater URL")
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "Paracci-Updater",
            },
        )
        response = self._urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS)
        status = getattr(response, "status", 200)
        final_url = response.geturl() if hasattr(response, "geturl") else url
        if status != 200 or _https_url(final_url) is None:
            response.close()
            raise ValueError("invalid updater response")
        return response

    def _hide_no_update(self) -> None:
        with self._lock:
            self._release = None
            self._state = "no_update"
            self._visible = False
            self._action = "none"
            self._size_bytes = None
            self._downloaded_bytes = 0
            self._verification_status = ""
            self._error_code = ""

    def _set_check_failed(self) -> None:
        with self._lock:
            self._release = None
            self._state = "check_failed"
            self._visible = False
            self._action = "none"
            self._size_bytes = None
            self._downloaded_bytes = 0
            self._verification_status = ""
            self._error_code = "check_failed"

    @staticmethod
    def _remove_temp_dir(path: Path | None) -> None:
        if path is not None:
            shutil.rmtree(path, ignore_errors=True)
