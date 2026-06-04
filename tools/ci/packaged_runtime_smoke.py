from __future__ import annotations

import argparse
import http.cookiejar
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SMOKE_PIN = "Correct-Horse-95175328"


class SmokeFailure(RuntimeError):
    pass


def normalize_platform(platform: str) -> str:
    normalized = platform.lower()
    if normalized in {"windows", "win32", "win"}:
        return "windows"
    if normalized in {"linux", "ubuntu"}:
        return "linux"
    if normalized in {"macos", "darwin", "mac"}:
        return "macos"
    raise SmokeFailure(f"Unsupported release smoke platform: {platform!r}")


def default_executable(repo_root: Path, platform: str) -> Path:
    if platform == "windows":
        return repo_root / "builds" / "windows" / "Paracci" / "Paracci.exe"
    if platform == "macos":
        app_executable = (
            repo_root
            / "builds"
            / "macos"
            / "Paracci.app"
            / "Contents"
            / "MacOS"
            / "Paracci"
        )
        return app_executable if app_executable.exists() else repo_root / "builds" / "macos" / "Paracci"
    return repo_root / "builds" / "linux" / "Paracci" / "Paracci"


def reserve_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.bind(("127.0.0.1", 0))
        return int(probe.getsockname()[1])


def scrub_runtime_env(data_root: Path) -> dict[str, str]:
    env = os.environ.copy()
    env.pop("PARACCI_LOOPBACK_TOKEN", None)
    for name in (
        "OQS_INSTALL_PATH",
        "LIBOQS_LIB_DIR",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
    ):
        env.pop(name, None)
    env["PATH"] = os.pathsep.join(
        part
        for part in env.get("PATH", "").split(os.pathsep)
        if "_oqs" not in part.lower() and "liboqs" not in part.lower()
    )
    env["DATA_DIR"] = str(data_root / "data")
    env["PYOQS_VERSION"] = "paracci-smoke-no-autoinstall"
    env["QT_QPA_PLATFORM"] = "offscreen"
    return env


def smoke_packaged_runtime(executable: Path, timeout_seconds: int = 90) -> None:
    if not executable.is_file():
        raise SmokeFailure(f"Packaged executable not found: {executable}")

    port = reserve_loopback_port()
    origin = f"http://127.0.0.1:{port}"
    token: str | None = None
    data_root = Path(tempfile.mkdtemp(prefix="paracci-smoke-")).resolve()
    env = scrub_runtime_env(data_root)

    proc = subprocess.Popen(
        [str(executable), "--no-gui", "--port", str(port)],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )

    output_lines: list[str] = []
    output_events: queue.Queue[str] = queue.Queue()

    def collect_output() -> None:
        if proc.stdout:
            for line in proc.stdout:
                output_lines.append(line)
                output_events.put(line)

    output_thread = threading.Thread(target=collect_output, daemon=True)
    output_thread.start()

    def stop_process() -> None:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)

    def redact(text: str) -> str:
        redacted = re.sub(r"([?&]token=)[^&\s]+", r"\1<redacted>", text)
        return redacted.replace(token, "<redacted>") if token else redacted

    def output_tail() -> str:
        return redact("".join(output_lines)[-4000:])

    def fail(message: str) -> None:
        stop_process()
        output_thread.join(timeout=1)
        raise SmokeFailure(f"{message}\n--- packaged app output ---\n{output_tail()}")

    try:
        deadline = time.time() + timeout_seconds
        while token is None and time.time() < deadline:
            if proc.poll() is not None:
                fail(f"Packaged app exited early with code {proc.returncode}")
            try:
                line = output_events.get(timeout=0.25)
            except queue.Empty:
                continue
            marker = "http://127.0.0.1:"
            if marker not in line or "/__paracci_bootstrap?" not in line:
                continue
            entrypoint = urllib.parse.urlparse(line.strip())
            candidate = urllib.parse.parse_qs(entrypoint.query).get("token", [""])[0]
            if (
                entrypoint.scheme != "http"
                or entrypoint.hostname != "127.0.0.1"
                or entrypoint.port != port
                or entrypoint.path != "/__paracci_bootstrap"
                or not candidate
            ):
                fail("Packaged app printed an invalid authenticated entrypoint")
            token = candidate
        if token is None:
            fail("Timed out waiting for packaged app authenticated entrypoint")

        while time.time() < deadline:
            if proc.poll() is not None:
                fail(f"Packaged app exited early with code {proc.returncode}")
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    break
            except OSError:
                time.sleep(1)
        else:
            fail("Timed out waiting for packaged app to listen")

        jar = http.cookiejar.CookieJar()
        opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))

        def request(path: str, form: dict[str, str] | None = None, csrf: str | None = None):
            headers = {
                "Host": f"127.0.0.1:{port}",
                "Origin": origin,
                "X-Paracci-Token": token,
            }
            data = None
            if form is not None:
                data = urllib.parse.urlencode(form).encode("utf-8")
                headers["Content-Type"] = "application/x-www-form-urlencoded"
                if csrf:
                    headers["X-CSRF-Token"] = csrf
            req = urllib.request.Request(origin + path, data=data, headers=headers)
            return opener.open(req, timeout=45)

        response = request(f"/__paracci_bootstrap?token={urllib.parse.quote(token)}&next=/")
        html = response.read().decode("utf-8", "replace")
        csrf_match = re.search(r'name="paracci-csrf-token"\s+content="([^"]+)"', html)
        if not csrf_match:
            response = request("/unlock")
            html = response.read().decode("utf-8", "replace")
            csrf_match = re.search(r'name="paracci-csrf-token"\s+content="([^"]+)"', html)
        if not csrf_match:
            fail("Could not extract CSRF token from packaged app")

        csrf = csrf_match.group(1)
        request("/unlock", {"pin": SMOKE_PIN}, csrf).read()
        request("/unlock/2fa/setup", {"action": "skip"}, csrf).read()
        response = request(
            "/session/new",
            {
                "label": "Release smoke",
                "session_ttl": "0",
            },
            csrf,
        )
        body = response.read().decode("utf-8", "replace")
        final_url = response.geturl()
        if "/session/" not in final_url:
            snippet = re.sub(r"\s+", " ", body)[:1000]
            fail(
                "ML-KEM session creation did not complete. "
                f"Final URL: {final_url}. Body: {snippet}"
            )

        print(f"Packaged ML-KEM smoke test passed: {final_url}")
    except SmokeFailure:
        raise
    except Exception as exc:
        fail(f"Smoke test failed: {exc}")
    finally:
        stop_process()
        output_thread.join(timeout=1)
        shutil.rmtree(data_root, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run Paracci packaged runtime smoke validation.")
    parser.add_argument(
        "--platform",
        default=os.environ.get("RUNNER_OS") or sys.platform,
        help="Target platform: windows, linux, or macos. Defaults to RUNNER_OS/sys.platform.",
    )
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repository root containing builds/<platform>/ outputs.",
    )
    parser.add_argument(
        "--executable",
        type=Path,
        help="Override packaged executable path.",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=90,
        help="Maximum time to wait for startup and session creation.",
    )
    args = parser.parse_args(argv)

    try:
        platform = normalize_platform(args.platform)
        executable = args.executable or default_executable(args.repo_root.resolve(), platform)
        smoke_packaged_runtime(executable.resolve(), args.timeout_seconds)
        return 0
    except SmokeFailure as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
