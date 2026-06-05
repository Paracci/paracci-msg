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
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterable
from html.parser import HTMLParser
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SMOKE_PIN = "Correct-Horse-95175328"
LINUX_FALLBACK_FIELD = "allow_linux_passphrase_fallback"
TOKEN_FIELD_NAME = (
    r"(?:token|csrf|csrf[-_]token|browser[-_]token|bearer[-_]token|bootstrap[-_]token|"
    r"native[-_]save[-_]token|preview[-_]token|_paracci_token|_csrf_token|"
    r"paracci[-_]csrf[-_]token|paracci[-_]browser[-_]token|"
    r"x[-_]csrf[-_]token|x[-_]paracci[-_](?:token|native[-_]save))"
)


class SmokeFailure(RuntimeError):
    pass


class UnlockPageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.csrf: str | None = None
        self.offers_linux_fallback = False
        self._in_auth_form = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attributes = {name.lower(): value for name, value in attrs}
        tag = tag.lower()
        if tag == "form" and attributes.get("id") == "authForm":
            self._in_auth_form = True
        if (
            tag == "meta"
            and attributes.get("name") == "paracci-csrf-token"
            and attributes.get("content")
        ):
            self.csrf = attributes["content"]
        if (
            tag == "input"
            and self._in_auth_form
            and attributes.get("name") == LINUX_FALLBACK_FIELD
        ):
            self.offers_linux_fallback = True

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "form" and self._in_auth_form:
            self._in_auth_form = False


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


def parse_unlock_page(html: str) -> tuple[str | None, bool]:
    parser = UnlockPageParser()
    parser.feed(html)
    parser.close()
    return parser.csrf, parser.offers_linux_fallback


def unlock_form(platform: str, offers_linux_fallback: bool) -> dict[str, str]:
    form = {"pin": SMOKE_PIN}
    if platform == "linux" and offers_linux_fallback:
        form[LINUX_FALLBACK_FIELD] = "1"
    return form


def _replace_root(text: str, root: Path | str) -> str:
    root_text = str(root)
    if not root_text or root_text in {"/", "\\"}:
        return text
    variants = {root_text, root_text.replace("\\", "/"), root_text.replace("/", "\\")}
    for variant in sorted(variants, key=len, reverse=True):
        if variant:
            text = re.sub(re.escape(variant), "<local-path>", text, flags=re.IGNORECASE)
    return text


def redact_sensitive(
    value: object,
    *,
    known_secrets: Iterable[str] = (),
    roots: Iterable[Path | str] = (),
) -> str:
    text = str(value)
    secrets = [SMOKE_PIN, *(secret for secret in known_secrets if secret)]
    for secret in sorted(set(secrets), key=len, reverse=True):
        text = text.replace(secret, "<redacted>")

    redaction_roots = [REPO_ROOT, Path.home(), Path(tempfile.gettempdir()), *roots]
    for root in sorted(redaction_roots, key=lambda item: len(str(item)), reverse=True):
        text = _replace_root(text, root)

    replacements = (
        (
            re.compile(
                rf"(<meta\b(?=[^>]*\bname\s*=\s*[\"']{TOKEN_FIELD_NAME}[\"'])"
                rf"[^>]*\bcontent\s*=\s*[\"'])[^\"']*([\"'])",
                re.I,
            ),
            r"\1<redacted>\2",
        ),
        (
            re.compile(
                rf"(<input\b(?=[^>]*\bname\s*=\s*[\"']{TOKEN_FIELD_NAME}[\"'])"
                rf"[^>]*\bvalue\s*=\s*[\"'])[^\"']*([\"'])",
                re.I,
            ),
            r"\1<redacted>\2",
        ),
        (
            re.compile(rf"([?&]{TOKEN_FIELD_NAME}=)[^&\s\"'<>]+", re.I),
            r"\1<redacted>",
        ),
        (
            re.compile(rf"([\"']{TOKEN_FIELD_NAME}[\"']\s*:\s*[\"'])[^\"']+([\"'])", re.I),
            r"\1<redacted>\2",
        ),
        (
            re.compile(rf"(\b{TOKEN_FIELD_NAME}\b\s*[:=]\s*[\"']?)[^&,\s\"'}}<>]+", re.I),
            r"\1<redacted>",
        ),
        (
            re.compile(
                r"((?:authorization|proxy-authorization|cookie|set-cookie|"
                r"x-csrf-token|x-paracci-token|x-paracci-native-save)\s*[:=]\s*)[^\r\n]+",
                re.I,
            ),
            r"\1<redacted>",
        ),
        (
            re.compile(r"(\bBearer\s+)[A-Za-z0-9._~+/=-]+", re.I),
            r"\1<redacted>",
        ),
        (
            re.compile(r"(/preview/)[A-Za-z0-9_-]{16,}", re.I),
            r"\1<redacted>",
        ),
        (
            re.compile(
                r"(?im)^(\s*(?:secret|passphrase|password|api[_-]?key|private[_-]?key)"
                r"\s*[:=]\s*)[^\r\n]+"
            ),
            r"\1<redacted>",
        ),
        (
            re.compile(r"(?i)(\bDATA_DIR\s*[:=]\s*)[^\r\n]+"),
            r"\1<local-path>",
        ),
        (
            re.compile(r"(?i)\b[A-Za-z]:[\\/]+[^\\/\s\"'<>|]+(?:[\\/][^\\\r\n\"'<>|]+)*"),
            "<local-path>",
        ),
        (
            re.compile(r"(?i)\\\\+[^\\\s\"'<>|]+\\+[^\\\s\"'<>|]+(?:\\+[^\\\r\n\"'<>|]+)*"),
            "<local-path>",
        ),
        (
            re.compile(
                r"(?i)(?<![A-Za-z0-9_./-])/(?:Users|home|root|tmp|var/tmp|private/var/folders|"
                r"var/folders|var/lib|var/cache|var/log|workspace|mnt|opt|usr|etc|srv|run|"
                r"lib|bin|sbin|Applications)/[^\s\"'<>]+"
            ),
            "<local-path>",
        ),
    )
    for pattern, replacement in replacements:
        text = pattern.sub(replacement, text)
    return text


def format_failure_message(
    message: object,
    output: object,
    *,
    known_secrets: Iterable[str] = (),
    roots: Iterable[Path | str] = (),
) -> str:
    known_secrets = tuple(known_secrets)
    roots = tuple(roots)
    safe_message = redact_sensitive(message, known_secrets=known_secrets, roots=roots)
    safe_output = redact_sensitive(output, known_secrets=known_secrets, roots=roots)
    if not safe_output:
        return safe_message
    return f"{safe_message}\n--- packaged app output ---\n{safe_output[-4000:]}"


def response_failure_message(
    stage: str,
    final_url: str,
    body: str,
    *,
    known_secrets: Iterable[str] = (),
    roots: Iterable[Path | str] = (),
) -> str:
    known_secrets = tuple(known_secrets)
    roots = tuple(roots)
    safe_stage = redact_sensitive(stage, known_secrets=known_secrets, roots=roots)
    safe_url = redact_sensitive(final_url, known_secrets=known_secrets, roots=roots)
    safe_body = redact_sensitive(body, known_secrets=known_secrets, roots=roots)
    snippet = re.sub(r"\s+", " ", safe_body).strip()[:1000] or "<empty>"
    return f"{safe_stage} Final URL: {safe_url}. Body: {snippet}"


def _response_text(response) -> str:
    return response.read().decode("utf-8", "replace")


def _response_path(response) -> str:
    return urllib.parse.urlparse(response.geturl()).path


def complete_authenticated_flow(
    platform: str,
    request: Callable[..., object],
    fail: Callable[[str], None],
    *,
    known_secrets: list[str],
    roots: Iterable[Path | str] = (),
) -> str:
    roots = tuple(roots)
    unlock_response = request("/unlock")
    unlock_html = _response_text(unlock_response)
    csrf, offers_linux_fallback = parse_unlock_page(unlock_html)
    if not csrf:
        fail(
            response_failure_message(
                "Could not extract CSRF token from packaged app.",
                unlock_response.geturl(),
                unlock_html,
                known_secrets=known_secrets,
                roots=roots,
            )
        )
        raise AssertionError("Failure callback returned unexpectedly.")
    known_secrets.append(csrf)

    setup_response = request("/unlock", unlock_form(platform, offers_linux_fallback), csrf)
    setup_body = _response_text(setup_response)
    if _response_path(setup_response) != "/unlock/2fa/setup":
        fail(
            response_failure_message(
                "Device setup did not reach optional 2FA setup.",
                setup_response.geturl(),
                setup_body,
                known_secrets=known_secrets,
                roots=roots,
            )
        )
        raise AssertionError("Failure callback returned unexpectedly.")

    skip_response = request("/unlock/2fa/setup", {"action": "skip"}, csrf)
    skip_body = _response_text(skip_response)
    if _response_path(skip_response) != "/":
        fail(
            response_failure_message(
                "Optional 2FA setup did not complete.",
                skip_response.geturl(),
                skip_body,
                known_secrets=known_secrets,
                roots=roots,
            )
        )
        raise AssertionError("Failure callback returned unexpectedly.")

    session_response = request(
        "/session/new",
        {
            "label": "Release smoke",
            "session_ttl": "0",
        },
        csrf,
    )
    session_body = _response_text(session_response)
    final_url = session_response.geturl()
    session_path = _response_path(session_response)
    session_id = session_path.removeprefix("/session/")
    if not re.fullmatch(r"[0-9a-f]{32}", session_id):
        fail(
            response_failure_message(
                "ML-KEM session creation did not complete.",
                final_url,
                session_body,
                known_secrets=known_secrets,
                roots=roots,
            )
        )
        raise AssertionError("Failure callback returned unexpectedly.")
    return final_url


def smoke_packaged_runtime(executable: Path, platform: str, timeout_seconds: int = 90) -> None:
    platform = normalize_platform(platform)
    base_roots = [REPO_ROOT, executable, executable.parent]
    if not executable.is_file():
        raise SmokeFailure(
            redact_sensitive(f"Packaged executable not found: {executable}", roots=base_roots)
        )

    port = reserve_loopback_port()
    origin = f"http://127.0.0.1:{port}"
    token: str | None = None
    known_secrets = [SMOKE_PIN]
    data_root = Path(tempfile.mkdtemp(prefix="paracci-smoke-")).resolve()
    roots = [*base_roots, data_root, data_root / "data"]
    env = scrub_runtime_env(data_root)
    proc: subprocess.Popen[str] | None = None
    output_thread: threading.Thread | None = None
    output_lines: list[str] = []
    output_events: queue.Queue[str] = queue.Queue()

    def collect_output() -> None:
        if proc and proc.stdout:
            for line in proc.stdout:
                output_lines.append(line)
                output_events.put(line)

    def stop_process() -> None:
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=10)

    def fail(message: str) -> None:
        stop_process()
        if output_thread is not None:
            output_thread.join(timeout=1)
        raise SmokeFailure(
            format_failure_message(
                message,
                "".join(output_lines),
                known_secrets=known_secrets,
                roots=roots,
            )
        )

    try:
        proc = subprocess.Popen(
            [str(executable), "--no-gui", "--port", str(port)],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
        )
        output_thread = threading.Thread(target=collect_output, daemon=True)
        output_thread.start()

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
            if candidate:
                known_secrets.append(candidate)
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
            try:
                return opener.open(req, timeout=45)
            except urllib.error.HTTPError as exc:
                body = exc.read().decode("utf-8", "replace")
                fail(
                    response_failure_message(
                        f"HTTP request for {path} failed with status {exc.code}. Headers: {exc.headers}",
                        exc.geturl(),
                        body,
                        known_secrets=known_secrets,
                        roots=roots,
                    )
                )
            except urllib.error.URLError as exc:
                fail(f"HTTP request for {path} failed: {exc.reason}")
            raise AssertionError("Failure callback returned unexpectedly.")

        request(f"/__paracci_bootstrap?token={urllib.parse.quote(token)}&next=/").read()
        complete_authenticated_flow(
            platform,
            request,
            fail,
            known_secrets=known_secrets,
            roots=roots,
        )
        print("Packaged ML-KEM smoke test passed.")
    except SmokeFailure as exc:
        raise SmokeFailure(
            redact_sensitive(exc, known_secrets=known_secrets, roots=roots)
        ) from None
    except Exception as exc:
        fail(f"Smoke test failed: {exc.__class__.__name__}: {exc}")
    finally:
        stop_process()
        if output_thread is not None:
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
    repo_root = args.repo_root.resolve()
    executable: Path | None = None

    try:
        platform = normalize_platform(args.platform)
        executable = (args.executable or default_executable(repo_root, platform)).resolve()
        smoke_packaged_runtime(executable, platform, args.timeout_seconds)
        return 0
    except Exception as exc:
        roots = [repo_root]
        if executable is not None:
            roots.extend([executable, executable.parent])
        message = redact_sensitive(
            f"{exc.__class__.__name__}: {exc}",
            roots=roots,
        )
        print(f"[ERROR] {message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
