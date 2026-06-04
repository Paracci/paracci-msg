from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence


REPO_ROOT = Path(__file__).resolve().parents[2]
LIBOQS_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PY_COMPILE_TARGETS = (
    "run.py",
    "paracci/desktop/services.py",
    "paracci/ui_api/facade.py",
    "paracci/bridge/worker.py",
)
WINDOWS_COMMAND_LAUNCHERS = {
    "npm": "npm.cmd",
    "npx": "npx.cmd",
}


class NativeVerifyError(RuntimeError):
    pass


@dataclass(frozen=True)
class Profile:
    name: str
    platform: str
    install_dependencies: bool
    build_frontend: bool
    require_liboqs_pin: bool
    playwright_with_deps: bool
    ci_environment: bool


@dataclass(frozen=True)
class CommandStep:
    name: str
    command: tuple[str, ...]
    env: dict[str, str] | None = None


PROFILES: dict[str, Profile] = {
    "windows-ci": Profile(
        name="windows-ci",
        platform="windows",
        install_dependencies=True,
        build_frontend=True,
        require_liboqs_pin=True,
        playwright_with_deps=False,
        ci_environment=True,
    ),
    "linux-ci": Profile(
        name="linux-ci",
        platform="linux",
        install_dependencies=True,
        build_frontend=True,
        require_liboqs_pin=True,
        playwright_with_deps=True,
        ci_environment=True,
    ),
    "windows-local": Profile(
        name="windows-local",
        platform="windows",
        install_dependencies=True,
        build_frontend=True,
        require_liboqs_pin=True,
        playwright_with_deps=False,
        ci_environment=True,
    ),
    "linux-docker": Profile(
        name="linux-docker",
        platform="linux",
        install_dependencies=False,
        build_frontend=True,
        require_liboqs_pin=True,
        playwright_with_deps=True,
        ci_environment=True,
    ),
}


def default_python_command(profile: Profile, repo_root: Path) -> str:
    if profile.name == "windows-local":
        local_venv_python = repo_root / ".venv" / "Scripts" / "python.exe"
        if local_venv_python.is_file():
            return str(Path(".venv") / "Scripts" / "python.exe")
    return "python"


def build_steps(profile: Profile, python_command: str) -> list[CommandStep]:
    steps: list[CommandStep] = []

    if profile.install_dependencies:
        steps.extend(
            [
                CommandStep("Install Node dependencies", ("npm", "ci")),
            ]
        )

    if profile.build_frontend:
        steps.append(CommandStep("Build frontend assets", ("npm", "run", "build")))

    if profile.install_dependencies:
        steps.extend(
            [
                CommandStep("Upgrade pip", (python_command, "-m", "pip", "install", "--upgrade", "pip")),
                CommandStep(
                    "Install locked Python runtime dependencies",
                    (python_command, "-m", "pip", "install", "--require-hashes", "-r", "requirements.lock"),
                ),
                CommandStep(
                    "Install locked Python development dependencies",
                    (python_command, "-m", "pip", "install", "--require-hashes", "-r", "requirements-dev.lock"),
                ),
            ]
        )

    playwright_command = ["npx", "playwright", "install"]
    if profile.playwright_with_deps:
        playwright_command.append("--with-deps")
    playwright_command.append("chromium")

    steps.extend(
        [
            CommandStep(
                "Audit locked Python dependencies",
                (python_command, "-m", "pip_audit", "-r", "requirements.lock", "-r", "requirements-dev.lock"),
            ),
            CommandStep(
                "Run Python test suite",
                (
                    python_command,
                    "-m",
                    "pytest",
                    "paracci/tests",
                    "-v",
                    "--timeout=120",
                    "--timeout-method=thread",
                ),
            ),
            CommandStep("Run clipboard JavaScript tests", ("node", "--test", "paracci/tests/test_session_clipboard.mjs")),
            CommandStep("Install Playwright Chromium", tuple(playwright_command)),
            CommandStep(
                "Run Python runtime browser console smoke",
                ("node", "tools/ci/browser_console_smoke.mjs", "--python", python_command),
            ),
            CommandStep("Run Guardian audit", (python_command, "paracci/audits/guardian.py")),
            CommandStep(
                "Check native launcher compiles",
                (python_command, "-m", "py_compile", *PY_COMPILE_TARGETS),
            ),
        ]
    )
    return steps


def _resolve_command_token(
    profile: Profile,
    command: str,
    repo_root: Path,
    which: Callable[[str], str | None],
) -> str | None:
    command_path = Path(command)
    if command_path.is_absolute():
        return command if command_path.is_file() else None
    if len(command_path.parts) > 1:
        return command if (repo_root / command_path).is_file() else None

    candidates = (command,)
    if profile.platform == "windows" and command in WINDOWS_COMMAND_LAUNCHERS:
        candidates = (WINDOWS_COMMAND_LAUNCHERS[command], command)

    for candidate in candidates:
        if which(candidate) is not None:
            return candidate
    return None


def resolve_command(
    profile: Profile,
    command: str,
    repo_root: Path,
    which: Callable[[str], str | None] = shutil.which,
) -> str:
    resolved = _resolve_command_token(profile, command, repo_root, which)
    if resolved is None:
        raise NativeVerifyError(f"Required command not found for {profile.name}: {command}")
    return resolved


def ensure_required_tools(
    profile: Profile,
    python_command: str,
    repo_root: Path,
    which: Callable[[str], str | None] = shutil.which,
) -> None:
    required = [python_command, "node", "npm", "npx"]
    missing = [
        command
        for command in required
        if _resolve_command_token(profile, command, repo_root, which) is None
    ]
    if missing:
        names = ", ".join(missing)
        raise NativeVerifyError(f"Required command not found for {profile.name}: {names}")


def _parse_marker(marker: Path) -> dict[str, str]:
    try:
        lines = marker.read_text(encoding="ascii").splitlines()
    except OSError as exc:
        raise NativeVerifyError("liboqs source marker was not found under OQS_INSTALL_PATH.") from exc

    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value
    return values


def validate_liboqs_install(profile: Profile, env: Mapping[str, str]) -> None:
    if not profile.require_liboqs_pin:
        return

    required_env = ("LIBOQS_VERSION", "LIBOQS_EXPECTED_COMMIT", "OQS_INSTALL_PATH", "LIBOQS_LIB_DIR")
    missing_env = [name for name in required_env if not env.get(name)]
    if missing_env:
        raise NativeVerifyError(
            "Pinned liboqs validation requires environment variables: "
            + ", ".join(missing_env)
        )

    version = env["LIBOQS_VERSION"]
    expected_commit = env["LIBOQS_EXPECTED_COMMIT"]
    if not LIBOQS_COMMIT_RE.fullmatch(expected_commit):
        raise NativeVerifyError("LIBOQS_EXPECTED_COMMIT must be a 40-character lowercase hex SHA.")

    install_path = Path(env["OQS_INSTALL_PATH"])
    lib_dir = Path(env["LIBOQS_LIB_DIR"])
    marker_values = _parse_marker(install_path / ".paracci-liboqs-source")

    if (
        marker_values.get("version") != version
        or marker_values.get("expected_commit") != expected_commit
        or marker_values.get("actual_commit") != expected_commit
    ):
        raise NativeVerifyError("liboqs source marker does not match the expected immutable source pin.")

    if profile.platform == "windows":
        candidates = ("oqs.dll", "liboqs.dll")
    elif profile.platform == "macos":
        candidates = ("liboqs.dylib",)
    else:
        candidates = ("liboqs.so",)

    if not any((lib_dir / name).is_file() for name in candidates):
        raise NativeVerifyError("liboqs shared library was not found under LIBOQS_LIB_DIR.")


def redact_sensitive(value: object, repo_root: Path = REPO_ROOT, extra_roots: Sequence[Path | str] = ()) -> str:
    text = str(value)

    redaction_roots = [
        repo_root,
        Path.home(),
        Path(tempfile.gettempdir()),
        *(Path(root) for root in extra_roots if root),
    ]
    for root in redaction_roots:
        root_text = str(root)
        if root_text:
            text = text.replace(root_text, "<local-path>")
            text = text.replace(root_text.replace("\\", "/"), "<local-path>")

    replacements = (
        (
            re.compile(r"([?&](?:token|csrf|csrf_token|preview_token|native_save_token|_paracci_token|_csrf_token)=)[^&\s\"'<>]+", re.I),
            r"\1<redacted>",
        ),
        (
            re.compile(r"((?:authorization|cookie|set-cookie|x-csrf-token|x-paracci-token)\s*[:=]\s*)[^\r\n]+", re.I),
            r"\1<redacted>",
        ),
        (
            re.compile(r"(?im)^(\s*(?:secret|token|passphrase|password|api[_-]?key)\s*[:=]\s*)[^\r\n]+"),
            r"\1<redacted>",
        ),
        (
            re.compile(r"(?i)\b[A-Za-z]:[\\/]+Users[\\/]+[^\\/\s]+(?:[\\/][^\s\"'<>]*)?"),
            "<local-path>",
        ),
        (
            re.compile(r"(?i)(?<![A-Za-z0-9_./-])/(?:Users|home)/[^/\s]+(?:/[^\s\"'<>]*)?"),
            "<local-path>",
        ),
        (
            re.compile(r"(?i)(?<![A-Za-z0-9_./-])/(?:tmp|var/folders)/[^\s\"'<>]+"),
            "<local-path>",
        ),
    )
    for pattern, replacement in replacements:
        text = pattern.sub(replacement, text)
    return text


def run_step(step: CommandStep, profile: Profile, repo_root: Path, base_env: Mapping[str, str]) -> None:
    print(f"\n==> {step.name}", flush=True)
    env = os.environ.copy()
    env.update(base_env)
    if profile.ci_environment:
        env["CI"] = "true"
    env.setdefault("QT_QPA_PLATFORM", "offscreen")
    if step.env:
        env.update(step.env)

    launch_command = (resolve_command(profile, step.command[0], repo_root), *step.command[1:])
    process = subprocess.Popen(
        launch_command,
        cwd=repo_root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
    )
    assert process.stdout is not None
    for line in process.stdout:
        redacted = redact_sensitive(line, repo_root)
        print(redacted, end="", flush=True)
    returncode = process.wait()
    if returncode != 0:
        command = " ".join(redact_sensitive(part, repo_root) for part in launch_command)
        raise NativeVerifyError(
            f"{step.name} failed with exit code {returncode}: {command}"
        )


def run_profile(profile: Profile, python_command: str, repo_root: Path, env: Mapping[str, str]) -> None:
    ensure_required_tools(profile, python_command, repo_root)
    validate_liboqs_install(profile, env)
    for step in build_steps(profile, python_command):
        run_step(step, profile, repo_root, env)


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run Paracci Native Verification parity checks.")
    parser.add_argument("--profile", required=True, choices=sorted(PROFILES))
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    parser.add_argument(
        "--python",
        dest="python_command",
        help="Python command or executable path to use for Python validation commands.",
    )
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = args.repo_root.resolve()
    profile = PROFILES[args.profile]
    python_command = args.python_command or default_python_command(profile, repo_root)

    try:
        print(f"Native Verification profile: {profile.name}")
        print(f"Python command: {redact_sensitive(python_command, repo_root)}")
        run_profile(profile, python_command, repo_root, os.environ)
    except NativeVerifyError as exc:
        print(f"[ERROR] {redact_sensitive(exc, repo_root)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
