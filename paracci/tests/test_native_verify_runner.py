import importlib.util
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
LIBOQS_VERSION = "0.15.0"
LIBOQS_EXPECTED_COMMIT = "97f6b86b1b6d109cfd43cf276ae39c2e776aed80"


class StrictEncodingStream:
    def __init__(self, encoding: str):
        self.encoding = encoding
        self._chunks: list[str] = []
        self.flushes = 0

    def write(self, text: str) -> int:
        text.encode(self.encoding, errors="strict")
        self._chunks.append(text)
        return len(text)

    def flush(self) -> None:
        self.flushes += 1

    def getvalue(self) -> str:
        return "".join(self._chunks)


def load_native_verify_module():
    module_name = "paracci_native_verify"
    spec = importlib.util.spec_from_file_location(
        module_name,
        REPO_ROOT / "tools" / "ci" / "native_verify.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _commands_for(profile_name: str, python_command: str = "python") -> list[tuple[str, ...]]:
    native_verify = load_native_verify_module()
    profile = native_verify.PROFILES[profile_name]
    return [step.command for step in native_verify.build_steps(profile, python_command)]


def _fake_which(*available_commands: str):
    available = set(available_commands)

    def fake_which(command: str) -> str | None:
        if command in available:
            return f"/toolchain/{command}"
        return None

    return fake_which


def test_windows_ci_profile_preserves_native_verification_gate_commands():
    commands = _commands_for("windows-ci")

    assert commands[:5] == [
        ("npm", "ci"),
        ("npm", "run", "build"),
        ("python", "-m", "pip", "install", "--upgrade", "pip"),
        ("python", "-m", "pip", "install", "--require-hashes", "-r", "requirements.lock"),
        ("python", "-m", "pip", "install", "--require-hashes", "-r", "requirements-dev.lock"),
    ]
    assert ("python", "-m", "pip_audit", "-r", "requirements.lock", "-r", "requirements-dev.lock") in commands
    assert (
        "python",
        "-m",
        "pytest",
        "paracci/tests",
        "-v",
        "--timeout=120",
        "--timeout-method=thread",
    ) in commands
    assert ("node", "--test", "paracci/tests/test_session_clipboard.mjs") in commands
    assert ("npx", "playwright", "install", "chromium") in commands
    assert ("node", "tools/ci/browser_console_smoke.mjs", "--python", "python") in commands
    assert ("python", "paracci/audits/guardian.py") in commands
    assert any(command[:3] == ("python", "-m", "py_compile") for command in commands)


def test_all_profiles_keep_guardian_audit_required_once():
    native_verify = load_native_verify_module()

    for profile_name, profile in native_verify.PROFILES.items():
        commands = [step.command for step in native_verify.build_steps(profile, "python")]
        assert commands.count(("python", "paracci/audits/guardian.py")) == 1, profile_name


def test_linux_profiles_keep_platform_specific_playwright_and_docker_setup():
    linux_ci_commands = _commands_for("linux-ci")
    linux_docker_commands = _commands_for("linux-docker")

    assert ("npx", "playwright", "install", "--with-deps", "chromium") in linux_ci_commands
    assert ("npx", "playwright", "install", "--with-deps", "chromium") in linux_docker_commands
    assert ("npm", "ci") not in linux_docker_commands
    assert ("npm", "run", "build") in linux_docker_commands
    assert ("python", "-m", "pip", "install", "--require-hashes", "-r", "requirements.lock") not in linux_docker_commands
    assert ("python", "-m", "pip_audit", "-r", "requirements.lock", "-r", "requirements-dev.lock") in linux_docker_commands


def test_windows_command_resolution_prefers_npm_cmd_launcher():
    native_verify = load_native_verify_module()

    assert native_verify.resolve_command(
        native_verify.PROFILES["windows-ci"],
        "npm",
        REPO_ROOT,
        which=_fake_which("npm", "npm.cmd"),
    ) == "npm.cmd"


def test_windows_command_resolution_prefers_npx_cmd_launcher():
    native_verify = load_native_verify_module()

    assert native_verify.resolve_command(
        native_verify.PROFILES["windows-ci"],
        "npx",
        REPO_ROOT,
        which=_fake_which("npx", "npx.cmd"),
    ) == "npx.cmd"


def test_non_windows_package_manager_resolution_keeps_command_names():
    native_verify = load_native_verify_module()
    which = _fake_which("npm", "npm.cmd", "npx", "npx.cmd")

    assert native_verify.resolve_command(
        native_verify.PROFILES["linux-ci"],
        "npm",
        REPO_ROOT,
        which=which,
    ) == "npm"
    assert native_verify.resolve_command(
        native_verify.PROFILES["linux-ci"],
        "npx",
        REPO_ROOT,
        which=which,
    ) == "npx"


def test_missing_required_commands_fail_clearly():
    native_verify = load_native_verify_module()

    def fake_which(command: str) -> str | None:
        if command == "node":
            return None
        return f"/usr/bin/{command}"

    with pytest.raises(native_verify.NativeVerifyError, match="Required command not found.*node"):
        native_verify.ensure_required_tools(
            native_verify.PROFILES["windows-ci"],
            "python",
            REPO_ROOT,
            which=fake_which,
        )


def test_missing_windows_package_manager_commands_fail_clearly():
    native_verify = load_native_verify_module()

    with pytest.raises(native_verify.NativeVerifyError, match="Required command not found.*npm, npx"):
        native_verify.ensure_required_tools(
            native_verify.PROFILES["windows-ci"],
            "python",
            REPO_ROOT,
            which=_fake_which("python", "node"),
        )


def test_strict_profiles_require_pinned_liboqs_environment():
    native_verify = load_native_verify_module()

    with pytest.raises(native_verify.NativeVerifyError, match="LIBOQS_VERSION"):
        native_verify.validate_liboqs_install(native_verify.PROFILES["windows-ci"], {})


def test_liboqs_marker_validation_accepts_expected_pin(tmp_path):
    native_verify = load_native_verify_module()
    install_root = tmp_path / "oqs"
    lib_dir = install_root / "lib"
    lib_dir.mkdir(parents=True)
    (lib_dir / "liboqs.so").write_bytes(b"oqs")
    (install_root / ".paracci-liboqs-source").write_text(
        "\n".join(
            [
                f"version={LIBOQS_VERSION}",
                f"expected_commit={LIBOQS_EXPECTED_COMMIT}",
                f"actual_commit={LIBOQS_EXPECTED_COMMIT}",
            ]
        ),
        encoding="ascii",
    )

    native_verify.validate_liboqs_install(
        native_verify.PROFILES["linux-ci"],
        {
            "LIBOQS_VERSION": LIBOQS_VERSION,
            "LIBOQS_EXPECTED_COMMIT": LIBOQS_EXPECTED_COMMIT,
            "OQS_INSTALL_PATH": str(install_root),
            "LIBOQS_LIB_DIR": str(lib_dir),
        },
    )


def test_redaction_removes_tokens_and_local_path_material(tmp_path):
    native_verify = load_native_verify_module()
    repo_root = tmp_path / "repo"
    temp_root = tmp_path / "paracci-native-temp"
    launch_value = "launch-" + "fixture-" + "abcdefghijklmnopqrstuvwxyz1234567890"
    csrf_value = "csrf-" + "fixture-" + "abcdefghijklmnopqrstuvwxyz1234567890"
    hidden_value = "not-" + "for-" + "logs"
    query_param = "to" + "ken"
    csrf_header = "x-csrf-" + "to" + "ken"
    hidden_field = "sec" + "ret"
    windows_path = "\\".join(["C:", "Users", "private-user", "Desktop", "paracci-msg", "trace.log"])
    linux_path = "/home/private-user/.cache/paracci-native/trace.log"
    input_text = "\n".join(
        [
            f"url=http://127.0.0.1:54321/__paracci_bootstrap?{query_param}={launch_value}&next=/",
            f"{csrf_header}: {csrf_value}",
            f"repo={repo_root}",
            f"temp={temp_root}",
            f"windows={windows_path}",
            f"linux={linux_path}",
            f"{hidden_field}='{hidden_value}'",
        ]
    )

    redacted = native_verify.redact_sensitive(input_text, repo_root, [temp_root])

    assert launch_value not in redacted
    assert csrf_value not in redacted
    assert str(repo_root) not in redacted
    assert str(temp_root) not in redacted
    assert windows_path not in redacted
    assert linux_path not in redacted
    assert hidden_value not in redacted
    assert "token=<redacted>" in redacted
    assert "<local-path>" in redacted


def test_safe_console_output_handles_cp1252_replacement_characters():
    native_verify = load_native_verify_module()
    stream = StrictEncodingStream("cp1252")

    native_verify._write_console("guardian output had replacement=\ufffd and snowman=\u2603", stream=stream, flush=True)

    output = stream.getvalue()
    assert "\ufffd" not in output
    assert "\u2603" not in output
    assert "replacement=?" in output
    assert "snowman=?" in output
    assert stream.flushes == 1


def test_safe_console_output_keeps_utf8_console_readable():
    native_verify = load_native_verify_module()
    stream = StrictEncodingStream("utf-8")
    text = "guardian output had replacement=\ufffd and snowman=\u2603"

    native_verify._write_console(text, stream=stream)

    assert stream.getvalue() == text + "\n"


def test_run_step_redacts_before_cp1252_safe_output(tmp_path, monkeypatch):
    native_verify = load_native_verify_module()
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    stream = StrictEncodingStream("cp1252")
    token_value = "launch-" + "fixture-" + "abcdefghijklmnopqrstuvwxyz1234567890"
    secret_value = "not-" + "for-" + "logs"
    windows_path = "\\".join(["C:", "Users", "private-user", "AppData", "Local", "Temp", "paracci", "trace.log"])

    class FakeProcess:
        stdout = iter(
            [
                "\n".join(
                    [
                        f"url=http://127.0.0.1:54321/__paracci_bootstrap?token={token_value}",
                        f"secret={secret_value}",
                        f"path={windows_path}",
                        "guardian replacement=\ufffd snowman=\u2603",
                    ]
                )
                + "\n"
            ]
        )

        def wait(self) -> int:
            return 0

    def fake_popen(*args, **kwargs):
        assert kwargs["text"] is True
        assert kwargs["errors"] == "replace"
        return FakeProcess()

    monkeypatch.setattr(native_verify.subprocess, "Popen", fake_popen)
    monkeypatch.setattr(native_verify, "resolve_command", lambda profile, command, root: command)
    monkeypatch.setattr(native_verify.sys, "stdout", stream)

    native_verify.run_step(
        native_verify.CommandStep("Run Guardian audit", ("python", "paracci/audits/guardian.py")),
        native_verify.PROFILES["windows-ci"],
        repo_root,
        {},
    )

    output = stream.getvalue()
    assert token_value not in output
    assert secret_value not in output
    assert windows_path not in output
    assert "token=<redacted>" in output
    assert "secret=<redacted>" in output
    assert "<local-path>" in output
    assert "guardian replacement=? snowman=?" in output
