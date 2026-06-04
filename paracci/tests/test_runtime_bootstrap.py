from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from paracci.tools.runtime_bootstrap import BOOTSTRAPPED_ENV, ensure_runtime_dependencies


def _missing_import(_module_name: str):
    raise ImportError("missing test dependency")


def test_source_missing_dependency_creates_dev_venv_and_reexecs(tmp_path):
    script_path = tmp_path / "run.py"
    script_path.write_text("# launcher\n", encoding="ascii")
    calls = []

    def fake_run(command, **kwargs):
        calls.append((command, kwargs))
        if command[:3] == ["source-python", "-m", "venv"]:
            py_exe = tmp_path / ".venv" / "Scripts" / "python.exe"
            py_exe.parent.mkdir(parents=True)
            py_exe.write_text("", encoding="ascii")
        return SimpleNamespace(returncode=0)

    fake_sys = SimpleNamespace(
        platform="win32",
        executable="source-python",
        stderr=sys.stderr,
    )

    with pytest.raises(SystemExit) as error:
        ensure_runtime_dependencies(
            tmp_path,
            script_path=script_path,
            argv=["--no-gui", "--port", "54321"],
            sys_module=fake_sys,
            environ={},
            import_module=_missing_import,
            run_command=fake_run,
            exit_func=sys.exit,
        )

    assert error.value.code == 0
    py_exe = tmp_path / ".venv" / "Scripts" / "python.exe"
    assert calls[0][0] == ["source-python", "-m", "venv", str(tmp_path / ".venv")]
    assert calls[1][0][:6] == [str(py_exe), "-m", "pip", "install", "--require-hashes", "-r"]
    assert calls[2][0] == [str(py_exe), str(script_path), "--no-gui", "--port", "54321"]
    assert calls[2][1]["env"][BOOTSTRAPPED_ENV] == "1"


def test_frozen_missing_dependency_fails_without_venv_bootstrap(tmp_path, capsys):
    calls = []
    fake_sys = SimpleNamespace(
        platform="win32",
        executable="packaged-python",
        stderr=sys.stderr,
        frozen=True,
    )

    with pytest.raises(SystemExit) as error:
        ensure_runtime_dependencies(
            tmp_path,
            script_path=tmp_path / "Paracci.exe",
            argv=["--no-gui"],
            sys_module=fake_sys,
            environ={},
            import_module=_missing_import,
            run_command=lambda *args, **kwargs: calls.append((args, kwargs)),
            exit_func=sys.exit,
        )

    captured = capsys.readouterr()
    assert error.value.code == 1
    assert calls == []
    assert not (tmp_path / ".venv").exists()
    assert "Packaged runtime is missing required bundled Python dependencies." in captured.err
    assert ".venv" not in captured.err


def test_frozen_dependency_available_continues_without_bootstrap(tmp_path):
    calls = []
    fake_sys = SimpleNamespace(
        platform="win32",
        executable="packaged-python",
        stderr=sys.stderr,
        frozen=True,
    )

    handled = ensure_runtime_dependencies(
        tmp_path,
        script_path=tmp_path / "Paracci.exe",
        argv=["--no-gui", "--port", "54321"],
        sys_module=fake_sys,
        environ={},
        import_module=lambda _module_name: object(),
        run_command=lambda *args, **kwargs: calls.append((args, kwargs)),
        exit_func=sys.exit,
    )

    assert handled is False
    assert calls == []
