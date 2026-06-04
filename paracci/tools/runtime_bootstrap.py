from __future__ import annotations

import importlib
import os
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Callable, Iterable, Sequence


BOOTSTRAPPED_ENV = "PARACCI_VENV_BOOTSTRAPPED"
REQUIRED_RUNTIME_MODULES = ("yoyo",)


def is_frozen_runtime(sys_module: ModuleType = sys) -> bool:
    return bool(getattr(sys_module, "frozen", False) or hasattr(sys_module, "_MEIPASS"))


def _venv_python(venv_dir: Path, platform_name: str) -> Path:
    if platform_name == "win32":
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _missing_modules(
    required_modules: Iterable[str],
    import_module: Callable[[str], object],
) -> list[str]:
    missing: list[str] = []
    for module_name in required_modules:
        try:
            import_module(module_name)
        except ImportError:
            missing.append(module_name)
    return missing


def ensure_runtime_dependencies(
    root_dir: Path,
    *,
    script_path: Path,
    argv: Sequence[str] | None = None,
    required_modules: Iterable[str] = REQUIRED_RUNTIME_MODULES,
    sys_module: ModuleType = sys,
    environ: dict[str, str] | None = None,
    import_module: Callable[[str], object] = importlib.import_module,
    run_command: Callable[..., object] = subprocess.run,
    exit_func: Callable[[int], object] = sys.exit,
) -> bool:
    """Ensure source launches have dependencies without bootstrapping packaged apps.

    Returns False when dependencies are already importable and startup should
    continue in the current process. Missing dependencies either re-exec source
    mode in a venv or fail closed for frozen packaged mode.
    """
    root_dir = Path(root_dir)
    script_path = Path(script_path)
    env_source = environ if environ is not None else os.environ
    missing = _missing_modules(required_modules, import_module)
    if not missing:
        return False

    if is_frozen_runtime(sys_module):
        print(
            "[ERROR] Packaged runtime is missing required bundled Python dependencies.",
            file=getattr(sys_module, "stderr", sys.stderr),
        )
        print(
            "[ERROR] Rebuild the packaged app with the locked runtime environment.",
            file=getattr(sys_module, "stderr", sys.stderr),
        )
        exit_func(1)
        return True

    if env_source.get(BOOTSTRAPPED_ENV):
        print(
            "[ERROR] Running inside virtual environment but dependencies are still missing.",
            file=getattr(sys_module, "stderr", sys.stderr),
        )
        print(
            "[ERROR] Please install dependencies by running: pip install -r requirements.lock",
            file=getattr(sys_module, "stderr", sys.stderr),
        )
        exit_func(1)
        return True

    platform_name = getattr(sys_module, "platform", sys.platform)
    venv_dir = root_dir / ".venv"
    appdata_local = env_source.get("LOCALAPPDATA")
    appdata_venv = Path(appdata_local) / "Paracci" / ".venv" if appdata_local else None

    target_python: Path | None = None
    if venv_dir.exists():
        py_exe = _venv_python(venv_dir, platform_name)
        if py_exe.exists():
            target_python = py_exe
    elif appdata_venv and appdata_venv.exists():
        py_exe = _venv_python(appdata_venv, platform_name)
        if py_exe.exists():
            target_python = py_exe

    if not target_python:
        print("[*] Virtual environment (.venv) not found. Creating a new virtual environment...", flush=True)
        try:
            run_command([getattr(sys_module, "executable", sys.executable), "-m", "venv", str(venv_dir)], check=True)
            py_exe = _venv_python(venv_dir, platform_name)

            if py_exe.exists():
                print("[*] Installing dependencies into the virtual environment...", flush=True)
                req_args = [
                    str(py_exe),
                    "-m",
                    "pip",
                    "install",
                    "--require-hashes",
                    "-r",
                    str(root_dir / "requirements.lock"),
                ]
                if (root_dir / "requirements-dev.lock").exists():
                    req_args.extend(["-r", str(root_dir / "requirements-dev.lock")])
                run_command(req_args, check=True)
                target_python = py_exe
        except Exception as exc:
            print(
                f"[ERROR] Failed to automatically create virtual environment and install dependencies: {exc}",
                file=getattr(sys_module, "stderr", sys.stderr),
            )
            print("[ERROR] Please create a virtual environment manually:", file=getattr(sys_module, "stderr", sys.stderr))
            if platform_name == "win32":
                print(
                    "    python -m venv .venv\n    .\\.venv\\Scripts\\activate\n    pip install -r requirements.lock",
                    file=getattr(sys_module, "stderr", sys.stderr),
                )
            else:
                print(
                    "    python -m venv .venv\n    source .venv/bin/activate\n    pip install -r requirements.lock",
                    file=getattr(sys_module, "stderr", sys.stderr),
                )
            exit_func(1)
            return True

    if target_python:
        print(f"[*] Re-running script inside virtual environment: {target_python}", flush=True)
        child_env = dict(env_source)
        child_env[BOOTSTRAPPED_ENV] = "1"
        try:
            result = run_command([str(target_python), str(script_path)] + list(argv or []), env=child_env)
            exit_func(int(getattr(result, "returncode", 0)))
            return True
        except KeyboardInterrupt:
            exit_func(130)
            return True
        except Exception as exc:
            print(
                f"[ERROR] Failed to execute script within virtual environment: {exc}",
                file=getattr(sys_module, "stderr", sys.stderr),
            )
            exit_func(1)
            return True

    return False
