"""Windows/Linux native desktop build helper.

Primary deployment path: pyside6-deploy for the PySide6 Qt Quick/QML shell.
PyInstaller is intentionally no longer the default because Paracci no longer
ships a Flask/pywebview shell.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def build() -> int:
    tool = shutil.which("pyside6-deploy")
    if not tool:
        print("[ERROR] pyside6-deploy was not found. Install requirements first.")
        return 1

    cmd = [
        tool,
        str(ROOT / "run.py"),
        "--name",
        "Paracci",
    ]
    print("[INFO] Running:", " ".join(cmd))
    return subprocess.call(cmd, cwd=ROOT)


if __name__ == "__main__":
    raise SystemExit(build())
