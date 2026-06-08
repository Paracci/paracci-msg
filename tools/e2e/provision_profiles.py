"""Provision isolated E2E profiles without logging test credentials."""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import sys
import tempfile
from pathlib import Path

from PIL import Image


MARKER_NAME = ".paracci-e2e-root"
MARKER_VALUE = "paracci-e2e-v1"
ROOT_PREFIX = "paracci-e2e-"
REPO_ROOT = Path(__file__).resolve().parents[2]
COVER_DIR_NAME = "covers"
LARGE_COVER_NAME = "phase3-large-cover.png"
TINY_COVER_NAME = "phase3-tiny-cover.png"


def validate_root(raw_root: str) -> Path:
    root = Path(raw_root).resolve(strict=True)
    temp_root = Path(tempfile.gettempdir()).resolve(strict=True)

    try:
        root.relative_to(temp_root)
    except ValueError as exc:
        raise ValueError("E2E profile root must be inside the system temporary directory.") from exc

    if not root.name.startswith(ROOT_PREFIX):
        raise ValueError("E2E profile root has an invalid name.")

    marker = root / MARKER_NAME
    if not marker.is_file() or marker.read_text(encoding="ascii").strip() != MARKER_VALUE:
        raise ValueError("E2E profile root marker is missing or invalid.")

    return root


def provision_covers(root: Path) -> dict[str, str]:
    cover_dir = root / COVER_DIR_NAME
    cover_dir.mkdir(mode=0o700)

    covers = {
        "large": (LARGE_COVER_NAME, (1024, 1024), (32, 96, 160)),
        "tiny": (TINY_COVER_NAME, (32, 32), (160, 64, 32)),
    }
    result = {}
    for key, (filename, size, color) in covers.items():
        cover_path = cover_dir / filename
        with Image.new("RGB", size, color) as image:
            image.save(cover_path, format="PNG")
        result[key] = cover_path.relative_to(root).as_posix()
    return result


def provision_profiles(root: Path, passphrase: str) -> dict[str, object]:
    if not 12 <= len(passphrase) <= 128:
        raise ValueError("E2E passphrase length is invalid.")

    captured_output = io.StringIO()
    with contextlib.redirect_stdout(captured_output), contextlib.redirect_stderr(captured_output):
        sys.path.insert(0, str(REPO_ROOT))
        from paracci.tools import dev_setup

        previous_pin = dev_setup.DEFAULT_PIN
        dev_setup.DEFAULT_PIN = passphrase
        try:
            dev_setup.create_dev_profiles(root)
        finally:
            dev_setup.DEFAULT_PIN = previous_pin

    return {
        "profiles": ["x", "y"],
        "covers": provision_covers(root),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Provision isolated Paracci E2E profiles.")
    parser.add_argument("--root", required=True, help="Marked temporary E2E root.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        root = validate_root(args.root)
        passphrase = sys.stdin.readline().rstrip("\r\n")
        result = provision_profiles(root, passphrase)
    except Exception:
        print("E2E profile provisioning failed.", file=sys.stderr)
        return 1

    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
