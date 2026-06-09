import json
import secrets
import subprocess
import sys
import tempfile
from pathlib import Path

from conftest import oqs_required


REPO_ROOT = Path(__file__).resolve().parents[2]
PROVISIONER = REPO_ROOT / "tools" / "e2e" / "provision_profiles.py"
MARKER_NAME = ".paracci-e2e-root"
MARKER_VALUE = "paracci-e2e-v1\n"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
EXPECTED_COVERS = {
    "large": "covers/phase3-large-cover.png",
    "tiny": "covers/phase3-tiny-cover.png",
}


def _run_provisioner(root: Path, passphrase: str):
    return subprocess.run(
        [sys.executable, str(PROVISIONER), "--root", str(root)],
        cwd=REPO_ROOT,
        input=f"{passphrase}\n",
        text=True,
        capture_output=True,
        timeout=120,
        check=False,
    )


def test_profile_provisioner_rejects_unmarked_roots(tmp_path):
    passphrase = secrets.token_urlsafe(24)

    result = _run_provisioner(tmp_path, passphrase)

    assert result.returncode == 1
    assert result.stdout == ""
    assert result.stderr.strip() == "E2E profile provisioning failed."
    assert passphrase not in result.stderr


@oqs_required
def test_profile_provisioner_creates_isolated_profiles_without_logging_passphrase():
    passphrase = secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix="paracci-e2e-pytest-") as raw_root:
        root = Path(raw_root)
        (root / MARKER_NAME).write_text(MARKER_VALUE, encoding="ascii")

        result = _run_provisioner(root, passphrase)

        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout) == {
            "profiles": ["x", "y"],
            "covers": EXPECTED_COVERS,
        }
        assert result.stderr == ""
        assert passphrase not in result.stdout
        assert (root / "data_x" / "sessions.db").is_file()
        assert (root / "data_y" / "sessions.db").is_file()

        resolved_root = root.resolve(strict=True)
        resolved_repo = REPO_ROOT.resolve(strict=True)
        for relative_text in EXPECTED_COVERS.values():
            relative_path = Path(relative_text)
            assert not relative_path.is_absolute()
            assert ".." not in relative_path.parts

            cover_path = (root / relative_path).resolve(strict=True)
            assert cover_path.relative_to(resolved_root) == relative_path
            assert resolved_repo not in cover_path.parents
            assert cover_path.read_bytes().startswith(PNG_SIGNATURE)

        assert {path.name for path in (root / "covers").iterdir()} == {
            "phase3-large-cover.png",
            "phase3-tiny-cover.png",
        }

    assert not root.exists()
