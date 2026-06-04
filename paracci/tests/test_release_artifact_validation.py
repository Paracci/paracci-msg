import importlib.util
import re
import stat
import zipfile
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_validation_module():
    spec = importlib.util.spec_from_file_location(
        "paracci_release_artifact_validation",
        REPO_ROOT / "tools" / "ci" / "release_artifact_validation.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def write_bytes(path: Path, data: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def mark_executable(path: Path) -> Path:
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


def write_zip(path: Path, entries: dict[str, bytes]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    return path


def make_repo_root(tmp_path: Path) -> Path:
    (tmp_path / "VERSION").write_text("1.6.0\n", encoding="ascii")
    (tmp_path / "installer" / "linux").mkdir(parents=True)
    (tmp_path / "installer" / "linux" / "paracci.desktop").write_text(
        "[Desktop Entry]\nName=Paracci\nMimeType=application/x-paracci;\n",
        encoding="utf-8",
    )
    (tmp_path / "installer" / "linux" / "application-x-paracci.xml").write_text(
        "<mime-info xmlns=\"http://www.freedesktop.org/standards/shared-mime-info\">"
        "<mime-type type=\"application/x-paracci\" />"
        "</mime-info>",
        encoding="utf-8",
    )
    return tmp_path


def make_windows_build(root: Path, *, include_setup: bool = True, setup_bytes: bytes = b"MZsetup") -> None:
    payload = root / "builds" / "windows" / "Paracci"
    write_bytes(payload / "Paracci.exe", b"MZexe")
    write_bytes(payload / "_internal" / "python312.dll", b"MZpython")
    if include_setup:
        write_bytes(root / "builds" / "windows" / "Paracci-Setup-v1.6.0.exe", setup_bytes)


def make_linux_build(root: Path, *, appimage_bytes: bytes = b"\x7fELFappimage") -> None:
    payload = root / "builds" / "linux" / "Paracci"
    mark_executable(write_bytes(payload / "Paracci", b"linux-exe"))
    mark_executable(write_bytes(root / "builds" / "linux" / "Paracci-1.6.0-x86_64.AppImage", appimage_bytes))
    write_bytes(root / "builds" / "linux" / "paracci_1.6.0_amd64.deb", b"!<arch>\npackage")


def make_release_assets(root: Path, *, portable_zip: bool = True) -> Path:
    assets = root / "release-assets"
    write_bytes(assets / "windows" / "Paracci-Setup-v1.6.0.exe", b"MZsetup")
    portable = assets / "windows" / "Paracci-Portable-v1.6.0.zip"
    if portable_zip:
        write_zip(
            portable,
            {
                "Paracci-Portable-v1.6.0/Paracci.exe": b"MZexe",
                "Paracci-Portable-v1.6.0/_internal/python312.dll": b"MZpython",
                "Paracci-Portable-v1.6.0/data": b"",
            },
        )
    else:
        write_bytes(portable, b"not-a-zip")
    write_zip(assets / "linux" / "Paracci-Linux.zip", {"Paracci/Paracci": b"linux-exe"})
    write_bytes(assets / "linux" / "Paracci-1.6.0-x86_64.AppImage", b"\x7fELFappimage")
    write_bytes(assets / "linux" / "paracci_1.6.0_amd64.deb", b"!<arch>\npackage")
    return assets


def test_windows_prepare_creates_portable_zip_and_manifest(tmp_path):
    validation = load_validation_module()
    root = make_repo_root(tmp_path)
    make_windows_build(root)

    outputs = validation.prepare_build_assets(root, "windows")

    portable_zip = root / "builds" / "windows" / "Paracci-Portable-v1.6.0.zip"
    validation.validate_windows_portable_zip(portable_zip, "1.6.0")
    assert portable_zip in outputs
    assert not (root / "builds" / "windows" / "Paracci-Portable-v1.6.0").exists()
    manifest = (root / "builds" / "windows" / "SHA256SUMS.txt").read_text(encoding="utf-8")
    assert "Paracci-Setup-v1.6.0.exe" in manifest
    assert "Paracci-Portable-v1.6.0.zip" in manifest


def test_linux_build_validation_reports_skipped_native_ci_checks(tmp_path, capsys):
    validation = load_validation_module()
    root = make_repo_root(tmp_path)
    make_linux_build(root)

    messages = validation.validate_build(root, "linux")

    assert any("Skipped Linux native CI package checks" in message for message in messages)
    assert "Skipped Linux native CI package checks" in capsys.readouterr().out


def test_missing_required_windows_artifact_fails(tmp_path):
    validation = load_validation_module()
    root = make_repo_root(tmp_path)
    make_windows_build(root, include_setup=False)

    with pytest.raises(validation.ReleaseValidationError, match="Windows setup executable"):
        validation.validate_build(root, "windows")


def test_zero_byte_release_artifact_fails(tmp_path):
    validation = load_validation_module()
    root = make_repo_root(tmp_path)
    make_windows_build(root, setup_bytes=b"")

    with pytest.raises(validation.ReleaseValidationError, match="empty"):
        validation.validate_build(root, "windows")


def test_malformed_linux_outputs_fail(tmp_path):
    validation = load_validation_module()
    root = make_repo_root(tmp_path)
    make_linux_build(root, appimage_bytes=b"not-elf")

    with pytest.raises(validation.ReleaseValidationError, match="ELF"):
        validation.validate_build(root, "linux")


def test_malformed_release_zip_fails(tmp_path):
    validation = load_validation_module()
    root = make_repo_root(tmp_path)
    assets = make_release_assets(root, portable_zip=False)

    with pytest.raises(validation.ReleaseValidationError, match="ZIP archive"):
        validation.resolve_release_assets(root, assets, "v1.6.0")


def test_release_tag_must_match_canonical_version(tmp_path):
    validation = load_validation_module()
    root = make_repo_root(tmp_path)
    assets = make_release_assets(root)

    with pytest.raises(validation.ReleaseValidationError, match="does not match canonical VERSION"):
        validation.resolve_release_assets(root, assets, "v9.9.9")


def test_manifest_generation_rejects_missing_or_empty_files(tmp_path):
    validation = load_validation_module()
    missing = tmp_path / "missing.bin"
    empty = write_bytes(tmp_path / "empty.bin", b"")

    with pytest.raises(validation.ReleaseValidationError, match="not found"):
        validation.write_manifest(tmp_path / "SHA256SUMS.txt", [missing])
    with pytest.raises(validation.ReleaseValidationError, match="empty"):
        validation.write_manifest(tmp_path / "SHA256SUMS.txt", [empty])


def test_new_release_validation_sources_do_not_commit_local_machine_paths():
    users = b"Users"
    forbidden = re.compile(
        rb"(?i)(?:[A-Za-z]:[\\/]+"
        + users
        + rb"[\\/]+|\\\\+"
        + users
        + rb"\\\\+|/"
        + users
        + rb"/)"
    )
    for relative_path in (
        "tools/ci/packaged_runtime_smoke.py",
        "tools/ci/release_artifact_validation.py",
        "paracci/docs/TESTS.md",
    ):
        data = (REPO_ROOT / relative_path).read_bytes()
        assert not forbidden.search(data), relative_path
