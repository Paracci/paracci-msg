from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from xml.etree import ElementTree


REPO_ROOT = Path(__file__).resolve().parents[2]
APP_NAME = "Paracci"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
WINDOWS_SETUP_RE = re.compile(r"^Paracci-Setup-v(?P<version>\d+\.\d+\.\d+)$")
SUPPORTED_PLATFORMS = {"windows", "linux", "macos"}


class ReleaseValidationError(RuntimeError):
    pass


def _record(messages: list[str], message: str) -> None:
    messages.append(message)
    print(message)


def normalize_platform(platform: str) -> str:
    normalized = platform.lower()
    if normalized in {"windows", "win32", "win"}:
        return "windows"
    if normalized in {"linux", "ubuntu"}:
        return "linux"
    if normalized in {"macos", "darwin", "mac"}:
        return "macos"
    raise ReleaseValidationError(f"Unsupported platform: {platform!r}")


def host_platform() -> str:
    if sys.platform == "win32":
        return "windows"
    if sys.platform == "darwin":
        return "macos"
    return "linux"


def read_version(repo_root: Path) -> str:
    version_file = repo_root / "VERSION"
    try:
        version = version_file.read_text(encoding="ascii").strip()
    except OSError as exc:
        raise ReleaseValidationError(f"Canonical version file not found: {version_file}") from exc
    if not VERSION_RE.fullmatch(version):
        raise ReleaseValidationError(f"VERSION must contain MAJOR.MINOR.PATCH, got {version!r}.")
    return version


def ensure_within(parent: Path, child: Path) -> Path:
    parent_resolved = parent.resolve()
    child_resolved = child.resolve()
    try:
        child_resolved.relative_to(parent_resolved)
    except ValueError as exc:
        raise ReleaseValidationError(f"Refusing to operate outside {parent_resolved}: {child_resolved}") from exc
    return child_resolved


def require_dir(path: Path, description: str) -> Path:
    if not path.is_dir():
        raise ReleaseValidationError(f"{description} not found: {path}")
    return path


def require_file(path: Path, description: str, *, executable: bool = False) -> Path:
    if not path.is_file():
        raise ReleaseValidationError(f"{description} not found: {path}")
    if path.stat().st_size <= 0:
        raise ReleaseValidationError(f"{description} is empty: {path}")
    if executable and not os.access(path, os.X_OK):
        raise ReleaseValidationError(f"{description} is not executable: {path}")
    return path


def unique_file(root: Path, pattern: str, description: str, *, required: bool = True) -> Path | None:
    matches = sorted(path for path in root.glob(pattern) if path.is_file())
    if not matches:
        if required:
            raise ReleaseValidationError(f"Expected exactly one {description} matching {pattern!r}; found 0.")
        return None
    if len(matches) != 1:
        raise ReleaseValidationError(
            f"Expected exactly one {description} matching {pattern!r}; found {len(matches)}."
        )
    return require_file(matches[0], description)


def require_mz(path: Path, description: str) -> None:
    require_file(path, description)
    if path.read_bytes()[:2] != b"MZ":
        raise ReleaseValidationError(f"{description} is not a plausible Windows PE file: {path}")


def require_elf(path: Path, description: str) -> None:
    require_file(path, description)
    if path.read_bytes()[:4] != b"\x7fELF":
        raise ReleaseValidationError(f"{description} is not a plausible ELF file: {path}")


def require_deb_ar(path: Path) -> None:
    require_file(path, "Linux Debian package")
    if path.read_bytes()[:8] != b"!<arch>\n":
        raise ReleaseValidationError(f"Linux Debian package is not a plausible ar archive: {path}")


def safe_zip_entry_name(filename: str, description: str) -> str:
    normalized = filename.replace("\\", "/").rstrip("/")
    if not normalized:
        raise ReleaseValidationError(f"{description} contains an empty ZIP entry name.")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        raise ReleaseValidationError(f"{description} contains an absolute ZIP entry: {filename}")
    parts = [part for part in normalized.split("/") if part]
    if any(part in {".", ".."} for part in parts):
        raise ReleaseValidationError(f"{description} contains an unsafe ZIP entry: {filename}")
    return "/".join(parts)


def reject_zip_symlink(entry: zipfile.ZipInfo, description: str) -> None:
    mode = entry.external_attr >> 16
    if stat.S_IFMT(mode) == stat.S_IFLNK:
        raise ReleaseValidationError(f"{description} contains a symlink ZIP entry: {entry.filename}")


def require_zip(path: Path, description: str, required_entries: tuple[str, ...] = ()) -> None:
    require_file(path, description)
    if not zipfile.is_zipfile(path):
        raise ReleaseValidationError(f"{description} is not a ZIP archive: {path}")
    with zipfile.ZipFile(path) as archive:
        bad_entry = archive.testzip()
        if bad_entry:
            raise ReleaseValidationError(f"{description} has a corrupt ZIP entry: {bad_entry}")
        names = set()
        for entry in archive.infolist():
            reject_zip_symlink(entry, description)
            names.add(safe_zip_entry_name(entry.filename, description))
    for entry in required_entries:
        if entry.rstrip("/") not in names:
            raise ReleaseValidationError(f"{description} is missing required ZIP entry: {entry}")


def assert_linux_metadata(repo_root: Path) -> None:
    desktop_file = require_file(
        repo_root / "installer" / "linux" / "paracci.desktop",
        "Linux desktop entry",
    )
    mime_file = require_file(
        repo_root / "installer" / "linux" / "application-x-paracci.xml",
        "Linux MIME definition",
    )
    desktop_text = desktop_file.read_text(encoding="utf-8")
    if "MimeType=application/x-paracci;" not in desktop_text:
        raise ReleaseValidationError("Linux desktop entry does not register application/x-paracci.")
    try:
        ElementTree.parse(mime_file)
    except ElementTree.ParseError as exc:
        raise ReleaseValidationError(f"Linux MIME definition is malformed: {mime_file}") from exc


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_manifest(manifest: Path, files: list[Path]) -> list[str]:
    selected = [path for path in files if str(path)]
    if not selected:
        raise ReleaseValidationError("No files were provided for manifest generation.")
    lines = []
    for path in selected:
        require_file(path, f"Manifest input {path}")
        lines.append(f"{sha256_file(path)}  {path.name}")
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("=== Recomputed SHA256SUMS.txt ===")
    print(manifest.read_text(encoding="utf-8"), end="")
    return lines


def write_platform_manifest(platform_dir: Path, files: list[Path]) -> Path:
    manifest = platform_dir / "SHA256SUMS.txt"
    write_manifest(manifest, files)
    return manifest


def validate_windows_build(repo_root: Path) -> tuple[Path, Path, str]:
    build_dir = repo_root / "builds" / "windows"
    payload_dir = require_dir(build_dir / APP_NAME, "Windows onedir payload")
    executable = payload_dir / "Paracci.exe"
    runtime_dll = payload_dir / "_internal" / "python312.dll"
    require_mz(executable, "Windows packaged executable")
    require_mz(runtime_dll, "Windows Python runtime DLL")

    setup = unique_file(build_dir, "Paracci-Setup-v*.exe", "Windows setup executable")
    assert setup is not None
    require_mz(setup, "Windows setup executable")
    match = WINDOWS_SETUP_RE.fullmatch(setup.stem)
    if not match:
        raise ReleaseValidationError(f"Could not determine installer version from {setup.name}.")
    return setup, payload_dir, match.group("version")


def validate_windows_portable_zip(zip_path: Path, version: str) -> None:
    root = f"Paracci-Portable-v{version}"
    require_zip(
        zip_path,
        "Windows portable archive",
        (
            f"{root}/Paracci.exe",
            f"{root}/_internal/python312.dll",
            f"{root}/data",
        ),
    )


def windows_portable_version_from_name(zip_path: Path) -> str:
    portable_match = re.fullmatch(r"Paracci-Portable-v(?P<version>\d+\.\d+\.\d+)\.zip", zip_path.name)
    if not portable_match:
        raise ReleaseValidationError(f"Unexpected Windows portable archive name: {zip_path.name}")
    return portable_match.group("version")


def safe_extract_zip(zip_path: Path, destination: Path, description: str) -> None:
    if destination.exists() and any(destination.iterdir()):
        raise ReleaseValidationError(f"Refusing to extract into a non-empty directory: {destination}")
    destination.mkdir(parents=True, exist_ok=True)
    destination_resolved = destination.resolve()
    with zipfile.ZipFile(zip_path) as archive:
        for entry in archive.infolist():
            reject_zip_symlink(entry, description)
            relative_name = safe_zip_entry_name(entry.filename, description)
            target = ensure_within(destination_resolved, destination_resolved / relative_name)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(entry) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def extract_windows_portable_zip(zip_path: Path, destination: Path, version: str | None = None) -> Path:
    version = version or windows_portable_version_from_name(zip_path)
    validate_windows_portable_zip(zip_path, version)
    safe_extract_zip(zip_path, destination, "Windows portable archive")
    root_dir = require_dir(destination / f"Paracci-Portable-v{version}", "Extracted Windows portable root")
    executable = root_dir / "Paracci.exe"
    runtime_dll = root_dir / "_internal" / "python312.dll"
    require_mz(executable, "Extracted Windows packaged executable")
    require_mz(runtime_dll, "Extracted Windows Python runtime DLL")
    require_dir(root_dir / "data", "Extracted Windows portable data directory")
    return executable


def validate_linux_build(repo_root: Path, native_ci_checks: bool, messages: list[str]) -> tuple[Path, Path, Path]:
    build_dir = repo_root / "builds" / "linux"
    payload_dir = require_dir(build_dir / APP_NAME, "Linux onedir payload")
    executable = payload_dir / "Paracci"
    require_file(executable, "Linux packaged executable", executable=True)

    appimage = unique_file(build_dir, "Paracci-*-x86_64.AppImage", "Linux AppImage")
    deb = unique_file(build_dir, "paracci_*_amd64.deb", "Linux Debian package")
    assert appimage is not None and deb is not None
    require_file(appimage, "Linux AppImage", executable=True)
    require_elf(appimage, "Linux AppImage")
    require_deb_ar(deb)
    assert_linux_metadata(repo_root)

    if native_ci_checks:
        run_linux_native_checks(repo_root, appimage, deb, messages)
    else:
        _record(messages, "Skipped Linux native CI package checks; run with --native-ci-checks on Linux CI.")

    return payload_dir, appimage, deb


def validate_macos_build(repo_root: Path, native_ci_checks: bool, messages: list[str]) -> tuple[Path, Path | None, Path | None]:
    build_dir = repo_root / "builds" / "macos"
    dmg = unique_file(build_dir, "Paracci-*-macOS.dmg", "macOS DMG")
    assert dmg is not None
    app = build_dir / "Paracci.app"
    binary = build_dir / "Paracci"
    if app.is_dir():
        plist = require_file(app / "Contents" / "Info.plist", "macOS bundle Info.plist")
        text = plist.read_text(encoding="utf-8", errors="replace")
        if "com.paracci.message" not in text:
            raise ReleaseValidationError("macOS bundle Info.plist does not register com.paracci.message.")
        compat: Path | None = app
    elif binary.is_file():
        require_file(binary, "macOS compatibility executable", executable=True)
        compat = binary
    else:
        raise ReleaseValidationError(f"macOS payload not found in {build_dir}")

    if native_ci_checks and host_platform() == "macos":
        run_command(["hdiutil", "verify", str(dmg)], cwd=repo_root)
    else:
        _record(messages, "Skipped macOS native DMG verification; run with --native-ci-checks on macOS CI.")

    return dmg, app if app.is_dir() else None, binary if binary.is_file() else None


def validate_build(repo_root: Path, platform: str, native_ci_checks: bool = False) -> list[str]:
    platform = normalize_platform(platform)
    messages: list[str] = []
    if platform == "windows":
        setup, payload_dir, _version = validate_windows_build(repo_root)
        _record(messages, f"Validated Windows build payload: {payload_dir}")
        _record(messages, f"Validated Windows setup executable: {setup}")
    elif platform == "linux":
        payload_dir, appimage, deb = validate_linux_build(repo_root, native_ci_checks, messages)
        _record(messages, f"Validated Linux onedir payload: {payload_dir}")
        _record(messages, f"Validated Linux AppImage: {appimage}")
        _record(messages, f"Validated Linux Debian package: {deb}")
    elif platform == "macos":
        dmg, app, binary = validate_macos_build(repo_root, native_ci_checks, messages)
        _record(messages, f"Validated macOS DMG: {dmg}")
        _record(messages, f"Validated macOS compatibility payload: {app or binary}")
    else:
        raise AssertionError(platform)
    return messages


def prepare_windows_assets(repo_root: Path) -> list[Path]:
    setup, payload_dir, version = validate_windows_build(repo_root)
    build_dir = repo_root / "builds" / "windows"
    portable_dir = build_dir / f"Paracci-Portable-v{version}"
    portable_zip = build_dir / f"Paracci-Portable-v{version}.zip"
    ensure_within(build_dir, portable_dir)
    ensure_within(build_dir, portable_zip)

    if (payload_dir / "data").exists():
        raise ReleaseValidationError(
            f"Refusing to prepare installer assets from payload containing {payload_dir / 'data'}."
        )
    shutil.rmtree(portable_dir, ignore_errors=True)
    if portable_zip.exists():
        portable_zip.unlink()
    shutil.copytree(payload_dir, portable_dir)
    (portable_dir / "data").mkdir()

    with zipfile.ZipFile(portable_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(portable_dir.rglob("*")):
            archive.write(path, path.relative_to(build_dir).as_posix())
    validate_windows_portable_zip(portable_zip, version)
    shutil.rmtree(portable_dir)
    write_platform_manifest(build_dir, [setup, portable_zip])
    return [setup, portable_zip]


def prepare_linux_assets(repo_root: Path) -> list[Path]:
    messages: list[str] = []
    payload_dir, appimage, deb = validate_linux_build(repo_root, native_ci_checks=False, messages=messages)
    build_dir = repo_root / "builds" / "linux"
    executable = payload_dir / "Paracci"
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    appimage.chmod(appimage.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

    linux_zip = build_dir / "Paracci-Linux.zip"
    if linux_zip.exists():
        linux_zip.unlink()
    with zipfile.ZipFile(linux_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(payload_dir.rglob("*")):
            archive.write(path, path.relative_to(build_dir).as_posix())
    require_zip(linux_zip, "Linux compatibility archive", ("Paracci/Paracci",))
    write_platform_manifest(build_dir, [linux_zip, appimage, deb])
    shutil.rmtree(payload_dir)
    return [linux_zip, appimage, deb]


def prepare_macos_assets(repo_root: Path) -> list[Path]:
    messages: list[str] = []
    dmg, app, binary = validate_macos_build(repo_root, native_ci_checks=False, messages=messages)
    build_dir = repo_root / "builds" / "macos"
    if app is not None:
        compat_zip = build_dir / "Paracci-macOS.zip"
        if compat_zip.exists():
            compat_zip.unlink()
        with zipfile.ZipFile(compat_zip, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(app.rglob("*")):
                archive.write(path, path.relative_to(build_dir).as_posix())
        require_zip(compat_zip, "macOS compatibility archive", ("Paracci.app/Contents/Info.plist",))
        write_platform_manifest(build_dir, [compat_zip, dmg])
        shutil.rmtree(app)
        return [compat_zip, dmg]
    assert binary is not None
    compat_binary = build_dir / "Paracci-macOS"
    if compat_binary.exists():
        compat_binary.unlink()
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    binary.rename(compat_binary)
    write_platform_manifest(build_dir, [compat_binary, dmg])
    return [compat_binary, dmg]


def prepare_build_assets(repo_root: Path, platform: str) -> list[Path]:
    platform = normalize_platform(platform)
    if platform == "windows":
        return prepare_windows_assets(repo_root)
    if platform == "linux":
        return prepare_linux_assets(repo_root)
    if platform == "macos":
        return prepare_macos_assets(repo_root)
    raise AssertionError(platform)


def validate_release_portable_assets(
    win_setup: Path,
    win_portable: Path,
    linux_zip: Path,
    linux_appimage: Path,
    linux_deb: Path,
) -> None:
    require_mz(win_setup, "Windows setup release asset")
    portable_match = re.fullmatch(r"Paracci-Portable-v(?P<version>\d+\.\d+\.\d+)\.zip", win_portable.name)
    if not portable_match:
        raise ReleaseValidationError(f"Unexpected Windows portable archive name: {win_portable.name}")
    validate_windows_portable_zip(win_portable, portable_match.group("version"))
    require_zip(linux_zip, "Linux compatibility release asset", ("Paracci/Paracci",))
    require_elf(linux_appimage, "Linux AppImage release asset")
    require_deb_ar(linux_deb)


def resolve_release_assets(
    repo_root: Path,
    release_assets: Path,
    release_tag: str,
    github_output: Path | None = None,
) -> dict[str, str]:
    version = read_version(repo_root)
    expected_tag = f"v{version}"
    if release_tag != expected_tag:
        raise ReleaseValidationError(
            f"Release tag {release_tag!r} does not match canonical VERSION {expected_tag}."
        )

    windows_dir = require_dir(release_assets / "windows", "Downloaded Windows release artifact")
    linux_dir = require_dir(release_assets / "linux", "Downloaded Linux release artifact")
    macos_dir = release_assets / "macos"

    win_setup = unique_file(windows_dir, "Paracci-Setup-v*.exe", "Windows setup release asset")
    win_portable = unique_file(windows_dir, "Paracci-Portable-v*.zip", "Windows portable release asset")
    linux_zip = unique_file(linux_dir, "Paracci-Linux.zip", "Linux compatibility release asset")
    linux_appimage = unique_file(linux_dir, "Paracci-*-x86_64.AppImage", "Linux AppImage release asset")
    linux_deb = unique_file(linux_dir, "paracci_*_amd64.deb", "Linux Debian release asset")
    assert win_setup and win_portable and linux_zip and linux_appimage and linux_deb
    validate_release_portable_assets(win_setup, win_portable, linux_zip, linux_appimage, linux_deb)
    linux_appimage.chmod(linux_appimage.stat().st_mode | stat.S_IXUSR)

    macos_file = ""
    macos_dmg_file = ""
    if macos_dir.is_dir():
        dmg = unique_file(macos_dir, "Paracci-*-macOS.dmg", "macOS DMG release asset", required=False)
        if dmg is not None:
            macos_dmg_file = str(dmg)
        compat_zip = macos_dir / "Paracci-macOS.zip"
        compat_binary = macos_dir / "Paracci-macOS"
        if compat_zip.is_file():
            require_zip(compat_zip, "macOS compatibility release asset")
            macos_file = str(compat_zip)
        elif compat_binary.is_file():
            require_file(compat_binary, "macOS compatibility release asset")
            compat_binary.chmod(compat_binary.stat().st_mode | stat.S_IXUSR)
            macos_file = str(compat_binary)

    outputs = {
        "win_setup_file": str(win_setup),
        "win_portable_file": str(win_portable),
        "macos_file": macos_file,
        "macos_dmg_file": macos_dmg_file,
        "linux_zip_file": str(linux_zip),
        "linux_appimage_file": str(linux_appimage),
        "linux_deb_file": str(linux_deb),
        "package_version": version,
    }
    if github_output is not None:
        with github_output.open("a", encoding="utf-8") as handle:
            for key, value in outputs.items():
                handle.write(f"{key}={value}\n")
    return outputs


def run_command(
    cmd: list[str],
    *,
    cwd: Path,
    env: dict[str, str] | None = None,
    check: bool = True,
    capture_output: bool = False,
) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(
        cmd,
        cwd=cwd,
        env=env,
        text=True,
        check=False,
        capture_output=capture_output,
    )
    if check and result.returncode != 0:
        output = ""
        if capture_output:
            output = f"\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        raise ReleaseValidationError(f"Command failed ({result.returncode}): {' '.join(cmd)}{output}")
    return result


def require_command(name: str) -> None:
    if shutil.which(name) is None:
        raise ReleaseValidationError(f"Required native validation command not found: {name}")


def run_linux_native_checks(repo_root: Path, appimage: Path, deb: Path, messages: list[str]) -> None:
    if host_platform() != "linux":
        raise ReleaseValidationError("--native-ci-checks for Linux must run on a Linux host.")
    for command in ("desktop-file-validate", "dpkg-deb", "sudo", "timeout", "xvfb-run"):
        require_command(command)

    run_command(["desktop-file-validate", "installer/linux/paracci.desktop"], cwd=repo_root)

    runner_temp = Path(os.environ.get("RUNNER_TEMP") or tempfile.mkdtemp(prefix="paracci-native-checks-"))
    extract_dir = runner_temp / "paracci-appimage-extract"
    shutil.rmtree(extract_dir, ignore_errors=True)
    extract_dir.mkdir(parents=True)
    run_command([str(appimage.resolve()), "--appimage-extract"], cwd=extract_dir)
    root = extract_dir / "squashfs-root"
    require_file(root / "AppRun", "Extracted AppImage AppRun", executable=True)
    require_file(
        root / "usr" / "share" / "applications" / "paracci.desktop",
        "Extracted AppImage desktop entry",
    )
    require_file(
        root / "usr" / "share" / "mime" / "packages" / "application-x-paracci.xml",
        "Extracted AppImage MIME definition",
    )
    desktop_text = (root / "usr" / "share" / "applications" / "paracci.desktop").read_text(
        encoding="utf-8"
    )
    if "MimeType=application/x-paracci;" not in desktop_text:
        raise ReleaseValidationError("Extracted AppImage desktop entry is missing .paracci MIME registration.")

    run_command(["dpkg-deb", "--info", str(deb)], cwd=repo_root)
    installed = False
    try:
        run_command(["sudo", "dpkg", "-i", str(deb)], cwd=repo_root)
        installed = True
        require_file(Path("/opt/paracci/Paracci"), "Installed Debian executable", executable=True)
        if not Path("/usr/local/bin/paracci").is_symlink():
            raise ReleaseValidationError("Installed Debian package did not create /usr/local/bin/paracci.")
        require_file(Path("/usr/share/applications/paracci.desktop"), "Installed desktop entry")
        require_file(
            Path("/usr/share/mime/packages/application-x-paracci.xml"),
            "Installed MIME definition",
        )
        if Path("/opt/paracci/data").exists():
            raise ReleaseValidationError("Installed Debian package created portable data directory.")
    finally:
        if installed:
            run_command(["sudo", "dpkg", "-r", "paracci"], cwd=repo_root, check=False)
    for removed_path in (
        Path("/opt/paracci"),
        Path("/usr/local/bin/paracci"),
        Path("/usr/share/applications/paracci.desktop"),
        Path("/usr/share/mime/packages/application-x-paracci.xml"),
    ):
        if removed_path.exists() or removed_path.is_symlink():
            raise ReleaseValidationError(f"Debian package removal left path behind: {removed_path}")

    gui_log = runner_temp / "paracci-appimage-gui.log"
    env = os.environ.copy()
    env["APPIMAGE_EXTRACT_AND_RUN"] = "1"
    result = run_command(
        ["timeout", "20s", "xvfb-run", "-a", str(appimage)],
        cwd=repo_root,
        env=env,
        check=False,
        capture_output=True,
    )
    gui_log.write_text((result.stdout or "") + (result.stderr or ""), encoding="utf-8")
    if result.returncode != 124:
        raise ReleaseValidationError(
            "Expected the AppImage GUI process to remain active until timeout; "
            f"status={result.returncode}\n{gui_log.read_text(encoding='utf-8')}"
        )
    _record(messages, "Validated Linux native package install/remove and AppImage GUI timeout smoke.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate Paracci release package artifacts.")
    parser.add_argument("--repo-root", type=Path, default=REPO_ROOT)
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate-build")
    validate_parser.add_argument("--platform", required=True, choices=sorted(SUPPORTED_PLATFORMS))
    validate_parser.add_argument("--native-ci-checks", action="store_true")

    prepare_parser = subparsers.add_parser("prepare-build-assets")
    prepare_parser.add_argument("--platform", required=True, choices=sorted(SUPPORTED_PLATFORMS))

    resolve_parser = subparsers.add_parser("resolve-release-assets")
    resolve_parser.add_argument("--release-assets", type=Path, required=True)
    resolve_parser.add_argument("--release-tag", required=True)
    resolve_parser.add_argument("--github-output", type=Path)

    manifest_parser = subparsers.add_parser("write-manifest")
    manifest_parser.add_argument("--manifest", type=Path, required=True)
    manifest_parser.add_argument("--file", dest="files", action="append", default=[])

    extract_parser = subparsers.add_parser("extract-windows-portable-zip")
    extract_parser.add_argument("--zip", dest="zip_path", type=Path, required=True)
    extract_parser.add_argument("--destination", type=Path, required=True)
    extract_parser.add_argument("--version")

    args = parser.parse_args(argv)
    repo_root = args.repo_root.resolve()

    try:
        if args.command == "validate-build":
            validate_build(repo_root, args.platform, native_ci_checks=args.native_ci_checks)
        elif args.command == "prepare-build-assets":
            prepare_build_assets(repo_root, args.platform)
        elif args.command == "resolve-release-assets":
            resolve_release_assets(repo_root, args.release_assets, args.release_tag, args.github_output)
        elif args.command == "write-manifest":
            write_manifest(args.manifest, [Path(path) for path in args.files if path])
        elif args.command == "extract-windows-portable-zip":
            executable = extract_windows_portable_zip(
                args.zip_path.resolve(),
                args.destination.resolve(),
                args.version,
            )
            print(executable)
        else:
            raise AssertionError(args.command)
        return 0
    except ReleaseValidationError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
