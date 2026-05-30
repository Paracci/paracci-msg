import importlib.util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_build_module():
    spec = importlib.util.spec_from_file_location("paracci_build_script", REPO_ROOT / "build.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_canonical_version_is_valid_and_read_by_build_script():
    build = load_build_module()
    assert (REPO_ROOT / "VERSION").read_text(encoding="ascii").strip() == "1.6.0"
    assert build.read_app_version() == ("1.6.0", (1, 6, 0))


def test_windows_version_resource_is_generated_from_canonical_version(tmp_path, monkeypatch):
    build = load_build_module()
    generated = tmp_path / "file_version_info.txt"
    monkeypatch.setattr(build, "VERSION_INFO_FILE", generated)

    build.write_version_info("1.6.0", (1, 6, 0))

    text = generated.read_text(encoding="utf-8")
    assert "filevers=(1, 6, 0, 0)" in text
    assert "prodvers=(1, 6, 0, 0)" in text
    assert "StringStruct('ProductVersion', '1.6.0.0')" in text


def test_package_build_receives_canonical_version(tmp_path, monkeypatch):
    build = load_build_module()
    script = tmp_path / "build_package.sh"
    script.write_text("# build package\n", encoding="ascii")
    called = []
    monkeypatch.setattr(build, "run", lambda cmd, **kwargs: called.append(cmd) or 0)

    assert build.run_native_package_build("linux", "linux", script, "AppImage", "1.6.0") == 0
    assert called == [["bash", str(script), "1.6.0"]]


def test_spec_and_release_workflow_consume_version_without_rewriting_sources():
    spec_text = (REPO_ROOT / "paracci.spec").read_text(encoding="utf-8")
    workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert 'VERSION_FILE = ROOT / "VERSION"' in spec_text
    assert 'VERSION_INFO_FILE = ROOT / "build_metadata" / "file_version_info.txt"' in spec_text
    assert '"CFBundleVersion": APP_VERSION' in spec_text
    assert 'Path("VERSION").read_text' in workflow
    assert "Inject release version metadata" not in workflow
    assert "APP_VERSION =" not in workflow


def test_windows_spec_collects_the_complete_onedir_payload():
    spec_text = (REPO_ROOT / "paracci.spec").read_text(encoding="utf-8")
    windows_block = spec_text.rsplit('if sys.platform == "win32":', 1)[1].split(
        'elif sys.platform == "darwin":', 1
    )[0]

    assert "exclude_binaries=True" in windows_block
    assert "coll = COLLECT(" in windows_block
    assert "a.binaries" in windows_block
    assert "a.zipfiles" in windows_block
    assert "a.datas" in windows_block


def test_windows_output_preserves_the_complete_onedir_payload(tmp_path, monkeypatch):
    build = load_build_module()
    monkeypatch.setattr(build, "DIST_DIR", tmp_path / "dist")
    monkeypatch.setattr(build, "BUILD_DIR", tmp_path / "builds")

    source = build.DIST_DIR / build.APP_NAME
    internal = source / "_internal"
    internal.mkdir(parents=True)
    runtime_name = f"python{build.sys.version_info.major}{build.sys.version_info.minor}.dll"
    (source / "Paracci.exe").write_bytes(b"exe")
    (internal / runtime_name).write_bytes(b"python-runtime")

    build.move_outputs("windows")

    payload = build.BUILD_DIR / "windows" / build.APP_NAME
    assert (payload / "Paracci.exe").read_bytes() == b"exe"
    assert (payload / "_internal" / runtime_name).read_bytes() == b"python-runtime"
    assert not source.exists()


def test_windows_output_fails_closed_without_the_python_runtime_dll(tmp_path, monkeypatch):
    build = load_build_module()
    monkeypatch.setattr(build, "DIST_DIR", tmp_path / "dist")
    monkeypatch.setattr(build, "BUILD_DIR", tmp_path / "builds")

    source = build.DIST_DIR / build.APP_NAME
    (source / "_internal").mkdir(parents=True)
    (source / "Paracci.exe").write_bytes(b"exe")

    with pytest.raises(SystemExit) as error:
        build.move_outputs("windows")

    assert error.value.code == 1
    assert source.exists()
    assert not (build.BUILD_DIR / "windows" / build.APP_NAME).exists()


def test_windows_release_publishes_only_complete_payloads():
    workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert '$runtimeDll = "builds\\windows\\Paracci\\_internal\\python312.dll"' in workflow
    assert 'Test-Path -LiteralPath $runtimeDll -PathType Leaf' in workflow
    assert "$_.FullName.Replace('\\', '/') -eq $expectedRuntimeEntry" in workflow
    assert "${{ steps.resolve.outputs.win_setup_file }}" in workflow
    assert "${{ steps.resolve.outputs.win_portable_file }}" in workflow
    assert "${{ steps.resolve.outputs.win_file }}" not in workflow
    assert "Windows compatibility" not in workflow
    assert "subject-path: builds/windows/Paracci/Paracci.exe" not in workflow
    assert "vt-scan/Paracci-Windows.exe" not in workflow
    assert '"$hash  Paracci.exe"' not in workflow
