import importlib.util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def load_build_module():
    spec = importlib.util.spec_from_file_location("paracci_build_script", REPO_ROOT / "build.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def test_canonical_version_is_valid_and_read_by_build_script():
    build = load_build_module()
    assert (REPO_ROOT / "VERSION").read_text(encoding="ascii").strip() == "1.5.1"
    assert build.read_app_version() == ("1.5.1", (1, 5, 1))


def test_windows_version_resource_is_generated_from_canonical_version(tmp_path, monkeypatch):
    build = load_build_module()
    generated = tmp_path / "file_version_info.txt"
    monkeypatch.setattr(build, "VERSION_INFO_FILE", generated)

    build.write_version_info("1.5.1", (1, 5, 1))

    text = generated.read_text(encoding="utf-8")
    assert "filevers=(1, 5, 1, 0)" in text
    assert "prodvers=(1, 5, 1, 0)" in text
    assert "StringStruct('ProductVersion', '1.5.1.0')" in text


def test_package_build_receives_canonical_version(tmp_path, monkeypatch):
    build = load_build_module()
    script = tmp_path / "build_package.sh"
    script.write_text("# build package\n", encoding="ascii")
    called = []
    monkeypatch.setattr(build, "run", lambda cmd, **kwargs: called.append(cmd) or 0)

    assert build.run_native_package_build("linux", "linux", script, "AppImage", "1.5.1") == 0
    assert called == [["bash", str(script), "1.5.1"]]


def test_spec_and_release_workflow_consume_version_without_rewriting_sources():
    spec_text = (REPO_ROOT / "paracci.spec").read_text(encoding="utf-8")
    workflow = (REPO_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")

    assert 'VERSION_FILE = ROOT / "VERSION"' in spec_text
    assert 'VERSION_INFO_FILE = ROOT / "build_metadata" / "file_version_info.txt"' in spec_text
    assert '"CFBundleVersion": APP_VERSION' in spec_text
    assert 'Path("VERSION").read_text' in workflow
    assert "Inject release version metadata" not in workflow
    assert "APP_VERSION =" not in workflow
