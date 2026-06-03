import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SQLCIPHER_VERSION = "0.5.7"
PYTEST_TIMEOUT_VERSION = "2.4.0"


def _read(relative_path: str) -> str:
    return (REPO_ROOT / relative_path).read_text(encoding="utf-8")


def _package_block(lock_text: str, package: str) -> str:
    match = re.search(
        rf"^{re.escape(package)}==[^\n]+(?:\n(?![A-Za-z0-9_.-]+==).*)*",
        lock_text,
        flags=re.MULTILINE,
    )
    assert match, f"{package} is missing from lockfile"
    return match.group(0)


def test_sqlcipher_runtime_requirement_is_exactly_pinned_and_hashed():
    requirements = _read("requirements.txt")
    lock = _read("requirements.lock")

    assert re.search(rf"^sqlcipher3-wheels=={re.escape(SQLCIPHER_VERSION)}$", requirements, re.MULTILINE)
    assert not re.search(r"^sqlcipher3-wheels\s*[<>~!]", requirements, re.MULTILINE)

    block = _package_block(lock, "sqlcipher3-wheels")
    assert block.startswith(f"sqlcipher3-wheels=={SQLCIPHER_VERSION} \\")
    assert block.count("--hash=sha256:") >= 2
    assert "# via -r requirements.txt" in block


def test_native_timeout_plugin_is_dev_lock_controlled():
    requirements = _read("requirements-dev.txt")
    lock = _read("requirements-dev.lock")

    assert re.search(rf"^pytest-timeout=={re.escape(PYTEST_TIMEOUT_VERSION)}$", requirements, re.MULTILINE)

    block = _package_block(lock, "pytest-timeout")
    assert block.startswith(f"pytest-timeout=={PYTEST_TIMEOUT_VERSION} \\")
    assert block.count("--hash=sha256:") == 2
    assert "# via -r requirements-dev.txt" in block


def test_bootstrap_and_ci_do_not_install_sqlcipher_outside_runtime_lock():
    for relative_path in (
        "run.py",
        "paracci/tools/dev_setup.py",
        ".github/workflows/release.yml",
        ".github/workflows/native_verify.yml",
        "Dockerfile.test",
    ):
        text = _read(relative_path)
        assert "sqlcipher3-wheels" not in text
        assert "Install SQLCipher Python package" not in text


def test_ci_and_docker_install_python_dependencies_with_hashes():
    release = _read(".github/workflows/release.yml")
    native = _read(".github/workflows/native_verify.yml")
    dockerfile = _read("Dockerfile.test")

    for workflow in (release, native):
        assert "python -m pip install --require-hashes -r requirements.lock" in workflow
        assert "python -m pip install --require-hashes -r requirements-dev.lock" in workflow

    assert "pip install pytest-timeout" not in native
    assert "pytest-timeout" not in native

    assert "python -m pip install --ignore-installed --break-system-packages --require-hashes -r requirements.lock" in dockerfile
    assert "python -m pip install --ignore-installed --break-system-packages --require-hashes -r requirements-dev.lock" in dockerfile
