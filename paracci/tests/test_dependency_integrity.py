import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SQLCIPHER_VERSION = "0.5.7"
PYTEST_TIMEOUT_VERSION = "2.4.0"
PIP_VERSION = "26.1.2"
LIBOQS_VERSION = "0.15.0"
LIBOQS_EXPECTED_COMMIT = "97f6b86b1b6d109cfd43cf276ae39c2e776aed80"


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


def test_pip_tool_dependency_is_safe_and_hash_locked():
    lock = _read("requirements-dev.lock")

    block = _package_block(lock, "pip")
    assert block.startswith(f"pip=={PIP_VERSION} \\")
    assert block.count("--hash=sha256:") == 2
    assert "#   pip-api" in block
    assert "#   pip-tools" in block


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
    native_runner = _read("tools/ci/native_verify.py")
    dockerfile = _read("Dockerfile.test")

    assert "python -m pip install --require-hashes -r requirements.lock" in release
    assert "python -m pip install --require-hashes -r requirements-dev.lock" in release
    assert '"--require-hashes", "-r", "requirements.lock"' in native_runner
    assert '"--require-hashes", "-r", "requirements-dev.lock"' in native_runner
    assert "tools/ci/native_verify.py --profile windows-ci" in native
    assert "tools/ci/native_verify.py --profile linux-ci" in native

    assert "pip install pytest-timeout" not in native
    assert "pytest-timeout" not in native

    assert "python -m pip install --ignore-installed --break-system-packages --require-hashes -r requirements.lock" in dockerfile
    assert "python -m pip install --ignore-installed --break-system-packages --require-hashes -r requirements-dev.lock" in dockerfile


def test_liboqs_native_action_requires_immutable_source_pin():
    action = _read(".github/actions/install-liboqs/action.yml")

    assert re.search(
        r"(?m)^  expected-commit:\n(?:    [^\n]*\n)*?    required: true",
        action,
    )
    assert "^[0-9a-f]{40}$" in action
    assert "LIBOQS_EXPECTED_COMMIT: ${{ inputs.expected-commit }}" in action
    assert "key: liboqs-${{ runner.os }}-${{ runner.arch }}-${{ inputs.version }}-${{ inputs.expected-commit }}" in action

    clone_step = action.index('git clone --branch "$LIBOQS_VERSION" --depth 1 https://github.com/open-quantum-safe/liboqs.git')
    resolve_step = action.index('actual_commit="$(git -C liboqs rev-parse HEAD)"')
    mismatch_step = action.index("does not match expected commit")
    cmake_step = action.index("cmake -S liboqs -B liboqs/build")
    assert clone_step < resolve_step < mismatch_step < cmake_step

    assert ".paracci-liboqs-source" in action
    assert "marker_values.get(\"actual_commit\") != expected_commit" in action


def test_release_and_native_workflows_pin_liboqs_source_commit():
    expected_env = f'LIBOQS_EXPECTED_COMMIT: "{LIBOQS_EXPECTED_COMMIT}"'
    expected_version_env = f'LIBOQS_VERSION: "{LIBOQS_VERSION}"'

    for relative_path, expected_calls in (
        (".github/workflows/release.yml", 2),
        (".github/workflows/native_verify.yml", 1),
    ):
        workflow = _read(relative_path)
        assert expected_version_env in workflow
        assert expected_env in workflow
        assert workflow.count("uses: ./.github/actions/install-liboqs") == expected_calls
        assert workflow.count("version: ${{ env.LIBOQS_VERSION }}") == expected_calls
        assert workflow.count("expected-commit: ${{ env.LIBOQS_EXPECTED_COMMIT }}") == expected_calls
        assert 'version: "0.15.0"' not in workflow


def test_docker_native_profile_pins_liboqs_source_commit():
    dockerfile = _read("Dockerfile.test")

    assert f"ENV LIBOQS_VERSION={LIBOQS_VERSION}" in dockerfile
    assert f"ENV LIBOQS_EXPECTED_COMMIT={LIBOQS_EXPECTED_COMMIT}" in dockerfile
    assert 'git clone --branch "$LIBOQS_VERSION" --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs' in dockerfile
    assert 'actual_commit="$(git -C /tmp/liboqs rev-parse HEAD)"' in dockerfile
    assert 'if [ "$actual_commit" != "$LIBOQS_EXPECTED_COMMIT" ]; then' in dockerfile
    assert "liboqs source mismatch" in dockerfile
    assert ".paracci-liboqs-source" in dockerfile
    assert "python tools/ci/native_verify.py --profile linux-docker" in dockerfile


def test_readme_documents_verified_liboqs_source_pin():
    readme = _read("README.md")

    assert f'$env:LIBOQS_VERSION = "{LIBOQS_VERSION}"' in readme
    assert f'$env:LIBOQS_EXPECTED_COMMIT = "{LIBOQS_EXPECTED_COMMIT}"' in readme
    assert "git clone --branch $env:LIBOQS_VERSION --depth=1 https://github.com/open-quantum-safe/liboqs" in readme
    assert "$actualCommit = git -C liboqs rev-parse HEAD" in readme
    assert "the expected commit is the integrity" in readme
    assert "git clone --depth=1 https://github.com/open-quantum-safe/liboqs" not in readme
