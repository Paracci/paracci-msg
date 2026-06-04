from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


def _workflow(name: str) -> str:
    return (REPO_ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def test_release_workflow_has_no_online_updater_signing_authority():
    workflow = _workflow("release.yml")

    for forbidden in (
        "RELEASE_SIGNING_KEY",
        "RELEASE_SIGNING_PASSPHRASE",
        "signing_key.pem",
        "tools/sign_release_manifest.py",
        "Write release signing key",
        "Sign release manifest",
    ):
        assert forbidden not in workflow

    assert "            SHA256SUMS.txt.sig" not in workflow


def test_release_workflow_recomputes_manifest_and_creates_draft_release():
    workflow = _workflow("release.yml")

    resolve_step = workflow.index("- name: Resolve release files")
    manifest_step = workflow.index("- name: Generate canonical SHA256SUMS.txt")
    release_step = workflow.index("- name: Create GitHub Release")

    assert resolve_step < manifest_step < release_step
    assert "tools/ci/release_artifact_validation.py resolve-release-assets" in workflow
    assert "tools/ci/release_artifact_validation.py write-manifest" in workflow
    assert "tools/ci/packaged_runtime_smoke.py" in workflow
    assert "cat release-assets/windows/SHA256SUMS.txt" not in workflow
    assert "release-assets/linux/SHA256SUMS.txt" not in workflow
    assert "draft: true" in workflow
    assert "draft: false" not in workflow


def test_python_runtime_browser_console_smoke_runs_in_ci_gates():
    for workflow_name in ("release.yml", "native_verify.yml"):
        workflow = _workflow(workflow_name)

        assert "npx playwright install" in workflow
        assert "chromium" in workflow
        assert "node tools/ci/browser_console_smoke.mjs --python python" in workflow


def test_publish_workflow_recomputes_hashes_before_accepting_signature_or_publish():
    workflow = _workflow("publish_signed_release.yml")

    require_draft_step = workflow.index("- name: Require draft release and download assets")
    verify_step = workflow.index("- name: Verify every package checksum and detached signature")
    attach_step = workflow.index("- name: Attach signature and publish release")
    checksum_step = workflow.index("actual_digest = hashlib.sha256((root / filename).read_bytes()).hexdigest()")
    decode_step = workflow.index('signature = base64.b64decode(os.environ["MANIFEST_SIGNATURE_B64"], validate=True)')
    signature_verify_step = workflow.index("if not verify_checksum_signature(manifest, signature):")
    signature_write_step = workflow.index('(root / "SHA256SUMS.txt.sig").write_bytes(signature)')
    signature_upload_step = workflow.index('gh release upload "$RELEASE_TAG" release-assets/SHA256SUMS.txt.sig --clobber')
    publish_step = workflow.index('gh release edit "$RELEASE_TAG" --draft=false')

    assert require_draft_step < verify_step < attach_step
    assert "test \"$(gh release view \"$RELEASE_TAG\" --json isDraft --jq '.isDraft')\" = \"true\"" in workflow
    assert checksum_step < decode_step < signature_verify_step < signature_write_step
    assert signature_write_step < signature_upload_step < publish_step


def test_publish_workflow_requires_exact_expected_release_assets():
    workflow = _workflow("publish_signed_release.yml")

    for required_pattern in (
        "Paracci-Setup-v*.exe",
        "Paracci-Portable-v*.zip",
        "Paracci-Linux.zip",
        "Paracci-*-x86_64.AppImage",
        "paracci_*_amd64.deb",
    ):
        assert required_pattern in workflow

    assert "SHA256SUMS.txt contains a duplicate entry" in workflow
    assert "SHA256SUMS.txt does not contain exactly the required release assets" in workflow
    assert "Checksum mismatch for {filename}" in workflow
