import importlib.util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
ANALYSIS = (
    "vt-scan/Paracci-Windows-Setup.exe=https://www.virustotal.com/gui/file/windows,"
    "vt-scan/Paracci-Linux.zip=https://www.virustotal.com/gui/file/linux"
)


def load_release_notes_module():
    spec = importlib.util.spec_from_file_location(
        "paracci_release_notes",
        REPO_ROOT / "tools" / "ci" / "release_notes.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def base_release_body() -> str:
    return """## Paracci v1.7.1

#### Build Provenance (Sigstore / SLSA Level 2)
Build provenance details.

> **Why might antivirus flag it?** Explanation.

---

> 🔍 Source code: All application logic is in this repository and open for audit.
"""


def legacy_virustotal_section(report: str) -> str:
    return f"""#### VirusTotal Scan

| File | Analysis |
|------|----------|
| `old.exe` | [Report]({report}) |
"""


def assert_single_current_section(notes, body: str) -> None:
    assert body.count(notes.VIRUSTOTAL_HEADING) == 1
    assert body.count(notes.VIRUSTOTAL_START_MARKER) == 1
    assert body.count(notes.VIRUSTOTAL_END_MARKER) == 1
    assert "https://www.virustotal.com/gui/file/windows" in body
    assert "https://www.virustotal.com/gui/file/linux" in body


def test_upsert_inserts_one_virustotal_section_when_missing():
    notes = load_release_notes_module()

    updated = notes.upsert_virustotal_section(base_release_body(), ANALYSIS)

    assert_single_current_section(notes, updated)
    assert updated.index("#### Build Provenance") < updated.index(notes.VIRUSTOTAL_HEADING)
    assert updated.index(notes.VIRUSTOTAL_HEADING) < updated.index(
        "> **Why might antivirus flag it?**"
    )


def test_upsert_replaces_one_existing_legacy_section():
    notes = load_release_notes_module()
    body = base_release_body().replace(
        "> **Why might antivirus flag it?**",
        legacy_virustotal_section("https://old.invalid/report")
        + "\n> **Why might antivirus flag it?**",
    )

    updated = notes.upsert_virustotal_section(body, ANALYSIS)

    assert_single_current_section(notes, updated)
    assert "https://old.invalid/report" not in updated


def test_upsert_replaces_existing_legacy_placeholder():
    notes = load_release_notes_module()
    placeholder = (
        "#### VirusTotal Scan\n\n"
        "_VirusTotal scan links are added automatically after the signed draft is published._"
    )
    body = base_release_body().replace(
        "> **Why might antivirus flag it?**",
        placeholder + "\n\n> **Why might antivirus flag it?**",
    )

    updated = notes.upsert_virustotal_section(body, ANALYSIS)

    assert_single_current_section(notes, updated)
    assert "added automatically after the signed draft is published" not in updated


def test_upsert_normalizes_two_existing_sections_to_one():
    notes = load_release_notes_module()
    body = base_release_body().replace(
        "> **Why might antivirus flag it?**",
        legacy_virustotal_section("https://old.invalid/first")
        + "\n> **Why might antivirus flag it?**",
    )
    body += "\n" + legacy_virustotal_section("https://old.invalid/second")

    updated = notes.upsert_virustotal_section(body, ANALYSIS)

    assert_single_current_section(notes, updated)
    assert "https://old.invalid/first" not in updated
    assert "https://old.invalid/second" not in updated
    assert updated.count("Source code: All application logic") == 1


def test_upsert_is_byte_idempotent():
    notes = load_release_notes_module()

    once = notes.upsert_virustotal_section(base_release_body(), ANALYSIS)
    twice = notes.upsert_virustotal_section(once, ANALYSIS)

    assert twice == once


@pytest.mark.parametrize(
    "body, message",
    [
        (
            "<!-- paracci-release:virustotal:start -->\n"
            "#### VirusTotal Scan\n",
            "start marker has no end marker",
        ),
        (
            "<!-- paracci-release:virustotal:end -->\n",
            "end marker has no start marker",
        ),
        (
            "<!-- paracci-release:virustotal:start -->\n"
            "<!-- paracci-release:virustotal:start -->\n"
            "#### VirusTotal Scan\n"
            "<!-- paracci-release:virustotal:end -->\n",
            "markers are nested",
        ),
    ],
)
def test_upsert_rejects_malformed_markers(body: str, message: str):
    notes = load_release_notes_module()

    with pytest.raises(notes.ReleaseNotesError, match=message):
        notes.upsert_virustotal_section(body, ANALYSIS)


def test_generated_body_has_valid_checksum_fence_and_expected_order():
    notes = load_release_notes_module()

    body = notes.generate_release_body(
        release_tag="v1.7.1",
        package_version="1.7.1",
        repository="Paracci/paracci-msg",
        virustotal_analysis=ANALYSIS,
        include_macos=False,
        include_macos_checksum=False,
    )

    fence_lines = [
        index
        for index, line in enumerate(body.splitlines())
        if line.startswith("```")
    ]
    assert len(fence_lines) == 4
    assert body.count("```") == 4

    checksum_start = body.index("To verify a downloaded package checksum")
    checksum_end = body.index("#### Build Provenance")
    checksum_block = body[checksum_start:checksum_end]
    assert checksum_block.count("```") == 2
    assert "Get-FileHash Paracci-Setup-v1.7.1.exe" in checksum_block
    assert "Get-FileHash Paracci-Portable-v1.7.1.zip" in checksum_block
    assert "sha256sum Paracci-Linux.zip" in checksum_block

    assert body.index("#### SHA-256 Checksums") < body.index("#### Build Provenance")
    assert body.index("#### Build Provenance") < body.index(notes.VIRUSTOTAL_HEADING)
    assert body.index(notes.VIRUSTOTAL_HEADING) < body.index(
        "> **Why might antivirus flag it?**"
    )
    assert body.count("Source code: All application logic") == 1
