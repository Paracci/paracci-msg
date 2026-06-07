from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path


VIRUSTOTAL_START_MARKER = "<!-- paracci-release:virustotal:start -->"
VIRUSTOTAL_END_MARKER = "<!-- paracci-release:virustotal:end -->"
VIRUSTOTAL_HEADING = "#### VirusTotal Scan"
ANTIVIRUS_NOTE_PREFIX = "> **Why might antivirus flag it?**"
SOURCE_AUDIT_TEXT = "Source code: All application logic is in this repository and open for audit."
HEADING_RE = re.compile(r"^#{1,6}\s+\S")
SEPARATOR_RE = re.compile(r"^\s*---+\s*$")


class ReleaseNotesError(RuntimeError):
    pass


def parse_virustotal_analysis(
    analysis: str,
    *,
    require_results: bool,
) -> list[tuple[str, str]]:
    results = []
    for entry in filter(None, analysis.split(",")):
        filename, separator, url = entry.partition("=")
        filename = filename.strip()
        url = url.strip()
        if not separator or not filename or not url.startswith("https://"):
            raise ReleaseNotesError("VirusTotal action returned an unexpected analysis result.")
        results.append((Path(filename).name, url))
    if require_results and not results:
        raise ReleaseNotesError("VirusTotal action returned no analysis results.")
    return results


def render_virustotal_section(
    analysis: str,
    *,
    require_results: bool,
) -> str:
    results = parse_virustotal_analysis(analysis, require_results=require_results)
    lines = [
        VIRUSTOTAL_START_MARKER,
        VIRUSTOTAL_HEADING,
        "",
    ]
    if results:
        lines.extend(
            [
                "| File | Analysis |",
                "|------|----------|",
                *(f"| `{filename}` | [Report]({url}) |" for filename, url in results),
            ]
        )
    else:
        lines.append("_VirusTotal scan links are unavailable._")
    lines.append(VIRUSTOTAL_END_MARKER)
    return "\n".join(lines)


def _code_fence_mask(lines: list[str]) -> list[bool]:
    mask = []
    in_fence = False
    for line in lines:
        stripped = line.strip()
        mask.append(in_fence)
        if stripped.startswith("```"):
            in_fence = not in_fence
    return mask


def _marker_ranges(lines: list[str], in_code_fence: list[bool]) -> list[tuple[int, int]]:
    ranges = []
    start = None
    for index, line in enumerate(lines):
        if in_code_fence[index]:
            continue
        stripped = line.strip()
        if stripped == VIRUSTOTAL_START_MARKER:
            if start is not None:
                raise ReleaseNotesError("VirusTotal release-note markers are nested.")
            start = index
        elif stripped == VIRUSTOTAL_END_MARKER:
            if start is None:
                raise ReleaseNotesError("VirusTotal release-note end marker has no start marker.")
            headings = sum(
                1
                for inner_index in range(start + 1, index)
                if not in_code_fence[inner_index]
                and lines[inner_index].strip() == VIRUSTOTAL_HEADING
            )
            if headings != 1:
                raise ReleaseNotesError(
                    "VirusTotal release-note markers must contain exactly one VirusTotal section."
                )
            ranges.append((start, index))
            start = None
    if start is not None:
        raise ReleaseNotesError("VirusTotal release-note start marker has no end marker.")
    return ranges


def _is_legacy_section_boundary(line: str) -> bool:
    stripped = line.strip()
    return (
        bool(HEADING_RE.match(stripped))
        or bool(SEPARATOR_RE.match(stripped))
        or stripped.startswith(ANTIVIRUS_NOTE_PREFIX)
        or SOURCE_AUDIT_TEXT in stripped
    )


def _virustotal_ranges(lines: list[str]) -> list[tuple[int, int]]:
    in_code_fence = _code_fence_mask(lines)
    ranges = _marker_ranges(lines, in_code_fence)
    covered = {
        index
        for start, end in ranges
        for index in range(start, end + 1)
    }

    index = 0
    while index < len(lines):
        if (
            index not in covered
            and not in_code_fence[index]
            and lines[index].strip() == VIRUSTOTAL_HEADING
        ):
            end = index + 1
            while end < len(lines):
                if (
                    end not in covered
                    and not in_code_fence[end]
                    and _is_legacy_section_boundary(lines[end])
                ):
                    break
                end += 1
            ranges.append((index, end - 1))
            covered.update(range(index, end))
            index = end
        else:
            index += 1
    return sorted(ranges)


def _remove_virustotal_sections(body: str) -> tuple[list[str], int | None]:
    lines = body.splitlines()
    ranges = _virustotal_ranges(lines)
    if not ranges:
        return lines, None

    removed = {
        index
        for start, end in ranges
        for index in range(start, end + 1)
    }
    first_start = ranges[0][0]
    first_position = sum(
        1
        for index in range(first_start)
        if index not in removed
    )
    return [line for index, line in enumerate(lines) if index not in removed], first_position


def _insert_section(lines: list[str], position: int, section: str) -> str:
    prefix = lines[:position]
    suffix = lines[position:]
    while prefix and not prefix[-1].strip():
        prefix.pop()
    while suffix and not suffix[0].strip():
        suffix.pop(0)

    output = list(prefix)
    if output:
        output.append("")
    output.extend(section.splitlines())
    if suffix:
        output.append("")
        output.extend(suffix)
    return "\n".join(output).rstrip() + "\n"


def upsert_virustotal_section(body: str, analysis: str) -> str:
    section = render_virustotal_section(analysis, require_results=True)
    lines, first_prior_position = _remove_virustotal_sections(body)

    antivirus_position = next(
        (
            index
            for index, line in enumerate(lines)
            if line.strip().startswith(ANTIVIRUS_NOTE_PREFIX)
        ),
        None,
    )
    if antivirus_position is not None:
        position = antivirus_position
    elif first_prior_position is not None:
        position = min(first_prior_position, len(lines))
    else:
        position = len(lines)
    return _insert_section(lines, position, section)


def generate_release_body(
    *,
    release_tag: str,
    package_version: str,
    repository: str,
    virustotal_analysis: str,
    include_macos: bool,
    include_macos_checksum: bool,
) -> str:
    virustotal_section = render_virustotal_section(
        virustotal_analysis,
        require_results=False,
    )
    lines = [
        f"## Paracci {release_tag}",
        '<!-- paracci-update: {"protocol_version": 4} -->',
        "",
        "### 📦 Download",
        "",
        "| Platform | File | Notes |",
        "|----------|------|-------|",
        (
            f"| Windows installer | `Paracci-Setup-{release_tag}.exe` | "
            "Standard Mode; per-user installation with uninstaller |"
        ),
        (
            f"| Windows portable | `Paracci-Portable-{release_tag}.zip` | "
            "Extract and run; keeps data beside the executable |"
        ),
    ]
    if include_macos:
        lines.extend(
            [
                (
                    f"| macOS DMG | `Paracci-{package_version}-macOS.dmg` | "
                    "Drag to Applications; not notarized, so first launch may require Open Anyway |"
                ),
                "| macOS compatibility | `Paracci-macOS.zip` | Retained bundle archive |",
            ]
        )
    lines.extend(
        [
            (
                f"| Linux AppImage | `Paracci-{package_version}-x86_64.AppImage` | "
                "Universal package; run `chmod +x` after download |"
            ),
            (
                f"| Linux Debian/Ubuntu | `paracci_{package_version}_amd64.deb` | "
                "Installs desktop and `.paracci` MIME registration |"
            ),
            "| Linux compatibility | `Paracci-Linux.zip` | Retained complete onedir archive |",
            "",
            "---",
            "",
            "### 🔐 Security & Integrity",
            "",
            "#### SHA-256 Checksums",
            "Published releases attach `SHA256SUMS.txt` and its offline Ed25519",
            "signature `SHA256SUMS.txt.sig`. Paracci verifies this signature",
            "before trusting installer checksums.",
            "",
            "To verify a downloaded package checksum after verifying the manifest signature:",
            "```",
            (
                f"# Windows (PowerShell):  Get-FileHash Paracci-Setup-{release_tag}.exe "
                "-Algorithm SHA256"
            ),
            (
                f"# Windows portable:     Get-FileHash Paracci-Portable-{release_tag}.zip "
                "-Algorithm SHA256"
            ),
        ]
    )
    if include_macos_checksum:
        lines.append(
            f"# macOS:                 shasum -a 256 Paracci-{package_version}-macOS.dmg"
        )
    lines.extend(
        [
            (
                "# Linux:                 sha256sum Paracci-Linux.zip "
                f"Paracci-{package_version}-x86_64.AppImage "
                f"paracci_{package_version}_amd64.deb"
            ),
            "```",
            "",
            "#### Build Provenance (Sigstore / SLSA Level 2)",
            "Each published application artifact has GitHub Actions build provenance.",
            "You can verify the attestation without trusting us:",
            "```bash",
            f"gh attestation verify Paracci-Setup-{release_tag}.exe \\",
            f"  --repo {repository}",
            "```",
            "Or browse the attestations tab:",
            f"https://github.com/{repository}/attestations",
            "",
            *virustotal_section.splitlines(),
            "",
            ANTIVIRUS_NOTE_PREFIX + " PyInstaller bundles the Python interpreter",
            '> inside the executable. This "packing" technique is sometimes flagged as',
            "> heuristic-suspicious by AV engines even when the code is clean.",
            "> The source code is fully open and auditable above.",
            "",
            "---",
            "",
            "> 🔍 " + SOURCE_AUDIT_TEXT,
        ]
    )
    return "\n".join(lines) + "\n"


def _macos_release_state(release_assets: Path) -> tuple[bool, bool]:
    macos_dir = release_assets / "macos"
    has_dmg = any(macos_dir.glob("Paracci-*-macOS.dmg"))
    has_compatibility = (macos_dir / "Paracci-macOS.zip").is_file()
    return has_dmg or has_compatibility, has_dmg


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate and update Paracci release notes.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate_parser = subparsers.add_parser("generate-body")
    generate_parser.add_argument("--release-tag", required=True)
    generate_parser.add_argument("--package-version", required=True)
    generate_parser.add_argument("--repository", required=True)
    generate_parser.add_argument("--release-assets", type=Path, default=Path("release-assets"))
    generate_parser.add_argument("--output", type=Path, required=True)

    upsert_parser = subparsers.add_parser("upsert-virustotal")
    upsert_parser.add_argument("--body", type=Path, required=True)

    args = parser.parse_args(argv)
    analysis = os.environ.get("VT_ANALYSIS", "")

    try:
        if args.command == "generate-body":
            include_macos, include_macos_checksum = _macos_release_state(args.release_assets)
            body = generate_release_body(
                release_tag=args.release_tag,
                package_version=args.package_version,
                repository=args.repository,
                virustotal_analysis=analysis,
                include_macos=include_macos,
                include_macos_checksum=include_macos_checksum,
            )
            args.output.write_text(body, encoding="utf-8")
        elif args.command == "upsert-virustotal":
            body = args.body.read_text(encoding="utf-8")
            args.body.write_text(
                upsert_virustotal_section(body, analysis),
                encoding="utf-8",
            )
        else:
            raise AssertionError(args.command)
        return 0
    except ReleaseNotesError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
