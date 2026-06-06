import re
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


DOC_PATHS = [
    REPO_ROOT / "AGENTS.md",
    REPO_ROOT / "paracci" / "docs" / "SECURITY_ENGINEERING.md",
    REPO_ROOT / "paracci" / "docs" / "SECURITY_REGRESSION_LEDGER.md",
]

RELEASE_SIGNING_DOC_PATHS = [
    REPO_ROOT / "README.md",
    REPO_ROOT / "SECURITY.md",
    REPO_ROOT / "paracci" / "docs" / "SECURITY_ENGINEERING.md",
]

CARRIER_TRANSPORT_DOC_PATH = REPO_ROOT / "paracci" / "docs" / "CARRIER_TRANSPORT.md"

EXPECTED_LEDGER_COMMITS = [
    "df35a2f07638df74ab745f0ec0cb3cdf1bd6c7d6",
    "dbc7cc659dbef229f85a049587011a2a0fc910f9",
    "c24ec7155011721ba4234d8a7c4cbf239999e635",
    "e559e743afb2ce289c57b72b0984e66b9710a2b7",
    "ba6bbde14611beef2117956ff7bddba38f031f87",
    "dbaf594429055900b0e93b0c9e006b85e3a5b054",
    "4369492db56653354618440d2efab6c9abc5d3b7",
    "6121e1790e1e0ebf18c0bf989c293b9b6de74e2e",
    "4999c0e6cbae193daebe0e5aae886f2563f5961f",
    "b56bb540103145683471b80c9b1bc56ff5b8a0da",
    "84619d20c9df83d1c26f79c6ec86028becb27790",
    "43443de1b7fab760dfc1e8d7e00eddff18fbf793",
    "204c458039f9406ab6296da0a3200ecc5bc48015",
]

REQUIRED_AGENT_PHRASES = [
    "Identify the affected trust boundary before coding.",
    "## Before Editing",
    "## Before Committing",
    "Analysis, audit, review, and reporting tasks must not create commits",
    "Implementation and fix tasks must run focused validation and create one local commit",
    "Never run `git push` from this repository.",
    "Verify no raw audit reports, scratch artifacts, private scan outputs",
    "Never commit local user-home, Desktop, temp/cache, or absolute workspace paths",
]

REQUIRED_ENGINEERING_PHRASES = [
    "## Security Review Checklist For Code Changes",
    "## When To Stop And Ask For A Plan Review",
    "## Offline Setup And Responder Files",
    "## `.paracci` Message Envelopes",
    "## Key Evolution And Ratchet State",
    "## BurnDB Single-Open Registry",
    "## Flask Loopback Server",
    "## Service Worker, Bootstrap, And Bearer Token Flow",
    "## pywebview Bridge",
    "## Preview And Content Routes",
    "## Native Filesystem Save, Open, Import, And Reveal Flows",
    "## UIApi And JSON-RPC Boundary",
    "## Release And Updater Trust",
    "## Dependency And Native-Library Supply Chain",
    "## Platform Device Key Binding",
    "The updater signing private key must remain offline.",
    "GitHub Actions must not contain `RELEASE_SIGNING_KEY` or `RELEASE_SIGNING_PASSPHRASE`",
    "Draft releases must not be manually published",
    "`publish_signed_release.yml` must verify the offline signature before publication.",
    "Release manifests must be recomputed from the actual assets",
    "2FA-enabled profiles must never become active from passphrase-only native unlock.",
    "must enforce size caps before read, parse, decrypt, unpack, or schema handling",
    "Rejection and security logs must use allowlisted diagnostic fields.",
    "Runtime dependencies must be exact-pinned and hash-locked.",
    "Native cryptography dependencies must be pinned to an immutable commit or digest",
    "Preview content must not inline active or ambiguous MIME types",
    "Image decoding must enforce pixel, dimension, frame-count, and decompression budgets",
    "`bond_nonce` is valid only for the initial unbonded X-to-Y step 0 bonding envelope.",
    "UIApi must not accept raw filesystem paths from untrusted JSON or UI parameters.",
    "Linux Secret Service fallback must require explicit user consent",
    "Preview windows must block external navigation consistently",
    "Committed docs, tests, and code must not contain local machine paths",
]

FORBIDDEN_PRIVATE_REFERENCES = [
    "SECURITY_AUDIT_1.6.0.md",
    "paracci/scratch/security-audits",
    "Codex Security artifact",
    "Codex Security artifacts",
    "worker ledger",
    "worker ledgers",
    "PoC transcript",
    "proof-of-concept transcript",
    "exploit transcript",
    "rollout-",
    "rollout_path",
    "validation_script.py",
    "validate_finding.py",
]

FORBIDDEN_PRIVATE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?im)^\s*(?:secret|token|passphrase|password|api[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]"),
]

REQUIRED_RELEASE_SIGNING_DOC_PHRASES = [
    "GitHub Actions must not contain `RELEASE_SIGNING_KEY` or `RELEASE_SIGNING_PASSPHRASE`",
    "`VT_API_KEY` may remain only for VirusTotal scanning",
    "Draft releases must not be manually published",
    "verify the offline signature",
]

_USERS = b"Users"
_LOCAL_USER = b"k" + b"agan"
FORBIDDEN_TRACKED_CONTENT_PATTERNS = [
    (
        "windows user-home absolute path",
        re.compile(rb"(?i)\b[A-Za-z]:[\\/]+" + _USERS + rb"[\\/]+"),
    ),
    (
        "macos user-home absolute path",
        re.compile(rb"(?i)(?<![A-Za-z0-9_./-])/" + _USERS + rb"/"),
    ),
    (
        "escaped users path",
        re.compile(rb"(?i)\\\\+" + _USERS + rb"\\\\+"),
    ),
    (
        "local username in path context",
        re.compile(
            rb"(?i)(?:[\\/]"
            + re.escape(_LOCAL_USER)
            + rb"[\\/]|"
            + re.escape(_LOCAL_USER)
            + rb"[\\/]+(?:Desktop|AppData|Downloads|Documents|Temp|\.codex)\b)"
        ),
    ),
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],
        cwd=REPO_ROOT,
        check=True,
        capture_output=True,
    )
    return [
        REPO_ROOT / rel.decode("utf-8")
        for rel in result.stdout.split(b"\0")
        if rel
    ]


def test_security_guardrail_docs_exist():
    for path in DOC_PATHS:
        assert path.is_file(), f"{path.relative_to(REPO_ROOT)} is missing"


def test_carrier_transport_doc_records_skeleton_security_model():
    doc = " ".join(_read(CARRIER_TRANSPORT_DOC_PATH).split())
    required_phrases = [
        "Carrier mode is optional and disabled by default.",
        "Normal `.paracci` export, import, and open flows remain the default behavior.",
        "`png_lossless_v1` and `qr_matrix_v1` are planned carrier kind constants only.",
        "They remain unsupported until dedicated adapters and regressions are added.",
        "Carrier transport is an outer wrapper only.",
        "It must not change the existing",
        "`.paracci` setup, responder, or message envelope formats.",
        "Extraction must produce bounded `.paracci` bytes",
        "pass those bytes into",
        "the existing validation, import, open, and decrypt paths",
        "Carrier failures must be stable and generic.",
        "payload bytes, tokens, passphrases, decrypted content, raw carrier internals",
        "filenames, or sensitive paths",
        "sent as a file or document, not as an inline photo.",
        "QR/Matrix carrier work must be described as visible robust transport",
        "not invisible steganography",
    ]
    forbidden_claims = [
        "undetectable",
        "cannot be detected",
        "bypasses existing validation",
        "enabled by default",
    ]

    for phrase in required_phrases:
        assert phrase in doc
    doc_lower = doc.lower()
    for claim in forbidden_claims:
        assert claim not in doc_lower


def test_agents_doc_records_required_agent_workflow():
    doc = _read(REPO_ROOT / "AGENTS.md")

    for phrase in REQUIRED_AGENT_PHRASES:
        assert phrase in doc


def test_security_engineering_doc_records_required_invariants():
    doc = _read(REPO_ROOT / "paracci" / "docs" / "SECURITY_ENGINEERING.md")

    for phrase in REQUIRED_ENGINEERING_PHRASES:
        assert phrase in doc


def test_release_signing_docs_record_offline_key_custody():
    for path in RELEASE_SIGNING_DOC_PATHS:
        doc = _read(path)
        for phrase in REQUIRED_RELEASE_SIGNING_DOC_PHRASES:
            assert phrase in doc, f"{path.relative_to(REPO_ROOT)} missing {phrase!r}"


def test_security_regression_ledger_records_all_remediation_commits():
    ledger = _read(REPO_ROOT / "paracci" / "docs" / "SECURITY_REGRESSION_LEDGER.md")

    assert "| ID / Title | Status | Related commit | Component | Change triggers | Security invariant | Regression-test expectation | Note |" in ledger
    for commit in EXPECTED_LEDGER_COMMITS:
        assert commit in ledger
    assert ledger.count("Do not include raw exploit details here.") >= len(EXPECTED_LEDGER_COMMITS)


def test_private_reference_filter_allows_normal_security_terms():
    for allowed in ("audit", "security review", "passphrase", "private key", "proof"):
        assert allowed not in FORBIDDEN_PRIVATE_REFERENCES


def test_repo_safe_security_docs_do_not_name_private_artifacts():
    combined = "\n".join(_read(path) for path in DOC_PATHS)

    for forbidden in FORBIDDEN_PRIVATE_REFERENCES:
        assert forbidden not in combined
    for pattern in FORBIDDEN_PRIVATE_PATTERNS:
        assert not pattern.search(combined), pattern.pattern


def test_tracked_repo_content_does_not_commit_local_machine_paths():
    violations = []

    for path in _tracked_files():
        data = path.read_bytes()
        rel = path.relative_to(REPO_ROOT).as_posix()
        for label, pattern in FORBIDDEN_TRACKED_CONTENT_PATTERNS:
            if pattern.search(data):
                violations.append(f"{rel}: {label}")

    assert not violations, (
        "Committed content contains local machine path material:\n"
        + "\n".join(violations[:50])
    )
