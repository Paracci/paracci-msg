import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]


DOC_PATHS = [
    REPO_ROOT / "AGENTS.md",
    REPO_ROOT / "paracci" / "docs" / "SECURITY_ENGINEERING.md",
    REPO_ROOT / "paracci" / "docs" / "SECURITY_REGRESSION_LEDGER.md",
]

EXPECTED_LEDGER_COMMITS = [
    "b4476c974d69bb632e92e4a1bff576ab6f8bdb8b",
    "45b22236b1efb8e2d96ad6f396c7826fc165499d",
    "4bfd4d3ef387cc0173d1c3b697846e67833d2217",
    "715173ab159150e6eb068cc9b798f0383b28657a",
    "6ba5bf88909e3d86d373c69b7cbb9be12b396bd5",
    "efd7b581b6a408298aafec7b4c2c0249c17fd186",
    "283fc4a9dfdc316d8538e2c1e58d9f3d59b360c0",
    "a4a1ecc6c270da6f1384b2ad4cd8e3e3867b121d",
    "b56bcf0d23a5baf010cfca97a8ba34d958d38e86",
    "d12cec22c16d74867ba3bab6cfb344ff09f7dee2",
    "f183fd0eb8fdbfe7b095488d33f75747b920fbe9",
    "c2de0de689162592ef5144e4487d06e52ee07807",
    "4b6e213f781eb7e911466bbea12f27f1c7bb98ac",
]

REQUIRED_AGENT_PHRASES = [
    "Identify the affected trust boundary before coding.",
    "## Before Editing",
    "## Before Committing",
    "Analysis, audit, review, and reporting tasks must not create commits",
    "Implementation and fix tasks must run focused validation and create one local commit",
    "Never run `git push` from this repository.",
    "Verify no raw audit reports, scratch artifacts, private scan outputs",
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
    "<local-user-path>",
    "<local-user-path>",
]

FORBIDDEN_PRIVATE_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----"),
    re.compile(r"(?im)^\s*(?:secret|token|passphrase|password|api[_-]?key)\s*[:=]\s*['\"][^'\"]+['\"]"),
]


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def test_security_guardrail_docs_exist():
    for path in DOC_PATHS:
        assert path.is_file(), f"{path.relative_to(REPO_ROOT)} is missing"


def test_agents_doc_records_required_agent_workflow():
    doc = _read(REPO_ROOT / "AGENTS.md")

    for phrase in REQUIRED_AGENT_PHRASES:
        assert phrase in doc


def test_security_engineering_doc_records_required_invariants():
    doc = _read(REPO_ROOT / "paracci" / "docs" / "SECURITY_ENGINEERING.md")

    for phrase in REQUIRED_ENGINEERING_PHRASES:
        assert phrase in doc


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
