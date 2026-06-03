# Paracci Agent Guardrails

Paracci is a security-sensitive, offline-first desktop application for encrypted two-party file exchange. Treat every change as if it may affect local secrets, encrypted content, single-open message semantics, device binding, release trust, loopback isolation, preview safety, or native filesystem boundaries.

Future agents must not treat Paracci like a normal web app, CRUD app, or generic Flask project. The app is a local desktop system whose browser UI, Flask loopback server, native bridge, encrypted envelope protocol, and release pipeline all cross security boundaries.

## Core Rule

Identify the affected trust boundary before coding. If the boundary is unclear, inspect the relevant files and tests first, then write down the boundary you are changing. Do not patch symptoms in the UI or tests while leaving the backend, protocol, bridge, or release trust boundary unchanged.

Use these repo-safe references when planning security-sensitive work:

- `paracci/docs/SECURITY_ENGINEERING.md` for subsystem invariants and expected regression style.
- `paracci/docs/SECURITY_REGRESSION_LEDGER.md` for sanitized fixed vulnerability classes and the tests that should protect them.
- `README.md`, `SECURITY.md`, and `paracci/docs/SECURITY_SHIELDS.md` for the public security model and documented limitations.

## Before Editing

- Confirm whether the task is analysis-only, documentation-only, or implementation/fix work.
- Run `git status --short` and note whether the worktree is already dirty.
- Identify the trust boundary being changed: protocol, envelope parsing, ratchet state, BurnDB, loopback auth, service-worker bearer flow, pywebview bridge, preview route, native file broker, UIApi/JSON-RPC, device binding, updater, release workflow, or dependency supply chain.
- Read the nearest security invariants and the closest focused tests before editing.
- Prefer centralized enforcement at the backend, protocol, service, or bridge boundary. UI-only checks are not authorization.
- For security-sensitive behavior changes, plan a regression test that would fail without the fix.
- If the change touches cryptography, updater trust, loopback authentication, native filesystem access, preview rendering, device-key binding, or release workflow policy, stop and get a plan review before implementation unless the user already approved a specific plan.

## Non-Negotiable Boundaries

- Do not weaken cryptography, transcript/session identity binding, envelope authentication, key evolution, burn tracking, device-key binding, loopback authentication, CSRF validation, preview protections, updater signing, dependency integrity, or trusted file-broker boundaries.
- Do not bypass or relax security checks to make tests easier. Fix the test setup or add a narrower regression instead.
- Security fixes require regression tests that would fail without the fix.
- Keep compatibility paths narrow and documented. Legacy read paths must not become new write paths.
- Do not add new privileged bridge methods, public routes, file operations, dependency install paths, or release publication paths without checking the relevant trust boundary.

## Audit And Implementation Workflow

- Analysis, audit, review, and reporting tasks must not create commits unless the user explicitly requests a commit.
- Documentation/guardrail tasks may create a commit only when the user asks for implementation plus a commit.
- Implementation and fix tasks must run focused validation and create one local commit after successful validation unless the user says otherwise.
- Never run `git push` from this repository.
- Do not run broad audits, deep scans, or dependency sweeps unless the task explicitly asks for them.
- If prior reports, memories, or summaries are mentioned, treat them as routing hints only. Verify the live checkout before calling a weakness fixed or reachable.

## Before Committing

- Run the focused tests for the changed boundary and any requested static checks.
- Run `git diff --check`.
- Stage only intended source, test, and repo-safe documentation files.
- Inspect `git diff --cached --name-only` and confirm the staged set contains only the intended files.
- Verify no raw audit reports, scratch artifacts, private scan outputs, exploit material, proof transcripts, disposable validation scripts, secrets, private keys, signing keys, tokens, passphrases, decrypted data, local user paths, or machine-specific files are staged.
- Run `git diff --cached --check`.
- Create one local commit with a clear message after validation. Do not push.

## Repository Hygiene

- Never commit raw audit reports, scratch artifacts, private scan artifacts, exploit payloads, proof transcripts, disposable validation scripts, secrets, private keys, signing keys, tokens, passphrases, decrypted data, local user paths, or machine-specific details.
- Keep local-only security work under ignored scratch locations and verify those files remain untracked.
- Documentation intended for the repository must describe sanitized vulnerability classes, fixed invariants, expected reasoning, and regression expectations only.
- If a task asks for security memory or guardrails, write repo-safe summaries. Do not copy private report text or sensitive investigation notes into tracked files.
