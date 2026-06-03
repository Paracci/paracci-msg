# Paracci Agent Guardrails

Paracci is a security-sensitive, offline-first desktop application for encrypted two-party file exchange. Treat every change as if it may affect local secrets, encrypted content, device binding, release trust, or loopback isolation.

## Non-Negotiable Boundaries

- Do not weaken cryptography, session identity binding, envelope authentication, burn tracking, device-key binding, loopback authentication, CSRF validation, preview protections, updater signing, dependency integrity, or trusted file-broker boundaries.
- Do not bypass or relax security checks to make tests easier. Fix the test setup or add a narrower regression instead.
- Security fixes require regression tests that would fail without the fix.
- Keep compatibility paths narrow and documented. Legacy read paths must not become new write paths.

## Audit And Implementation Workflow

- Audit, review, and reporting tasks must not create commits unless the user explicitly requests a commit.
- Implementation and fix tasks must run focused validation and create one local commit after successful validation unless the user says otherwise.
- Never run `git push` from this repository.
- Before committing, inspect the staged set and confirm it contains only the intended source, test, and repo-safe documentation files.

## Repository Hygiene

- Never commit raw audit reports, scratch artifacts, private scan artifacts, exploit payloads, proof transcripts, disposable validation scripts, secrets, private keys, signing keys, tokens, passphrases, decrypted data, local user paths, or machine-specific details.
- Keep local-only security work under ignored scratch locations and verify those files remain untracked.
- Documentation intended for the repository must describe sanitized vulnerability classes, fixed invariants, and regression expectations only.
- If a task asks for security memory or guardrails, write repo-safe summaries. Do not copy private report text or sensitive investigation notes into tracked files.
