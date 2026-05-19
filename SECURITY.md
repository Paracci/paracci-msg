# Security Policy

Thank you for helping keep Paracci secure. As an independent, security-focused open-source project, we welcome and appreciate contributions and reports from security researchers.

## Supported Versions

Only the latest released version of Paracci receives security updates and patches. If you discover a vulnerability, please ensure you can reproduce it on the latest release before reporting.

| Version | Supported |
| :--- | :--- |
| Latest Release | Yes |
| < Latest Release | No |

## Reporting a Vulnerability

If you believe you have found a security vulnerability in Paracci, please **do not open a public GitHub Issue**. Public issues can expose users to risk before a fix is available.

Instead, please report the vulnerability privately using GitHub's private vulnerability reporting feature:
https://github.com/Paracci/paracci-msg/security/advisories/new

### What to Include in Your Report
To help us triage and resolve the issue quickly, please include:
- **Description**: A detailed description of the vulnerability and its potential impact.
- **Steps to Reproduce**: Clear, step-by-step instructions (and proof-of-concept code, if applicable) to reproduce the behavior.
- **Affected Component**: Specify which component is affected:
  - Core Cryptography (`paracci/core/`)
  - Session or Envelope Protocol
  - Burn Registry
  - Loopback Server (e.g., token, CSRF, header validation)
  - Desktop / Platform Device Key Binding (DPAPI, Keychain, Secret Service)
  - Attachment Staging Path
  - User Interface (UI)
- **Impact Assessment**: Your assessment of the threat severity and potential impact.
- **Suggested Fix**: Any proposed code changes or remediation steps, if available.

### Response & Triage Timeline
Because Paracci is an independent open-source project without dedicated full-time security staff:
- We will acknowledge receipt of your report within **7 days**.
- If we confirm the vulnerability, we will communicate a target fix timeline within **14 days** of reproduction.

---

## Scope

### In Scope
We consider the following to be valid security vulnerabilities:
- Cryptographic implementation errors in `paracci/core/`
- Weaknesses in the session management or envelope protocol
- Bypass vectors or replay attacks affecting the SQLite-based burn registry
- Authentication or access control bypasses in the Flask loopback server (e.g., token verification, CSRF, header validation)
- Failures in the platform-native device key binding implementation (Windows DPAPI, macOS Keychain, Linux Secret Service)
- Path traversal, arbitrary file read, or file write vulnerabilities via the attachment staging path
- Vulnerabilities in third-party dependencies that have a confirmed, exploitable impact on Paracci

### Out of Scope
The following areas are explicitly excluded from our security scope:
- Attacks requiring physical access to an already-unlocked device (e.g., extracting keys from a running memory dump or reading unencrypted database files while the user is logged in)
- Theoretical weaknesses or cryptographic generalities without a demonstrated, practical exploit path
- Missing security features (such as Double Ratchet or post-quantum KEM) that are already explicitly documented as out-of-scope or not implemented in the current security model
- Antivirus false positives on PyInstaller-packaged application bundles (which are a known issue with PyInstaller and are documented separately)
- Social engineering, phishing, or physical coercion attacks against Paracci users
- Vulnerabilities in upstream dependencies that do not have a demonstrated impact on Paracci's specific usage and threat model

---

## Security Model Reference

Paracci is designed with specific architectural trade-offs to enable a serverless, offline-first encrypted desktop application. Before auditing, please review our security model documentation:

- [README.md](README.md) (Security Model section) — For a high-level overview of our security design.
- [SECURITY_SHIELDS.md](paracci/docs/SECURITY_SHIELDS.md) — For details on platform-native device key binding (shields) and their platform-specific limitations.
- [ARCHITECTURE.md](paracci/docs/ARCHITECTURE.md) — For the threat model governing our Flask + pywebview loopback backend architecture.

Please note that Paracci's documented design limitations (such as the absence of a Double Ratchet protocol, the lack of post-quantum KEM, or the reliance on a local loopback web backend) are known, deliberate design trade-offs and are not treated as vulnerabilities.

---

## Disclosure Policy

- **Responsible Disclosure**: We request that you allow us a reasonable timeframe to address and patch the vulnerability before disclosing it publicly or to third parties.
- **Attribution**: We believe in giving credit where credit is due. Unless you explicitly request anonymity, we will gladly credit you in our release notes and commit logs when the fix is deployed.
