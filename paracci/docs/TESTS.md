# Test Structure & Scope

Paracci maintains automated test coverage across its core cryptography engine, session lifecycles, and desktop integrations.

## Running Tests

Run all unit and integration tests from the repository root:

```powershell
python -m pytest paracci/tests -q
node --test paracci/tests/test_session_clipboard.mjs
```

Run the security and dependency audit suite:

```powershell
python paracci/audits/guardian.py
```

Run dependency vulnerability scanning:

```powershell
python -m pip_audit -r requirements.lock -r requirements-dev.lock
```

Run the focused pre-push release validation contract tests:

```powershell
.venv\Scripts\python.exe -m pytest paracci/tests/test_release_artifact_validation.py paracci/tests/test_release_workflow_security.py paracci/tests/test_build_metadata.py -q
.venv\Scripts\python.exe -m pytest paracci/tests/test_security_docs.py -q
```

Run the Python-runtime browser console smoke before release candidates or when
frontend/bootstrap/runtime validation changes. This is not part of the quick
unit-test loop because it launches Paracci plus a real Chromium browser:

```powershell
npx playwright install chromium
node tools/ci/browser_console_smoke.mjs --python .venv\Scripts\python.exe
```

```bash
npx playwright install chromium
node tools/ci/browser_console_smoke.mjs --python python
```

The smoke starts `run.py --no-gui` on a random loopback port with an isolated
temporary `DATA_DIR` and browser profile. It opens the authenticated bootstrap
URL printed by the Python runtime, follows the normal service-worker bearer
flow to the Flask-rendered setup/unlock page, and fails on unexpected browser
`pageerror`, unhandled promise rejection, `console.error`, same-origin static
asset failures, or app/static 4xx/5xx responses needed for page load. Failure
output is redacted and must not include bearer tokens, CSRF tokens, local paths,
or temporary profile/data directories.

After building a release candidate for the current platform, run the local packaged smoke and artifact checks before pushing a tag:

```powershell
# Windows after: python build.py --clean --installer
.venv\Scripts\python.exe tools/ci/packaged_runtime_smoke.py --platform windows
.venv\Scripts\python.exe tools/ci/release_artifact_validation.py validate-build --platform windows
.venv\Scripts\python.exe tools/ci/release_artifact_validation.py prepare-build-assets --platform windows
```

```bash
# Linux after: python build.py --clean --appimage --deb
python tools/ci/packaged_runtime_smoke.py --platform linux
python tools/ci/release_artifact_validation.py validate-build --platform linux
python tools/ci/release_artifact_validation.py prepare-build-assets --platform linux
```

The `Build & Release` workflow still owns CI-only release steps: Linux AppImage extraction, Debian install/remove checks, AppImage GUI timeout smoke, artifact upload, Sigstore attestation, VirusTotal scanning, and draft GitHub Release creation. The publish workflow remains the only place that verifies the offline manifest signature and publishes the draft.

---

## Test Areas

### 1. Cryptography Primitives
- Key generation, signature validation, and shared secret derivation (X25519).
- Key derivation and hardening (HKDF-SHA512/HKDF-SHA256 current protocol keys, fixed Argon2id passphrase derivation, and legacy envelope-read compatibility).
- Symmetric envelope encryption and tamper/modification detection (ChaCha20-Poly1305 AEAD).
- Process memory sanitation (wipe buffers and arrays).

### 2. Session Lifecycle
- Generating authenticated setup metadata (initiator and responder setup files).
- Handshake verification and out-of-band safety code computation.
- Session bonding and master key derivation.
- SQLite-bound encrypted session state preservation.

### 3. Envelope Protocol
- Sealing and opening `.paracci` message packages.
- Rate limits, step-based evolution ratchets, deliberate out-of-order rejection, and anti-replay counters.
- Legacy v1/v2 message reads and current v3 direct message-key encryption.
- Expiration checks and Time-To-Live (TTL) enforcement.
- Safe assembly/extraction of zipped payload contents (limit verification).

### 4. Burn Database
- Single-use message opening checks and SQLite transaction atomic registrations.
- Transition states: Reserved/Opening, Burned, and Failed (retry window recovery).
- Safe file-overwrite and delete functions.
- Local brute-force rates, failed unlock delays, and lockout limits.

### 5. Desktop Integrations
- Platform-native credential store bindings (Windows DPAPI, macOS Keychain, Linux Secret Service).
- Verification of two-factor decryption locking behavior per platform.
- Graceful key-binding service failure fallbacks.

### 6. App Server & UI Routes
- Verification of local Flask server routing and Bearer token check.
- Header validation (Host, Origin, Referer, and Fetch Metadata).
- CSRF validation and cookie flag checks.

---

## Test Gaps & Release Checklist
- **WebView Interface Manual Check**: Launch the application locally under different platforms using `--debug` mode to manually verify the UI layout, attachments drawer, and configuration settings.
- **Multi-User Simulation**: Run parallel debug modes (`run.py --user x` and `run.py --user y`) to execute Alice-and-Bob handshake ceremonies and verify message delivery.
- **Standalone Binary Packaging Gates**: Packaged executables require confirmation on clean target operating systems to verify native shell loading, anti-screenshot behaviors, and proper device key storage registration.
