# Test Structure & Scope

Paracci maintains automated test coverage across its core cryptography engine, session lifecycles, and desktop integrations.

## Running Tests

Run quick local unit and integration tests from the repository root:

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

Run the Native Verification parity gate before pushing CI/release changes. This
is intentionally separate from the quick test loop because it installs locked
dependencies, builds frontend assets, runs the full pytest timeout gate, runs
Guardian, runs the Node tests, installs Playwright Chromium, and launches the
Python-runtime browser-console smoke:

```powershell
$env:LIBOQS_VERSION = "0.15.0"
$env:LIBOQS_EXPECTED_COMMIT = "97f6b86b1b6d109cfd43cf276ae39c2e776aed80"
$env:OQS_INSTALL_PATH = "<liboqs-install-prefix>"
$env:LIBOQS_LIB_DIR = "<liboqs-install-prefix>\bin"
.venv\Scripts\python.exe tools\ci\native_verify.py --profile windows-local --python .venv\Scripts\python.exe
```

The local parity profile requires the same pinned liboqs source marker that CI
uses: `<liboqs-install-prefix>\.paracci-liboqs-source` with `version`,
`expected_commit`, and `actual_commit` values matching the expected immutable
source pin. Missing Python, Node, npm, npx, Playwright, pip-audit, Guardian, or
liboqs prerequisites fail the parity command instead of being silently skipped.

Run the Docker/Linux parity path with the test image when validating Linux
behavior from Windows:

```powershell
docker build -f Dockerfile.test -t paracci-linux-test .
docker run --rm -v "${PWD}:/workspace" -v "/workspace/node_modules" paracci-linux-test
```

GitHub Actions still owns runner-only setup for Native Verification: repository
checkout, pinned Node/Python setup actions, Ubuntu apt packages, and the
`.github/actions/install-liboqs` composite action that builds and exports the
pinned native liboqs library. The shared runner owns validation orchestration
after that setup is complete.

Run the focused pre-push release validation contract tests:

```powershell
.venv\Scripts\python.exe -m pytest paracci/tests/test_release_artifact_validation.py paracci/tests/test_release_workflow_security.py paracci/tests/test_build_metadata.py -q
.venv\Scripts\python.exe -m pytest paracci/tests/test_security_docs.py -q
```

Run the focused PNG carrier transport tests:

```powershell
.venv\Scripts\python.exe -m pytest paracci/tests/test_carrier_core.py paracci/tests/test_carrier_png.py -q
.venv\Scripts\python.exe -m pytest paracci/tests/test_carrier_services.py -q
.venv\Scripts\python.exe -m pytest paracci/tests/test_carrier_routes.py -q
.venv\Scripts\python.exe -m pytest paracci/tests/test_carrier_ui.py paracci/tests/test_security_docs.py -q
node --test paracci/tests/test_carrier_ui.mjs
```

These suites cover carrier limits and generic errors, PNG round trips and image
budgets, downstream setup/message validation, BurnDB replay behavior, trusted
file-reference and save-grant scopes, loopback route protections, raw-path
rejection, secondary/default-off UI behavior, conservative locale wording, and
the absence of PNG auto-detection in normal `.paracci` controls.

## Playwright Session Workspace E2E

The local Playwright suite is the deterministic browser-level replacement for
repeatable manual QA of the unified session workspace. It launches the real
`run.py --no-gui` source runtime with fresh temporary profiles, uses Chromium
with one worker and no retries, binds and navigates only to `127.0.0.1`, and
fails external requests or unexpected browser, console, network, and
same-origin HTTP errors.

The current ten-test suite covers:

- Phase 1 bootstrap, service-worker bearer setup, CSRF state, and loopback-only
  browser policy.
- Phase 2 standard `.paracci` first-message round trip, attachment presentation,
  single-open state, and a precisely scoped replay rejection.
- Phase 3 PNG carrier message round trip, insufficient-capacity handling, and
  isolation between standard and carrier drop targets.
- Phase 4A desktop layout stability at `1280x900` and the `900x700` compact
  desktop window, including no document-level horizontal overflow, reachable
  session controls, obvious-overlap checks, accessible names, keyboard
  reachability, tab behavior, and visible focus indicators.
- Phase 4B attachment removal through a standard round trip, saving-disabled
  attachment presentation, and global routing for standard-message and
  attachment drops.

This is a Windows/Linux desktop application harness. Compact viewport checks
are desktop narrow-window regressions for pywebview/browser window layout
stability. They do not expand platform coverage beyond supported desktop
window sizes. The accessibility checks cover basic names, keyboard reachability,
tab behavior, and focus visibility; they are not a full accessibility audit.

Browser E2E proves the source-runtime browser workflow only. It does not prove
native save grants, native attachment staging, UIApi or pywebview bridge
behavior, operating-system file dialogs, credential-store integration, or
packaged executable behavior. Keep those claims in focused Python and native
boundary tests and in the packaged-runtime validation described below.

### Local Pre-Release Commands

Set the source runtime used by Playwright:

```powershell
$env:PARACCI_E2E_PYTHON = (Resolve-Path '.\.venv\Scripts\python.exe').Path
```

Run the P0 release-gate E2E set:

```powershell
npx playwright test paracci/tests/e2e/bootstrap-policy.spec.mjs paracci/tests/e2e/p0-standard.spec.mjs paracci/tests/e2e/p0-carrier.spec.mjs --config playwright.config.mjs
```

Run the full local Playwright E2E suite, including the P1 desktop layout,
accessibility, attachment-editing, saving-disabled, and drop-routing coverage:

```powershell
npx playwright test --config playwright.config.mjs
```

Run the focused Node session-state and carrier-UI tests:

```powershell
node --test paracci/tests/test_session_state.mjs paracci/tests/test_carrier_ui.mjs
```

Run the focused Python profile-provisioning, carrier route/UI, and documentation
guard tests:

```powershell
.venv\Scripts\python.exe -m pytest paracci/tests/test_e2e_profile_provisioner.py paracci/tests/test_carrier_ui.py paracci/tests/test_carrier_routes.py paracci/tests/test_security_docs.py -q
```

Finish with diff validation:

```powershell
git diff --check
git diff --cached --check
```

The browser suite, Node tests, and Python tests protect different boundaries.
Do not substitute one for another: Playwright covers real browser workflows,
Node covers session and frontend state contracts, Python covers provisioning,
routes, security policy, and native-boundary logic, and focused native
bridge/save-grant tests remain required because browser E2E cannot prove those
privileged operations.

### Artifacts And Debugging

Playwright traces, screenshots, reports, videos, downloads, and redacted failure
logs belong only under the ignored `output/playwright/` tree. Use traces locally
to diagnose failures, then leave them untracked. Do not publish them or attach
them to releases. Treat traces as locally sensitive because they may contain
synthetic decrypted content or ephemeral authentication context.

Never stage Playwright output, generated `.paracci` files, carrier PNGs,
downloads, traces, screenshots, logs, local paths, secrets, tokens, keys,
passphrases, release artifacts, or files under `prototypes/`. Before committing,
inspect the staged names and content:

```powershell
git diff --cached --name-only
git diff --cached --check
git diff --cached --name-only | Select-String 'output[\\/]playwright|prototypes|\.(paracci|png|zip|log)$'
$localPathPattern = '[A-Za-z]:' + '[\\/]|/' + 'home/'
$privateKeyPattern = 'BEGIN .*PRIVATE' + ' KEY'
git diff --cached -- | Select-String "$localPathPattern|$privateKeyPattern"
git status --short --untracked-files=all
```

The two `Select-String` scans should produce no matches. Also inspect the staged
diff directly for credentials or sensitive values that do not match those
patterns.

### E2E Maintenance

- Update the affected E2E helper and specs in the same change as a session UI
  behavior or locator change.
- Keep page-driver helpers thin and assertion-free. Assertions belong in specs.
- Prefer accessible roles and labels, followed by existing stable IDs. Add
  `data-e2e` only when necessary for a dynamic or ambiguous behavior-oriented
  locator.
- Do not add broad console, network, or HTTP allowlists, skips, xfails, or
  retries to hide regressions.
- Scope every expected negative HTTP response to the exact method, path, status,
  and test step. All other 4xx/5xx responses, console errors, page errors,
  request failures, and external requests remain failures.
- Use only synthetic in-memory or temporary files and isolated temporary
  profiles. Never use caller-provided files or persistent user data.

Run the Python-runtime browser console smoke before release candidates or when
frontend/bootstrap/runtime validation changes. This is not part of the quick
unit-test loop because it launches Paracci plus a real Chromium browser:

```powershell
npx playwright install chromium
node tools/ci/browser_console_smoke.mjs --runtime python --python .venv\Scripts\python.exe
```

```bash
npx playwright install chromium
node tools/ci/browser_console_smoke.mjs --runtime python --python python
```

The legacy shorthand remains supported:

```powershell
node tools/ci/browser_console_smoke.mjs --python .venv\Scripts\python.exe
```

The smoke starts `run.py --no-gui` on a random loopback port with an isolated
temporary `DATA_DIR` and browser profile. It opens the authenticated bootstrap
URL printed by the Python runtime, follows the normal service-worker bearer
flow to the Flask-rendered setup/unlock page, and fails on unexpected browser
`pageerror`, unhandled promise rejection, `console.error`, same-origin static
asset failures, or app/static 4xx/5xx responses needed for page load. Failure
output is redacted and must not include bearer tokens, CSRF tokens, local paths,
or temporary profile/data directories.

Paracci E2E viewport checks target Windows and Linux desktop use. Compact
desktop window cases are desktop narrow-window regressions for
pywebview/browser window layout stability: they verify desktop layout stability
and no horizontal overflow at supported desktop window sizes. Viewport
dimensions do not imply additional platform coverage.

After building a Windows release candidate, run the same browser-console policy
against the frozen executable before preparing release assets:

```powershell
npx playwright install chromium
node tools/ci/browser_console_smoke.mjs --runtime executable --executable builds\windows\Paracci\Paracci.exe --python .venv\Scripts\python.exe
```

After `prepare-build-assets` creates the Windows portable archive, run the
portable ZIP smoke. The command extracts the ZIP into a temporary directory,
validates the expected portable layout, runs the extracted `Paracci.exe`, and
lets the extracted portable `data` directory isolate runtime data:

```powershell
$zip = Get-ChildItem -LiteralPath builds\windows -Filter 'Paracci-Portable-v*.zip' | Select-Object -First 1
node tools/ci/browser_console_smoke.mjs --runtime portable-zip --zip $zip.FullName --python .venv\Scripts\python.exe
```

After building a release candidate for the current platform, run the local packaged smoke and artifact checks before pushing a tag:

```powershell
# Windows after: python build.py --clean --installer
node tools/ci/browser_console_smoke.mjs --runtime executable --executable builds\windows\Paracci\Paracci.exe --python .venv\Scripts\python.exe
.venv\Scripts\python.exe tools/ci/packaged_runtime_smoke.py --platform windows
.venv\Scripts\python.exe tools/ci/release_artifact_validation.py validate-build --platform windows
.venv\Scripts\python.exe tools/ci/release_artifact_validation.py prepare-build-assets --platform windows
$zip = Get-ChildItem -LiteralPath builds\windows -Filter 'Paracci-Portable-v*.zip' | Select-Object -First 1
node tools/ci/browser_console_smoke.mjs --runtime portable-zip --zip $zip.FullName --python .venv\Scripts\python.exe
```

```bash
# Linux after: python build.py --clean --appimage --deb
python tools/ci/packaged_runtime_smoke.py --platform linux
python tools/ci/release_artifact_validation.py validate-build --platform linux
python tools/ci/release_artifact_validation.py prepare-build-assets --platform linux
```

The `Build & Release` workflow still owns CI-only release steps: Windows packaged executable and portable ZIP browser-console smoke, Linux AppImage extraction, Debian install/remove checks, AppImage GUI timeout smoke, artifact upload, Sigstore attestation, VirusTotal scanning, and draft GitHub Release creation. The publish workflow remains the only place that verifies the offline manifest signature and publishes the draft.

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
- Isolated `dev_setup.py` X/Y profiles, clean unlock-rate state, and the first-message Flask open that bonds Y.

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

### 7. Optional PNG Carrier Transport
- Shared carrier and extracted-payload limits, stable generic errors, and unsupported carrier-kind handling.
- Lossless PNG capacity estimation, exact extracted bytes, metadata stripping, and image decode budgets.
- Existing setup, responder, message, bonding, decrypt, package, and BurnDB validation after extraction.
- Purpose-scoped one-shot trusted references and size-limited managed save grants.
- Protected Flask routes, bounded multipart input, raw-path rejection, no-store behavior, and redacted failures.
- Collapsed secondary controls, explicit PNG selection, safe localized errors, and unchanged normal `.paracci` forms and drop zones.

---

## PNG Carrier Manual Validation

Use temporary test files outside the repository and do not commit generated PNG
or `.paracci` files.

1. Complete the normal initiator/responder setup ceremony and verify the normal `.paracci` outputs remain primary.
2. Explicitly expand the optional carrier panel, select a sufficiently large lossless PNG cover, and export initiator setup into a PNG carrier.
3. Import that setup carrier and verify the normal responder `.paracci` file is the primary result.
4. Export the responder into a PNG carrier only through the separate secondary action, then import it into the initiator session.
5. Seal a message through both the normal `.paracci` flow and the explicit PNG carrier flow; open both through their matching controls.
6. Verify wrong, corrupt, truncated, or modified PNGs fail with localized generic errors and no backend detail.
7. Verify a cover with insufficient capacity produces no output and exposes no capacity internals.
8. Confirm browser output downloads PNG bytes and Windows native output consumes the existing one-shot save grant.
9. Confirm carrier and cover source files remain present and unchanged after import, open, export, and seal.
10. Confirm normal `.paracci` drop zones do not auto-detect PNG files and all affected pages render without console errors.

## Test Gaps & 1.8.0 Release Checklist

- **Focused Carrier Gate**: Run all carrier Python and Node commands listed above.
- **Normal Flow Regression Gate**: Run the full Python suite so setup, responder, message seal/open, package, loopback, broker, and native behavior remain covered outside carrier-specific tests.
- **Browser Session Workspace Gate**: Run the P0 Playwright release gate, then the full local Playwright suite. Keep the Python-runtime browser-console smoke as the separate bootstrap/render policy check.
- **Windows Candidate Gate**: After a later version bump and package build, run executable and portable-ZIP browser smoke, packaged runtime smoke, artifact validation, and the manual native save-grant checks above.
- **Linux Candidate Gate**: Run Docker/Linux parity before release and packaged-runtime validation after building Linux candidates.
- **Version Gate**: Keep root `VERSION` unchanged during Task 6. Perform the 1.8.0 version bump only after carrier acceptance and release-candidate validation.
- **Signing Gate**: Preserve the 1.7.1 offline Ed25519 release-signing model. CI may create a draft, but publication must continue through the signed-manifest verification workflow.
- **Artifact Hygiene Gate**: Do not commit generated carriers, `.paracci` files, screenshots, logs, release artifacts, local paths, tokens, keys, passphrases, or secrets. Traces and downloads are also local-only artifacts.
- **Native WebView Manual Check**: Use platform-local debug runs only for pywebview and operating-system behavior that browser E2E cannot prove. Do not repeat the automated desktop layout stability, attachment-editing, saving-disabled, or drop-routing checks as routine manual browser QA.
- **Multi-User Simulation**: The isolated Playwright profile pair covers the source-runtime X-to-Y first-message route and subsequent receiver send capability. Reserve parallel debug runs (`run.py --user x` and `run.py --user y`) for native integration investigation rather than the routine browser pre-release gate.
- **Standalone Binary Packaging Gates**: Packaged executables require confirmation on clean target operating systems to verify native shell loading, anti-screenshot behaviors, and proper device key storage registration.
