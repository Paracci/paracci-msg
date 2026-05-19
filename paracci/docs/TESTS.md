# Test Structure & Scope

Paracci maintains automated test coverage across its core cryptography engine, session lifecycles, and desktop integrations.

## Running Tests

Run all unit and integration tests from the repository root:

```powershell
python -m pytest paracci/tests -q
```

Run the security and dependency audit suite:

```powershell
python paracci/audits/guardian.py
```

Run dependency vulnerability scanning:

```powershell
python -m pip_audit -r requirements.lock -r requirements-dev.lock
```

---

## Test Areas

### 1. Cryptography Primitives
- Key generation, signature validation, and shared secret derivation (X25519).
- Key derivation and hardening (HKDF-SHA512, HKDF-SHA256, and Argon2id profiles).
- Symmetric envelope encryption and tamper/modification detection (ChaCha20-Poly1305 AEAD).
- Process memory sanitation (wipe buffers and arrays).

### 2. Session Lifecycle
- Generating authenticated setup metadata (initiator and responder setup files).
- Handshake verification and out-of-band safety code computation.
- Session bonding and master key derivation.
- SQLite-bound encrypted session state preservation.

### 3. Envelope Protocol
- Sealing and opening `.paracci` message packages.
- Rate limits, step-based evolution ratchets, and anti-replay counters.
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
