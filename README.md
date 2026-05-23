# Paracci

Paracci is a serverless, offline-first desktop application for secure, two-party encrypted file exchange without external network or account dependencies.

## What Paracci Is — And Is Not

Paracci is **not** a real-time messaging application and makes no claim to be. It does not compete with Signal, Wire, or Briar. Those applications are designed for instant online communication through centralized or federated infrastructure. Paracci is designed for a fundamentally different use case:

> Two people who want cryptographically strong, deniable, single-open, locally replay-blocked message exchange — completely offline, with no trusted third party involved at any step.

Think of it as a **locked envelope** that only the intended recipient can open, tracked so that an opened envelope cannot be opened again on this device. Copies of the envelope on other devices or storage locations are not affected by this local registry.

### Designed For

- Exchanging sensitive information without a shared platform account.
- Situations where network availability or trust in third-party services is a concern.
- Users who need local-only, air-gappable secure document exchange.
- Journalists, researchers, or individuals who need provable delivery without server metadata.

### Not Designed For

- Real-time or instant messaging.
- Group conversations.
- Multi-device synchronization.
- Always-on availability or push notifications.

---

## How It Works

1. **Session Setup** — Alice and Bob perform a one-time authenticated handshake by exchanging two setup files (initiator and responder). These files contain signed public metadata: identity keys, session parameters, and evolution settings. They are integrity-protected but **not confidential**. No server is involved.
2. **Sealing a Message** — Alice writes a message, optionally attaches files, and seals it. Paracci produces a fully authenticated and encrypted `.paracci` message envelope (`.msg`) that only the intended recipient can decrypt with session-derived keys. Alice sends the file to Bob through any trusted channel.
3. **Opening a Message** — Bob opens the envelope in his Paracci app. The message is decrypted in memory and displayed once. Once opened, the envelope cannot be opened again on this device. Copies of this file on other devices or storage locations are not affected by this local registry.

---

## Security Model

### Cryptographic Design

- **Authenticated Key Exchange**: Session setup uses signed identity keypairs with safety-code confirmation. The setup files (initiator/responder) carry signed public metadata; they are integrity-protected but not confidential. Both parties must verify the safety code out-of-band before the session is active.
- **Hybrid Post-Quantum Key Exchange**: Paracci uses a hybrid X25519 + ML-KEM-768 key exchange. Both classical and post-quantum secrets must be compromised to break the session key. Session keys are additionally bound to the Ed25519 identity keys of both parties and the exact key material exchanged (ML-KEM public key and ciphertext) via a SHA3-256 handshake transcript. This prevents unknown-key-share attacks and cryptographically ties each session to the specific identities of Alice and Bob.
- **Envelope Encryption**: Every message envelope is sealed with AEAD (ChaCha20-Poly1305) using session-derived keys. ChaCha20-Poly1305 authentication is the message-envelope integrity and tamper-detection boundary. Legacy v1 files with the former outer seal remain readable, but the seal is not trusted as authenticity.
- **Forward-Advancing Key Chain**: Session send/receive keys advance with each message step using an HKDF-based ratchet. Replaying an old envelope is rejected by the local registry and step counter.
- **Single-Use Burn Tracking**: Every envelope carries a unique ID. Paracci atomically registers opens in a local SQLite database (`BurnDB`). An opened envelope cannot be opened again on this device. Copies on other devices or storage locations are not affected by this local registry.
- **Key Hardening**: The local device key is derived from a user passphrase using Argon2id with fixed parameters (t=2, m=64MB, p=4), which meet OWASP minimum recommendations. Configurable cost profiles (standard, paranoid, and quantum/Maximum) are applied to session and envelope key hardening.

### Device Key Protection

To protect the local database (`BurnDB`) against offline attacks and credential theft, Paracci binds the master decryption key to the local platform's secure credential store. Unlocking the database requires **both** the user's passphrase and the active platform-native user session (a two-factor model):

- **Windows**: Binds the device key using the Windows Data Protection API (DPAPI) via native `ctypes` bindings in [dpapi_win.py](paracci/desktop/dpapi_win.py). DPAPI encrypts a platform-specific key factor using keys tied to the Windows user account's credentials. If the SQLite database is copied to a different Windows account or machine, it cannot be decrypted.
- **macOS**: Stores the platform key factor in the macOS system Keychain via `Security.framework` bindings in [keychain_mac.py](paracci/desktop/keychain_mac.py), restricting access to the logged-in macOS user account.
- **Linux**: Integrates with the `org.freedesktop.secrets` D-Bus API in [secret_service_linux.py](paracci/desktop/secret_service_linux.py) to store the key factor in the user's active keyring (e.g., GNOME Keyring or KWallet). If no keyring daemon is running, the application alerts the user and falls back to passphrase-only security.

Platform dispatching is handled dynamically by [device_key_binding.py](paracci/desktop/device_key_binding.py).

### What Is Not Claimed

Paracci does **not** implement a Double Ratchet or post-compromise recovery protocol. If a session's key material is compromised, past and future messages in that session may be at risk until the users establish a new session. For most offline file-exchange use cases this is an acceptable trade-off; users who require post-compromise recovery should establish new sessions periodically.

Paracci uses a hybrid X25519 + ML-KEM-768 key exchange. Both classical and post-quantum secrets must be compromised to break the session key, and active sessions bind the derived keys to both parties' Ed25519 identities through a SHA3-256 handshake transcript. The higher-cost Argon2id profiles apply to session and envelope key hardening only, and should not be interpreted as a replacement for the hybrid exchange.

### Platform-Native Shields

These controls are best-effort and platform-dependent. See [SECURITY_SHIELDS.md](paracci/docs/SECURITY_SHIELDS.md) for exact guarantees and limitations per platform.

- **Screen Capture Reduction**: Uses native OS APIs where available (`SetWindowDisplayAffinity` on Windows) to reduce common capture exposure.
- **Clipboard Auto-Clear**: Clears decrypted clipboard contents after a configurable timeout. Local processes may read the clipboard before clearing.
- **Recent-Item Cleanup**: Attempts to remove `.paracci` file references from OS recent-document lists on startup.
- **Memory-Bound Decryption**: Decrypted payloads are dropped from Paracci-controlled caches on lock, close, or navigation. Copies may exist in Python runtime, OS, or WebView memory outside direct control.

### Local Architecture

Paracci uses a Flask + pywebview architecture. The Flask server binds strictly to `127.0.0.1` on a randomly assigned loopback port and is protected by a per-launch bearer token, Origin/Host validation, CSRF protection, and strict session cookie flags. All privileged routes require the token. The pywebview window blocks all navigation to external URLs.

This is a loopback web backend, not a native IPC channel. The threat model and its limitations are documented in [SECURITY_SHIELDS.md](paracci/docs/SECURITY_SHIELDS.md).

---

## Build Dependencies

Paracci uses `liboqs-python` for the post-quantum KEM foundation. The Python wheel installs through the locked requirements file, but loading the wrapper may build or load the native `liboqs` shared library.

Install these tools before running KEM tests or packaging builds:

- Python 3.10 or newer.
- Git.
- CMake.
- A C compiler. On Windows, use Visual Studio Build Tools/MSVC from a Developer PowerShell so CMake can discover the compiler.

For a manual Windows `liboqs` install, build a shared library and export symbols:

```powershell
git clone --depth=1 https://github.com/open-quantum-safe/liboqs
cmake -S liboqs -B liboqs\build -DCMAKE_INSTALL_PREFIX="<liboqs-install-prefix>" -DCMAKE_WINDOWS_EXPORT_ALL_SYMBOLS=TRUE -DBUILD_SHARED_LIBS=ON
cmake --build liboqs\build --parallel 8
cmake --build liboqs\build --target install
```

Then make the native library visible by adding the install prefix's `bin` directory to `PATH`, or set:

```powershell
$env:OQS_INSTALL_PATH = "<liboqs-install-prefix>"
```

If CMake cannot auto-detect MSVC, add `-G "Visual Studio 17 2022" -A x64` to the configure command.

---

## Install And Run

```powershell
# Clone the repository
git clone https://github.com/Paracci/paracci-msg.git
cd paracci-msg

# Set up virtual environment
python -m venv .venv
.\.venv\Scripts\activate

# Install locked runtime dependencies
pip install --require-hashes -r requirements.lock

# Run the app
python run.py
```

### Development Launch Options

```powershell
# Install locked runtime plus development/audit tooling
pip install --require-hashes -r requirements.lock
pip install --require-hashes -r requirements-dev.lock
```

```powershell
# Run with distinct data profiles to test locally (Alice and Bob flow)
python run.py --user x     # Launches on local port 5000 using data_x/
python run.py --user y     # Launches on local port 5001 using data_y/

# Run as a headless web server only
python run.py --no-gui

# Enable developer inspector tools inside the webview
python run.py --debug
```

---

## Architecture

- [run.py](run.py): Desktop launcher. Starts a Flask daemon thread on a random loopback port, injects the per-launch token, and opens a native pywebview window.
- [paracci/app/](paracci/app/): Flask backend (`routes.py`, `i18n_manager.py`) and Web UI assets (`templates/`, `static/`).
- [paracci/core/](paracci/core/): Cryptography primitives, envelope packaging, session management, burn registry, key evolution, and OS-specific security shields. Includes [constants.py](paracci/core/constants.py) for protocol constants.
- [paracci/desktop/](paracci/desktop/): Native desktop helper services, including platform-specific credential store integration (Windows DPAPI, macOS Keychain, Linux Secret Service).
- [paracci/audits/](paracci/audits/): Internal QA, dependency, performance, and translation auditing suite.
- [paracci/docs/](paracci/docs/): Security model documentation and shield guarantees.

---

## Tests and Auditing

Run all unit and integration tests in the [paracci/tests](paracci/tests) directory:

```powershell
python -m pytest paracci\tests -q
```

Audit locked Python dependencies for known CVEs:

```powershell
python -m pip_audit -r requirements.lock -r requirements-dev.lock
```

Run the automated security and dependency audit suite in [guardian.py](paracci/audits/guardian.py):

```powershell
python paracci\audits\guardian.py
```

---

## Build & Release

Paracci is packaged as a self-contained application. No Python environment is required to run a packaged release.

Windows releases provide two supported distribution modes:

- `Paracci-Setup-v<version>.exe` installs Paracci per user under `%LOCALAPPDATA%\Programs\Paracci` and stores application data under `%LOCALAPPDATA%\Paracci`.
- `Paracci-Portable-v<version>.zip` contains the complete application folder plus its portable `data` directory; extract the folder before running `Paracci.exe`.

### Local Compilation

To compile the application locally using [build.py](build.py):

```powershell
python build.py --install --clean
# Output: builds/windows/Paracci/ (folder containing Paracci.exe and dependencies)
#         builds/macos/Paracci-macOS
#         builds/linux/Paracci-Linux

# Windows only, with Inno Setup 6 installed:
python build.py --clean --installer
# Installer output: builds/windows/Paracci-Setup-v<version>.exe
```

### Automated GitHub Release

Pushing a version tag triggers the multi-platform build pipeline:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions builds Windows, macOS, and Linux packages in parallel, creates the Windows installer and portable archive, signs release artifacts with Sigstore build provenance attestations, runs automated VirusTotal scans, and publishes them under GitHub Releases.

> **Note on antivirus warnings:** PyInstaller bundles the Python runtime into the executable. Some heuristic antivirus engines flag self-extracting Python bundles as suspicious. The VirusTotal scan results and Sigstore attestations are published with every release for independent verification.

---

## License

This software is licensed under the custom **Paracci Source-Available License (Version 1.0)**.

- You are granted the right to read and audit the source code for security verification and educational use.
- You are strictly prohibited from distributing compiled binaries, creating derivative works, or modifying the application's built-in self-integrity verification and security shields.
- See the [LICENSE](LICENSE) file for the full legal terms.
