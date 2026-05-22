# System Architecture

Paracci is built around an offline, secure file-exchange messaging model. It integrates a local Flask backend service wrapped in a native `pywebview` windowing shell.

## Layers

### 1. Web Front-End ([templates/](paracci/app/templates/) and [static/](paracci/app/static/))

The user interface is designed using modern CSS layouts and custom components:
- **HTML/CSS templates**: Rendered by Flask, styled with HSL tokens, and optimized for seamless desktop dimensions.
- **JavaScript UI Controllers (`auth.js`, `session.js`, `app.js`)**: Handle client-side interactions, dynamic DOM rendering, inline message sanitization (via DOMPurify), code-copy operations, and input verification.
- **Strict Content Security Policy (CSP)**: Ensures all inline scripting, attribute execution (`script-src-attr 'none'`), and unauthorized resource loads are blocked.

### 2. Local Flask Server ([routes.py](paracci/app/routes.py))

A local web server handles application routing and API endpoints:
- Exposes REST endpoints to the Web UI for loading data, sealing envelopes, verifying passphrases/2FA, and importing files.
- Binds strictly to `127.0.0.1` (localhost) on a randomly assigned port.
- Requires a per-launch bearer token and bootstrap session before protected routes are usable.
- Validates Host, Origin, Referer, and Fetch Metadata headers for privileged requests.
- Enforces CSRF tokens on unsafe methods and uses trusted-host configuration plus strict SameSite/HttpOnly session flags.

### 3. Shared UI API ([facade.py](paracci/ui_api/facade.py))

A stable bridge between the Flask server routes and the underlying core services:
- Transforms internal Python objects into JSON-safe Data Transfer Objects (DTOs).
- Restricts file-heavy operations to path-based references.

### 4. Native Desktop Services ([desktop/](paracci/desktop/))

Coordinates platform-native system utilities:
- [services.py](paracci/desktop/services.py): Implements core services such as `DeviceService` (initialization, lock, unlock, 2FA setup), `SessionService` (handshake and session coordination), `MessageService` (envelope processing), `SettingsService` (user configs), `I18nService` (translation management), and `ShieldService` (exposure reduction).
- [device_key_binding.py](paracci/desktop/device_key_binding.py): Dispatches device-key binding operations to platform-specific modules.
- [dpapi_win.py](paracci/desktop/dpapi_win.py): Windows-specific key binding using the Data Protection API (DPAPI) via ctypes.
- [keychain_mac.py](paracci/desktop/keychain_mac.py): macOS-specific key binding using Keychain services via the Security.framework API.
- [secret_service_linux.py](paracci/desktop/secret_service_linux.py): Linux-specific key binding using the freedesktop.org Secret Service D-Bus API.

### 5. Core Engine ([core/](paracci/core/))

The cryptographic and logic core:
- [crypto.py](paracci/core/crypto.py): Implements primitives including X25519 key exchange, HKDF-SHA512, ChaCha20-Poly1305 AEAD, Argon2id, and the hybrid shared-secret combiner.
- [quantum_kem.py](paracci/core/quantum_kem.py): Wraps ML-KEM-768 operations through `liboqs-python`.
- [hybrid_kem.py](paracci/core/hybrid_kem.py): Coordinates ML-KEM setup, encapsulation, decapsulation, and validation for hybrid session handshakes.
- [constants.py](paracci/core/constants.py): Frozen protocol-stable constants and identifiers used throughout the application to ensure backwards compatibility.
- [session.py](paracci/core/session.py): Coordinates Handshake V3 hybrid X25519 + ML-KEM setup, generates initiator/responder files containing authenticated public metadata, and derives session key seeds.
- [preview_store.py](paracci/core/preview_store.py): Thread-safe, in-memory store managing short-lived, token-scoped preview sessions for message attachments.
- [envelope.py](paracci/core/envelope.py): Packages encrypted message payloads and attachment ZIP archives.
- [package.py](paracci/core/package.py): Manages in-memory ZIP extraction and safety limits (uncompressed size, entry count, compression ratio).
- [burn.py](paracci/core/burn.py): Enforces database transaction-bound message burn registries and device key storage.
- [shields/](paracci/core/shields/): Contains platform-specific implementations (Windows, macOS, Linux) for clipboard clearing, anti-screenshot protection, and recent document cleanup.

---

## Handshake File Formats

Paracci supports two formats for exchanging handshake and session setup configurations:
- **v3 Legacy (Wrapped)**: Encrypts the session setup metadata using a key derived from the session ID. Legacy clients and imports decrypt the wrapper payload using the derived key.
- **v4 Current (Plaintext JSON Header)**: Serializes setup data as plaintext JSON appended directly after the 22-byte magic binary header. Contains identity public keys, hybrid ML-KEM details, and an Ed25519 signature verified against the sender's identity.
- **Migration & Compatibility**: The system dynamically inspects the file version header byte. If a v3 legacy wrapped handshake is detected, it falls back to wrapped decryption to ensure seamless backward compatibility during import.

---

## Preview System

Message attachment previewing is isolated from main application privileges:
- **PreviewStore** ([preview_store.py](paracci/core/preview_store.py)): A RAM-only, thread-safe manager that constructs brief, unique tokens for decrypted attachments.
- **Routes**: Exposes Flask routes `/preview/<token>` to load the preview document layout and `/preview/<token>/content` to stream the underlying bytes securely.
- **Window Isolation**: Opened preview frames run inside a restricted webview containing a restricted `PreviewWindowApi` instead of the main window's privileged `ProApi`. Actions are scoped to the matching token, preventing attachment environments from executing high-privilege operations.
- **Download Enforcement**: Server-side routes enforce `allow_download` restrictions. If disabled, non-image requests abort with HTTP 403, and image formats are degraded and watermarked.

---

## Navigation Security

Main UI and preview browser controls mitigate external link execution:
- **JS Navigation Guard**: A window-load script injected at the pywebview frame initialization that intercepts and cancels clicks on external `href`s, form submissions, and `window.open` requests directing traffic outside local loopback boundaries.
- **Link Neutralization**: Markdown contents are sanitized with DOMPurify, enforcing the `MARKDOWN_FRAGMENT_HREF_RE` pattern on all anchor tags to strip external URIs before DOM insertion.

---

## Startup Flow

1. [run.py](run.py) parses command-line arguments and sets up data directories.
2. Clears system-level recent-items queues and sweeps expired temporary directories.
3. Launches a background thread to run the Flask web daemon.
4. Generates a secure random bootstrap token, exports `PARACCI_LOOPBACK_TOKEN`, `PARACCI_LOOPBACK_HOST`, and `PARACCI_LOOPBACK_PORT`, then constructs a loopback launch URL.
5. Launches `pywebview` pointing to the loopback URL.
6. The `pywebview` engine starts a native browser frame (Chromium/WebView2 on Windows, WebKit on macOS/Linux), disabling external page navigation and exposing developer tools only in debug mode.

---

## Deployment

The application is bundled into a single-file executable using PyInstaller:
- Python runtime, Flask backend, static assets, templates, and libraries are compressed into a single package.
- On startup, the executable decompresses the runtime files to a temporary directory (`_MEI...`) and executes [run.py](run.py).
- Windows builds configure display affinity flags to obscure the screen capture interface.
