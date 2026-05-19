# System Architecture

Paracci is built around an offline, secure file-exchange messaging model. It integrates a local Flask backend service wrapped in a native `pywebview` windowing shell.

## Layers

### 1. Web Front-End (`paracci/app/templates/` and `paracci/app/static/`)

The user interface is designed using modern CSS layouts and custom components:
- **HTML/CSS templates**: Rendered by Flask, styled with HSL tokens, and optimized for seamless desktop dimensions.
- **JavaScript UI Controllers (`auth.js`, `session.js`, `app.js`)**: Handle client-side interactions, dynamic DOM rendering, inline message sanitization (via DOMPurify), code-copy operations, and input verification.
- **Strict Content Security Policy (CSP)**: Ensures all inline scripting, attribute execution (`script-src-attr 'none'`), and unauthorized resource loads are blocked.

### 2. Local Flask Server (`paracci/app/routes.py`)

A local web server handles application routing and API endpoints:
- Exposes REST endpoints to the Web UI for loading data, sealing envelopes, verifying passwords/2FA, and importing files.
- Binds strictly to `127.0.0.1` (localhost) on a randomly assigned port (unless overridden).
- Enforces strict token-based session validation to prevent unauthorized local processes from accessing the endpoints.

### 3. Shared UI API (`paracci/ui_api/facade.py`)

A stable bridge between the Flask server routes and the underlying core services:
- Transforms internal python objects into JSON-safe Data Transfer Objects (DTOs).
- Restricts file-heavy operations to path-based references.

### 4. Native Desktop Services (`paracci/desktop/services.py`)

Coordinates platform-native system utilities:
- `DeviceService`: Manages initialization, lock, unlock, 2FA setup, and encrypted TOTP secret persistence.
- `SessionService`: Loads and saves sessions, coordinates handshakes, and computes evolution metadata.
- `MessageService`: Encrypts/decrypts envelope files and coordinates message burn operations.
- `SettingsService`: Manages localized user configuration files.
- `I18nService`: Standardized translation helper that reads static internationalization dictionaries.
- `ShieldService`: Coordinates platform-specific anti-forensics adapters.

### 5. Core Engine (`paracci/core/`)

The cryptographic and logic core:
- `crypto.py`: Implements primitives including X25519 key exchange, HKDF-SHA512, ChaCha20-Poly1305 AEAD, and Argon2id.
- `session.py`: Coordinates Handshake V2 steps (initiator/responder file generation) and derives session key seeds.
- `envelope.py`: Packages encrypted message payloads and attachment ZIP archives.
- `package.py`: Manages in-memory ZIP extraction and safety limits (uncompressed size, entry count, compression ratio).
- `burn.py`: Enforces database transaction-bound message burn registries and device key storage.
- `shields/`: Contains platform-specific implementations (Windows, macOS, Linux) for clipboard clearing, anti-screenshot protection, and recent document cleanup.

---

## Startup Flow

1. `run.py` parses command-line arguments and sets up data directories.
2. Clears system-level recent-items queues and sweeps expired temporary directories.
3. Launches a background thread to run the Flask web daemon.
4. Generates a secure random bootstrap token and constructs a loopback launch URL.
5. Launches `pywebview` pointing to the loopback URL.
6. The `pywebview` engine starts a native browser frame (Chromium via WinForms on Windows, WebKit on macOS/Linux), disabling external page navigation and exposing developer tools only in debug mode.

---

## Deployment

The application is bundled into a single-file executable using PyInstaller:
- Python runtime, Flask backend, static assets, templates, and libraries are compressed into a single package.
- On startup, the executable decompresses the runtime files to a temporary directory (`_MEI...`) and executes `run.py`.
- Windows builds configure display affinity flags to obscure the screen capture interface.
