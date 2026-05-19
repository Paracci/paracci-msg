# Paracci Secure Messaging

Paracci is an offline secure messaging application built around `.paracci` envelope files, encrypted local session metadata, single-use burn tracking, and OS-specific security shields.

The application uses a **Flask + pywebview** architecture to deliver a native, high-performance desktop application interface while maintaining robust security boundaries.

## Architecture

- **`run.py`**: The desktop launcher. Starts a background Flask daemon thread bound strictly to a random local loopback port, then instantiates a native `pywebview` window (Chromium on Windows, WebKit on macOS/Linux).
- **`paracci/app/`**: Flask backend logic (`routes.py`, `i18n_manager.py`) and Web UI assets (`templates/`, `static/`).
- **`paracci/core/`**: Cryptography primitives, envelope packaging, session management, burn registry, config, and OS-specific security shields.
- **`paracci/desktop/`**: Native desktop system helper services.
- **`paracci/audits/`**: Internal QA security, dependency, performance, and translation auditing suite.

## Security Model

- **Local-Only Isolation**: The loopback web server binds strictly to `127.0.0.1` on a dynamically requested random free port, preventing external network exposure.
- **Navigation Guard**: The native WebView window blocks all outbound page navigations to external URLs, ensuring code execution remains strictly within the local environment.
- **Platform-Native Shields**:
  - **Screen Capture Reduction**: Uses best-effort native OS APIs where available (for example, `SetWindowDisplayAffinity` on Windows) to reduce common window capture exposure.
  - **Clipboard Auto-Clear**: Copies decrypted text to the clipboard with an automated clearing timeout; local processes may read clipboard contents before clearing.
  - **Recent-Item Cleanup**: Attempts to sweep known "Recent Documents" locations on startup, without guaranteeing complete forensic trace removal.
- **Memory-Bound Decryption**: Decrypted message payloads and attachments are dropped from Paracci-controlled caches on close, lock, or navigation; Python, browser, OS, and library copies may still exist outside direct control. See [`paracci/docs/SECURITY_SHIELDS.md`](paracci/docs/SECURITY_SHIELDS.md).

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

## Tests and Auditing

Run the test suite and internal security audits to verify protocol integrity:

```powershell
# Run all unit and integration tests
python -m pytest paracci\tests -q

# Audit locked Python dependencies
python -m pip_audit -r requirements.lock -r requirements-dev.lock

# Run the automated security and dependency audit suite
python paracci\audits\guardian.py
```

## Build & Release

Paracci compiles into single-file, standalone executable binaries. No Python environment is required to run the packaged applications.

### Local Compilation (Current OS)

```powershell
# Windows
python build.py --install --clean
# Output: builds/windows/Paracci.exe

# macOS / Linux
python build.py --install --clean
# Output: builds/macos/Paracci-macOS  or  builds/linux/Paracci-Linux
```

### Automated GitHub Release Workflow

Pushing a version tag triggers the parallel multi-platform packaging pipeline:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions compiles the binaries for Windows, macOS, and Linux in parallel, signs them using Sigstore build provenance attestations, performs automated VirusTotal scans, and publishes them under GitHub Releases.

## License

This software is licensed under the custom **Paracci Source-Available License (Version 1.0)**. 
- You are granted the right to read and audit the source code for security verification and educational use.
- You are strictly prohibited from distributing compiled binaries, creating derivative works, or modifying the application's built-in self-integrity verification and security shields.
- See the [LICENSE](LICENSE) file for the full legal terms.
