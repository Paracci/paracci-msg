# Paracci Secure Messaging

Paracci is an offline secure messaging application built around `.paracci`
envelope files, encrypted local session metadata, single-use burn tracking, and
OS-specific security shields.

The active migration target is dual-native:

- Windows/Linux: PySide6 Qt Quick/QML shell over the Python UI API.
- macOS: SwiftUI/AppKit shell over the Python stdio JSON-RPC worker.
- Fallback/reference: the earlier Qt Widgets shell is retained temporarily behind
  `python run.py --ui widgets`.

The previous Flask + pywebview UI is no longer the launch path.

## Current Architecture

- `run.py`: native desktop launcher. Defaults to QML on Windows/Linux.
- `paracci/ui_api/`: JSON-safe UI facade above native services.
- `paracci/bridge/worker.py`: newline-delimited JSON-RPC worker for macOS.
- `paracci/desktop/qml_app.py`: Qt Quick/QML shell and Python controller.
- `platform/macos/ParacciMac/`: SwiftUI/AppKit macOS app scaffold.
- `paracci/desktop/qt_app.py`: temporary Qt Widgets fallback/reference.
- `paracci/core/`: cryptography, session setup, envelopes, package handling,
  burn registry, config, and OS shields.

## Security Model

- All messaging remains file-based and offline.
- Existing `.paracci` files, `sessions.db`, `config.json`, and i18n JSON files
  remain compatible.
- The native app removes the loopback web server, browser DOM, JavaScript
  bridge, web downloads, and WebView runtime from normal operation.
- macOS presentation calls Python through stdio JSON-RPC, not HTTP.
- Decrypted messages and attachments are short-lived UI/API state and are
  cleared from the reading room cache when closed or locked.
- Anti-screenshot protection is platform honest: Windows is strongest, macOS is
  best-effort through window sharing restrictions, and Linux varies by
  compositor/session.

## Install And Run

```powershell
python -m venv .venv
.\.venv\Scripts\activate
pip install -r requirements.txt
python run.py
```

Useful development launch options:

```powershell
python run.py --user x
python run.py --user y
python run.py --ui widgets
python run.py --data-dir C:\Users\you\AppData\Roaming\Paracci
```

## macOS App

The SwiftUI shell lives under `platform/macos/ParacciMac` and uses
`PARACCI_WORKER_PATH` during development:

```bash
cd platform/macos/ParacciMac
PARACCI_WORKER_PATH=/absolute/path/to/paracci/bridge/worker.py swift run ParacciMac
```

Packaging will bundle the Python runtime and worker inside the `.app`.

## Design Source

Figma design file:
[Paracci Dual-Native Redesign](https://www.figma.com/design/O1kQi5Y1sWhrRe5pZdDJWs)

The file contains foundations, component specs, macOS frames, Windows/Linux QML
frames, and QA comparison frames within the account's three-page limit.

## Native Data Migration

On first native launch without an explicit `--data-dir`, Paracci selects the OS
data location through `core/shields` and copies the legacy `paracci/data`
directory into that location if the native directory is empty. The source data is
not modified. A `.native_migration.json` marker is written after SQLite
integrity and config JSON validation. Encrypted session metadata decryptability
is verified after the user unlocks, when the device key is available.

## Tests

```powershell
python -m pytest paracci\tests -q
python paracci\audits\guardian.py
```

The tests include core protocol compatibility, native service coverage, UI API
command coverage, JSON-RPC worker mapping, QML smoke/visual coverage, and macOS
SwiftPM worker bridge coverage in the macOS CI lane.

## Build

Paracci ships pre-built standalone executables — no Python installation needed.

### Local build (current platform)

```powershell
# Windows
pip install -r requirements.txt
python build.py --install --clean
# Output: builds/windows/Paracci.exe
```

```bash
# macOS / Linux
pip install -r requirements.txt
python build.py --install --clean
# Output: builds/macos/Paracci-macOS  OR  builds/linux/Paracci-Linux
```

### Automated release builds (GitHub Actions)

Push a version tag to trigger the full pipeline:

```bash
git tag v1.0.0
git push origin v1.0.0
```

GitHub Actions builds on Windows, macOS, and Linux in parallel, then publishes
a GitHub Release containing all three binaries.

---

## Security Verification

Every release binary can be independently verified through three mechanisms.

### 1 — SHA-256 Checksums

Each release includes a `SHA256SUMS.txt` file. Verify your download:

```powershell
# Windows (PowerShell)
(Get-FileHash Paracci.exe -Algorithm SHA256).Hash
```

```bash
# macOS / Linux
sha256sum Paracci-Linux
sha256sum Paracci-macOS.zip
```

Compare the output against the hash in `SHA256SUMS.txt` attached to the release.

### 2 — Build Provenance Attestation (Sigstore / SLSA Level 2)

Every binary is cryptographically signed by GitHub's Sigstore integration.
The signature proves the file was built from a specific, unmodified commit of
this repository — not from a tampered or third-party source.

```bash
# Requires GitHub CLI (gh)
gh attestation verify Paracci.exe --repo <owner>/paracci-msg
gh attestation verify Paracci-Linux --repo <owner>/paracci-msg
```

Or browse attestations directly:
`https://github.com/<owner>/paracci-msg/attestations`

### 3 — VirusTotal Scan (automated)

After each release is published, GitHub Actions automatically submits all three
binaries to [VirusTotal](https://www.virustotal.com) and appends the scan report
links to the release notes.

> **Note on AV heuristics:** PyInstaller bundles the Python interpreter inside
> the executable. Some antivirus engines flag this "packing" technique as
> heuristic-suspicious even when the code is entirely clean. The full source
> code is open and auditable in this repository.

### 4 — Source Code Audit

The entire application is open source. You can run directly from source without
trusting any binary:

```bash
git clone https://github.com/<owner>/paracci-msg
cd paracci-msg
pip install -r requirements.txt
python run.py
```
