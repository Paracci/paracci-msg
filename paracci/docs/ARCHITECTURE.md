# Dual-Native System Architecture

Paracci is moving to a dual-native application model while keeping the Python
protocol and persistence layers authoritative.

## Layers

### 1. Shared UI API (`ui_api/`)

`paracci/ui_api/facade.py` is the stable boundary above native services. It
returns JSON-safe DTOs only and keeps file-heavy operations path-based. Opened
attachments are held in a short-lived cache keyed by `open_id` and
`attachment_id`.

### 2. Windows/Linux UI (`desktop/qml_app.py` and `desktop/qml/`)

The active Windows/Linux shell uses PySide6 Qt Quick/QML. Python controllers
expose UI API commands to QML through `QObject` slots/signals. This shell must
not import Qt Widgets, WebEngine, WebView, Flask, or pywebview.

`desktop/qt_app.py` remains as an explicit fallback/reference only.

### 3. macOS UI (`platform/macos/ParacciMac/`)

The macOS app is SwiftUI/AppKit. SwiftUI owns presentation, sidebars, toolbars,
settings, inspector layout, and commands. AppKit bridges are reserved for narrow
platform behavior such as window sharing restrictions and secure clipboard
handling.

Swift talks to Python through `paracci/bridge/worker.py`, a stdio
newline-delimited JSON-RPC process. There is no localhost listener.

### 4. Native Services (`desktop/services.py`)

Services replace the old Flask route-owned workflows:

- `DeviceService`: init, unlock, lock, 2FA verification, encrypted 2FA secret
  storage.
- `SessionService`: list/load/save sessions, create/import/finalize handshakes,
  export handshake files, fingerprint/evolution summaries.
- `MessageService`: package attachments, seal messages, open messages, burn
  single-use IDs, and return in-memory reading-room DTOs.
- `SettingsService`: existing `config.json` wrapper.
- `I18nService`: Flask-free JSON translation loader.
- `ShieldService`: OS security adapter wrapper.

### 5. Core (`core/`)

The core remains the protocol and security source of truth:

- `crypto.py`: X25519, HKDF-SHA512, ChaCha20-Poly1305, Argon2id, IDs, hashes.
- `session.py`: X/Y handshake, encrypted session metadata, session files.
- `envelope.py`: stable public API for `.paracci` message files.
- `package.py`: ZIP package for markdown text, metadata, and attachments.
- `burn.py`: SQLite persistence, device unlock key, burn registry.
- `shields/`: OS-specific clipboard, secure delete, recent-doc clearing, and
  anti-screenshot support.

## Startup

1. `run.py` parses launch arguments and selects `desktop.qml_app` by default.
2. `desktop.services.configure_data_dir()` selects or migrates the native data
   directory.
3. Recent documents are cleared where supported.
4. Auto-cleanup deletes old `.paracci` files from the configured downloads dir.
5. Windows/Linux launch the QML shell.
6. macOS release builds launch the SwiftUI app, which starts the Python worker.

## Compatibility

The migration preserves:

- `.paracci` initiator, responder, and message files
- `sessions.db`
- encrypted session metadata AAD labels
- burn registry rows
- `config.json`
- i18n JSON files
- core protocol constants and header offsets

2FA secrets are upgraded on read: legacy plaintext `device_meta.2fa_secret`
values are re-encrypted with the unlocked device key under
`2fa_secret_enc_v1`, then the legacy plaintext key is removed.

## Envelope API

`core/envelope.py` exposes the frozen compatible API:

```python
seal_envelope(payload_bytes, session, single_use=True, ttl_seconds=0) -> SealedEnvelope
open_envelope(file_bytes, session) -> OpenedEnvelope
```

## Deployment

Windows/Linux use PySide6 deployment with QML assets included. macOS uses the
SwiftUI app bundle plus a bundled Python runtime and worker. Both paths must
pass core, service, UI API, worker, security, and packaging smoke gates before
the Qt Widgets fallback is removed.
