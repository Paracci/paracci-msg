# Native Application Layer

The application layer is split by platform while sharing one Python service/UI
API boundary.

## Shared Boundary

`paracci/ui_api` exposes device, 2FA, settings, sessions, message, attachment,
profile, and armor-report commands as JSON-safe DTOs. It does not expose raw
protocol objects to either frontend.

## Windows/Linux

`paracci/desktop/qml_app.py` loads `paracci/desktop/qml/Main.qml` and exposes the
UI API through a `QObject` controller. QML owns the premium custom shell,
navigation, toolbar, composer, reading room, inspector, and native file-dialog
workflows.

## macOS

`platform/macos/ParacciMac` is a SwiftUI/AppKit app. It owns native sidebars,
toolbars, commands, settings, inspectors, file panels, and platform-specific
window behavior. It calls `paracci/bridge/worker.py` over stdio JSON-RPC.

## Temporary Fallback

`paracci/desktop/qt_app.py` remains available through `python run.py --ui
widgets` until QML and SwiftUI parity gates pass.

## Native State

The native app does not use:

- Flask cookies
- browser `localStorage`
- `fetch`
- `FormData`
- DOMPurify
- marked.js
- pywebview JavaScript bridges
- local HTTP routes
- WebView or WebEngine rendering

Sensitive opened-message state is cleared from the UI API cache when the reading
room closes, the opened item is cleared, or the device locks. This is best-effort
process memory hygiene, not a claim of perfect memory zeroization.
