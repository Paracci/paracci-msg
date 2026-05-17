# ParacciMac

Native macOS SwiftUI/AppKit shell for Paracci Secure Messaging.

The SwiftUI app owns presentation, windows, commands, settings, file panels, and
platform behavior. It talks to the Python protocol core through
`paracci/bridge/worker.py` using newline-delimited JSON-RPC over stdio. It must
not start a local HTTP server, embed WebView/WebEngine, or duplicate protocol
logic.

Development launch:

```bash
PARACCI_WORKER_PATH=/absolute/path/to/paracci/bridge/worker.py swift run ParacciMac
```

Packaging will bundle the Python runtime, `paracci` package, and worker script
inside the `.app`; codesign and notarization are tracked as release gates.
