# Security Shields & Platform Protection

Paracci implements OS-specific security integrations and platform shields as defense-in-depth measures to reduce data exposure. These shields are best-effort controls; they do not guarantee absolute protection against physical memory acquisition, hardware-level capture, compromised system clipboards, or advanced filesystem forensics.

## Common Limitations

- **Burn Semantics**: Once a message envelope is opened, its unique ID is permanently recorded in the local SQLite database registry. An opened envelope cannot be opened again on this device. Copies on other devices or storage locations are not affected by this local registry.
- **Memory Retention**: Python strings, Python `bytes`, and bytearrays are immutable in memory. Paracci clears its own direct references upon closing or locking, but copies may temporarily persist in the Python runtime garbage collector, Flask response buffers, webview engine cache, or operating system swap space.
- **Clipboard Exposure**: The clipboard auto-clear feature attempts to erase copied data after a user-defined delay. Native Windows copies are marked to prevent admission to built-in Clipboard History and cloud clipboard sync. Existing history entries, browser-only copies, and third-party clipboard managers remain outside that protection.
- **Secure File Deletion**: Paracci uses secure-delete logic to overwrite file blocks and deletes them from the filesystem. Journaling filesystems, SSD wear-leveling algorithms, system snapshots, cloud-sync daemons, and system backups may still retain copies of the data on physical storage.
- **System Logs & Recent Items**: Paracci attempts to clean up references from system recent-documents queues, but system shell indexes or search providers may index filenames and access metadata.

---

## Device Key Protection

To mitigate offline storage decryption attacks, Paracci binds its local database encryption key to both the user's passphrase and the platform's secure credential store. Unlocking the database requires both the passphrase and the active platform-native user session (a two-factor model):

- **Windows DPAPI**: Binds the device key using the Windows Data Protection API (DPAPI). Keys are protected by Windows credentials tied to the active user account session. See [dpapi_win.py](paracci/desktop/dpapi_win.py).
- **macOS Keychain**: Stores key factors in the macOS system Keychain via the Security.framework, restricting access to the logged-in macOS user. See [keychain_mac.py](paracci/desktop/keychain_mac.py).
- **Linux Secret Service**: Integrates with the `org.freedesktop.secrets` D-Bus API to store key factors in the active keyring daemon (e.g., GNOME Keyring, KWallet). Falls back to passphrase-only security if no keyring is running. See [secret_service_linux.py](paracci/desktop/secret_service_linux.py).

Platform routing and fallbacks are coordinated by [device_key_binding.py](paracci/desktop/device_key_binding.py).

---

## Key Hardening (Argon2id)

The local device key is derived from the user's passphrase using Argon2id with fixed parameters (t=2, m=64MB, p=4), which meet OWASP minimum recommendations. This is the correct use of Argon2id for low-entropy user input. Active session and message keys come from high-entropy hybrid X25519 + ML-KEM-768 material expanded with HKDF-SHA512; they are not processed with Argon2id. A legacy-only Argon2 read path remains for queued v1/v2 envelopes created by older versions.
- **Post-Quantum Security**: Paracci uses a hybrid X25519 + ML-KEM-768 key exchange. Both classical and post-quantum secrets must be compromised to break the session key.
- **Transcript Identity Binding**: Session keys are bound to both parties' Ed25519 identity keys via a handshake transcript (SHA3-256). Unknown-key-share resistance is reinforced at the key derivation layer, not only at the signature verification layer.

---

## Ordered Message Opening and Ratchet Progression

Paracci intentionally enforces monotonic receive-key progression. If a user opens
`msg_step_000010_*.paracci` before `msg_step_000009_*.paracci`, the receive
ratchet advances through step 10. The step 9 envelope is then older than the
current receive state and can never be decrypted on that device.

This is deliberate. Supporting late or out-of-order decryption would require
retaining skipped receive-key material or intermediate ratchet states, increasing
sensitive state and attack surface. Paracci prioritizes key hygiene over delivery
flexibility.

Open message envelopes in received step order. New message filenames include the
step number to help users sort pending files before opening; older filenames may
not.

Known limitation: this protocol is intended for careful, ordered file exchange,
not high-volume or out-of-order messaging.

---

## Local Loopback Threat Model

Paracci runs a local Flask server wrapped by a `pywebview` shell. This loopback architecture is not a native IPC channel, and its security relies on several strict boundaries:
- **Port Isolation**: Flask binds strictly to `127.0.0.1` on a randomly assigned port.
- **Access Authentication**: All privileged backend routes require a unique, cryptographically random bearer token generated at launch.
- **Header & CSRF Validation**: The server validates Host, Origin, Referer, and Fetch Metadata headers to block cross-origin requests. CSRF tokens are enforced on all unsafe methods.
- **Sandboxed WebView**: The `pywebview` window blocks all navigation to external domains and disables developer inspector tools (unless debug mode is enabled).

### Navigation Security

External navigation is blocked via a JavaScript guard injected on window load. All external links in rendered message content are neutralized before DOM insertion.

### Preview System Security

- **Token Isolation**: Preview windows are isolated from main app privileges by exposing a limited, token-scoped `PreviewWindowApi` instead of the privileged `ProApi`. Preview URLs require cryptographically secure random tokens.
- **Server-Side Download Enforcement**: The server routes check the `allow_download` property of the preview entry. If downloads are prohibited, attempts to download or fetch the original attachment binary return HTTP 403, and image previews are dynamically degraded and watermarked.

---

## Platform Shield Matrix

| Platform | Capture Reduction | Secure File Delete | Clipboard Clear |
| --- | --- | --- | --- |
| **Windows** | Attempts `SetWindowDisplayAffinity` to hide the window from capture software. Does not block physical cameras, remote desktop software, or administrator-level capture tools. | Best-effort overwrite/delete via Windows filesystem calls. | Native copies auto-clear after delay and use `ExcludeClipboardContentFromMonitorProcessing` to avoid new built-in Win+V/cloud-history entries; earlier or third-party history remains possible. |
| **macOS** | Attempts `NSWindowSharingNone` to restrict window sharing. Does not block native screenshots, screen recordings, or hardware capture. | Best-effort overwrite/delete via Unix filesystem commands. | Auto-clear after delay; Paracci implements no system clipboard-history control on macOS. |
| **Linux** | Unimplemented. Screenshot blocking is compositor-specific and not supported across X11 and Wayland environments. | Best-effort `shred` or overwrite/delete. | Auto-clear using `xclip` or `wl-copy` if installed; Paracci implements no system clipboard-history control on Linux. |

When the UI is opened in browser-only mode, it cannot add the Windows native history-exclusion marker. Paracci warns users in that path to clear operating-system clipboard history manually when applicable.

---

## Contributor Copywriting Rules

- **Recommended Terms**: Use "best-effort", "attempts", "reduces exposure", "drops references", and "auto-clears after a delay".
- **Prohibited Terms**: Avoid "prevents screenshots", "guarantees deletion", "wipes instantly", "securely deletes", "erases RAM", and "cannot be recovered".
