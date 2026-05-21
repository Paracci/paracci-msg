# Security Shields & Platform Protection

Paracci implements OS-specific security integrations and platform shields as defense-in-depth measures to reduce data exposure. These shields are best-effort controls; they do not guarantee absolute protection against physical memory acquisition, hardware-level capture, compromised system clipboards, or advanced filesystem forensics.

## Common Limitations

- **Burn Semantics**: Once a message envelope is opened, its unique ID is permanently recorded in the local SQLite database registry. An opened envelope cannot be opened again on this device. Copies on other devices or storage locations are not affected by this local registry.
- **Memory Retention**: Python strings, Python `bytes`, and bytearrays are immutable in memory. Paracci clears its own direct references upon closing or locking, but copies may temporarily persist in the Python runtime garbage collector, Flask response buffers, webview engine cache, or operating system swap space.
- **Clipboard Exposure**: The clipboard auto-clear feature erases copied data after a user-defined delay. However, malicious processes or clipboard managers running on the host system can read clipboard contents before the clear command runs.
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

The local device key is derived from the user's passphrase using Argon2id with fixed parameters (t=2, m=64MB, p=4), which meet OWASP minimum recommendations. Configurable cost profiles (standard, paranoid, and quantum/Maximum) are applied to session and envelope key hardening, not to device key derivation.
- **Post-Quantum Security**: Paracci uses a hybrid X25519 + ML-KEM-768 key exchange. Both classical and post-quantum secrets must be compromised to break the session key. Argon2id hardening is a separate key-hardening layer, not a replacement for the hybrid exchange.

---

## Local Loopback Threat Model

Paracci runs a local Flask server wrapped by a `pywebview` shell. This loopback architecture is not a native IPC channel, and its security relies on several strict boundaries:
- **Port Isolation**: Flask binds strictly to `127.0.0.1` on a randomly assigned port.
- **Access Authentication**: All privileged backend routes require a unique, cryptographically random bearer token generated at launch.
- **Header & CSRF Validation**: The server validates Host, Origin, Referer, and Fetch Metadata headers to block cross-origin requests. CSRF tokens are enforced on all unsafe methods.
- **Sandboxed WebView**: The `pywebview` window blocks all navigation to external domains and disables developer inspector tools (unless debug mode is enabled).

---

## Platform Shield Matrix

| Platform | Capture Reduction | Secure File Delete | Clipboard Clear |
| --- | --- | --- | --- |
| **Windows** | Attempts `SetWindowDisplayAffinity` to hide the window from capture software. Does not block physical cameras, remote desktop software, or administrator-level capture tools. | Best-effort overwrite/delete via Windows filesystem calls. | Auto-clear after delay; contents remain readable before clearing. |
| **macOS** | Attempts `NSWindowSharingNone` to restrict window sharing. Does not block native screenshots, screen recordings, or hardware capture. | Best-effort overwrite/delete via Unix filesystem commands. | Auto-clear after delay; contents remain readable before clearing. |
| **Linux** | Unimplemented. Screenshot blocking is compositor-specific and not supported across X11 and Wayland environments. | Best-effort `shred` or overwrite/delete. | Auto-clear using `xclip` or `wl-copy` if installed; contents remain readable before clearing. |

---

## Contributor Copywriting Rules

- **Recommended Terms**: Use "best-effort", "attempts", "reduces exposure", "drops references", and "auto-clears after a delay".
- **Prohibited Terms**: Avoid "prevents screenshots", "guarantees deletion", "wipes instantly", "securely deletes", "erases RAM", and "cannot be recovered".
