# Core Modules

`paracci/core` remains independent of the UI. Both the native Qt layer and any
future CLI/test harnesses should call these modules through `desktop/services.py`
unless they are protocol tests.

## `crypto.py`

Provides X25519 key generation/ECDH, HKDF-SHA512 derivation,
ChaCha20-Poly1305 encryption, Argon2id PIN/session work factors, message IDs,
fingerprints, hashes, and best-effort memory hygiene helpers.

## `session.py`

Owns X/Y session setup:

- initiator file creation
- responder file creation
- initiator finalization
- bond nonce handling
- encrypted `SessionMeta` serialization for SQLite

## `envelope.py`

Owns `.paracci` message files. The stable public API is:

```python
seal_envelope(payload_bytes, session, single_use=True, ttl_seconds=0)
open_envelope(file_bytes, session)
```

The module preserves the v2 message format with a 52-byte header, payload block,
sync block, and 16-byte authenticity seal.

## `package.py`

Builds and extracts the encrypted ZIP payload containing `message.md`,
`metadata.json`, attachments, and random padding.

## `burn.py`

Provides `BurnDB`, device key initialization/unlock, burn registry, 2FA metadata
storage primitives, and secure-delete delegation.

## `config.py`

Loads and saves `config.json` under `DATA_DIR`.

## `shields/`

Implements OS-specific best-effort security integration:

- Windows: screen capture reduction, best-effort delete, clipboard auto-clear,
  recent-doc cleanup.
- macOS: data directory, best-effort delete, clipboard auto-clear, recent-doc
  cleanup, and best-effort window sharing restriction.
- Linux: XDG data directory, `shred` fallback, clipboard tools, recent-doc
  cleanup, and an explicit unimplemented capture-reduction stub.

See `SECURITY_SHIELDS.md` before changing shield guarantees or product copy.
