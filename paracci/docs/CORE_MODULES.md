# Core Modules

The modules in `paracci/core` are independent of the web and desktop UI layers. Other layers (such as UI API controllers or test suites) interact with these modules via native Python imports or through the native desktop services layer.

## [constants.py](paracci/core/constants.py)

Contains frozen protocol-stable byte constants and labels. This layer ensures long-term backwards compatibility across files, sessions, and database structures.

## [crypto.py](paracci/core/crypto.py)

Provides cryptographic primitives:
- X25519 key pair generation and ECDH key exchange.
- Hybrid X25519 + ML-KEM shared-secret combination through `derive_hybrid_shared_secret`.
- HKDF-SHA512 and HKDF-SHA256 derivation.
- ChaCha20-Poly1305 AEAD symmetric encryption.
- Fixed-parameter Argon2id device master-key derivation for user passphrases.
- Message ID generation, cryptographic hashing, and process memory wipe/hygiene helpers.

## [quantum_kem.py](paracci/core/quantum_kem.py)

Wraps ML-KEM-768 operations behind a small API:
- `kem_generate_keypair()`
- `kem_encapsulate(public_key)`
- `kem_decapsulate(secret_key, ciphertext)`

This is the only core module that imports `liboqs-python`.

## [hybrid_kem.py](paracci/core/hybrid_kem.py)

Coordinates the post-quantum side of the session handshake:
- Initiator ML-KEM key generation.
- Responder encapsulation.
- Initiator decapsulation.
- Validation of v3 hybrid setup metadata and legacy-session rejection.

## [session.py](paracci/core/session.py)

Coordinates the two-party hybrid session setup. Active sessions use the v4 signed plaintext JSON handshake format, while legacy sessions are initialized via the v3 wrapped handshake format. Handshake files (initiator and responder setup files) carry signed public metadata, including ML-KEM public data and ciphertext. They are integrity-protected but **not confidential**. Session keys are derived from the hybrid X25519 + ML-KEM shared secret and evolved deterministically.

- Initiator and responder setup file creation (v4 plaintext JSON format).
- Backward-compatible legacy v3 wrapped handshake parsing and import.
- Session bonding ceremonies.
- Serialization of encrypted session metadata stored in the database.

## [preview_store.py](paracci/core/preview_store.py)

Thread-safe, in-memory store for short-lived preview tokens. Coordinates preview sessions:
- Generates 32-byte cryptographically secure random tokens.
- Manages `PreviewEntry` objects (RAM-only file bytes, filename, mime type, and download flags).
- Enforces time-to-live (TTL) validation and background token revocation.

## [envelope.py](paracci/core/envelope.py)

Manages `.paracci` message files. The stable public API is:

```python
seal_envelope(payload_bytes, session, single_use=True, ttl_seconds=0)
open_envelope(file_bytes, session)
```

Envelopes use the active v2 format (HEADER + payload_len + payload_nonce + payload_ciphertext + sync_nonce + sync_ciphertext) and are encrypted and authenticated using ChaCha20-Poly1305 AEAD and session-derived keys, removing the hardcoded HMAC seal used in v1. Each envelope includes a unique message ID and step identifier to prevent replay attacks and unauthorized access. Legacy v1 envelopes with the former outer seal remain readable by stripping that trailer before parsing, but envelope authenticity and integrity are strictly provided by AEAD authentication.

## [package.py](paracci/core/package.py)

Handles in-memory assembly and parsing of the encrypted envelope ZIP payload containing `message.md`, `metadata.json`, optional attachments, and random padding to prevent traffic analysis.

## [burn.py](paracci/core/burn.py)

Enforces single-use and TTL guarantees:
- Manages the SQLite-based `BurnDB` store.
- Enforces burn semantics: once an envelope is registered as opened, it cannot be opened again on this device. Copies of the envelope on other devices or storage locations are unaffected.
- Manages device-key storage and unlock. The device key uses fixed Argon2id parameters; configurable workload profiles belong to session and envelope key hardening.
- Integrates local rate-limiting and lockout durations to block automated brute-force attacks on the local vault.
- Coordinates secure file-overwrite and deletion routines.

## [config.py](paracci/core/config.py)

Loads and saves localized user parameters in `config.json`.

## [shields/](paracci/core/shields/)

Coordinates platform-dependent exposure mitigation adapters (such as anti-screenshotting, clipboard cleanup, and recent-items sweeps). See [SECURITY_SHIELDS.md](paracci/docs/SECURITY_SHIELDS.md) for full capability details.
