# Test Structure And Scope

Run the full Python release gate from the repository root:

```powershell
python -m pytest paracci\tests -q
```

Run audits:

```powershell
python paracci\audits\guardian.py
```

## Covered Areas

- Cryptography primitives: X25519, HKDF, ChaCha20-Poly1305, AAD tamper
  rejection, message ID fingerprints.
- Evolution and ratchet behavior: deterministic steps, bond seed derivation,
  expiry handling.
- Session lifecycle: initiator creation, responder import, initiator finalize,
  encrypted session metadata round trips.
- Envelope protocol: X-to-Y and Y-to-X messages, bond nonce ceremony, self-open
  rejection, tampered file rejection, TTL rejection, wrong-session rejection.
- Burn/device persistence: single-use burn registry, TTL pre-checks, PIN-based
  device unlock.
- Native services: Flask-free session/message round trip, encrypted 2FA metadata
  upgrade, and first-launch data copy behavior.
- UI API: command coverage, JSON-safe DTOs, path-based file operations, opened
  attachment cache, and save-permission enforcement.
- Worker bridge: JSON-RPC success/error envelope mapping.
- QML shell: offscreen load and controller error mapping.
- QML visual smoke: nonblank shell render at `900x640`, `1180x820`, and
  `1440x900`.
- macOS SwiftPM: worker bridge round trip through `swift test` on macOS CI.

## Current Gaps

- SwiftUI tests require macOS and run under SwiftPM in the macOS CI lane.
- Packaging smoke tests still need Windows, Ubuntu, and macOS runners with real
  app launch, unlock, session import/create, seal/open, save/export, and clean
  close.
- Visual regression checks for QML/macOS frames are planned after the platform
  shells reach workflow parity.
