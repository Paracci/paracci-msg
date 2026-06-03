# Security Engineering Invariants

Paracci is an offline-first desktop application that handles encrypted message envelopes, local device keys, and short-lived preview capabilities. These invariants are repo-safe guardrails for maintainers and coding agents. They intentionally describe security classes and required behaviors, not private audit material or exploit details.

## Release And Updater Trust

- The updater signing private key must remain offline. CI must not sign updater-trusted manifests with an online repository secret.
- CI may build release assets and draft releases, but the updater-trusted manifest signature must come from the offline signing ceremony.
- Release manifests must be recomputed from the actual assets that will be published, then verified before publication. Do not trust prepackaged manifest files from build outputs without rehashing the release assets.
- Publishing must fail closed if expected assets are missing, duplicated, renamed unexpectedly, mismatched, or signature verification fails.

## Device Unlock And 2FA

- 2FA-enabled profiles must never become active from passphrase-only native unlock.
- A native unlock may prove the passphrase and device binding, but the profile stays pending until the required TOTP verification succeeds.
- Failed or expired pending unlock state must not leave usable decrypted key material behind.

## Input Size And Parsing

- Setup, responder, and `.paracci` message envelopes must enforce size caps before read, parse, decrypt, unpack, or schema handling.
- Size limits must apply consistently across Flask routes, native UIApi import/open flows, and core package/envelope entry points.
- Inner package extraction limits remain defense-in-depth; they do not replace outer pre-read and pre-parse caps.

## Log Redaction

- Rejection and security logs must use allowlisted diagnostic fields.
- Logs must not include bearer tokens, preview tokens, CSRF values, session identifiers, secrets, private keys, passphrases, decrypted content, raw request bodies, or sensitive local paths.
- Rejection logs should identify the route shape and rejection class without recording attacker-controlled sensitive values.

## Dependency Integrity

- Runtime dependencies must be exact-pinned and hash-locked.
- Native cryptography dependencies must be pinned to an immutable commit or digest and verified before build or cache reuse.
- Do not add ad hoc install steps that bypass lockfiles, hash checks, or native source verification.
- Dependency integrity controls belong in requirements, workflows, build actions, and audit tests together.

## Preview Safety

- Preview content must not inline active or ambiguous MIME types on the local app origin.
- Non-image, active, ambiguous, or unsafe preview bytes must be rejected or forced into download-safe handling according to the current preview policy.
- Image decoding must enforce pixel, dimension, frame-count, and decompression budgets before producing displayable previews.
- Preview windows must block external navigation consistently for clicks, forms, scripted opens, and window-location changes.
- Preview capability tokens narrow attachment access; they must not expand into general loopback authority or privileged native bridge access.

## Protocol Bonding

- `bond_nonce` is valid only for the initial unbonded X-to-Y step 0 bonding envelope.
- Post-bond envelopes must reject `bond_nonce`.
- Responder-originated, nonzero-step, replayed, or otherwise out-of-role `bond_nonce` usage must fail closed.

## UIApi File Boundaries

- UIApi must not accept raw filesystem paths from untrusted JSON or UI parameters.
- User-selected or native-activated files must be represented by trusted broker references with purpose, expiry, and single-use semantics where applicable.
- Save, import, open, preview, and reveal operations must resolve through the broker or managed output locations, not arbitrary caller-supplied paths.

## Linux Secret Service Fallback

- Linux Secret Service fallback must require explicit user consent before passphrase-only device-key protection is used.
- Fallback state must remain visible in device-binding status until the profile is rebound to Secret Service.
- Secret Service errors and fallback warnings must not leak profile identifiers, local paths, tokens, passphrases, or backend exception details.
