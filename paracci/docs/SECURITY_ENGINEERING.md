# Security Engineering Invariants

Paracci is an offline-first desktop application that handles encrypted setup files, `.paracci` message envelopes, local device keys, single-open message state, loopback web requests, native bridge calls, short-lived preview capabilities, and release/update trust. These invariants are repo-safe guardrails for maintainers and coding agents. They intentionally describe security classes and required behaviors, not private audit material or exploit details.

Paracci should be reasoned about as a local encrypted desktop system, not as a normal web app. The attacker model includes malicious files opened by the user, hostile local web content trying to reach loopback routes, compromised or confusing preview content, stale or replayed envelopes, dependency or release asset drift, and untrusted UI/JSON parameters attempting to cross into native filesystem or device-key operations.

## Security Review Checklist For Code Changes

- Name the affected trust boundary before editing.
- Read the relevant invariant below and the nearest regression tests before changing code.
- Confirm which input is trusted, which input is attacker-controlled, and where authority is granted.
- Keep authorization and validation at the backend, protocol, service, bridge, or release boundary. UI-only checks are not sufficient.
- Preserve fail-closed behavior for malformed, replayed, over-limit, unauthorized, unsigned, or out-of-scope inputs.
- Keep compatibility paths narrow. Legacy read paths must not become new write paths.
- Add or update focused regression tests for security-sensitive changes; tests should fail without the fix or invariant.
- Keep logs and errors useful but redacted. Do not record tokens, secrets, passphrases, decrypted content, raw request bodies, or sensitive local paths.
- Committed docs, tests, and code must not contain local machine paths, local usernames in path context, or machine-specific temp/cache locations.
- Do not add dependency, workflow, bridge, route, or filesystem shortcuts that bypass existing policy checks.

## When To Stop And Ask For A Plan Review

Stop and ask for a plan review before implementing changes that affect:

- Cryptography, transcript binding, key derivation, envelope authentication, or ratchet state.
- Updater trust, release signing, release publication, checksum manifests, or trusted release assets.
- Loopback authentication, service-worker bearer flow, CSRF, Host/Origin/Referer/Fetch Metadata validation, or public route allowlists.
- Native filesystem save, open, reveal, import, attachment staging, or broker reference handling.
- Preview MIME policy, preview content routes, preview window navigation, or attachment download controls.
- Platform device-key binding, 2FA unlock state, Secret Service fallback, DPAPI, or Keychain behavior.
- Dependency pinning, hash locks, native-library source selection, cache reuse, or build workflow install paths.

## Offline Setup And Responder Files

What must remain true:

- Setup and responder files are authenticated public metadata for session establishment; they are integrity-protected but not confidential.
- The handshake transcript must continue to bind session identity and key-exchange material exactly as documented.
- Setup and responder inputs must enforce size caps before read, parse, decrypt, unpack, or schema handling.
- Legacy handshake handling must stay migration-only where documented and must not silently create weaker new sessions.

Unsafe changes to avoid:

- Accepting older or malformed setup formats as current writable session formats.
- Moving validation after expensive parsing or cryptographic work.
- Treating setup metadata as trusted because it came from a local file picker.
- Changing identity, KEM, or transcript fields without a protocol review.

Regression-test style:

- Core/session tests should reject malformed, oversized, unsupported, or transcript-inconsistent setup inputs before session activation.
- Compatibility tests should prove legacy files remain limited to documented read or migration behavior.

## `.paracci` Message Envelopes

What must remain true:

- Message envelopes must remain authenticated and encrypted before payload or attachment data is trusted.
- Current envelopes must use the ratchet-derived message key directly for AEAD authentication and decryption.
- Setup, responder, and `.paracci` message envelopes must enforce size caps before read, parse, decrypt, unpack, or schema handling.
- Attachment package extraction limits remain defense-in-depth; they do not replace outer input caps.

Unsafe changes to avoid:

- Parsing nested package data, trusting filenames, or allocating large buffers before outer envelope limits are checked.
- Treating decrypted metadata as safe for filesystem, preview, or UI use without the next boundary's validation.
- Expanding legacy payload-key compatibility into new write behavior.

Regression-test style:

- Envelope and package tests should reject over-limit, malformed, replay-shaped, or tampered inputs before expensive parsing or unsafe extraction.
- Route and native-service tests should prove import/open flows use the same outer limits.

## Key Evolution And Ratchet State

What must remain true:

- Send and receive keys must advance monotonically according to the protocol.
- Older pending envelopes must remain rejected after the receive state advances past their step.
- `bond_nonce` is valid only for the initial unbonded X-to-Y step 0 bonding envelope.
- Post-bond envelopes must reject `bond_nonce`.
- Responder-originated, nonzero-step, replayed, or otherwise out-of-role `bond_nonce` usage must fail closed.

Unsafe changes to avoid:

- Retaining skipped receive keys for convenience.
- Allowing out-of-order decryption without a protocol-level design change.
- Reusing initialization-only bonding fields in post-bond traffic.
- Reconstructing ratchet state from caller-supplied message metadata.

Regression-test style:

- Protocol tests should prove ordered-open semantics, replay rejection, post-bond `bond_nonce` rejection, and failure on role/step mismatch.
- Tests should assert state does not roll back after a failed or stale open attempt.

## BurnDB Single-Open Registry

What must remain true:

- BurnDB is the local single-open registry for envelope IDs on this device.
- Registering an open must be atomic with the state changes that make the envelope unusable again on this device.
- Device unlock and BurnDB access must not expose usable decrypted key material after failure, expiry, or lock.
- 2FA-enabled profiles must never become active from passphrase-only native unlock.

Unsafe changes to avoid:

- Checking burn state outside the transaction that records the open.
- Adding alternate open paths that bypass BurnDB.
- Treating passphrase success as full unlock when 2FA is configured.
- Leaving pending unlock material usable after timeout, failure, or cancellation.

Regression-test style:

- Burn and service tests should prove replay attempts fail, stale state cannot reopen an envelope, and pending 2FA unlock state is cleaned on failure or expiry.

## Flask Loopback Server

What must remain true:

- Flask must bind to loopback only and protected routes must require the per-launch bearer.
- Host, Origin, Referer, Fetch Metadata, CSRF, and session-cookie policy must remain centralized and fail closed.
- The public route allowlist must stay narrow and intentional.
- Rejection and security logs must use allowlisted diagnostic fields.
- Logs must not include bearer tokens, preview tokens, CSRF values, session identifiers, secrets, private keys, passphrases, decrypted content, raw request bodies, or sensitive local paths.

Unsafe changes to avoid:

- Adding per-route exceptions instead of preserving centralized loopback policy.
- Letting a Flask session cookie substitute for the bearer on protected routes.
- Logging raw URLs, headers, cookies, request bodies, local paths, or token values.
- Expanding public routes because a frontend flow is hard to bootstrap.

Regression-test style:

- Loopback tests should verify bearer-first access, header and CSRF rejection, narrow public-route behavior, safe diagnostics, and no sensitive sentinel values in logs.

## Service Worker, Bootstrap, And Bearer Token Flow

What must remain true:

- The browser bearer transport must remain memory-only and same-origin.
- Protected document and preview requests must fail closed if the service worker cannot initialize or seed the bearer.
- Preview capability tokens narrow attachment access; they must not expand into general loopback authority or privileged native bridge access.

Unsafe changes to avoid:

- Persisting bearer tokens in local storage, query strings, logs, templates, or long-lived browser state.
- Treating page-visible bearer knowledge as permission for privileged native filesystem writes.
- Allowing navigation into protected UI before bootstrap is complete.

Regression-test style:

- Navigation and loopback tests should prove protected pages require bearer reseeding, unsupported bootstrap fails closed, and preview tokens do not bypass main loopback auth.

## pywebview Bridge

What must remain true:

- The privileged bridge must expose only intentional desktop capabilities.
- Bridge methods must not accept untrusted raw paths, shell-shaped values, or caller-minted authority for native actions.
- Preview windows must expose a restricted API rather than the main privileged bridge.

Unsafe changes to avoid:

- Adding broad save, open, reveal, clipboard, or process-launch bridge methods without a second authority boundary.
- Trusting a browser-visible token as the only authorization for privileged native writes.
- Sharing main-window bridge APIs with preview windows.

Regression-test style:

- Navigation, bridge, and session tests should prove removed or restricted bridge methods are absent, preview windows stay restricted, and privileged calls require brokered grants or native user selection.

## Preview And Content Routes

What must remain true:

- Preview content must not inline active or ambiguous MIME types on the local app origin.
- Non-image, active, ambiguous, or unsafe preview bytes must be rejected or forced into download-safe handling according to the current preview policy.
- Image decoding must enforce pixel, dimension, frame-count, and decompression budgets before producing displayable previews.
- Preview windows must block external navigation consistently for clicks, forms, scripted opens, and window-location changes.
- Download controls must be enforced server-side, not only in the UI.

Unsafe changes to avoid:

- Inferring safety from filename extension alone.
- Returning original unsafe bytes inline because a preview UI asks for them.
- Moving image budget checks after decoding or transformation.
- Allowing external navigation from preview content.

Regression-test style:

- Preview route and template tests should prove unsafe MIME types are rejected or downloaded safely, image limits fail closed, non-downloadable bytes are not exposed inline, and external navigation is blocked.

## Native Filesystem Save, Open, Import, And Reveal Flows

What must remain true:

- Files chosen by the user or activated by the OS must enter through trusted broker references, managed output locations, or native dialogs.
- Save, import, open, preview, and reveal operations must resolve through the broker or managed output locations, not arbitrary caller-supplied paths.
- Broker references should be scoped by purpose, expiry, and single-use semantics where applicable.

Unsafe changes to avoid:

- Accepting raw paths from JSON, query strings, DOM data, or message metadata.
- Reintroducing legacy broad native save methods.
- Letting preview or loopback callers choose arbitrary destinations.
- Following traversal, symlink, relative, or out-of-scope paths without broker validation.

Regression-test style:

- UIApi and native service tests should reject relative, traversal, nonexistent, out-of-scope, or caller-supplied paths while accepting valid brokered references and managed outputs.

## UIApi And JSON-RPC Boundary

What must remain true:

- UIApi must not accept raw filesystem paths from untrusted JSON or UI parameters.
- UIApi DTOs must remain JSON-safe views of backend state, not authority tokens unless explicitly designed as such.
- UIApi should centralize validation where Flask routes and native bridge flows share behavior.

Unsafe changes to avoid:

- Passing UI JSON directly into core, filesystem, unlock, preview, or native service operations.
- Adding compatibility aliases that bypass current broker or unlock checks.
- Treating client-provided IDs, paths, filenames, or capability strings as trusted.

Regression-test style:

- UIApi tests should cover both Flask-facing and native-facing call shapes, including rejection of forged references and preservation of valid managed flows.

## Release And Updater Trust

What must remain true:

- The updater signing private key must remain offline. CI must not sign updater-trusted manifests with an online repository secret.
- CI may build release assets and draft releases, but the updater-trusted manifest signature must come from the offline signing ceremony.
- Release manifests must be recomputed from the actual assets that will be published, then verified before publication. Do not trust prepackaged manifest files from build outputs without rehashing the release assets.
- Publishing must fail closed if expected assets are missing, duplicated, renamed unexpectedly, mismatched, or signature verification fails.

Unsafe changes to avoid:

- Putting updater signing authority into CI, repository secrets, generated artifacts, or release workflow variables.
- Publishing a manifest that was not recomputed from the exact draft assets.
- Letting missing signatures or checksum mismatches fall back to unsigned update installation.

Regression-test style:

- Updater and workflow tests should prove CI cannot sign updater-trusted metadata, publication rehashes draft assets, signatures are verified, and mismatch or missing asset cases fail closed.

## Dependency And Native-Library Supply Chain

What must remain true:

- Runtime dependencies must be exact-pinned and hash-locked.
- Native cryptography dependencies must be pinned to an immutable commit or digest and verified before build or cache reuse.
- Do not add ad hoc install steps that bypass lockfiles, hash checks, or native source verification.
- Dependency integrity controls belong in requirements, workflows, build actions, and audit tests together.

Unsafe changes to avoid:

- Adding bare `pip install`, mutable tag-only native source, unverified cache reuse, or workflow-only dependency paths.
- Updating requirements without lockfile hashes and dependency-integrity tests.
- Treating a native source tag as the trust boundary when the commit or digest is available.

Regression-test style:

- Dependency tests should prove lockfiles contain exact hashes, workflows use the locked install paths, native source commits or digests are checked before build, and cache markers fail closed on drift.

## Platform Device Key Binding

What must remain true:

- Device key protection must bind local database access to the user passphrase and the active platform credential store when available.
- Linux Secret Service fallback must require explicit user consent before passphrase-only device-key protection is used.
- Fallback state must remain visible in device-binding status until the profile is rebound to Secret Service.
- Secret Service errors and fallback warnings must not leak profile identifiers, local paths, tokens, passphrases, or backend exception details.

Unsafe changes to avoid:

- Silently downgrading platform-bound protection to passphrase-only protection.
- Hiding fallback state from UIApi status or user-visible security state.
- Logging platform credential errors with sensitive details.
- Treating platform-specific failures as successful binding.

Regression-test style:

- Device-binding tests should prove fallback requires consent, reports fallback state, redacts backend details, blocks silent downgrade, and preserves normal DPAPI, Keychain, and Secret Service success paths.
