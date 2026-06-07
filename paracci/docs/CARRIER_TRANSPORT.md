# Carrier Transport

This document records the 1.8.0 carrier transport skeleton and PNG lossless
core adapter. It defines the security model and implementation boundaries
before carrier transport is exposed through user-facing flows.

## Status

- Carrier mode is optional and disabled by default.
- Normal `.paracci` export, import, and open flows remain the default behavior.
- `png_lossless_v1` is implemented as a core-only PNG lossless carrier adapter.
- `qr_matrix_v1` remains a planned carrier kind constant only. It remains
  unsupported until a dedicated adapter and regressions are added.
- An internal service bridge can extract supported carrier payloads into the
  existing setup import and message open services.
- A headless trusted-ref command boundary exists for future native UI use.
  Carrier commands consume one-shot trusted file references and return managed
  save grants for output.
- The current implementation does not add QR/Matrix logic, UI routes, frontend
  controls, public native-save routes, file associations, or new dependencies.

## Security Model

Carrier transport is an outer wrapper only. It must not change the existing
`.paracci` setup, responder, or message envelope formats.

Extraction must produce bounded `.paracci` bytes and then pass those bytes into
the existing validation, import, open, and decrypt paths. Extraction must not
bypass signature checks, AEAD authentication, transcript binding, device
binding, BurnDB, envelope size caps, package expansion limits, preview policy,
loopback authorization, native filesystem broker rules, or log redaction.
The internal service bridge does not auto-detect carrier files in normal
`.paracci` import or open flows.

Carrier failures must be stable and generic. Public errors must not include
payload bytes, tokens, passphrases, decrypted content, raw carrier internals,
filenames, or sensitive paths.

Carrier import and export command helpers must use trusted file references for
input. Carrier output must use managed save or download grant patterns, never
caller-provided destination paths. Source carrier and cover files are not
auto-deleted by carrier operations.

## Limits

- Carrier inputs and outputs are capped by `MAX_CARRIER_FILE_BYTES`.
- Extracted setup and responder payloads are capped by
  `MAX_EXTRACTED_SETUP_BYTES`.
- Extracted message payloads are capped by `MAX_EXTRACTED_MESSAGE_BYTES`.
- Image carrier adapters must respect the existing image pixel, dimension,
  frame-count, and decompression budgets before they decode or transform
  carrier images.

## PNG Lossless MVP

PNG lossless carrier work is limited to lossless PNG output. The adapter treats
source PNGs as untrusted input, enforces the shared carrier and image budgets,
normalizes supported single-frame PNGs to RGB or RGBA, writes a fresh PNG, and
does not preserve source PNG metadata.

The hidden PNG container stores a carrier marker, byte length, CRC32 value, and
the original `.paracci` bytes. CRC32 is used only to detect carrier corruption
or transport damage. It is not cryptographic authentication, does not prove
that extracted bytes are a valid Paracci envelope, and does not replace the
existing `.paracci` validation, open, or decrypt path.

Users must be warned that social platforms and messengers may recompress,
resize, or strip image data. Carrier PNGs should be sent as a file or document,
not as an inline photo.

## Planned MVP Kinds

QR/Matrix carrier work must be described as visible robust transport for small
payloads, not invisible steganography. It should be treated as a convenience
transport for constrained channels, not as a secrecy or detection-resistance
guarantee.

## Out Of Scope For This Task

- JPEG/DCT robust steganography.
- PDF, audio, or video carriers.
- Generic append or trailer carriers.
- Tor or network routing.
- File association for carrier files.
- Any default carrier export behavior.
