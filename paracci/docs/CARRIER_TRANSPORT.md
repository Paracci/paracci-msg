# Carrier Transport

This document records the 1.8.0 carrier transport skeleton. It defines the
security model and implementation boundaries before any carrier adapter is
enabled.

## Status

- Carrier mode is optional and disabled by default.
- Normal `.paracci` export, import, and open flows remain the default behavior.
- `png_lossless_v1` and `qr_matrix_v1` are planned carrier kind constants only.
  They remain unsupported until dedicated adapters and regressions are added.
- The skeleton does not add PNG logic, QR/Matrix logic, UI routes, frontend
  controls, native-save integration, UIApi commands, image decoding, or new
  dependencies.

## Security Model

Carrier transport is an outer wrapper only. It must not change the existing
`.paracci` setup, responder, or message envelope formats.

Extraction must produce bounded `.paracci` bytes and then pass those bytes into
the existing validation, import, open, and decrypt paths. Extraction must not
bypass signature checks, AEAD authentication, transcript binding, device
binding, BurnDB, envelope size caps, package expansion limits, preview policy,
loopback authorization, native filesystem broker rules, or log redaction.

Carrier failures must be stable and generic. Public errors must not include
payload bytes, tokens, passphrases, decrypted content, raw carrier internals,
filenames, or sensitive paths.

## Limits

- Carrier inputs and outputs are capped by `MAX_CARRIER_FILE_BYTES`.
- Extracted setup and responder payloads are capped by
  `MAX_EXTRACTED_SETUP_BYTES`.
- Extracted message payloads are capped by `MAX_EXTRACTED_MESSAGE_BYTES`.
- Future image carrier adapters must respect the existing image pixel,
  dimension, frame-count, and decompression budgets before they decode or
  transform carrier images.

## Planned MVP Kinds

PNG lossless carrier work must be limited to lossless PNG output. Users must be
warned that social platforms and messengers may recompress, resize, or strip
image data. Carrier PNGs should be sent as a file or document, not as an inline
photo.

QR/Matrix carrier work must be described as visible robust transport for small
payloads, not invisible steganography. It should be treated as a convenience
transport for constrained channels, not as a secrecy or detection-resistance
guarantee.

## Out Of Scope For This Skeleton

- JPEG/DCT robust steganography.
- PDF, audio, or video carriers.
- Generic append or trailer carriers.
- Tor or network routing.
- File association for carrier files.
- Any default carrier export behavior.
