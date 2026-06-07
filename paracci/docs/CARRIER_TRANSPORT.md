# Carrier Transport

This document defines the Paracci 1.8.0 PNG lossless carrier transport security
model, user workflow, and implementation boundaries.

## Status

- Carrier mode is optional and disabled by default.
- Normal `.paracci` export, import, and open flows remain the default behavior.
- `png_lossless_v1` is the only supported carrier kind.
- `qr_matrix_v1` remains a planned carrier kind constant only. It remains
  unsupported until a dedicated adapter and regressions are added.
- Explicit PNG carrier controls are available as collapsed, secondary UI
  actions. They do not alter or auto-detect files in normal `.paracci` forms or
  drop zones.
- Browser carrier operations use bounded multipart uploads and PNG downloads.
  Native carrier operations use purpose-scoped, one-shot trusted references
  and existing one-shot managed save grants.
- The implementation does not add QR/Matrix logic, public native-save routes,
  file associations, or carrier-specific dependencies.

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

Carrier routes remain protected by the existing loopback bearer, CSRF,
same-origin/source-header, no-store, and redaction controls. Raw path-shaped
fields are rejected before file, trusted-reference, or carrier helpers run.

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
resize, convert, or strip image data. Carrier PNGs should be sent as a
file/document, not as an inline photo.

PNG carrier transport does not guarantee invisibility, resistance to
steganalysis, or survival after image transformation. Existing Paracci
envelope authentication and AEAD decryption remain the security authority for
extracted content.

## User Workflow

- Keep the normal `.paracci` export, import, seal, and open actions as the
  primary workflow.
- Expand the optional PNG carrier panel only when carrier transport is wanted.
- For export, select a lossless PNG cover and use the explicit carrier action.
  Insufficient capacity fails without producing output.
- For import or open, select the explicit carrier action. Extraction returns
  bounded, untrusted bytes to the normal setup or message validation path.
- Importing an initiator setup carrier still produces the normal responder
  `.paracci` file as the primary result. Exporting that responder into a PNG
  carrier is a separate action.
- Browser output is a PNG download. Native output uses the existing one-shot,
  size-limited save grant flow.
- Carrier and cover source files are not automatically deleted or modified.

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
- Automatic carrier detection in normal `.paracci` controls.
