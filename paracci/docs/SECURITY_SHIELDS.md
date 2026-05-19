# Security Shields

Paracci shield controls are best-effort exposure reduction. They are useful
defense-in-depth, but they are not guarantees against memory recovery, screen
capture, clipboard scraping, or filesystem forensics.

## Common Limits

- Python `bytes` and `str` objects are immutable. Paracci can drop references
  it owns, but it cannot overwrite every runtime, Flask response, DOM string,
  base64, or library copy.
- Clipboard auto-clear reduces residual exposure after the configured delay.
  Local processes may still read clipboard contents before the clear runs.
- Secure-delete helpers attempt overwrite and removal, but SSD wear leveling,
  journaling filesystems, snapshots, backups, and cloud-synced directories can
  retain data outside Paracci's control.
- Recent-document cleanup only targets known OS locations and cannot remove all
  traces that other tools, shells, indexes, or sync providers may create.

## Platform Matrix

| Platform | Capture reduction | Secure delete | Clipboard clear |
| --- | --- | --- | --- |
| Windows | Attempts `SetWindowDisplayAffinity`; does not cover external cameras, privileged capture, every screen-share tool, or unsupported windows. | Best-effort overwrite/delete only. | Auto-clear after delay; readable before clearing. |
| macOS | Attempts `NSWindowSharingNone`; does not block every screenshot, recording, or privileged capture path. | Best-effort overwrite/delete only. | Auto-clear after delay; readable before clearing. |
| Linux | Unimplemented because X11/Wayland support is compositor-specific. | Best-effort `shred`/overwrite/delete only. | Auto-clear with `xclip` or `wl-copy` when available; readable before clearing. |

## Contributor Wording Rules

Use: "best-effort", "attempts", "reduces exposure", "drops Paracci-owned
references", and "auto-clears after a delay".

Avoid: "prevents screenshots", "guarantees deletion", "wipes instantly",
"securely deletes", "erases RAM", and "cannot be recovered".
