# Dual-Native UI Guide

Paracci uses a bifurcated native design strategy:

- macOS follows SwiftUI/AppKit desktop conventions with native sidebars,
  toolbars, settings, inspectors, materials, commands, and narrow AppKit
  bridges.
- Windows/Linux use a custom premium Qt Quick/QML shell with the same workflow
  structure and semantic design tokens.

The design source is
[Paracci Dual-Native Redesign](https://www.figma.com/design/O1kQi5Y1sWhrRe5pZdDJWs).

## Structure

- The app shell is sidebar + toolbar + central workflow + optional inspector.
- Top-level commands are grouped in toolbar surfaces.
- Session metadata belongs in the inspector, not raw labels inside message
  content.
- Composer, open-message drop zone, reading room, and attachments are stable
  desktop work surfaces.

## Theme

Dark mode remains the default for the custom QML shell. The design source and
QML tokens include light, dark, and future `system` theme intent. macOS should
prefer system-adaptive colors/materials instead of hardcoded Apple-looking
skins.

Semantic color roles are used over decorative palettes:

- `background`
- `contentBackground`
- `controlGlass`
- `separator`
- `textPrimary`
- `textSecondary`
- `critical`
- `warning`
- `success`
- `focusRing`

## Components

The Figma file defines:

- sidebar row
- toolbar button
- status pill
- inspector row
- composer
- reading room
- attachment row
- security banner
- settings row

QML component files live under `paracci/desktop/qml/`. macOS equivalents live as
SwiftUI views under `platform/macos/ParacciMac/Sources/Views`.

## Security UX

- Security states are explicit and calm: Protected, Best effort, Unavailable,
  Blocked, Expired, and Burned.
- Anti-screenshot copy is platform honest.
- Clipboard/save restrictions are visible before action.
- Dangerous attachments use native warnings and conservative text preview.
- The UI must not claim perfect Python memory zeroization.

## Motion

Allowed motion is functional only: progress indicators, short fades, toolbar or
sidebar reveal, and subtle press feedback. Decorative blobs, neon glow, hover
lift, hover scale, parallax, and infinite ambient animations are not part of the
design system.
