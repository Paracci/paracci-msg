# Web UI & Frontend Design Guide

Paracci uses a single-frame web interface rendered by Flask (Jinja2 templates) and displayed inside a native `pywebview` window. The design features a premium, responsive layout styled with custom CSS.

## Layout & Navigation

- **Sidebar**: The main navigation hub, containing profiles, active sessions, and setting tabs.
- **Header/Toolbar**: Top action bar containing session configuration, sync actions, export/import buttons, and device state indicators (e.g. lock status, security level).
- **Central Canvas**: The main workspace containing the setup workflow, open-message reading room, or message composer.
- **Inspector Panel**: A collapsible panel displaying cryptographic safety codes, session TTL countdowns, and platform-native key binding status.

---

## Design System & Styling (CSS)

The frontend styling utilizes Vanilla CSS structured with custom properties. It avoids TailwindCSS or external frameworks to maintain complete control over visual aesthetics and security boundaries.

### CSS Variables & HSL Colors
Color roles are defined semantically using HSL color tokens to support harmonious adjustments:
- `--background`: Base dark canvas background.
- `--card-background`: Contrast backgrounds for containers and card components.
- `--text-primary` & `--text-secondary`: High and low contrast typography.
- `--accent`: Highlighting critical actions or focus rings.
- `--critical`, `--warning`, & `--success`: Clear semantic state indications.

### Visual Polish
- **Glassmorphism**: Backdrop blur filters (`backdrop-filter: blur()`) are applied to overlays, toolbars, and select dialogs to create a layered, premium aesthetic.
- **Harmonious Gradients**: Subtle background gradients are utilized to guide user focus and soften dark surfaces.
- **Micro-Animations**: Transitions on button hovers, form field focusing, and layout switching create a tactile, premium application feel.

---

## Front-End Security UX

- **State Indicators**: Safety and key-hardening profiles are displayed transparently (e.g., standard, paranoid, high, and maximum workload indicators).
- **Burn Semantics Feedback**: Clear messaging indicates when an envelope will be burned on open ("This envelope will be destroyed on this device after reading").
- **Clipboard & File Selection**: Timeouts for clipboard clearing and staging limits for files are visibly communicated in the UI.
- **No Path Exposing**: All folder and file selections utilize native OS dialogs managed by `pywebview`, hiding absolute system paths from the Web DOM.

---

## Component Directories

- **Jinja2 Templates**: Located in [templates/](paracci/app/templates/). Contains the layout scaffolding (`base.html`), setup flows (`setup.html`), message views (`message.html`), and benchmarks.
- **CSS Styles**: Located in [static/css/](paracci/app/static/css/). Contains the design system tokens, typography rules, layout utilities, and component-specific stylesheets.
- **JS Scripts**: Located in [static/js/](paracci/app/static/js/). Handles client-side forms, drop-zone file events, localized translations, and token authorization.
