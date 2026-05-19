# Application Layer

The Paracci application layer consists of a local Flask web server backend and a `pywebview` desktop window frame.

## Shared UI API Boundary

The frontend communicates with the backend via REST endpoints defined in [routes.py](paracci/app/routes.py). The [facade.py](paracci/ui_api/facade.py) class transforms internal Python objects into JSON-safe Data Transfer Objects (DTOs) and enforces path-based safety limits so that web content does not directly control filesystem paths.

## Desktop Shell Runtime

The application launcher [run.py](run.py) manages startup:
- Starts a background Flask server on `127.0.0.1` using a randomly assigned loopback port.
- Generates a per-launch cryptographically secure random bearer token.
- Sets strict HTTP headers, SameSite session cookies, and CORS controls.
- Instantiates a `pywebview` window pointing to the local loopback URL.
- The `pywebview` shell wraps the native browser rendering engine (e.g., WebView2 on Windows, WebKit on macOS/Linux) to display the interface. It restricts navigation, blocking all external URL requests.

## Web Front-End Interface

The user interface uses standard web technologies:
- **HTML Templates**: Located in [templates/](paracci/app/templates/), rendered server-side by Flask (Jinja2).
- **CSS Stylesheets**: Located in [static/css/](paracci/app/static/css/), implementing a responsive design system using glassmorphism, HSL color tokens, and custom layouts.
- **JavaScript UI Controllers**: Located in [static/js/](paracci/app/static/js/), managing DOM manipulation, forms, and network requests to the local Flask endpoints.
- **Security Headers & CSP**: Enforces a strict Content Security Policy (CSP) blocking unauthorized script execution, external resources, and unsafe inline styles.

## Memory & Native State Hygiene

Opened message contents and decrypted files are held in process memory only while active. Decrypted payloads are dropped from Flask caches and UI state on navigation, window lock, or session termination. Clipboard copies are automatically cleared after a user-configured timeout. 

For full details on the limitations of the loopback model and memory security, see [SECURITY_SHIELDS.md](paracci/docs/SECURITY_SHIELDS.md).
