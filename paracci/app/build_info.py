"""Build-time application and compatibility metadata."""

# Release builds rewrite APP_VERSION from the Git tag before packaging.
APP_VERSION = "1.4.0"

# Keep this synchronized with core.session.HANDSHAKE_VERSION.
SESSION_PROTOCOL_VERSION = 3
