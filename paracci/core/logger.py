import os
import sys

class ParacciLogger:
    """
    Paracci silent logging mechanism.
    In production mode, displays logs only in debug mode instead of stdout.
    """
    def __init__(self, name):
        """Initializes the logger instance."""
        self.name = name
        self.debug_mode = os.environ.get('PARACCI_DEBUG', '0') == '1'

    def info(self, msg):
        """Writes an informational message (Only in Debug mode)."""
        if self.debug_mode:
            sys.stdout.write(f"[*] [{self.name}] {msg}\n")

    def error(self, msg):
        """Writes an error message to stderr."""
        # Errors are always written to stderr but silently
        sys.stderr.write(f"[!] [{self.name}] ERROR: {msg}\n")

    def security(self, msg):
        """Writes security events (Only in Debug mode)."""
        # Security events are specially marked
        if self.debug_mode:
            sys.stdout.write(f"[🛡️] [{self.name}] SECURITY: {msg}\n")

def get_logger(name):
    """Returns a new logger with the specified name."""
    return ParacciLogger(name)
