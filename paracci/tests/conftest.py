"""
Shared pytest fixtures and markers for the Paracci test suite.

Provides ``oqs_required`` – a skip marker for tests that depend on
liboqs-python / the native liboqs C library.  When liboqs is not installed
(e.g. a CI environment where the native build step failed), these tests
are gracefully skipped instead of crashing the entire suite.
"""

import sys
import builtins
from unittest.mock import MagicMock

# Mock pywebview globally during tests to avoid GUI/WindowServer initialization hangs in headless environments (e.g. macOS CI)
sys.modules["webview"] = MagicMock()

import os
from pathlib import Path

# Mock macOS Keychain globally on headless CI to avoid hanging on locked keychain prompts
if os.environ.get("GITHUB_ACTIONS") == "true":
    project_root = Path(__file__).resolve().parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    try:
        from desktop import keychain_mac
        class FakeKeychainAdapter:
            def __init__(self):
                self.store_dict = {}
            def store(self, profile_id, data):
                self.store_dict[profile_id] = bytes(data)
            def load(self, profile_id):
                if profile_id not in self.store_dict:
                    raise keychain_mac.KeychainError("unwrap", "missing", code="missing")
                return bytearray(self.store_dict[profile_id])
            def delete(self, profile_id):
                self.store_dict.pop(profile_id, None)

        _fake_adapter = FakeKeychainAdapter()
        keychain_mac._get_adapter = lambda: _fake_adapter
    except Exception:
        pass

# Trace imports of test modules to diagnose hangs during pytest collection
_original_import = builtins.__import__
def _custom_import(name, *args, **kwargs):
    interesting = any(k in name for k in ("test", "core", "desktop", "sqlcipher", "oqs", "webview", "paracci"))
    if interesting:
        print(f"DEBUG: START Importing module -> {name}", flush=True)
    try:
        res = _original_import(name, *args, **kwargs)
        if interesting:
            print(f"DEBUG: END Importing module -> {name}", flush=True)
        return res
    except Exception as e:
        if interesting:
            print(f"DEBUG: ERROR Importing module -> {name}: {e}", flush=True)
        raise
builtins.__import__ = _custom_import

import pytest

try:
    import oqs  # noqa: F401

    HAS_OQS = True
except ImportError:
    HAS_OQS = False

oqs_required = pytest.mark.skipif(
    not HAS_OQS,
    reason="liboqs-python not available in this environment",
)
