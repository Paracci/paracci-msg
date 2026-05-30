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

# Trace imports of test modules to diagnose hangs during pytest collection
_original_import = builtins.__import__
def _custom_import(name, *args, **kwargs):
    if "test_" in name:
        print(f"DEBUG: Importing test module -> {name}", flush=True)
    return _original_import(name, *args, **kwargs)
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
