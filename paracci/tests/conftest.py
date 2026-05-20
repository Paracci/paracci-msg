"""
Shared pytest fixtures and markers for the Paracci test suite.

Provides ``oqs_required`` – a skip marker for tests that depend on
liboqs-python / the native liboqs C library.  When liboqs is not installed
(e.g. a CI environment where the native build step failed), these tests
are gracefully skipped instead of crashing the entire suite.
"""

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
