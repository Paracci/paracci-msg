import builtins
import sys
from pathlib import Path

import pytest

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import constants
from core.quantum_kem import (
    QuantumKEMError,
    kem_decapsulate,
    kem_encapsulate,
    kem_generate_keypair,
)

# ML-KEM-768 sizes from NIST FIPS 203 Table 3.
PUBLIC_KEY_BYTES = 1184
SECRET_KEY_BYTES = 2400
CIPHERTEXT_BYTES = 1088
SHARED_SECRET_BYTES = 32


def test_kem_spec_sizes_are_documented():
    assert constants.KEM_ALGORITHM == "ML-KEM-768"
    assert PUBLIC_KEY_BYTES == 1184
    assert SECRET_KEY_BYTES == 2400
    assert CIPHERTEXT_BYTES == 1088
    assert SHARED_SECRET_BYTES == 32


@oqs_required
def test_kem_generate_keypair_sizes():
    public_key, secret_key = kem_generate_keypair()

    assert isinstance(public_key, bytes)
    assert isinstance(secret_key, bytes)
    assert len(public_key) == PUBLIC_KEY_BYTES
    assert len(secret_key) == SECRET_KEY_BYTES


@oqs_required
def test_kem_encapsulate_decapsulate_round_trip():
    public_key, secret_key = kem_generate_keypair()

    ciphertext, sender_secret = kem_encapsulate(public_key)
    receiver_secret = kem_decapsulate(secret_key, ciphertext)

    assert isinstance(ciphertext, bytes)
    assert isinstance(sender_secret, bytes)
    assert isinstance(receiver_secret, bytes)
    assert len(ciphertext) == CIPHERTEXT_BYTES
    assert len(sender_secret) == SHARED_SECRET_BYTES
    assert len(receiver_secret) == SHARED_SECRET_BYTES
    assert receiver_secret == sender_secret


@oqs_required
def test_kem_cross_key_decapsulation_returns_different_secret():
    public_key, _secret_key = kem_generate_keypair()
    _other_public_key, other_secret_key = kem_generate_keypair()

    ciphertext, sender_secret = kem_encapsulate(public_key)
    wrong_receiver_secret = kem_decapsulate(other_secret_key, ciphertext)

    assert len(wrong_receiver_secret) == SHARED_SECRET_BYTES
    assert wrong_receiver_secret != sender_secret


def test_kem_unavailable_raises_quantum_error(monkeypatch):
    original_import = builtins.__import__

    def fail_oqs_import(name, *args, **kwargs):
        if name == "oqs":
            raise ImportError("mock missing oqs")
        return original_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_oqs_import)

    with pytest.raises(QuantumKEMError, match="liboqs-python"):
        kem_generate_keypair()
