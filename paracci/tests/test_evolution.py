"""
Unit tests for Paracci key evolution and security profiles.
Tests cover one-way advancement, step bounds, invalid profiles, and key derivation length.
"""

import sys
from pathlib import Path
from unittest.mock import patch
import pytest

from conftest import oqs_required

# Ensure core is in the python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.crypto import generate_identity_keypair
from core.session import create_initiator_session, SessionError
from core.evolution import (
    _advance_seed,
    compute_keys_at_step,
    validate_evo_step,
    EvoStepMismatchError,
    MAX_EVO_STEP,
    SECURITY_PROFILES,
    make_evo_config,
)
from core.envelope import _compute_work_key

def test_advance_seed_is_one_way():
    """Verify that _advance_seed is one-way: seed at step N cannot recover step N-1.
    
    This is cryptographically guaranteed by HKDF-SHA512. We test that advancing a seed 
    produces a new seed that is distinct from the original, and that modifying the step
    number produces an entirely different seed.
    """
    seed_0 = b"A" * 32
    seed_1 = _advance_seed(seed_0, 0)
    
    assert len(seed_1) == 32
    assert seed_1 != seed_0
    
    # Verify changing step changes the result
    seed_1_alt = _advance_seed(seed_0, 1)
    assert seed_1_alt != seed_1

def test_different_steps_produce_different_keys():
    """Verify that different evolution steps produce distinct message keys."""
    bond_seed = b"B" * 32
    step_0 = compute_keys_at_step(bond_seed, 0)
    step_1 = compute_keys_at_step(bond_seed, 1)
    
    assert step_0.key_x_to_y != step_1.key_x_to_y
    assert step_0.key_y_to_x != step_1.key_y_to_x
    assert step_0.next_seed != step_1.next_seed

@oqs_required
def test_evolution_invalid_profile_raises_error():
    """Verify that initiating a session with an invalid profile name raises a SessionError."""
    priv, pub = generate_identity_keypair()
    with pytest.raises(SessionError) as exc_info:
        create_initiator_session(
            label="Test",
            profile="nonexistent_profile_123",
            identity_priv=priv,
            identity_pub=pub,
        )
    assert "invalid security profile" in str(exc_info.value).lower()

def test_step_bound_enforcement():
    """Verify that step bounds are enforced and steps beyond MAX_EVO_STEP raise an error."""
    # Valid step
    assert validate_evo_step(MAX_EVO_STEP) == MAX_EVO_STEP
    
    # Beyond max step
    with pytest.raises(EvoStepMismatchError) as exc_info:
        validate_evo_step(MAX_EVO_STEP + 1)
    assert "too large" in str(exc_info.value).lower()
    
    # Negative step
    with pytest.raises(EvoStepMismatchError):
        validate_evo_step(-1)

def test_kdf_output_length_for_each_profile():
    """Verify that KDF output (work key) length is exactly 32 bytes for each profile.
    
    We mock the underlying argon2id hash_secret_raw call for standard, paranoid, and
    quantum profiles to prevent high CPU/memory consumption in tests.
    """
    msg_key = b"M" * 32
    header = b"H" * 52
    qseed = b"Q" * 32
    
    for name, params in SECURITY_PROFILES.items():
        config = make_evo_config(
            argon2_time=params["t"],
            argon2_mem=params["m"],
            argon2_par=params["p"],
        )
        
        with patch("core.envelope.hash_secret_raw") as mock_hash:
            mock_hash.return_value = b"X" * 32
            
            work_key = _compute_work_key(msg_key, header, qseed, config)
            
            assert len(work_key) == 32
            mock_hash.assert_called_once()
            kwargs = mock_hash.call_args[1]
            assert kwargs["secret"] == msg_key
            assert kwargs["salt"] == header + qseed
            assert kwargs["time_cost"] == params["t"]
            assert kwargs["memory_cost"] == params["m"]
            assert kwargs["parallelism"] == params["p"]
            assert kwargs["hash_len"] == 32
