"""
Unit tests for Paracci key evolution.
Tests cover one-way advancement, step bounds, and current configuration storage.
"""

import sys
from pathlib import Path
import pytest

# Ensure core is in the python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.evolution import (
    _advance_seed,
    compute_keys_at_step,
    validate_evo_step,
    EvoStepMismatchError,
    MAX_EVO_STEP,
    make_evo_config,
    serialize_evo_config,
    deserialize_evo_config,
)

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

def test_current_evo_config_contains_no_legacy_payload_kdf_parameters():
    config = make_evo_config(session_ttl_sec=60, created_at=1)

    assert config.legacy_argon2_time is None
    assert config.legacy_argon2_mem is None
    assert config.legacy_argon2_par is None
    assert deserialize_evo_config(serialize_evo_config(config)) == config
