"""
Paracci — core/evolution.py  (v2.1)
Evolution chain — message count based, bond_seed system.

CHANGES v2.1:
  - Argon2id parameters (time, mem, par) added to EvoConfig.
  - Support for customizable security profiles added.
"""

import struct
import time
from typing import NamedTuple, Optional

from .crypto import (
    hkdf_derive,
    KEY_LEN,
    LABEL_MSG_XY,
    LABEL_MSG_YX,
    LABEL_NEXT,
    pack_uint32,
)

EVO_UNLIMITED = 0


class EvoConfig(NamedTuple):
    """
    v2.1: TTL, Created, and Argon2id workload parameters.
    """
    session_ttl_sec: int
    created_at:      int
    argon2_time:     int
    argon2_mem:      int
    argon2_par:      int


class EvoStep(NamedTuple):
    step:       int
    key_x_to_y: bytes
    key_y_to_x: bytes
    next_seed:  bytes


# Internal helpers

def _advance_seed(seed: bytes, step: int) -> bytes:
    """Advances the seed one step (Ratchet)."""
    material = seed + pack_uint32(step)
    step_key = hkdf_derive(material, KEY_LEN, b"paracci.evo.step.v2")
    return hkdf_derive(step_key, KEY_LEN, LABEL_NEXT)


def _derive_msg_keys(seed: bytes, step: int) -> tuple[bytes, bytes, bytes]:
    """Returns: (key_x_to_y, key_y_to_x, next_seed)"""
    material = seed + pack_uint32(step)
    step_key = hkdf_derive(material, KEY_LEN, b"paracci.evo.step.v2")
    kxy      = hkdf_derive(step_key, KEY_LEN, LABEL_MSG_XY)
    kyx      = hkdf_derive(step_key, KEY_LEN, LABEL_MSG_YX)
    ns       = hkdf_derive(step_key, KEY_LEN, LABEL_NEXT)
    return kxy, kyx, ns


# Main functions

def compute_keys_at_step(bond_seed: bytes, step: int) -> EvoStep:
    """
    Computes keys for step N from bond_seed.
    """
    if step > 100000: # 100k step limit (for CPU safety)
        raise EvoStepMismatchError("Step count too large, rejected for CPU safety.")

    current = bond_seed
    for i in range(step):
        current = _advance_seed(current, i)
    kxy, kyx, ns = _derive_msg_keys(current, step)
    return EvoStep(step=step, key_x_to_y=kxy, key_y_to_x=kyx, next_seed=ns)


def compute_bond_seed(base_evo_seed: bytes, bond_nonce: bytes) -> bytes:
    """
    Derives the evolution seed after bonding.
    """
    return hkdf_derive(
        base_evo_seed,
        KEY_LEN,
        b"paracci.bond.seed.v1",
        salt=bond_nonce,
    )


def check_session_ttl(config: EvoConfig) -> None:
    """Checks if the session has expired."""
    if config.session_ttl_sec > 0:
        if int(time.time()) >= config.created_at + config.session_ttl_sec:
            raise EvoExpiredError("Session life expired.")


def session_expires_at(config: EvoConfig) -> int:
    """Returns exactly when the session will end."""
    if config.session_ttl_sec == 0:
        return 0
    return config.created_at + config.session_ttl_sec


def seconds_until_expiry(config: EvoConfig) -> int:
    """Returns the time remaining until session expiry in seconds."""
    if config.session_ttl_sec == 0:
        return -1
    return max(0, (config.created_at + config.session_ttl_sec) - int(time.time()))


# EvoConfig serialization

def make_evo_config(
    session_ttl_sec: int = EVO_UNLIMITED,
    created_at: Optional[int] = None,
    argon2_time: int = 2,
    argon2_mem: int = 65536,
    argon2_par: int = 4,
) -> EvoConfig:
    """Creates a new evolution configuration (EvoConfig)."""
    if created_at is None:
        created_at = int(time.time())
    return EvoConfig(
        session_ttl_sec=session_ttl_sec,
        created_at=created_at,
        argon2_time=argon2_time,
        argon2_mem=argon2_mem,
        argon2_par=argon2_par
    )


def serialize_evo_config(config: EvoConfig) -> bytes:
    """Converts the EvoConfig object to binary data."""
    # v2.1: TTL(4) + Created(4) + Time(2) + Mem(4) + Par(2) = 16 bytes
    return struct.pack(">IIHII", 
        config.session_ttl_sec, 
        config.created_at,
        config.argon2_time,
        config.argon2_mem,
        config.argon2_par
    )


def deserialize_evo_config(data: bytes) -> EvoConfig:
    """Converts binary data to an EvoConfig object."""
    if len(data) >= 18:
        # v2.1 format: TTL(4), Created(4), Time(2), Mem(4), Par(2)
        ttl, created, a_time, a_mem, a_par = struct.unpack(">IIHII", data[:18])
        return EvoConfig(ttl, created, a_time, a_mem, a_par)
    elif len(data) >= 16:
        # v1 compatibility: if 4 fields exist, ttl=3rd, created_at=4th
        _a, _b, ttl, created = struct.unpack(">IIII", data[:16])
        return EvoConfig(ttl, created, 2, 65536, 4)
    elif len(data) >= 8:
        # v2.0 format (fallback)
        ttl, created = struct.unpack(">II", data[:8])
        return EvoConfig(ttl, created, 2, 65536, 4)
    raise ValueError("EvoConfig data too short.")


# Error classes

class EvoExpiredError(Exception):
    pass


class EvoStepMismatchError(Exception):
    pass