"""
Protocol-stable byte constants for Paracci core cryptography.

These values are part of the compatibility surface. Do not change them without
adding an explicit version migration and compatibility tests for old files.
"""

# Frozen output of the former crypto._get_implicit_dna() helper. The suffix is
# intentionally preserved byte-for-byte so existing sessions and envelopes keep
# opening after removing docstring-derived label generation.
LEGACY_V3_LABEL_SUFFIX = b"\na octyyghb ePED"

DOMAIN_SESSION_MASTER_V3 = b"paracci.session.master.v3"
SESSION_MASTER_HKDF_LENGTH_V3 = 131

LABEL_MSG_XY_V3 = b"paracci.msg.x2y.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_MSG_YX_V3 = b"paracci.msg.y2x.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_SYNC_V3 = b"paracci.sync.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_EVO_SEED_V3 = b"paracci.evo.seed.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_EVO_STEP_V3 = b"paracci.evo.step.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_NEXT_V3 = b"paracci.evo.next.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_QUANTUM_V3 = b"paracci.quantum.shield.v3" + LEGACY_V3_LABEL_SUFFIX

# Frozen replacement for the former integrity.py file-seal secret:
# sha256(b"Paracci" * 3).digest().
ENVELOPE_FILE_SEAL_HMAC_KEY_V1 = bytes.fromhex(
    "742cb24573f8aeb6c3a46149a2b37d93e356ecee9095d0249be0711e19e03d7b"
)

# Optional entropy for the Windows DPAPI current-user device-key binding layer.
DPAPI_DEVICE_KEY_ENTROPY_V1 = b"paracci.device_key.dpapi.current_user.v1"
