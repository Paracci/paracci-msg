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
KEM_ALGORITHM = "ML-KEM-768"
HYBRID_KEM_DOMAIN = b"paracci.hybrid.kem.v1"

# Frozen legacy domain for reading v3 setup files that used the removed
# public session_id-derived AEAD wrapper.
LEGACY_HANDSHAKE_FILE_WRAPPER_DOMAIN_V3 = b"paracci.app.session.file.v1"

LABEL_MSG_XY_V3 = b"paracci.msg.x2y.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_MSG_YX_V3 = b"paracci.msg.y2x.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_SYNC_V3 = b"paracci.sync.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_EVO_SEED_V3 = b"paracci.evo.seed.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_EVO_STEP_V3 = b"paracci.evo.step.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_NEXT_V3 = b"paracci.evo.next.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_QUANTUM_V3 = b"paracci.quantum.shield.v3" + LEGACY_V3_LABEL_SUFFIX

# Optional entropy for the Windows DPAPI current-user device-key binding layer.
DPAPI_DEVICE_KEY_ENTROPY_V1 = b"paracci.device_key.dpapi.current_user.v1"
