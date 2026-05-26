"""
Protocol-stable byte constants for Paracci core cryptography.

These values are part of the compatibility surface. Do not change them without
adding an explicit version migration and compatibility tests for old files.
"""

# ==============================================================================
# LEGACY_V3_LABEL_SUFFIX
# ==============================================================================
# 1. WHAT THIS VALUE IS:
#    This byte string is the frozen output of the legacy crypto._get_implicit_dna()
#    helper function, captured and frozen at the point when that function was removed.
#
# 2. WHY IT IS HARDCODED / PROTOCOL-FROZEN:
#    In v3 sessions, this suffix was dynamically appended to all protocol labels 
#    used to derive message, synchronization, and evolution keys. Changing this 
#    value would change the derived keys for all existing v3 sessions. Because the 
#    keys are different, the application would fail to decrypt any existing v3 
#    message envelopes. It must remain exactly as defined to preserve backward 
#    compatibility with existing active sessions.
#
# 3. HOW TO VERIFY IT:
#    The original _get_implicit_dna() function read the module docstring of the old
#    paracci/core/crypto.py file and sampled characters at regular intervals:
#
#        def _get_implicit_dna():
#            d = __doc__ or "PARACCI_FALLBACK_DNA_PROTECTION_V3"
#            parts = [d[i] for i in range(0, min(len(d), 64), 4)]
#            return "".join(parts).encode('utf-8')[:16]
#
#    The exact docstring of paracci/core/crypto.py at that time was:
#        """
#        Paracci — core/crypto.py
#        Cryptographic base layer.
#        PROJECT_DNA: 0x50617261636369
#        DO_NOT_REMOVE_THIS_DOCSTRING_OR_CRYPTO_WILL_FAIL
#
#        Algorithms used:
#          - X25519         : ECDH key agreement
#        """
#
#    Mapping index `i` from `range(0, 64, 4)` to the docstring characters yields:
#      - 0:  '\n'  (Leading newline of the docstring)
#      - 4:  'a'   (From 'Para')
#      - 8:  ' '   (Space between 'Paracci' and '—')
#      - 12: 'o'   (From 'core')
#      - 16: 'c'   (From 'crypto')
#      - 20: 't'   (From 'crypto')
#      - 24: 'y'   (From '.py')
#      - 28: 'y'   (From 'Cryptographic')
#      - 32: 'g'   (From 'Cryptographic')
#      - 36: 'h'   (From 'Cryptographic')
#      - 40: 'b'   (From 'base')
#      - 44: ' '   (Space between 'base' and 'layer')
#      - 48: 'e'   (From 'layer')
#      - 52: 'P'   (From 'PROJECT_DNA')
#      - 56: 'E'   (From 'PROJECT_DNA')
#      - 60: 'D'   (From 'PROJECT_DNA')
#
#    This produces the string: "\na octyyghb ePED", which encodes to the exact 
#    16-byte value: b"\na octyyghb ePED".
#
# 4. CONSEQUENCES OF MODIFICATION:
#    If this constant is modified:
#      - Decryption of existing v3 envelopes will fail silently (no decryption possible).
#      - The encryption flow (write path) will succeed without raising any errors, 
#        but will generate envelopes using the incorrect key space.
#      - Total session incompatibility will be introduced.
# ==============================================================================
LEGACY_V3_LABEL_SUFFIX = b"\na octyyghb ePED"

# ==============================================================================
# DOMAIN_SESSION_MASTER_V3
# ==============================================================================
# 1. WHAT THIS VALUE IS:
#    The info string used in the HKDF-SHA512 derivation of the master key for
#    v3 sessions.
#
# 2. WHY IT IS HARDCODED:
#    It acts as the domain separation tag for v3 master key derivation. If altered,
#    all derived keys for v3 sessions will be incorrect, breaking decryption compatibility.
# ==============================================================================
DOMAIN_SESSION_MASTER_V3 = b"paracci.session.master.v3"

# ==============================================================================
# SESSION_MASTER_HKDF_LENGTH_V3
# ==============================================================================
# 1. WHAT THIS VALUE IS:
#    The frozen HKDF output key material length (in bytes) used during the 
#    derivation of v3 master session keys.
#
# 2. WHY IT IS HARDCODED:
#    In the legacy v3 key derivation pathway, the master key material length 
#    was dynamically computed from the system integrity anchor and the tamper 
#    factor. Changing this value would change the input size of the master HKDF 
#    derivation, which alters the resulting session key bytes. It must remain 
#    exactly 131 to allow existing v3 sessions to continue decrypting messages.
#
# 3. HOW TO VERIFY IT:
#    The length was originally calculated using the formula:
#        length = (KEY_LEN * 4) + (_ANCHOR % 4) + (get_tamper_factor() * 7)
#    where:
#      - KEY_LEN is 32.
#      - _ANCHOR is the sum of the lowercase ASCII/byte values of the DNA 
#        signature b"Paracci" (i.e. b"paracci"):
#        112 ('p') + 97 ('a') + 114 ('r') + 97 ('a') + 99 ('c') + 99 ('c') + 105 ('i') = 723.
#      - Under normal (non-tampered) execution, the tamper factor is 0.
#      - Therefore: length = (32 * 4) + (723 % 4) + (0 * 7) = 128 + 3 = 131.
#
# 4. CONSEQUENCES OF MODIFICATION:
#    Changing this constant will break the HKDF derivation step for all v3 
#    sessions, leading to incorrect keys and failed decryptions for all existing 
#    message history without raising any errors at write time.
# ==============================================================================
SESSION_MASTER_HKDF_LENGTH_V3 = 131

KEM_ALGORITHM = "ML-KEM-768"
HYBRID_KEM_DOMAIN = b"paracci.hybrid.kem.v1"
TRANSCRIPT_DOMAIN = b"paracci.transcript.v1"
HANDSHAKE_FILE_VERSION_V4 = 0x04  # legacy, transcript-unbound
HANDSHAKE_FILE_VERSION_V5 = 0x05
HANDSHAKE_FILE_VERSION_V6 = 0x06  # current, transcript-bound without protocol Argon2
HANDSHAKE_TRANSCRIPT_VERSION = 1

# ==============================================================================
# LEGACY_HANDSHAKE_FILE_WRAPPER_DOMAIN_V3
# ==============================================================================
# 1. WHAT THIS VALUE IS:
#    The info/domain binding constant used in HKDF when reading older v3 setup
#    handshake files.
#
# 2. WHY IT IS HARDCODED:
#    It binds the HKDF derivation for the public session-id wrapper. Changing this 
#    will cause the wrapper decryption to fail when reading v3 handshake files.
# ==============================================================================
LEGACY_HANDSHAKE_FILE_WRAPPER_DOMAIN_V3 = b"paracci.app.session.file.v1"

LABEL_MSG_XY_V3 = b"paracci.msg.x2y.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_MSG_YX_V3 = b"paracci.msg.y2x.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_SYNC_V3 = b"paracci.sync.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_EVO_SEED_V3 = b"paracci.evo.seed.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_EVO_STEP_V3 = b"paracci.evo.step.v3" + LEGACY_V3_LABEL_SUFFIX
LABEL_NEXT_V3 = b"paracci.evo.next.v3" + LEGACY_V3_LABEL_SUFFIX

# ==============================================================================
# DPAPI_DEVICE_KEY_ENTROPY_V1
# ==============================================================================
# 1. WHAT THIS VALUE IS:
#    The optional additional entropy byte string passed to Windows DPAPI 
#    (CryptProtectData and CryptUnprotectData) when securing the local device key.
#
# 2. WHY IT IS HARDCODED:
#    Windows DPAPI uses this entropy string as an additional secret factor 
#    to bind the encrypted data. If this value is changed, any previously encrypted
#    device keys will fail to decrypt, locking out the user from their profile and
#    stored keys.
#
# 3. CONSEQUENCES OF MODIFICATION:
#    Modifying this value will result in permanent local key access failure for
#    all existing installations using DPAPI Current-User binding, effectively
#    causing a full device lockout.
# ==============================================================================
DPAPI_DEVICE_KEY_ENTROPY_V1 = b"paracci.device_key.dpapi.current_user.v1"

# Maximum age of an in-progress burn reservation before crash recovery.
BURN_OPENING_STALE_SECONDS = 300
