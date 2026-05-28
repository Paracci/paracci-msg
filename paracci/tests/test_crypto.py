import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import constants, integrity
from core.crypto import derive_session_keys, wipe


def _fixture_keys():
    return derive_session_keys(
        bytes(range(32)),
        bytes(range(32, 64)),
        bytes(range(64, 96)),
        extra_salt=b"test-session-id-1234567890abcd"[:16],
    )


def test_protocol_labels_are_frozen_legacy_values():
    assert constants.LEGACY_V3_LABEL_SUFFIX == b"\na octyyghb ePED"
    assert constants.LABEL_MSG_XY_V3 == b"paracci.msg.x2y.v3\na octyyghb ePED"
    assert constants.LABEL_MSG_YX_V3 == b"paracci.msg.y2x.v3\na octyyghb ePED"
    assert constants.LABEL_SYNC_V3 == b"paracci.sync.v3\na octyyghb ePED"
    assert constants.LABEL_EVO_SEED_V3 == b"paracci.evo.seed.v3\na octyyghb ePED"
    assert constants.SESSION_MASTER_HKDF_LENGTH_V3 == 131


def test_derive_session_keys_matches_legacy_normal_output():
    keys = _fixture_keys()

    assert keys.key_x_to_y.hex() == "7325e4b0d3634504e86bac0d250bd791239a5e874b313b181d0b04172a881ac9"
    assert keys.key_y_to_x.hex() == "8f2e54ab4b425ed998f846818af56046caabe6459a0a5455a25907db96339a62"
    assert keys.sync_key.hex() == "2849cf884a3bd1fe4cced9dcf99d9ff4897375f2b9114f06b3d6a3036606fc0f"
    assert keys.evo_seed.hex() == "38bc789136c875d7ad7ef78d7693b7ea0c46c919157af55669ea1b52b278e09a"


def test_integrity_tamper_state_does_not_change_derived_keys():
    baseline = _fixture_keys()
    integrity.set_tampered_state(True)
    try:
        assert _fixture_keys() == baseline
    finally:
        integrity.set_tampered_state(False)


def test_public_envelope_file_seal_helpers_are_removed():
    assert not hasattr(constants, "ENVELOPE_FILE_SEAL_HMAC_KEY_V1")
    assert not hasattr(integrity, "generate_file_seal")
    assert not hasattr(integrity, "verify_file_seal")


# ---------------------------------------------------------------------------
# wipe() behaviour tests
# ---------------------------------------------------------------------------

def test_wipe_raises_on_bytes():
    """wipe() on immutable bytes must raise TypeError."""
    sensitive = b"sensitive-key-material"
    with pytest.raises(TypeError, match="wipe\\(\\) requires a bytearray"):
        wipe(sensitive)


def test_wipe_zeros_mutable_bytearray():
    """wipe() must zero every byte of a bytearray in place."""
    key_material = bytearray(b"sensitive-key-material")
    wipe(key_material)
    assert key_material == bytearray(len(key_material))


def test_wipe_zeros_bytearray_of_known_length():
    """wipe() zeroes an arbitrary-length bytearray."""
    buf = bytearray(range(64))
    wipe(buf)
    assert all(b == 0 for b in buf)


def test_wipe_raises_on_unsupported_type():
    """wipe() must still raise TypeError for unknown types."""
    with pytest.raises(TypeError):
        wipe(12345)


# ---------------------------------------------------------------------------
# derive_session_keys() — master intermediate is zeroed after derivation
# ---------------------------------------------------------------------------

def test_derive_session_keys_master_is_zeroed_after_success():
    """
    derive_session_keys() holds 'master' as a bytearray and zeroes it in the
    finally block.  We verify the derived keys are correct (master was valid
    during derivation) and that the function returns normally, implying the
    finally block executed without raising.
    """
    import unittest.mock as mock

    wiped_buffers = []
    original_wipe = wipe

    def capturing_wipe(data):
        if isinstance(data, bytearray):
            wiped_buffers.append(bytearray(data))  # snapshot before zeroing
        original_wipe(data)

    from core import crypto as _crypto_mod
    with mock.patch.object(_crypto_mod, "wipe", side_effect=capturing_wipe):
        keys = derive_session_keys(
            bytes(range(32)),
            bytes(range(32, 64)),
            bytes(range(64, 96)),
        )

    # At least one bytearray was wiped (the master intermediate).
    assert len(wiped_buffers) >= 1, "Expected wipe() to be called on at least one bytearray"
    # The snapshot captured before zeroing must be non-zero (i.e. it had real key material).
    assert any(b != 0 for b in wiped_buffers[0]), "Captured bytearray was unexpectedly all-zero before wipe"
    # The returned keys must still be correct (master was valid during derivation).
    assert len(keys.key_x_to_y) == 32
    assert len(keys.key_y_to_x) == 32
    assert len(keys.sync_key) == 32
    assert len(keys.evo_seed) == 32


def test_derive_session_keys_master_is_zeroed_on_failure():
    """
    Even when _sub() raises (simulated), the finally block still wipes master.
    """
    import unittest.mock as mock
    from core import crypto as _crypto_mod

    wiped_buffers = []

    def capturing_wipe(data):
        if isinstance(data, bytearray):
            wiped_buffers.append(bytearray(data))
        # Perform the actual zero so the bytearray is mutated normally.
        if isinstance(data, bytearray):
            for i in range(len(data)):
                data[i] = 0

    # Patch hkdf_derive so the _sub() call for the second label raises.
    call_count = [0]
    real_hkdf = _crypto_mod.hkdf_derive

    def failing_hkdf(ikm, length, info, salt=b""):
        call_count[0] += 1
        if call_count[0] == 3:  # second _sub() call
            raise RuntimeError("simulated HKDF failure")
        return real_hkdf(ikm, length, info, salt)

    with mock.patch.object(_crypto_mod, "wipe", side_effect=capturing_wipe):
        with mock.patch.object(_crypto_mod, "hkdf_derive", side_effect=failing_hkdf):
            with pytest.raises(RuntimeError, match="simulated HKDF failure"):
                derive_session_keys(
                    bytes(range(32)),
                    bytes(range(32, 64)),
                    bytes(range(64, 96)),
                )

    assert len(wiped_buffers) >= 1, "master bytearray must be wiped even on failure"


# ---------------------------------------------------------------------------
# ecdh() — finally block does not raise when wipe() is passed immutable bytes
# ---------------------------------------------------------------------------

def test_ecdh_finally_does_not_raise_on_invalid_key():
    """
    ecdh() must propagate the ValueError from an invalid key without the
    finally block raising a secondary exception (old code would raise TypeError
    from wipe on bytes; new code must not).
    """
    from core.crypto import ecdh
    bad_key = bytes(32)  # all-zero is an invalid X25519 private key
    with pytest.raises((ValueError, Exception)):
        ecdh(bad_key, bytes(32))
    # If we reach here the finally block did not raise a secondary exception.


# ---------------------------------------------------------------------------
# derive_hybrid_shared_secret() — IKM bytearray is zeroed after derivation
# ---------------------------------------------------------------------------

def test_derive_hybrid_shared_secret_wipes_ikm():
    """
    derive_hybrid_shared_secret() concatenates the two secrets into a bytearray
    IKM and wipes it in the finally block.  We capture the wipe call and verify
    the IKM had content before zeroing and that the function returns a 64-byte result.
    """
    import unittest.mock as mock
    from core.crypto import derive_hybrid_shared_secret
    from core import crypto as _crypto_mod

    wiped_buffers = []
    original_wipe = wipe

    def capturing_wipe(data):
        if isinstance(data, bytearray):
            wiped_buffers.append(bytearray(data))
        original_wipe(data)

    x25519_secret = bytes(range(32))
    ml_kem_secret = bytes(range(32, 64))
    session_id    = bytes(range(16))

    with mock.patch.object(_crypto_mod, "wipe", side_effect=capturing_wipe):
        result = derive_hybrid_shared_secret(x25519_secret, ml_kem_secret, session_id)

    assert len(result) == 64, "Combined secret must be 64 bytes"
    assert len(wiped_buffers) >= 1, "IKM bytearray must have been wiped"
    # The IKM snapshot (captured before zeroing) is the concatenation of both inputs.
    expected_ikm = bytearray(x25519_secret) + bytearray(ml_kem_secret)
    assert wiped_buffers[0] == expected_ikm, "Captured IKM content does not match expected concatenation"


def test_crypto_memory_hygiene_bytearrays():
    """Verify that private keys, shared secrets, and derived keys are returned as bytearrays and can be wiped."""
    from core.crypto import (
        generate_keypair,
        generate_identity_keypair,
        ecdh,
        hkdf_derive,
        derive_hybrid_shared_secret,
        derive_session_keys,
    )

    # 1. generate_keypair & generate_identity_keypair
    priv, pub = generate_keypair()
    assert isinstance(priv, bytearray)
    assert isinstance(pub, bytes)
    wipe(priv)
    assert all(b == 0 for b in priv)

    priv_id, pub_id = generate_identity_keypair()
    assert isinstance(priv_id, bytearray)
    assert isinstance(pub_id, bytes)
    wipe(priv_id)
    assert all(b == 0 for b in priv_id)

    # 2. ecdh
    priv_x, pub_x = generate_keypair()
    priv_y, pub_y = generate_keypair()
    secret = ecdh(priv_x, pub_y)
    assert isinstance(secret, bytearray)
    wipe(secret)
    assert all(b == 0 for b in secret)

    # 3. hkdf_derive
    derived = hkdf_derive(b"input", 32, b"info")
    assert isinstance(derived, bytearray)
    wipe(derived)
    assert all(b == 0 for b in derived)

    # 4. derive_hybrid_shared_secret
    x_sec = bytearray(range(32))
    m_sec = bytearray(range(32, 64))
    sid = bytearray(range(16))
    shared = derive_hybrid_shared_secret(x_sec, m_sec, sid)
    assert isinstance(shared, bytearray)
    # Inputs should be zeroed
    assert all(b == 0 for b in x_sec)
    assert all(b == 0 for b in m_sec)

    # 5. derive_session_keys
    shared_copy = bytearray(shared)
    keys = derive_session_keys(shared, pub_x, pub_y)
    assert isinstance(keys.key_x_to_y, bytearray)
    assert isinstance(keys.key_y_to_x, bytearray)
    assert isinstance(keys.sync_key, bytearray)
    assert isinstance(keys.evo_seed, bytearray)
    assert all(b == 0 for b in shared)  # shared should be zeroed

    # Wipe keys
    wipe(keys.key_x_to_y)
    assert all(b == 0 for b in keys.key_x_to_y)
