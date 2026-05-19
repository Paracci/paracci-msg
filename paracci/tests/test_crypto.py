import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import constants, integrity
from core.crypto import derive_session_keys


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


def test_file_seal_uses_frozen_compatibility_key():
    content = b"paracci-test-envelope-content"

    seal = integrity.generate_file_seal(content)

    assert seal.hex() == "da089b719462992a544eda7a9f21ac33"
    assert integrity.verify_file_seal(content, seal)
