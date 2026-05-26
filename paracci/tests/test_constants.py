import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import constants


def test_legacy_v3_label_suffix_tripwire():
    """
    Tripwire test: asserts the exact byte value of LEGACY_V3_LABEL_SUFFIX.
    If this value is changed, compatibility with all existing v3 message envelopes is lost.
    """
    assert constants.LEGACY_V3_LABEL_SUFFIX == b"\na octyyghb ePED"


def test_session_master_hkdf_length_v3_tripwire():
    """
    Tripwire test: asserts the exact value of SESSION_MASTER_HKDF_LENGTH_V3.
    Changing this breaks master key derivation for v3 message compatibility.
    """
    assert constants.SESSION_MASTER_HKDF_LENGTH_V3 == 131


def test_dpapi_device_key_entropy_v1_tripwire():
    """
    Tripwire test: asserts the exact value of DPAPI_DEVICE_KEY_ENTROPY_V1.
    Changing this causes permanent device key decryption failure under DPAPI current-user binding.
    """
    assert constants.DPAPI_DEVICE_KEY_ENTROPY_V1 == b"paracci.device_key.dpapi.current_user.v1"


def test_legacy_handshake_file_wrapper_domain_v3_tripwire():
    """
    Tripwire test: asserts the exact value of LEGACY_HANDSHAKE_FILE_WRAPPER_DOMAIN_V3.
    """
    assert constants.LEGACY_HANDSHAKE_FILE_WRAPPER_DOMAIN_V3 == b"paracci.app.session.file.v1"


def test_domain_session_master_v3_tripwire():
    """
    Tripwire test: asserts the exact value of DOMAIN_SESSION_MASTER_V3.
    """
    assert constants.DOMAIN_SESSION_MASTER_V3 == b"paracci.session.master.v3"
