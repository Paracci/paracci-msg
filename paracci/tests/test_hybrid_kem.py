import sys
from pathlib import Path

import pytest

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import constants, hybrid_kem
from core.crypto import (
    compute_handshake_transcript,
    derive_hybrid_shared_secret,
    ecdh,
    generate_keypair,
    new_message_id,
)
from core.hybrid_kem import (
    HybridKEMError,
    NO_POST_QUANTUM_ERROR,
    OLDER_VERSION_ERROR,
    initiator_kem_complete,
    initiator_kem_setup,
    responder_kem_respond,
    validate_hybrid_handshake_payload,
)
from core.quantum_kem import QuantumKEMError


def test_hybrid_domain_constant_is_frozen():
    assert constants.HYBRID_KEM_DOMAIN == b"paracci.hybrid.kem.v1"


def test_transcript_domain_constant_is_frozen():
    assert constants.TRANSCRIPT_DOMAIN == b"paracci.transcript.v1"


def _transcript_inputs() -> dict:
    return {
        "session_id": bytes(range(16)),
        "initiator_identity_pub": bytes(range(32)),
        "responder_identity_pub": bytes(range(32, 64)),
        "ml_kem_algorithm": constants.KEM_ALGORITHM,
        "ml_kem_public_key": bytes(i % 256 for i in range(1184)),
        "ml_kem_ciphertext": bytes((255 - i) % 256 for i in range(1088)),
    }


def _transcript(**overrides: object) -> bytes:
    inputs = _transcript_inputs()
    inputs.update(overrides)
    return compute_handshake_transcript(**inputs)


def test_compute_handshake_transcript_returns_32_bytes_and_is_deterministic():
    first = _transcript()
    second = _transcript()

    assert len(first) == 32
    assert first == second


def test_compute_handshake_transcript_is_sensitive_to_each_input():
    baseline = _transcript()
    inputs = _transcript_inputs()

    cases = [
        {"session_id": bytes([inputs["session_id"][0] ^ 0x01]) + inputs["session_id"][1:]},
        {
            "initiator_identity_pub": bytes([inputs["initiator_identity_pub"][0] ^ 0x01])
            + inputs["initiator_identity_pub"][1:]
        },
        {
            "responder_identity_pub": bytes([inputs["responder_identity_pub"][0] ^ 0x01])
            + inputs["responder_identity_pub"][1:]
        },
        {"ml_kem_algorithm": "ML-KEM-1024"},
        {
            "ml_kem_public_key": bytes([inputs["ml_kem_public_key"][0] ^ 0x01])
            + inputs["ml_kem_public_key"][1:]
        },
        {
            "ml_kem_ciphertext": bytes([inputs["ml_kem_ciphertext"][0] ^ 0x01])
            + inputs["ml_kem_ciphertext"][1:]
        },
    ]

    for override in cases:
        assert _transcript(**override) != baseline




@oqs_required
def test_derive_hybrid_shared_secret_both_parties_match():
    x_private, x_public = generate_keypair()
    y_private, y_public = generate_keypair()
    x25519_from_x = ecdh(x_private, y_public)
    x25519_from_y = ecdh(y_private, x_public)

    setup = initiator_kem_setup()
    response = responder_kem_respond(setup["ml_kem_public_key"])
    ml_kem_from_x = initiator_kem_complete(
        setup["ml_kem_secret_key"],
        response["ml_kem_ciphertext"],
    )
    ml_kem_from_y = response["ml_kem_shared_secret"]
    session_id = new_message_id()
    transcript = compute_handshake_transcript(
        session_id=session_id,
        initiator_identity_pub=bytes(range(32)),
        responder_identity_pub=bytes(range(32, 64)),
        ml_kem_algorithm=constants.KEM_ALGORITHM,
        ml_kem_public_key=setup["ml_kem_public_key"],
        ml_kem_ciphertext=response["ml_kem_ciphertext"],
    )

    hybrid_from_x = derive_hybrid_shared_secret(
        x25519_from_x,
        ml_kem_from_x,
        session_id,
        transcript,
    )
    hybrid_from_y = derive_hybrid_shared_secret(
        x25519_from_y,
        ml_kem_from_y,
        session_id,
        transcript,
    )

    assert len(hybrid_from_x) == 64
    assert hybrid_from_x == hybrid_from_y


def test_derive_hybrid_shared_secret_changes_when_inputs_change():
    x25519_shared = bytes(range(32))
    ml_kem_shared = bytes(range(32, 64))
    session_id = bytes(range(16))
    transcript = _transcript(session_id=session_id)

    baseline = derive_hybrid_shared_secret(x25519_shared, ml_kem_shared, session_id, transcript)
    changed_x25519 = derive_hybrid_shared_secret(
        bytes([x25519_shared[0] ^ 0x01]) + x25519_shared[1:],
        ml_kem_shared,
        session_id,
        transcript,
    )
    changed_ml_kem = derive_hybrid_shared_secret(
        x25519_shared,
        bytes([ml_kem_shared[0] ^ 0x01]) + ml_kem_shared[1:],
        session_id,
        transcript,
    )
    changed_session_id_value = bytes([session_id[0] ^ 0x01]) + session_id[1:]
    changed_session_id = derive_hybrid_shared_secret(
        x25519_shared,
        ml_kem_shared,
        changed_session_id_value,
        _transcript(session_id=changed_session_id_value),
    )

    assert changed_x25519 != baseline
    assert changed_ml_kem != baseline
    assert changed_session_id != baseline


def test_derive_hybrid_shared_secret_with_transcript_differs_from_compatibility_path():
    x25519_shared = bytes(range(32))
    ml_kem_shared = bytes(range(32, 64))
    session_id = bytes(range(16))

    legacy_compatible = derive_hybrid_shared_secret(x25519_shared, ml_kem_shared, session_id)
    transcript_bound = derive_hybrid_shared_secret(
        x25519_shared,
        ml_kem_shared,
        session_id,
        _transcript(session_id=session_id),
    )

    assert transcript_bound != legacy_compatible


def test_derive_hybrid_shared_secret_same_transcript_matches_for_both_parties():
    x25519_shared = bytes(range(32))
    ml_kem_shared = bytes(range(32, 64))
    session_id = bytes(range(16))
    transcript = _transcript(session_id=session_id)

    first = derive_hybrid_shared_secret(x25519_shared, ml_kem_shared, session_id, transcript)
    second = derive_hybrid_shared_secret(x25519_shared, ml_kem_shared, session_id, transcript)

    assert len(first) == 64
    assert first == second


def test_derive_hybrid_shared_secret_changes_when_transcript_changes():
    x25519_shared = bytes(range(32))
    ml_kem_shared = bytes(range(32, 64))
    session_id = bytes(range(16))

    first = derive_hybrid_shared_secret(
        x25519_shared,
        ml_kem_shared,
        session_id,
        _transcript(session_id=session_id),
    )
    second = derive_hybrid_shared_secret(
        x25519_shared,
        ml_kem_shared,
        session_id,
        _transcript(
            session_id=session_id,
            ml_kem_ciphertext=bytes([0x42]) + _transcript_inputs()["ml_kem_ciphertext"][1:],
        ),
    )

    assert first != second


@oqs_required
def test_hybrid_kem_round_trip():
    setup = initiator_kem_setup()

    response = responder_kem_respond(setup["ml_kem_public_key"])
    completed_secret = initiator_kem_complete(
        setup["ml_kem_secret_key"],
        response["ml_kem_ciphertext"],
    )

    assert response["ml_kem_shared_secret"] == completed_secret


def test_v1_setup_detection_message():
    with pytest.raises(HybridKEMError, match="older version of Paracci"):
        validate_hybrid_handshake_payload(
            {"handshake_version": 1},
            expected_kind="initiator",
        )
    try:
        validate_hybrid_handshake_payload(
            {"handshake_version": 1},
            expected_kind="initiator",
        )
    except HybridKEMError as exc:
        assert str(exc) == OLDER_VERSION_ERROR


def test_missing_version_setup_detection_message():
    with pytest.raises(HybridKEMError) as exc_info:
        validate_hybrid_handshake_payload({}, expected_kind="initiator")

    assert str(exc_info.value) == OLDER_VERSION_ERROR


def test_v2_setup_detection_message():
    with pytest.raises(HybridKEMError) as exc_info:
        validate_hybrid_handshake_payload(
            {"handshake_version": 2},
            expected_kind="initiator",
        )

    assert str(exc_info.value) == OLDER_VERSION_ERROR
    assert exc_info.value.i18n_key == "hybrid_kem_legacy_session"


def test_hybrid_kem_error_propagation(monkeypatch):
    def fail_kem(*_args, **_kwargs):
        raise QuantumKEMError("mock KEM failure")

    monkeypatch.setattr(hybrid_kem, "kem_generate_keypair", fail_kem)
    with pytest.raises(HybridKEMError, match="keypair generation failed"):
        initiator_kem_setup()

    monkeypatch.setattr(hybrid_kem, "kem_encapsulate", fail_kem)
    with pytest.raises(HybridKEMError, match="encapsulation failed"):
        responder_kem_respond(b"public-key")

    monkeypatch.setattr(hybrid_kem, "kem_decapsulate", fail_kem)
    with pytest.raises(HybridKEMError, match="decapsulation failed"):
        initiator_kem_complete(b"secret-key", b"ciphertext")
