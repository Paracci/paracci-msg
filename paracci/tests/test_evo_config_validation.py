import base64
import json
import struct
import sys
from pathlib import Path

import pytest

from conftest import oqs_required

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import envelope as envelope_module
from core import session as session_module
from core.crypto import (
    DerivedKeys,
    EncryptedBlob,
    NONCE_LEN,
    decrypt,
    encrypt,
    generate_identity_keypair,
    generate_keypair,
    random_bytes,
)
from core.evolution import (
    EvoConfig,
    MAX_LEGACY_ARGON2_MEM_KB,
    MAX_LEGACY_ARGON2_PAR,
    MAX_LEGACY_ARGON2_TIME,
    MAX_EVO_STEP,
    MAX_SESSION_TTL_SEC,
    compute_keys_at_step,
    deserialize_evo_config,
    make_evo_config,
    serialize_evo_config,
    validate_evo_step,
)
from core.session import (
    SESSION_STATE_ACTIVE,
    accept_initiator_and_create_responder,
    create_initiator_session,
    deserialize_session_meta,
    serialize_session_meta,
)


def _packed_evo_config(
    ttl: int = 0,
    created_at: int = 1,
    time_cost: int = 2,
    memory_cost: int = 65536,
    parallelism: int = 2,
) -> bytes:
    return struct.pack(">IIHII", ttl, created_at, time_cost, memory_cost, parallelism)


def _malicious_evo_config_hex() -> str:
    return _packed_evo_config(time_cost=MAX_LEGACY_ARGON2_TIME + 1).hex()


def _identity():
    private_key, public_key = generate_identity_keypair()
    return private_key, public_key


def _signed_initiator_file(evo_config_hex: str) -> bytes:
    identity_priv, identity_pub = _identity()
    _x_priv, x_pub = generate_keypair()
    session_id = random_bytes(16)
    payload = {
        "handshake_version": session_module.HANDSHAKE_VERSION,
        "session_id": session_id.hex(),
        "x_pub": x_pub.hex(),
        "x_identity_pub": identity_pub.hex(),
        "ml_kem_algorithm": session_module.KEM_ALGORITHM,
        "ml_kem_public_key": base64.b64encode(random_bytes(1184)).decode("ascii"),
        "evo_config": evo_config_hex,
        "label": "malicious",
        "username": "attacker",
        "created_at": 1,
    }
    payload["signature"] = session_module.sign_identity(
        identity_priv,
        session_module._handshake_signing_bytes(
            session_module.SIGN_INITIATOR_LABEL,
            payload,
        ),
    ).hex()
    header = session_module._build_file_header(session_module.TYPE_INITIATOR, session_id)
    return header + session_module._canonical_payload(payload)


def _valid_active_meta_with_config(evo_config: EvoConfig) -> session_module.SessionMeta:
    return session_module.SessionMeta(
        session_id=random_bytes(16),
        role="X",
        my_priv=random_bytes(32),
        my_pub=random_bytes(32),
        peer_pub=random_bytes(32),
        keys=DerivedKeys(
            key_x_to_y=random_bytes(32),
            key_y_to_x=random_bytes(32),
            sync_key=random_bytes(32),
            evo_seed=random_bytes(32),
        ),
        bond_seed=random_bytes(32),
        send_seed=random_bytes(32),
        recv_seed=random_bytes(32),
        bond_nonce=random_bytes(32),
        tx_count=0,
        rx_count=0,
        my_qseed=random_bytes(128),
        peer_qseed=random_bytes(128),
        peer_username=None,
        color="#0a84ff",
        evo_config=evo_config,
        state=SESSION_STATE_ACTIVE,
        label="test",
        created_at=1,
        my_identity_pub=random_bytes(32),
        peer_identity_pub=random_bytes(32),
        handshake_version=session_module.HANDSHAKE_VERSION,
        safety_confirmed=True,
        safety_confirmed_at=1,
    )


def test_deserialize_evo_config_accepts_supported_ceiling():
    cfg = EvoConfig(
        session_ttl_sec=MAX_SESSION_TTL_SEC,
        created_at=1,
        legacy_argon2_time=MAX_LEGACY_ARGON2_TIME,
        legacy_argon2_mem=MAX_LEGACY_ARGON2_MEM_KB,
        legacy_argon2_par=MAX_LEGACY_ARGON2_PAR,
    )

    assert deserialize_evo_config(serialize_evo_config(cfg)) == cfg


@pytest.mark.parametrize(
    "packed",
    [
        _packed_evo_config(time_cost=MAX_LEGACY_ARGON2_TIME + 1),
        _packed_evo_config(memory_cost=MAX_LEGACY_ARGON2_MEM_KB + 1),
        _packed_evo_config(parallelism=MAX_LEGACY_ARGON2_PAR + 1),
        _packed_evo_config(ttl=MAX_SESSION_TTL_SEC + 1),
    ],
)
def test_deserialize_evo_config_rejects_unbounded_values(packed):
    with pytest.raises(ValueError):
        deserialize_evo_config(packed)


def test_evolution_steps_are_bounded():
    with pytest.raises(Exception):
        validate_evo_step(-1)
    with pytest.raises(Exception):
        compute_keys_at_step(random_bytes(32), MAX_EVO_STEP + 1)


@oqs_required
def test_signed_malicious_initiator_rejects_legacy_compatibility_metadata_before_key_derivation(monkeypatch):
    malicious_file = _signed_initiator_file(_malicious_evo_config_hex())
    y_identity_priv, y_identity_pub = _identity()
    malicious_file = _signed_initiator_file(_malicious_evo_config_hex())
    y_identity_priv, y_identity_pub = _identity()

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("derive_session_keys should not be called")

    monkeypatch.setattr(session_module, "derive_session_keys", fail_if_called)

    with pytest.raises(session_module.SessionFileError, match="Invalid evolution configuration"):
        accept_initiator_and_create_responder(
            malicious_file,
            "Y",
            identity_pub=y_identity_pub,
            identity_priv=y_identity_priv,
        )


@oqs_required
def test_persisted_session_metadata_rejects_malicious_evo_config():
    identity_priv, identity_pub = _identity()
    meta, _init_file = create_initiator_session(
        "X",
        identity_pub=identity_pub,
        identity_priv=identity_priv,
    )
    device_key = random_bytes(32)
    encrypted = serialize_session_meta(meta, device_key)

    # --- Tamper with the v3 binary envelope ---
    # Decrypt the v3 envelope, parse it, corrupt the evo_config in the public
    # JSON section, re-assemble, re-encrypt, and verify that deserialization
    # catches the malicious evolution configuration.
    from core.session import (
        _SESSION_BINARY_VERSION,
        _SESSION_V3_AAD,
    )
    blob = EncryptedBlob(
        nonce=encrypted[:NONCE_LEN],
        ciphertext=encrypted[NONCE_LEN:],
    )
    plaintext = decrypt(device_key, blob, aad=_SESSION_V3_AAD)
    assert plaintext[:1] == _SESSION_BINARY_VERSION, "Expected v3 binary envelope"

    # Parse the envelope layout: [1B ver][4B secret_len][secret][4B json_len][json]
    secret_len = int.from_bytes(plaintext[1:5], "big")
    secret_blob = plaintext[5: 5 + secret_len]
    json_offset = 5 + secret_len
    json_len = int.from_bytes(plaintext[json_offset: json_offset + 4], "big")
    json_bytes = plaintext[json_offset + 4: json_offset + 4 + json_len]

    # Corrupt the evo_config in the public JSON
    data = json.loads(json_bytes.decode("utf-8"))
    data["evo_config"] = _malicious_evo_config_hex()
    tampered_json = json.dumps(data, separators=(",", ":")).encode("utf-8")

    # Reassemble the envelope with the tampered JSON
    tampered_plain = bytearray()
    tampered_plain += _SESSION_BINARY_VERSION
    tampered_plain += secret_len.to_bytes(4, "big")
    tampered_plain += secret_blob
    tampered_plain += len(tampered_json).to_bytes(4, "big")
    tampered_plain += tampered_json

    tampered_blob = encrypt(device_key, bytes(tampered_plain), aad=_SESSION_V3_AAD)

    with pytest.raises(ValueError):
        deserialize_session_meta(tampered_blob.nonce + tampered_blob.ciphertext, device_key)


def test_envelope_rejects_invalid_legacy_compatibility_metadata_for_current_seal(monkeypatch):
    invalid_config = EvoConfig(
        session_ttl_sec=0,
        created_at=1,
        legacy_argon2_time=MAX_LEGACY_ARGON2_TIME + 1,
        legacy_argon2_mem=65536,
        legacy_argon2_par=2,
    )
    meta = _valid_active_meta_with_config(invalid_config)

    def fail_if_called(*_args, **_kwargs):
        raise AssertionError("legacy Argon2 payload derivation should not be called")

    monkeypatch.setattr(envelope_module, "_derive_legacy_payload_key_v1_v2", fail_if_called)

    with pytest.raises(envelope_module.EnvelopeError, match="Invalid evolution configuration"):
        envelope_module.seal_envelope(b"blocked", meta)
