"""
Paracci - tests/test_core.py
Core modules integration and unit tests (v2 compatible).
ASCII-only version for cross-platform compatibility.
"""

import os
import sys
import time
import tempfile
from pathlib import Path

import pytest

from conftest import oqs_required

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.crypto import (
    generate_keypair, ecdh, derive_session_keys,
    encrypt, decrypt, EncryptedBlob,
    new_message_id, message_id_fingerprint,
    random_bytes, generate_identity_keypair,
    pack_uint32, pack_uint64,
)
from core.evolution import (
    make_evo_config, serialize_evo_config, deserialize_evo_config,
    compute_keys_at_step, compute_bond_seed, check_session_ttl,
    EvoExpiredError, EVO_UNLIMITED,
)
from core.session import (
    create_initiator_session,
    accept_initiator_and_create_responder,
    finalize_initiator_session,
    serialize_session_meta,
    deserialize_session_meta,
    apply_bond_nonce_to_y,
    confirm_safety_code,
    get_session_safety_code,
    SESSION_STATE_ACTIVE,
    SESSION_STATE_UNVERIFIED,
)
from core import envelope as envelope_module
from core.envelope import seal_envelope, open_envelope, EnvelopeError, EnvelopeTTLError
from core.burn import (
    BURN_STATUS_BURNED,
    BURN_STATUS_FAILED,
    BURN_STATUS_OPENING,
    BurnDB,
    BurnGuard,
    is_device_initialized,
    init_device,
    unlock_device,
    AlreadyBurnedError,
    TTLExpiredError,
)

PASS = "[OK]"
FAIL = "[FAIL]"
results = []

_create_initiator_session_impl = create_initiator_session
_accept_initiator_and_create_responder_impl = accept_initiator_and_create_responder


def _new_identity():
    priv, pub = generate_identity_keypair()
    return priv, pub


def create_initiator_session(*args, **kwargs):
    if "identity_pub" not in kwargs or "identity_priv" not in kwargs:
        identity_priv, identity_pub = _new_identity()
        kwargs["identity_pub"] = identity_pub
        kwargs["identity_priv"] = identity_priv
    return _create_initiator_session_impl(*args, **kwargs)


def accept_initiator_and_create_responder(*args, **kwargs):
    if "identity_pub" not in kwargs or "identity_priv" not in kwargs:
        identity_priv, identity_pub = _new_identity()
        kwargs["identity_pub"] = identity_pub
        kwargs["identity_priv"] = identity_priv
    return _accept_initiator_and_create_responder_impl(*args, **kwargs)


def confirm_pair(meta_x, meta_y):
    code_x = get_session_safety_code(meta_x)
    code_y = get_session_safety_code(meta_y)
    assert code_x == code_y
    return confirm_safety_code(meta_x, code_x), confirm_safety_code(meta_y, code_y)


def run_test(name: str, fn):
    try:
        fn()
        print(f"  {PASS} {name}")
        results.append((name, True, None))
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"  {FAIL} {name}")
        print(f"      Error: {e}")
        results.append((name, False, str(e)))


# ============================================================
# CRYPTO TESTS
# ============================================================
print("\n-- crypto.py --------------------------------------")


def test_keypair():
    priv, pub = generate_keypair()
    assert len(priv) == 32
    assert len(pub)  == 32
    assert priv != pub

run_test("Keypair generation (32 byte)", test_keypair)


def test_ecdh_symmetric():
    priv_x, pub_x = generate_keypair()
    priv_y, pub_y = generate_keypair()
    secret_x = ecdh(priv_x, pub_y)
    secret_y = ecdh(priv_y, pub_x)
    assert secret_x == secret_y, "ECDH not symmetric!"

run_test("ECDH symmetry (X and Y must produce same secret)", test_ecdh_symmetric)


def test_derived_keys_asymmetric():
    priv_x, pub_x = generate_keypair()
    priv_y, pub_y = generate_keypair()
    secret = ecdh(priv_x, pub_y)
    salt = b"test"
    keys = derive_session_keys(secret, pub_x, pub_y, extra_salt=salt)
    # All keys must be different
    all_keys = [keys.key_x_to_y, keys.key_y_to_x, keys.sync_key, keys.evo_seed]
    assert len(set(all_keys)) == 4, "Derived keys are the same!"

run_test("HKDF derivation - 4 different keys", test_derived_keys_asymmetric)


def test_encrypt_decrypt():
    key = random_bytes(32)
    plaintext = b"Secret message 12345"
    blob = encrypt(key, plaintext, aad=b"header")
    result = decrypt(key, blob, aad=b"header")
    assert result == plaintext

run_test("ChaCha20-Poly1305 encrypt/decrypt", test_encrypt_decrypt)


def test_aad_tamper():
    key = random_bytes(32)
    blob = encrypt(key, b"message", aad=b"original")
    try:
        decrypt(key, blob, aad=b"modified")
        assert False, "Modified AAD accepted!"
    except Exception:
        pass  # Expected

run_test("Poly1305 fail on AAD modification", test_aad_tamper)


def test_ciphertext_tamper():
    key = random_bytes(32)
    blob = encrypt(key, b"message")
    tampered = EncryptedBlob(nonce=blob.nonce, ciphertext=blob.ciphertext[:-1] + bytes([blob.ciphertext[-1] ^ 0xFF]))
    try:
        decrypt(key, tampered)
        assert False, "Modified ciphertext accepted!"
    except Exception:
        pass

run_test("Poly1305 fail on ciphertext modification", test_ciphertext_tamper)


def test_msg_id_fingerprint():
    mid = new_message_id()
    fp1 = message_id_fingerprint(mid)
    fp2 = message_id_fingerprint(mid)
    assert fp1 == fp2
    assert fp1 != mid  # Hash, not raw ID

run_test("MSG_ID fingerprint deterministic", test_msg_id_fingerprint)


# ============================================================
# EVOLUTION TESTS
# ============================================================
print("\n-- evolution.py ------------------------------------")


def test_evo_config_serialize():
    cfg = make_evo_config(session_ttl_sec=86400)
    data = serialize_evo_config(cfg)
    cfg2 = deserialize_evo_config(data)
    assert cfg == cfg2

run_test("EvoConfig serialization / restoration", test_evo_config_serialize)


def test_evo_step_deterministic():
    seed = random_bytes(32)
    s1 = compute_keys_at_step(seed, 5)
    s2 = compute_keys_at_step(seed, 5)
    assert s1.key_x_to_y == s2.key_x_to_y
    assert s1.key_y_to_x == s2.key_y_to_x

run_test("Evolution step deterministic (same seed -> same result)", test_evo_step_deterministic)


def test_evo_both_sides_same():
    """X and Y calculate the same evolution step independently."""
    priv_x, pub_x = generate_keypair()
    priv_y, pub_y = generate_keypair()
    session_id = new_message_id()

    secret_x = ecdh(priv_x, pub_y)
    secret_y = ecdh(priv_y, pub_x)

    keys_x = derive_session_keys(secret_x, pub_x, pub_y, extra_salt=session_id)
    keys_y = derive_session_keys(secret_y, pub_x, pub_y, extra_salt=session_id)

    assert keys_x.evo_seed == keys_y.evo_seed, "Evolution seeds mismatch!"

    bond_nonce = random_bytes(32)
    bond_seed_x = compute_bond_seed(keys_x.evo_seed, bond_nonce)
    bond_seed_y = compute_bond_seed(keys_y.evo_seed, bond_nonce)
    assert bond_seed_x == bond_seed_y

    step_x = compute_keys_at_step(bond_seed_x, 3)
    step_y = compute_keys_at_step(bond_seed_y, 3)

    assert step_x.key_x_to_y == step_y.key_x_to_y
    assert step_x.key_y_to_x == step_y.key_y_to_x
    assert keys_x.sync_key == keys_y.sync_key

run_test("X and Y produce same evolution step independently", test_evo_both_sides_same)


def test_evo_expired():
    cfg = make_evo_config(session_ttl_sec=1, created_at=int(time.time()) - 10)
    try:
        check_session_ttl(cfg)
        assert False, "Expired session accepted!"
    except EvoExpiredError:
        pass

run_test("Expired session must not produce evolution step", test_evo_expired)


# ============================================================
# SESSION TESTS
# ============================================================
print("\n-- session.py --------------------------------------")


@oqs_required
def test_full_session_handshake():
    """X -> Y -> X full handshake."""
    # X creates session
    meta_x, init_file = create_initiator_session(
        label="Secret with Y",
        session_ttl_sec=EVO_UNLIMITED,
    )
    assert meta_x.state == "pending"
    assert meta_x.keys is None

    # Y accepts initiator, creates session
    meta_y, resp_file = accept_initiator_and_create_responder(
        init_file, local_label="Secret with X"
    )
    assert meta_y.state == SESSION_STATE_UNVERIFIED
    assert meta_y.keys is not None
    assert meta_y.bond_seed is None # No message received yet

    # X accepts responder, finalizes session
    meta_x2 = finalize_initiator_session(meta_x, resp_file)
    assert meta_x2.state == SESSION_STATE_UNVERIFIED
    assert meta_x2.keys is not None
    assert meta_x2.bond_seed is not None # X generated bond seed on finalize
    assert meta_x2.bond_nonce is not None
    meta_x2, meta_y = confirm_pair(meta_x2, meta_y)
    assert meta_x2.state == SESSION_STATE_ACTIVE
    assert meta_y.state == SESSION_STATE_ACTIVE

    # X and Y have same evolution seed?
    assert meta_x2.keys.evo_seed == meta_y.keys.evo_seed

run_test("Full session handshake (X -> Y -> X)", test_full_session_handshake)


@oqs_required
def test_session_serialize():
    meta_x, init_file = create_initiator_session("Test")
    meta_y, resp_file = accept_initiator_and_create_responder(init_file, "Test")
    meta_x2 = finalize_initiator_session(meta_x, resp_file)

    device_key = random_bytes(32)
    enc = serialize_session_meta(meta_x2, device_key)
    restored = deserialize_session_meta(enc, device_key)

    assert restored.session_id == meta_x2.session_id
    assert restored.keys.evo_seed == meta_x2.keys.evo_seed
    assert restored.role == "X"

run_test("Session serialization / restoration", test_session_serialize)


# ============================================================
# ENVELOPE TESTS
# ============================================================
print("\n-- envelope.py -------------------------------------")


def _make_sessions():
    meta_x, init_file = create_initiator_session("Test", session_ttl_sec=EVO_UNLIMITED)
    meta_y, resp_file = accept_initiator_and_create_responder(init_file, "Test")
    meta_x2 = finalize_initiator_session(meta_x, resp_file)
    return confirm_pair(meta_x2, meta_y)


def _with_legacy_envelope_metadata(meta_x, meta_y):
    config = meta_x.evo_config._replace(
        legacy_argon2_time=1,
        legacy_argon2_mem=16384,
        legacy_argon2_par=1,
    )
    qseed = b"Q" * 128
    return (
        meta_x._replace(evo_config=config, my_qseed=qseed),
        meta_y._replace(evo_config=config, peer_qseed=qseed),
    )


def _legacy_v1_envelope(payload_bytes, session):
    if isinstance(payload_bytes, str):
        payload_bytes = payload_bytes.encode("utf-8")
    direction, msg_key, _next_seed, step = envelope_module._prepare_seal_keys(session)
    msg_id = new_message_id()
    expire_at = 0
    flags = 0
    header = (
        envelope_module.MAGIC_BYTES
        + bytes([envelope_module.LEGACY_FILE_VERSION, envelope_module.TYPE_MESSAGE])
        + session.session_id
        + msg_id
        + bytes([direction, flags])
        + pack_uint32(step)
        + pack_uint64(expire_at)
    )
    work_key = envelope_module._derive_legacy_payload_key_v1_v2(
        msg_key,
        header,
        session.my_qseed,
        session.evo_config,
    )
    payload_blob = encrypt(work_key, payload_bytes, aad=header)
    sync_raw = envelope_module._build_sync_payload(
        session.role,
        step,
        msg_id,
        session.bond_nonce if session.role == "X" and step == 0 else None,
    )
    sync_blob = encrypt(session.keys.sync_key, sync_raw, aad=header + b"sync")
    content = (
        header
        + pack_uint32(len(payload_blob.ciphertext))
        + payload_blob.nonce
        + payload_blob.ciphertext
        + sync_blob.nonce
        + sync_blob.ciphertext
    )
    return content + (b"\xff" * envelope_module.LEGACY_SEAL_SIZE)


@oqs_required
def test_x_sends_y_receives():
    meta_x, meta_y = _make_sessions()
    text = "Hello Y, this is a secret message."

    sealed = seal_envelope(text, meta_x, single_use=False)
    meta_x = meta_x._replace(
        tx_count=meta_x.tx_count + 1,
        send_seed=sealed.next_seed
    )
    
    opened = open_envelope(sealed.file_bytes, meta_y)
    assert opened.text == text
    
    # Y got bond_nonce from X!
    assert opened.bond_nonce is not None
    meta_y = apply_bond_nonce_to_y(meta_y, opened.bond_nonce)
    meta_y = meta_y._replace(
        rx_count=opened.next_step,
        recv_seed=opened.next_seed
    )
    assert meta_y.bond_seed == meta_x.bond_seed

run_test("X -> Y message send and open", test_x_sends_y_receives)


@oqs_required
def test_y_sends_x_receives():
    meta_x, meta_y = _make_sessions()
    
    # X must send first message for Y to bond
    sealed_x = seal_envelope("First message", meta_x)
    meta_x = meta_x._replace(
        tx_count=meta_x.tx_count + 1,
        send_seed=sealed_x.next_seed
    )
    
    opened_x = open_envelope(sealed_x.file_bytes, meta_y)
    meta_y = apply_bond_nonce_to_y(meta_y, opened_x.bond_nonce)
    meta_y = meta_y._replace(
        rx_count=opened_x.next_step,
        recv_seed=opened_x.next_seed
    )
    
    # Now Y replies
    text = "Hello X, here is my reply."
    sealed = seal_envelope(text, meta_y, single_use=False)
    meta_y = meta_y._replace(
        tx_count=meta_y.tx_count + 1,
        send_seed=sealed.next_seed
    )
    
    opened = open_envelope(sealed.file_bytes, meta_x)
    meta_x = meta_x._replace(
        rx_count=opened.next_step,
        recv_seed=opened.next_seed
    )
    assert opened.text == text

run_test("Y -> X message send and open", test_y_sends_x_receives)


@oqs_required
def test_x_cannot_open_own_message():
    meta_x, meta_y = _make_sessions()
    sealed = seal_envelope("my own message", meta_x)
    try:
        open_envelope(sealed.file_bytes, meta_x)
        assert False, "X opened its own message!"
    except EnvelopeError:
        pass

run_test("X must not open its own message", test_x_cannot_open_own_message)


@oqs_required
def test_y_cannot_open_own_message():
    meta_x, meta_y = _make_sessions()
    # X sends first msg so Y bonds
    sealed_x = seal_envelope("Hello Y", meta_x)
    opened_x = open_envelope(sealed_x.file_bytes, meta_y)
    meta_y = apply_bond_nonce_to_y(meta_y, opened_x.bond_nonce)
    meta_y = meta_y._replace(rx_count=opened_x.next_step, recv_seed=opened_x.next_seed)

    sealed = seal_envelope("my own message", meta_y)
    try:
        open_envelope(sealed.file_bytes, meta_y)
        assert False, "Y opened its own message!"
    except EnvelopeError:
        pass

run_test("Y must not open its own message", test_y_cannot_open_own_message)


@oqs_required
def test_tampered_file_rejected():
    meta_x, meta_y = _make_sessions()
    sealed = seal_envelope("message", meta_x)
    tampered = bytearray(sealed.file_bytes)
    tampered[60] ^= 0xFF  # Tamper a byte in payload
    try:
        open_envelope(bytes(tampered), meta_y)
        assert False, "Tampered file accepted!"
    except EnvelopeError:
        pass

run_test("Tampered file must be rejected", test_tampered_file_rejected)


@oqs_required
def test_legacy_v1_outer_seal_is_ignored_for_compatibility():
    meta_x, meta_y = _with_legacy_envelope_metadata(*_make_sessions())
    legacy_file = _legacy_v1_envelope("legacy message", meta_x)
    opened = open_envelope(legacy_file, meta_y)
    assert opened.text == "legacy message"

run_test("Legacy v1 outer seal is ignored for compatibility", test_legacy_v1_outer_seal_is_ignored_for_compatibility)


@oqs_required
def test_ttl_expired_message():
    meta_x, meta_y = _make_sessions()
    # TTL: 1 sec, simulate expired
    sealed = seal_envelope("ttl test", meta_x, ttl_seconds=1)

    # Set expire_at to past (offset 44)
    import struct
    raw = bytearray(sealed.file_bytes)
    expire_offset = 44
    past_time = int(time.time()) - 100
    raw[expire_offset:expire_offset+8] = struct.pack(">Q", past_time)
    
    try:
        open_envelope(bytes(raw), meta_y)
        assert False, "Expired message opened!"
    except (EnvelopeTTLError, EnvelopeError):
        pass

run_test("Expired message must not be opened", test_ttl_expired_message)


@oqs_required
def test_wrong_session_rejected():
    meta_x1, meta_y1 = _make_sessions()
    meta_x2, meta_y2 = _make_sessions()

    sealed = seal_envelope("session 1 message", meta_x1)
    try:
        open_envelope(sealed.file_bytes, meta_y2)
        assert False, "Wrong session opened message!"
    except EnvelopeError:
        pass

run_test("Message from wrong session must not be opened", test_wrong_session_rejected)


# ============================================================
# BURN TESTS
# ============================================================
print("\n-- burn.py -----------------------------------------")


def test_burn_workflow():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = BurnDB(os.path.join(tmpdir, "test.db"), device_key=random_bytes(32))
        guard = BurnGuard(db)

        msg_id = new_message_id()
        session_id = new_message_id()

        # First time: reserve before decrypt.
        reserved = guard.pre_open_check(msg_id, expire_at=0, single_use=True)
        assert reserved is True
        assert db.get_burn_status(msg_id) == BURN_STATUS_OPENING

        # A concurrent or repeated open cannot pass while the message is reserved.
        try:
            guard.pre_open_check(msg_id, expire_at=0, single_use=True)
            assert False, "Opening reservation allowed a second opener!"
        except AlreadyBurnedError:
            pass

        # Successful decrypt finalizes the burn.
        guard.post_open_burn(msg_id, session_id, direction=1, single_use=True, file_path=None)
        assert db.get_burn_status(msg_id) == BURN_STATUS_BURNED

        # Second time: reject
        try:
            guard.pre_open_check(msg_id, expire_at=0, single_use=True)
            assert False, "Burned message opened again!"
        except AlreadyBurnedError:
            pass

        # Failed decrypts are retryable until one attempt burns successfully.
        retry_msg_id = new_message_id()
        assert guard.pre_open_check(retry_msg_id, expire_at=0, single_use=True) is True
        guard.mark_open_failed(retry_msg_id, "decrypt failed")
        assert db.get_burn_status(retry_msg_id) == BURN_STATUS_FAILED

        assert guard.pre_open_check(retry_msg_id, expire_at=0, single_use=True) is True
        assert db.get_burn_status(retry_msg_id) == BURN_STATUS_OPENING
        guard.post_open_burn(retry_msg_id, session_id, direction=1, single_use=True, file_path=None)
        assert db.get_burn_status(retry_msg_id) == BURN_STATUS_BURNED

        # Expired messages are rejected before any reservation row is created.
        expired_msg_id = new_message_id()
        try:
            guard.pre_open_check(expired_msg_id, expire_at=int(time.time()) - 1, single_use=True)
            assert False, "Expired message created a burn reservation!"
        except TTLExpiredError:
            pass
        assert db.get_burn_status(expired_msg_id) is None
        db.close()

run_test("Single-use message burn workflow", test_burn_workflow)


def test_ttl_check():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = BurnDB(os.path.join(tmpdir, "test.db"))
        guard = BurnGuard(db)
        msg_id = new_message_id()

        past_expire = int(time.time()) - 60
        try:
            guard.pre_open_check(msg_id, expire_at=past_expire, single_use=False)
            assert False, "Expired message passed!"
        except TTLExpiredError:
            pass
        db.close()

run_test("TTL expired message burn check", test_ttl_check)


def test_device_key_persistence():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = BurnDB(os.path.join(tmpdir, "test.db"))
        pin = "Correct-Horse-95175328"
        key1 = init_device(db, pin)
        key2 = unlock_device(db, pin)
        assert key1 == key2
        assert len(key1) == 32
        db.close()

run_test("Device key persistence (PIN init -> unlock)", test_device_key_persistence)


@oqs_required
def test_session_db_roundtrip():
    with tempfile.TemporaryDirectory() as tmpdir:
        db = BurnDB(os.path.join(tmpdir, "test.db"))
        pin = "Correct-Horse-Session-95175328"
        device_key = init_device(db, pin)
        db = db.with_device_key(device_key)

        meta_x, init_file = create_initiator_session("DB Test")
        meta_y, resp_file = accept_initiator_and_create_responder(init_file, "DB Test")
        meta_x2 = finalize_initiator_session(meta_x, resp_file)

        enc = serialize_session_meta(meta_x2, device_key)
        db.save_session(
            session_id=meta_x2.session_id,
            label=meta_x2.label,
            state=meta_x2.state,
            encrypted_meta=enc,
            created_at=meta_x2.created_at,
        )

        row = db.load_session(meta_x2.session_id)
        assert row is not None
        restored = deserialize_session_meta(row[2], device_key)
        assert restored.session_id == meta_x2.session_id
        assert restored.keys.evo_seed == meta_x2.keys.evo_seed
        db.close()

run_test("Session DB save / load", test_session_db_roundtrip)


# ============================================================
# FULL INTEGRATION TEST
# ============================================================
print("\n-- Full Integration ---------------------------------")


@oqs_required
def test_full_conversation():
    """Two sides full conversation scenario."""
    meta_x, init_file = create_initiator_session(
        "Full Test", session_ttl_sec=EVO_UNLIMITED
    )
    meta_y, resp_file = accept_initiator_and_create_responder(init_file, "Full Test")
    meta_x = finalize_initiator_session(meta_x, resp_file)
    meta_x, meta_y = confirm_pair(meta_x, meta_y)

    messages = [
        ("X", "Hello Y, this is my first message."),
        ("Y", "Hello X, received!"),
        ("X", "Great. Connection looks secure."),
        ("Y", "Yes, nobody can read this."),
    ]

    for sender, text in messages:
        if sender == "X":
            sealed = seal_envelope(text, meta_x)
            meta_x = meta_x._replace(tx_count=meta_x.tx_count + 1, send_seed=sealed.next_seed)
            opened = open_envelope(sealed.file_bytes, meta_y)
            if opened.bond_nonce and not meta_y.is_bonded:
                meta_y = apply_bond_nonce_to_y(meta_y, opened.bond_nonce)
            meta_y = meta_y._replace(rx_count=opened.next_step, recv_seed=opened.next_seed)
        else:
            sealed = seal_envelope(text, meta_y)
            meta_y = meta_y._replace(tx_count=meta_y.tx_count + 1, send_seed=sealed.next_seed)
            opened = open_envelope(sealed.file_bytes, meta_x)
            meta_x = meta_x._replace(rx_count=opened.next_step, recv_seed=opened.next_seed)
        assert opened.text == text, f"Message mismatch: {text!r} != {opened.text!r}"

run_test("Full duplex conversation (4 messages)", test_full_conversation)


# ============================================================
# RESULT
# ============================================================
total   = len(results)
passed  = sum(1 for _, ok, _ in results if ok)
failed  = total - passed

if __name__ == "__main__":
    print(f"\n{'='*50}")
    print(f"  Total: {total}  |  Passed: {passed}  |  Failed: {failed}")
    if failed:
        print("\n  Failed tests:")
        for name, ok, err in results:
            if not ok:
                print(f"    {FAIL} {name}: {err}")
    print(f"{'='*50}\n")

    if failed:
        sys.exit(1)

