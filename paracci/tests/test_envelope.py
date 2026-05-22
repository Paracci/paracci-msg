"""
Unit tests for Paracci message envelopes.
Tests cover envelope v1/v2 compatibility, AAD binding, truncation, and key validation.
"""

import os
import sys
import time
from pathlib import Path
import pytest

from conftest import oqs_required

# Ensure core is in the python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.crypto import (
    generate_identity_keypair,
    pack_uint32,
    pack_uint64,
    encrypt,
)
from core.session import (
    create_initiator_session,
    accept_initiator_and_create_responder,
    finalize_initiator_session,
    confirm_safety_code,
    get_session_safety_code,
    apply_bond_nonce_to_y,
)
from core.envelope import (
    seal_envelope,
    open_envelope,
    EnvelopeError,
    EnvelopeTTLError,
    HEADER_SIZE,
    LEGACY_SEAL_SIZE,
    DIR_X_TO_Y,
    DIR_Y_TO_X,
)
from core import envelope as envelope_module

def _new_identity():
    priv, pub = generate_identity_keypair()
    return priv, pub

def _make_sessions():
    ipriv_x, ipub_x = _new_identity()
    ipriv_y, ipub_y = _new_identity()
    meta_x, init_file = create_initiator_session("Test", identity_priv=ipriv_x, identity_pub=ipub_x)
    meta_y, resp_file = accept_initiator_and_create_responder(init_file, "Test", identity_priv=ipriv_y, identity_pub=ipub_y)
    meta_x2 = finalize_initiator_session(meta_x, resp_file)
    
    code_x = get_session_safety_code(meta_x2)
    code_y = get_session_safety_code(meta_y)
    assert code_x == code_y
    
    return confirm_safety_code(meta_x2, code_x), confirm_safety_code(meta_y, code_y)

def _establish_bonded_pair():
    meta_x, meta_y = _make_sessions()
    # X sends first message to establish the bond on Y's side
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
    return meta_x, meta_y

@oqs_required
def test_v1_legacy_envelope_opens_correctly():
    """Test that a legacy v1 envelope with an appended 16-byte HMAC trailer opens correctly."""
    meta_x, meta_y = _establish_bonded_pair()
    payload_bytes = b"Legacy v1 payload data"
    
    direction, msg_key, _next_seed, step = envelope_module._prepare_seal_keys(meta_x)
    msg_id = envelope_module.new_message_id()
    header = (
        envelope_module.MAGIC_BYTES
        + bytes([envelope_module.LEGACY_FILE_VERSION, envelope_module.TYPE_MESSAGE])
        + meta_x.session_id
        + msg_id
        + bytes([direction, 0])
        + pack_uint32(step)
        + pack_uint64(0)
    )
    work_key = envelope_module._compute_work_key(
        msg_key,
        header,
        meta_x.my_qseed,
        meta_x.evo_config,
    )
    payload_blob = encrypt(work_key, payload_bytes, aad=header)
    sync_raw = envelope_module._build_sync_payload(
        meta_x.role,
        step,
        msg_id,
        None,
    )
    sync_blob = encrypt(meta_x.keys.sync_key, sync_raw, aad=header + b"sync")
    
    content = (
        header
        + pack_uint32(len(payload_blob.ciphertext))
        + payload_blob.nonce
        + payload_blob.ciphertext
        + sync_blob.nonce
        + sync_blob.ciphertext
    )
    v1_file_bytes = content + (b"\xff" * envelope_module.LEGACY_SEAL_SIZE)
    
    opened = open_envelope(v1_file_bytes, meta_y)
    assert opened.payload == payload_bytes
    assert opened.msg_id == msg_id
    assert opened.evo_step == step

@oqs_required
def test_v2_envelope_opens_correctly():
    """Test that a standard v2 envelope without an HMAC trailer opens correctly."""
    meta_x, meta_y = _establish_bonded_pair()
    text = "Standard v2 envelope payload"
    sealed = seal_envelope(text, meta_x, single_use=False)
    
    opened = open_envelope(sealed.file_bytes, meta_y)
    assert opened.text == text

@oqs_required
def test_aad_binding_tampered_session_id_rejected():
    """Test that altering the session_id in the header causes verification/decryption to fail."""
    meta_x, meta_y = _establish_bonded_pair()
    sealed = seal_envelope("Secret message", meta_x)
    
    # Tamper with the session_id in the header (offset 6 to 22)
    raw = bytearray(sealed.file_bytes)
    raw[10] ^= 0x01
    
    # Opening should be rejected as it doesn't match meta_y's session ID
    with pytest.raises(EnvelopeError) as exc_info:
        open_envelope(bytes(raw), meta_y)
    assert "This file does not belong to this session" in str(exc_info.value)
    
    # If we also modify the receiver session ID to match the tampered header, AEAD decryption must fail
    meta_y_tampered = meta_y._replace(session_id=bytes(raw[6:22]))
    with pytest.raises(EnvelopeError) as exc_info2:
        open_envelope(bytes(raw), meta_y_tampered)
    assert "decryption failed" in str(exc_info2.value).lower() or "sync block decryption failed" in str(exc_info2.value).lower()

@oqs_required
def test_aad_binding_tampered_direction_rejected():
    """Test that altering the direction field in the header is rejected."""
    meta_x, meta_y = _establish_bonded_pair()
    sealed = seal_envelope("Secret message", meta_x)
    
    # Change direction to an invalid value (offset 38)
    raw = bytearray(sealed.file_bytes)
    raw[38] = 3
    with pytest.raises(EnvelopeError) as exc_info:
        open_envelope(bytes(raw), meta_y)
    assert "direction" in str(exc_info.value).lower()
    
    # Change direction to DIR_Y_TO_X (valid value but wrong role direction for Y receiver)
    raw[38] = DIR_Y_TO_X
    with pytest.raises(EnvelopeError) as exc_info2:
        open_envelope(bytes(raw), meta_y)
    assert "cannot open your own message" in str(exc_info2.value).lower() or "direction" in str(exc_info2.value).lower()

@oqs_required
def test_aad_binding_tampered_step_number_rejected():
    """Test that altering the step number in the header is rejected by AAD check."""
    meta_x, meta_y = _establish_bonded_pair()
    sealed = seal_envelope("Secret message", meta_x)
    
    # Alter the evolution step number in the header (offset 40 to 44)
    raw = bytearray(sealed.file_bytes)
    raw[40:44] = pack_uint32(2)
    
    with pytest.raises(EnvelopeError) as exc_info:
        open_envelope(bytes(raw), meta_y)
    assert "decryption failed" in str(exc_info.value).lower() or "sync block decryption failed" in str(exc_info.value).lower()

@oqs_required
def test_truncated_envelope_rejected():
    """Test that a truncated envelope is rejected."""
    meta_x, meta_y = _establish_bonded_pair()
    sealed = seal_envelope("Secret message", meta_x)
    
    # Truncate the file bytes by removing the last 10 bytes
    truncated = sealed.file_bytes[:-10]
    with pytest.raises(EnvelopeError) as exc_info:
        open_envelope(truncated, meta_y)
    assert any(term in str(exc_info.value).lower() for term in ["too small", "truncated", "mismatch", "decryption failed"])

@oqs_required
def test_envelope_with_wrong_aead_key_rejected():
    """Test that opening an envelope with a session having a different key is rejected."""
    meta_x1, meta_y1 = _establish_bonded_pair()
    meta_x2, meta_y2 = _establish_bonded_pair()
    
    sealed = seal_envelope("Secret message", meta_x1)
    
    with pytest.raises(EnvelopeError) as exc_info:
        open_envelope(sealed.file_bytes, meta_y2)
    assert any(term in str(exc_info.value).lower() for term in ["does not belong to this session", "decryption failed", "sync block decryption failed"])
