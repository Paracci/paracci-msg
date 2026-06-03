from core import envelope as envelope_module


def craft_bond_nonce_envelope(payload_bytes, sender, bond_nonce):
    """Build a valid-AEAD message whose sync block carries bond_nonce."""
    if isinstance(payload_bytes, str):
        payload_bytes = payload_bytes.encode("utf-8")

    step = sender.tx_count
    msg_id = envelope_module.new_message_id()
    direction = (
        envelope_module.DIR_X_TO_Y
        if sender.role == "X"
        else envelope_module.DIR_Y_TO_X
    )
    header = envelope_module._build_header(
        sender.session_id,
        msg_id,
        direction,
        True,
        False,
        step,
        0,
    )

    current_seed = envelope_module.compute_bond_seed(sender.keys.evo_seed, bond_nonce)
    for ratchet_step in range(step):
        current_seed = envelope_module._advance_seed(current_seed, ratchet_step)
    kxy, kyx, _next_seed = envelope_module._derive_msg_keys(current_seed, step)
    msg_key = kxy if direction == envelope_module.DIR_X_TO_Y else kyx

    payload_blob = envelope_module.encrypt(msg_key, payload_bytes, aad=header)
    sync_raw = envelope_module._build_sync_payload(
        sender.role,
        step,
        msg_id,
        bond_nonce,
    )
    sync_blob = envelope_module.encrypt(
        sender.keys.sync_key,
        sync_raw,
        aad=header + b"sync",
    )

    return (
        header
        + envelope_module.pack_uint32(len(payload_blob.ciphertext))
        + payload_blob.nonce
        + payload_blob.ciphertext
        + sync_blob.nonce
        + sync_blob.ciphertext
    )
