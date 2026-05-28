# -*- coding: utf-8 -*-
from yoyo import step
import sys

def encrypt_fields_v1(conn):
    db = getattr(sys, "_paracci_migration_db", None)
    if db is None:
        raise RuntimeError("No DB instance in sys._paracci_migration_db.")
    
    burn_module = sys.modules[db.__class__.__module__]
    BOOTSTRAP_DEVICE_META_KEYS = burn_module.BOOTSTRAP_DEVICE_META_KEYS
    PROTECTED_VALUE_PREFIX = burn_module.PROTECTED_VALUE_PREFIX
    STORAGE_MIGRATION_KEY = burn_module.STORAGE_MIGRATION_KEY
    STORAGE_MIGRATION_COMPLETE = burn_module.STORAGE_MIGRATION_COMPLETE

    
    try:
        conn.execute(f"ATTACH DATABASE '{db.meta_db_path}' AS meta KEY ''")
    except Exception:
        pass

    cursor = conn.cursor()
    # 1. sessions table (label)
    for session_id, label in cursor.execute(
        "SELECT session_id, label FROM sessions"
    ).fetchall():
        if isinstance(label, bytes) and label.startswith(PROTECTED_VALUE_PREFIX):
            db._decrypt_protected_text("sessions", "label", session_id, label)
            continue
        encrypted_label = db._encrypt_protected_value("sessions", "label", session_id, label)
        cursor.execute(
            "UPDATE sessions SET label=? WHERE session_id=?",
            (encrypted_label, session_id),
        )

    # 2. burned_messages table (failure_reason)
    for fingerprint, reason in cursor.execute(
        "SELECT fingerprint, failure_reason FROM burned_messages WHERE failure_reason IS NOT NULL"
    ).fetchall():
        if isinstance(reason, bytes) and reason.startswith(PROTECTED_VALUE_PREFIX):
            db._decrypt_protected_text("burned_messages", "failure_reason", fingerprint, reason)
            continue
        encrypted_reason = db._encrypt_protected_value("burned_messages", "failure_reason", fingerprint, reason)
        cursor.execute(
            "UPDATE burned_messages SET failure_reason=? WHERE fingerprint=?",
            (encrypted_reason, fingerprint),
        )

    # 3. device_meta table
    for key, value in cursor.execute(
        f"SELECT key, value FROM {db._meta_prefix}device_meta"
    ).fetchall():
        if key in BOOTSTRAP_DEVICE_META_KEYS:
            continue
        if isinstance(value, bytes) and value.startswith(PROTECTED_VALUE_PREFIX):
            db._decrypt_protected_value("device_meta", "value", key, value)
            continue
        encrypted_value = db._encrypt_protected_value("device_meta", "value", key, value)
        cursor.execute(
            f"UPDATE {db._meta_prefix}device_meta SET value=? WHERE key=?",
            (encrypted_value, key),
        )

    # Write migration state marker to maintain compatibility with test suite
    db._write_migration_state(conn, STORAGE_MIGRATION_COMPLETE, STORAGE_MIGRATION_KEY)

steps = [
    step(encrypt_fields_v1)
]
