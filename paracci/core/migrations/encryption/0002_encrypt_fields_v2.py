# -*- coding: utf-8 -*-
from yoyo import step
import sys

def encrypt_fields_v2(conn):
    db = getattr(sys, "_paracci_migration_db", None)
    if db is None:
        raise RuntimeError("No DB instance in sys._paracci_migration_db.")

    burn_module = sys.modules[db.__class__.__module__]
    PROTECTED_VALUE_PREFIX = burn_module.PROTECTED_VALUE_PREFIX
    STORAGE_MIGRATION_V2_KEY = burn_module.STORAGE_MIGRATION_V2_KEY
    STORAGE_MIGRATION_COMPLETE = burn_module.STORAGE_MIGRATION_COMPLETE

    
    try:
        conn.execute(f"ATTACH DATABASE '{db.meta_db_path}' AS meta KEY ''")
    except Exception:
        pass

    cursor = conn.cursor()
    # 1. sessions table (state, created_at, updated_at)
    for session_id, state, created_at, updated_at in cursor.execute(
        "SELECT session_id, state, created_at, updated_at FROM sessions"
    ).fetchall():
        if not (isinstance(state, bytes) and state.startswith(PROTECTED_VALUE_PREFIX)):
            enc_state = db._encrypt_protected_value("sessions", "state", session_id, state)
            cursor.execute("UPDATE sessions SET state=? WHERE session_id=?", (enc_state, session_id))
        if not (isinstance(created_at, bytes) and created_at.startswith(PROTECTED_VALUE_PREFIX)):
            enc_created = db._encrypt_protected_value("sessions", "created_at", session_id, str(created_at))
            cursor.execute("UPDATE sessions SET created_at=? WHERE session_id=?", (enc_created, session_id))
        if not (isinstance(updated_at, bytes) and updated_at.startswith(PROTECTED_VALUE_PREFIX)):
            enc_updated = db._encrypt_protected_value("sessions", "updated_at", session_id, str(updated_at))
            cursor.execute("UPDATE sessions SET updated_at=? WHERE session_id=?", (enc_updated, session_id))

    # 2. burned_messages table (status, reserved_at, burned_at, failed_at, session_id, direction)
    for fingerprint, status, reserved_at, burned_at, failed_at, s_id, direction in cursor.execute(
        "SELECT fingerprint, status, reserved_at, burned_at, failed_at, session_id, direction FROM burned_messages"
    ).fetchall():
        if not (isinstance(status, bytes) and status.startswith(PROTECTED_VALUE_PREFIX)):
            enc_status = db._encrypt_protected_value("burned_messages", "status", fingerprint, status)
            cursor.execute("UPDATE burned_messages SET status=? WHERE fingerprint=?", (enc_status, fingerprint))
        if not (isinstance(reserved_at, bytes) and reserved_at.startswith(PROTECTED_VALUE_PREFIX)):
            enc_reserved = db._encrypt_protected_value("burned_messages", "reserved_at", fingerprint, str(reserved_at))
            cursor.execute("UPDATE burned_messages SET reserved_at=? WHERE fingerprint=?", (enc_reserved, fingerprint))
        if burned_at is not None and not (isinstance(burned_at, bytes) and burned_at.startswith(PROTECTED_VALUE_PREFIX)):
            enc_burned = db._encrypt_protected_value("burned_messages", "burned_at", fingerprint, str(burned_at))
            cursor.execute("UPDATE burned_messages SET burned_at=? WHERE fingerprint=?", (enc_burned, fingerprint))
        if failed_at is not None and not (isinstance(failed_at, bytes) and failed_at.startswith(PROTECTED_VALUE_PREFIX)):
            enc_failed = db._encrypt_protected_value("burned_messages", "failed_at", fingerprint, str(failed_at))
            cursor.execute("UPDATE burned_messages SET failed_at=? WHERE fingerprint=?", (enc_failed, fingerprint))
        if s_id is not None and not (isinstance(s_id, bytes) and s_id.startswith(PROTECTED_VALUE_PREFIX)):
            enc_sid = db._encrypt_protected_value("burned_messages", "session_id", fingerprint, s_id)
            cursor.execute("UPDATE burned_messages SET session_id=? WHERE fingerprint=?", (enc_sid, fingerprint))
        if direction is not None and not (isinstance(direction, bytes) and direction.startswith(PROTECTED_VALUE_PREFIX)):
            enc_dir = db._encrypt_protected_value("burned_messages", "direction", fingerprint, str(direction))
            cursor.execute("UPDATE burned_messages SET direction=? WHERE fingerprint=?", (enc_dir, fingerprint))

    # Write migration state marker to maintain compatibility with test suite
    db._write_migration_state(conn, STORAGE_MIGRATION_COMPLETE, STORAGE_MIGRATION_V2_KEY)

steps = [
    step(encrypt_fields_v2)
]
