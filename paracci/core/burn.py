"""
Paracci — core/burn.py
Single-use and TTL mechanism.

This module:
  - Registers the MSG_ID fingerprint of every opened message in the database
  - Strictly rejects any attempt to re-open the same file
  - Securely deletes the file from disk (overwrites, then deletes)
  - Burns the single-use message file immediately after reading
  - Never opens files whose TTL has expired
"""

import os
import sqlite3
import hashlib
import time
from pathlib import Path
from .shields import shield

from .crypto import (
    message_id_fingerprint,
    secure_hash,
    encrypt, 
    decrypt, 
    derive_master_key, 
    EncryptedBlob,
    random_bytes,
    wipe
)


# ---------------------------------------------------------------------------
# Database Setup
# ---------------------------------------------------------------------------

class BurnDB:
    """
    SQLite-based message burn registry and device key store.
    
    Tables:
      burned_messages : Fingerprints of opened messages
      sessions        : Session metadata (encrypted blob)
      device_meta     : Device identity and device_key salts
    """

    def __init__(self, db_path: str | Path):
        """Initializes the BurnDB instance and prepares the database connection."""
        self.db_path = str(db_path)
        self._conn: sqlite3.Connection | None = None
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        """Connects to the SQLite database in WAL mode with optimized settings."""
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        # Minimize cache on memory
        conn.execute("PRAGMA cache_size=64")
        return conn

    def _init_db(self):
        """Creates the database tables (burned_messages, sessions, device_meta)."""
        conn = self._connect()
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS burned_messages (
                fingerprint     BLOB PRIMARY KEY,   -- SHA3-256(msg_id)
                burned_at       INTEGER NOT NULL,   -- Unix timestamp
                session_id      BLOB,               -- Which session it belongs to
                direction       INTEGER             -- 1=X→Y, 2=Y→X
            );

            CREATE TABLE IF NOT EXISTS sessions (
                session_id      BLOB PRIMARY KEY,   -- 16 bytes
                label           TEXT NOT NULL,
                state           TEXT NOT NULL,
                encrypted_meta  BLOB NOT NULL,      -- serialize_session_meta output
                created_at      INTEGER NOT NULL,
                updated_at      INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS device_meta (
                key             TEXT PRIMARY KEY,
                value           BLOB NOT NULL
            );
        """)
        conn.commit()
        conn.close()

    # --- Message Burning ---

    def is_burned(self, msg_id: bytes) -> bool:
        """Has this MSG_ID been opened before?"""
        fingerprint = message_id_fingerprint(msg_id)
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT 1 FROM burned_messages WHERE fingerprint=?",
                (fingerprint,)
            ).fetchone()
            return row is not None
        finally:
            conn.close()

    def burn(self, msg_id: bytes, session_id: bytes, direction: int):
        """Registers the MSG_ID as burned."""
        fingerprint = message_id_fingerprint(msg_id)
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT OR IGNORE INTO burned_messages
                    (fingerprint, burned_at, session_id, direction)
                VALUES (?, ?, ?, ?)
                """,
                (fingerprint, int(time.time()), session_id, direction)
            )
            conn.commit()
        finally:
            conn.close()

    # --- Session Management ---

    def save_session(
        self,
        session_id: bytes,
        label: str,
        state: str,
        encrypted_meta: bytes,
        created_at: int,
    ):
        """Saves or updates session metadata."""
        conn = self._connect()
        now = int(time.time())
        try:
            conn.execute(
                """
                INSERT INTO sessions (session_id, label, state, encrypted_meta, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(session_id) DO UPDATE SET
                    label=excluded.label,
                    state=excluded.state,
                    encrypted_meta=excluded.encrypted_meta,
                    updated_at=excluded.updated_at
                """,
                (session_id, label, state, encrypted_meta, created_at, now)
            )
            conn.commit()
        finally:
            conn.close()

    def load_session(self, session_id: bytes) -> tuple | None:
        """Returns (label, state, encrypted_meta, created_at) or None."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT label, state, encrypted_meta, created_at FROM sessions WHERE session_id=?",
                (session_id,)
            ).fetchone()
            return row
        finally:
            conn.close()

    def list_sessions(self) -> list[dict]:
        """Lists all sessions."""
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT session_id, label, state, created_at, updated_at FROM sessions ORDER BY updated_at DESC"
            ).fetchall()
            return [
                {
                    "session_id": row[0],
                    "label":      row[1],
                    "state":      row[2],
                    "created_at": row[3],
                    "updated_at": row[4],
                }
                for row in rows
            ]
        finally:
            conn.close()

    def update_session_state(self, session_id: bytes, state: str, encrypted_meta: bytes):
        """Updates session state."""
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE sessions SET state=?, encrypted_meta=?, updated_at=? WHERE session_id=?",
                (state, encrypted_meta, int(time.time()), session_id)
            )
            conn.commit()
        finally:
            conn.close()

    # --- Device Metadata ---

    def get_device_meta(self, key: str) -> bytes | None:
        """Returns the specified key from device metadata (e.g., pin_salt)."""
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT value FROM device_meta WHERE key=?", (key,)
            ).fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def set_device_meta(self, key: str, value: bytes):
        """Registers or updates a new key-value pair in device metadata."""
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR REPLACE INTO device_meta (key, value) VALUES (?, ?)",
                (key, value)
            )
            conn.commit()
        finally:
            conn.close()

    def delete_device_meta(self, key: str):
        """Deletes the specified key from device metadata if it exists."""
        conn = self._connect()
        try:
            conn.execute("DELETE FROM device_meta WHERE key=?", (key,))
            conn.commit()
        finally:
            conn.close()

    # --- 2FA Management ---

    def is_2fa_enabled(self) -> bool:
        """Is 2FA active?"""
        val = self.get_device_meta("2fa_enabled")
        return val == b"1"

    def set_2fa_enabled(self, enabled: bool):
        """Sets the 2FA status."""
        self.set_device_meta("2fa_enabled", b"1" if enabled else b"0")

    def get_2fa_secret(self) -> str | None:
        """Returns the 2FA secret key."""
        val = self.get_device_meta("2fa_secret")
        return val.decode('utf-8') if val else None

    def set_2fa_secret(self, secret_bytes: bytes):
        """Saves the encrypted 2FA secret key."""
        self.set_device_meta("2fa_secret", secret_bytes)

    def get_2fa_secret_raw(self) -> bytes | None:
        """Returns the encrypted 2FA secret key as bytes."""
        return self.get_device_meta("2fa_secret")


# ---------------------------------------------------------------------------
# Secure File Deletion
# ---------------------------------------------------------------------------

def secure_delete(file_path: str | Path, passes: int = 3):
    """
    Destroys the file using the most secure system-specific method (Shield).
    """
    return shield.secure_delete(str(file_path))


# ---------------------------------------------------------------------------
# Main Control Flow
# ---------------------------------------------------------------------------

class BurnGuard:
    """
    Manages all security checks before and after message opening.
    """

    def __init__(self, db: BurnDB):
        """Initializes the BurnGuard instance with the specified database."""
        self.db = db

    def pre_open_check(self, msg_id: bytes, expire_at: int, single_use: bool) -> None:
        """
        Perform all checks before opening the message.
        Throws an exception if any check fails.
        """
        # 1. Has it been opened before?
        if self.db.is_burned(msg_id):
            raise AlreadyBurnedError(
                "This message was already opened and burned. It cannot be opened again."
            )

        # 2. TTL check
        if expire_at > 0:
            if int(time.time()) >= expire_at:
                raise TTLExpiredError(
                    "The message has expired. This envelope can no longer be opened."
                )

    def post_open_burn(
        self,
        msg_id: bytes,
        session_id: bytes,
        direction: int,
        single_use: bool,
        file_path: str | Path | None = None,
    ) -> None:
        """
        After the message is opened:
          - If single-use, register the MSG_ID as burned
          - If file path provided, delete securely
        """
        # Always burn single-use messages
        if single_use:
            self.db.burn(msg_id, session_id, direction)

        # Securely delete the file (if single-use or requested by caller)
        if file_path and single_use:
            secure_delete(file_path)

    def force_burn(
        self,
        msg_id: bytes,
        session_id: bytes,
        direction: int,
        file_path: str | Path | None = None,
    ) -> None:
        """
        Force burn the message (when user wants to delete manually).
        """
        self.db.burn(msg_id, session_id, direction)
        if file_path:
            secure_delete(file_path)


# ---------------------------------------------------------------------------
# Device Key Management
# ---------------------------------------------------------------------------

def is_device_initialized(db: BurnDB) -> bool:
    """Has the device been set up with a PIN before?"""
    return db.get_device_meta("pin_salt") is not None

def validate_pin_strength(pin: str):
    """
    Validates PIN code security.
    Criteria:
    - At least 8 characters
    - Cannot be all the same digits (e.g., 11111111)
    - Cannot be sequential digits (e.g., 12345678)
    """
    if len(pin) < 8:
        raise DeviceError("PIN code must be at least 8 characters.")
    
    if pin == pin[0] * len(pin):
        raise DeviceError("PIN code is too simple (all characters are the same).")
    
    # Simple sequential check
    if pin in "01234567890123456789" or pin in "98765432109876543210":
        raise DeviceError("PIN code must not consist of sequential digits.")


def init_device(db: BurnDB, pin: str) -> bytes:
    """
    Sets up the device for the first time:
    1. Produces a new pin_salt.
    2. Derives master_key from PIN.
    3. Produces a random device_key.
    4. Encrypts and saves the device_key with the master_key.
    """
    validate_pin_strength(pin)
    
    if is_device_initialized(db):
        raise DeviceError("Device already set up.")
    
    pin_salt = random_bytes(16)
    master_key = derive_master_key(pin, pin_salt)
    
    try:
        device_key = random_bytes(32)
        
        # Encrypt device_key with master_key
        blob = encrypt(master_key, device_key, aad=b"paracci.device_key.v1")
        
        # Save
        db.set_device_meta("pin_salt", pin_salt)
        db.set_device_meta("encrypted_device_key", blob.nonce + blob.ciphertext)
        
        return device_key
    finally:
        # Wipe master_key from memory
        if 'master_key' in locals():
            wipe(master_key)


def unlock_device(db: BurnDB, pin: str) -> bytes:
    """
    Unlocks the device key with the PIN.
    """
    pin_salt = db.get_device_meta("pin_salt")
    enc_data = db.get_device_meta("encrypted_device_key")
    
    if not pin_salt or not enc_data:
        raise DeviceError("Device not set up yet.")
    
    master_key = derive_master_key(pin, pin_salt)
    
    try:
        # enc_data: nonce(12) + ciphertext
        nonce = enc_data[:12]
        ciphertext = enc_data[12:]
        blob = EncryptedBlob(nonce=nonce, ciphertext=ciphertext)
        
        device_key = decrypt(master_key, blob, aad=b"paracci.device_key.v1")
        return device_key
    except Exception:
        raise DeviceError("Incorrect PIN.")
    finally:
        # Wipe master_key from memory
        if 'master_key' in locals():
            wipe(master_key)


# ---------------------------------------------------------------------------
# Error Classes
# ---------------------------------------------------------------------------

class AlreadyBurnedError(Exception):
    """Message has been opened and burned before."""


class TTLExpiredError(Exception):
    """Message TTL has expired."""


class DeviceError(Exception):
    """Error related to device key or PIN."""
