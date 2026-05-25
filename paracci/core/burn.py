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
import json
import math
import re
import time
from pathlib import Path
from .shields import shield
from .constants import BURN_OPENING_STALE_SECONDS

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

BURN_STATUS_OPENING = "opening"
BURN_STATUS_BURNED = "burned"
BURN_STATUS_FAILED = "failed"
BURN_STATUSES = (BURN_STATUS_OPENING, BURN_STATUS_BURNED, BURN_STATUS_FAILED)

PASSPHRASE_MIN_LENGTH = 12
PASSPHRASE_MAX_LENGTH = 128
PASSPHRASE_MIN_ENTROPY_BITS = 64
PASSPHRASE_NUMERIC_MIN_LENGTH = 20
PASSPHRASE_MIN_UNIQUE_CHARS = 5

UNLOCK_RATE_LIMIT_KEY = "unlock_rate_limit_v1"
UNLOCK_MAX_FAILED_ATTEMPTS = 5
UNLOCK_LOCKOUT_SECONDS = 300
UNLOCK_FAILURE_DELAYS = {
    2: 2,
    3: 5,
    4: 15,
}
TWO_FA_SECRET_KEY = "2fa_secret"
TWO_FA_SECRET_AAD = b"paracci.2fa_secret.v1"
TWO_FA_SECRET_NONCE_LEN = 12
TWO_FA_SECRET_TAG_LEN = 16
TWO_FA_SECRET_MIN_CIPHERTEXT_LEN = TWO_FA_SECRET_TAG_LEN + 1
LEGACY_TOTP_SECRET_RE = re.compile(r"^[A-Z2-7]{16,128}$")

_COMMON_WEAK_PASSPHRASES = {
    "password",
    "password1",
    "password12",
    "password123",
    "password1234",
    "passphrase",
    "letmein",
    "welcome",
    "admin",
    "administrator",
    "paracci",
    "qwerty",
    "qwerty123",
    "iloveyou",
}

_SEQUENCE_ROWS = (
    "01234567890123456789",
    "abcdefghijklmnopqrstuvwxyz",
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
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
        conn.executescript(f"""
            CREATE TABLE IF NOT EXISTS burned_messages (
                fingerprint     BLOB PRIMARY KEY,   -- SHA3-256(msg_id)
                status          TEXT NOT NULL CHECK(status IN {BURN_STATUSES!r}),
                reserved_at     INTEGER NOT NULL,   -- Unix timestamp
                burned_at       INTEGER,            -- Unix timestamp
                failed_at       INTEGER,            -- Unix timestamp
                session_id      BLOB,               -- Which session it belongs to
                failure_reason  TEXT,
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
        columns = {row[1] for row in conn.execute("PRAGMA table_info(burned_messages)")}
        if "status" not in columns:
            self._migrate_burned_messages(conn)
        self._cleanup_stale_opening(conn)
        conn.commit()
        conn.close()

    def _migrate_burned_messages(self, conn: sqlite3.Connection) -> None:
        """Migrates the legacy burn table into the state-machine schema."""
        conn.execute("ALTER TABLE burned_messages RENAME TO burned_messages_legacy")
        conn.execute(f"""
            CREATE TABLE burned_messages (
                fingerprint     BLOB PRIMARY KEY,
                status          TEXT NOT NULL CHECK(status IN {BURN_STATUSES!r}),
                reserved_at     INTEGER NOT NULL,
                burned_at       INTEGER,
                failed_at       INTEGER,
                session_id      BLOB,
                direction       INTEGER,
                failure_reason  TEXT
            )
        """)
        conn.execute(
            """
            INSERT OR IGNORE INTO burned_messages
                (fingerprint, status, reserved_at, burned_at, failed_at, session_id, direction, failure_reason)
            SELECT
                fingerprint, ?, burned_at, burned_at, NULL, session_id, direction, NULL
            FROM burned_messages_legacy
            """,
            (BURN_STATUS_BURNED,),
        )
        conn.execute("DROP TABLE burned_messages_legacy")

    def _cleanup_stale_opening(self, conn: sqlite3.Connection) -> None:
        """Deletes abandoned opening reservations left by a prior process."""
        stale_before = int(time.time()) - BURN_OPENING_STALE_SECONDS
        conn.execute(
            """
            DELETE FROM burned_messages
            WHERE status=? AND reserved_at < ?
            """,
            (BURN_STATUS_OPENING, stale_before),
        )

    # --- Message Burning ---

    def is_burned(self, msg_id: bytes) -> bool:
        """Is this MSG_ID currently reserved or already burned?"""
        return self.get_burn_status(msg_id) in {BURN_STATUS_OPENING, BURN_STATUS_BURNED}

    def get_burn_status(self, msg_id: bytes) -> str | None:
        """Returns the burn state for a MSG_ID, if present."""
        fingerprint = message_id_fingerprint(msg_id)
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT status FROM burned_messages WHERE fingerprint=?",
                (fingerprint,)
            ).fetchone()
            return row[0] if row else None
        finally:
            conn.close()

    def burn(self, msg_id: bytes, session_id: bytes, direction: int):
        """Registers the MSG_ID as burned in one terminal transaction."""
        fingerprint = message_id_fingerprint(msg_id)
        now = int(time.time())
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                INSERT INTO burned_messages
                    (fingerprint, status, reserved_at, burned_at, failed_at, session_id, direction, failure_reason)
                VALUES (?, ?, ?, ?, NULL, ?, ?, NULL)
                ON CONFLICT(fingerprint) DO UPDATE SET
                    status=excluded.status,
                    reserved_at=excluded.reserved_at,
                    burned_at=excluded.burned_at,
                    failed_at=NULL,
                    session_id=excluded.session_id,
                    direction=excluded.direction,
                    failure_reason=NULL
                """,
                (fingerprint, BURN_STATUS_BURNED, now, now, session_id, direction)
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def reserve_open(self, msg_id: bytes) -> bool:
        """Atomically claims a single-use message before decryption starts."""
        fingerprint = message_id_fingerprint(msg_id)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            now = int(time.time())
            stale_before = now - BURN_OPENING_STALE_SECONDS
            try:
                conn.execute(
                    """
                    INSERT INTO burned_messages
                        (fingerprint, status, reserved_at, burned_at, failed_at, session_id, direction, failure_reason)
                    VALUES (?, ?, ?, NULL, NULL, NULL, NULL, NULL)
                    """,
                    (fingerprint, BURN_STATUS_OPENING, now),
                )
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT status, reserved_at FROM burned_messages WHERE fingerprint=?",
                    (fingerprint,),
                ).fetchone()
                if row and row[0] == BURN_STATUS_FAILED:
                    updated = conn.execute(
                        """
                        UPDATE burned_messages
                        SET status=?, reserved_at=?, burned_at=NULL, failed_at=NULL,
                            session_id=NULL, direction=NULL, failure_reason=NULL
                        WHERE fingerprint=? AND status=?
                        """,
                        (BURN_STATUS_OPENING, now, fingerprint, BURN_STATUS_FAILED),
                    )
                    if updated.rowcount != 1:
                        conn.rollback()
                        raise AlreadyBurnedError(
                            "This message is already being opened or has been burned."
                        )
                elif row and row[0] == BURN_STATUS_OPENING and row[1] < stale_before:
                    updated = conn.execute(
                        """
                        UPDATE burned_messages
                        SET status=?, reserved_at=?, burned_at=NULL, failed_at=NULL,
                            session_id=NULL, direction=NULL, failure_reason=NULL
                        WHERE fingerprint=? AND status=? AND reserved_at < ?
                        """,
                        (
                            BURN_STATUS_OPENING,
                            now,
                            fingerprint,
                            BURN_STATUS_OPENING,
                            stale_before,
                        ),
                    )
                    if updated.rowcount != 1:
                        conn.rollback()
                        raise AlreadyBurnedError(
                            "This message is already being opened or has been burned."
                        )
                else:
                    conn.rollback()
                    raise AlreadyBurnedError(
                        "This message is already being opened or has been burned."
                    )
            conn.commit()
            return True
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def mark_open_burned(self, msg_id: bytes, session_id: bytes, direction: int) -> None:
        """Transitions a reserved message from opening to burned."""
        fingerprint = message_id_fingerprint(msg_id)
        now = int(time.time())
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            updated = conn.execute(
                """
                UPDATE burned_messages
                SET status=?, burned_at=?, failed_at=NULL, session_id=?, direction=?, failure_reason=NULL
                WHERE fingerprint=? AND status=?
                """,
                (BURN_STATUS_BURNED, now, session_id, direction, fingerprint, BURN_STATUS_OPENING),
            )
            if updated.rowcount != 1:
                conn.rollback()
                raise AlreadyBurnedError(
                    "This message was already opened and burned. It cannot be opened again."
                )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def mark_open_failed(self, msg_id: bytes, reason: str | None = None) -> None:
        """Transitions a reserved message from opening to failed so it can be retried."""
        fingerprint = message_id_fingerprint(msg_id)
        now = int(time.time())
        failure_reason = (reason or "")[:512]
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute(
                """
                UPDATE burned_messages
                SET status=?, failed_at=?, failure_reason=?
                WHERE fingerprint=? AND status=?
                """,
                (BURN_STATUS_FAILED, now, failure_reason, fingerprint, BURN_STATUS_OPENING),
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
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

    def session_exists(self, session_id: bytes) -> bool:
        """Return whether a plaintext session identifier is present locally."""
        conn = self._connect()
        try:
            return conn.execute(
                "SELECT 1 FROM sessions WHERE session_id=? LIMIT 1",
                (session_id,),
            ).fetchone() is not None
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

    def _decode_unlock_rate_limit(self, raw: bytes | None, now: int | None = None) -> dict:
        now = int(time.time()) if now is None else int(now)
        state = {"failed_attempts": 0, "locked_until": 0, "last_failed_at": 0}
        if raw:
            try:
                parsed = json.loads(raw.decode("utf-8"))
                state["failed_attempts"] = max(0, int(parsed.get("failed_attempts", 0)))
                state["locked_until"] = max(0, int(parsed.get("locked_until", 0)))
                state["last_failed_at"] = max(0, int(parsed.get("last_failed_at", 0)))
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError):
                state = {"failed_attempts": 0, "locked_until": 0, "last_failed_at": 0}
        state["retry_after_seconds"] = max(0, state["locked_until"] - now)
        return state

    def get_unlock_rate_limit(self, now: int | None = None) -> dict:
        """Returns durable unlock failure and lockout state."""
        raw = self.get_device_meta(UNLOCK_RATE_LIMIT_KEY)
        return self._decode_unlock_rate_limit(raw, now)

    def assert_unlock_allowed(self, now: int | None = None) -> None:
        """Raises when the durable unlock lockout window is still active."""
        state = self.get_unlock_rate_limit(now)
        if state["retry_after_seconds"] > 0:
            raise DeviceLockedError(state["retry_after_seconds"])

    def record_unlock_failure(self, now: int | None = None) -> dict:
        """Records one failed unlock attempt and returns the updated durable state."""
        now = int(time.time()) if now is None else int(now)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            row = conn.execute(
                "SELECT value FROM device_meta WHERE key=?",
                (UNLOCK_RATE_LIMIT_KEY,),
            ).fetchone()
            state = self._decode_unlock_rate_limit(row[0] if row else None, now)
            if state["retry_after_seconds"] > 0:
                conn.rollback()
                raise DeviceLockedError(state["retry_after_seconds"])

            failed_attempts = state["failed_attempts"] + 1
            if failed_attempts >= UNLOCK_MAX_FAILED_ATTEMPTS:
                delay = UNLOCK_LOCKOUT_SECONDS
            else:
                delay = UNLOCK_FAILURE_DELAYS.get(failed_attempts, 0)

            updated = {
                "failed_attempts": failed_attempts,
                "locked_until": now + delay if delay else 0,
                "last_failed_at": now,
            }
            encoded = json.dumps(updated, sort_keys=True, separators=(",", ":")).encode("utf-8")
            conn.execute(
                "INSERT OR REPLACE INTO device_meta (key, value) VALUES (?, ?)",
                (UNLOCK_RATE_LIMIT_KEY, encoded),
            )
            conn.commit()
            updated["retry_after_seconds"] = delay
            return updated
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def reset_unlock_failures(self) -> None:
        """Clears consecutive unlock failures after a successful unlock."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM device_meta WHERE key=?", (UNLOCK_RATE_LIMIT_KEY,))
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
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

    def _decode_legacy_2fa_secret(self, value) -> str | None:
        if isinstance(value, str):
            candidate = value.strip()
        elif isinstance(value, bytes):
            try:
                candidate = value.decode("ascii").strip()
            except UnicodeDecodeError:
                return None
        else:
            return None
        if LEGACY_TOTP_SECRET_RE.fullmatch(candidate):
            return candidate
        return None

    def _encrypted_2fa_secret_blob(self, value) -> EncryptedBlob:
        if not isinstance(value, bytes):
            raise DeviceError("Invalid 2FA secret metadata.")
        nonce = value[:TWO_FA_SECRET_NONCE_LEN]
        ciphertext = value[TWO_FA_SECRET_NONCE_LEN:]
        if (
            len(value) < TWO_FA_SECRET_NONCE_LEN + TWO_FA_SECRET_MIN_CIPHERTEXT_LEN
            or len(nonce) != TWO_FA_SECRET_NONCE_LEN
            or len(ciphertext) <= TWO_FA_SECRET_TAG_LEN
        ):
            raise DeviceError("Invalid 2FA secret metadata.")
        return EncryptedBlob(nonce=nonce, ciphertext=ciphertext)

    def get_2fa_secret(self, device_key: bytes | bytearray) -> str | None:
        """Returns the decrypted 2FA secret key, migrating legacy plaintext storage."""
        val = self.get_device_meta(TWO_FA_SECRET_KEY)
        if val is None:
            return None

        legacy_secret = self._decode_legacy_2fa_secret(val)
        if legacy_secret is not None:
            self.set_2fa_secret(legacy_secret, device_key)
            val = self.get_device_meta(TWO_FA_SECRET_KEY)

        try:
            blob = self._encrypted_2fa_secret_blob(val)
            return decrypt(device_key, blob, aad=TWO_FA_SECRET_AAD).decode("utf-8")
        except DeviceError:
            raise
        except Exception as exc:
            raise DeviceError("Invalid 2FA secret metadata.") from exc

    def set_2fa_secret(self, secret: str, device_key: bytes | bytearray) -> None:
        """Encrypts and saves the 2FA secret key."""
        normalized = (secret or "").strip()
        blob = encrypt(device_key, normalized.encode("utf-8"), aad=TWO_FA_SECRET_AAD)
        self.set_device_meta(TWO_FA_SECRET_KEY, blob.nonce + blob.ciphertext)

    def get_2fa_secret_raw(self) -> bytes | None:
        """Returns the encrypted 2FA secret key as bytes."""
        return self.get_device_meta(TWO_FA_SECRET_KEY)

    def delete_2fa_secret(self) -> None:
        """Deletes the stored 2FA secret key."""
        self.delete_device_meta(TWO_FA_SECRET_KEY)


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

    def pre_open_check(self, msg_id: bytes, expire_at: int, single_use: bool) -> bool:
        """
        Perform all checks before opening the message.
        Throws an exception if any check fails.
        Returns True when a single-use open reservation was created.
        """
        # TTL is checked before reserving so expired files do not create burn rows.
        if expire_at > 0:
            if int(time.time()) >= expire_at:
                raise TTLExpiredError(
                    "The message has expired. This envelope can no longer be opened."
                )

        if single_use:
            return self.db.reserve_open(msg_id)
        return False

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
            self.db.mark_open_burned(msg_id, session_id, direction)

        # Securely delete the file (if single-use or requested by caller)
        if file_path and single_use:
            secure_delete(file_path)

    def mark_open_failed(self, msg_id: bytes, reason: str | None = None) -> None:
        """
        Mark a reserved open attempt as failed so a valid message can be retried.
        """
        self.db.mark_open_failed(msg_id, reason)

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

def _compact_passphrase(passphrase: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", passphrase.casefold())


def _has_repeated_short_token(value: str) -> bool:
    if len(value) < 6:
        return False
    max_token_len = min(16, len(value) // 2)
    for token_len in range(1, max_token_len + 1):
        if len(value) % token_len != 0:
            continue
        repeats = len(value) // token_len
        if repeats >= 3 and value == value[:token_len] * repeats:
            return True
    return False


def _has_obvious_sequence(value: str, run_length: int = 4) -> bool:
    if len(value) < run_length:
        return False
    for i in range(0, len(value) - run_length + 1):
        chunk = value[i:i + run_length]
        for row in _SEQUENCE_ROWS:
            if chunk in row or chunk in row[::-1]:
                return True
    return False


def _uses_common_weak_phrase(value: str) -> bool:
    if value in _COMMON_WEAK_PASSPHRASES:
        return True
    for weak in _COMMON_WEAK_PASSPHRASES:
        if len(weak) >= 6 and value.startswith(weak) and value[len(weak):].isdigit():
            return True
    return False


def _estimate_passphrase_entropy(passphrase: str) -> float:
    pool_size = 0
    if any(ch.islower() for ch in passphrase):
        pool_size += 26
    if any(ch.isupper() for ch in passphrase):
        pool_size += 26
    if any(ch.isdigit() for ch in passphrase):
        pool_size += 10
    if any(ch.isspace() for ch in passphrase):
        pool_size += 1
    if any(not ch.isalnum() and not ch.isspace() for ch in passphrase):
        pool_size += 33
    if pool_size <= 1:
        return 0.0
    return len(passphrase) * math.log2(pool_size)


def is_device_initialized(db: BurnDB) -> bool:
    """Has the device been set up with a passphrase before?"""
    return db.get_device_meta("pin_salt") is not None

def validate_pin_strength(pin: str):
    """
    Validates passphrase strength. The function name is retained for callers.

    Criteria:
    - 12 to 128 characters
    - Numeric-only passphrases require at least 20 digits
    - Must have enough character diversity and estimated entropy
    - Must not be obvious sequences, common weak phrases, or repeated tokens
    """
    passphrase = pin or ""
    compact = _compact_passphrase(passphrase)

    if len(passphrase) < PASSPHRASE_MIN_LENGTH:
        raise DeviceError(f"Passphrase must be at least {PASSPHRASE_MIN_LENGTH} characters.")
    if len(passphrase) > PASSPHRASE_MAX_LENGTH:
        raise DeviceError(f"Passphrase must be at most {PASSPHRASE_MAX_LENGTH} characters.")
    if passphrase == passphrase[0] * len(passphrase):
        raise DeviceError("Passphrase is too simple because all characters are the same.")
    if passphrase.isdigit() and len(passphrase) < PASSPHRASE_NUMERIC_MIN_LENGTH:
        raise DeviceError(
            f"Numeric-only passphrases must be at least {PASSPHRASE_NUMERIC_MIN_LENGTH} digits."
        )
    if len(set(passphrase)) < PASSPHRASE_MIN_UNIQUE_CHARS:
        raise DeviceError(
            f"Passphrase must contain at least {PASSPHRASE_MIN_UNIQUE_CHARS} unique characters."
        )
    if _has_repeated_short_token(compact):
        raise DeviceError("Passphrase must not repeat a short token.")
    if _has_obvious_sequence(compact):
        raise DeviceError("Passphrase must not contain obvious keyboard or alphabet sequences.")
    if _uses_common_weak_phrase(compact):
        raise DeviceError("Passphrase is too common.")
    if _estimate_passphrase_entropy(passphrase) < PASSPHRASE_MIN_ENTROPY_BITS:
        raise DeviceError(
            f"Passphrase must have at least {PASSPHRASE_MIN_ENTROPY_BITS} bits of estimated entropy."
        )


def init_device(db: BurnDB, pin: str) -> bytearray:
    """
    Sets up the device for the first time:
    1. Produces a new pin_salt.
    2. Derives master_key from the passphrase.
    3. Produces a random device_key.
    4. Encrypts and saves the device_key with the master_key.
    """
    validate_pin_strength(pin)
    
    if is_device_initialized(db):
        raise DeviceError("Device already set up.")
    
    pin_salt = random_bytes(16)
    master_key = derive_master_key(pin, pin_salt)
    
    try:
        device_key = bytearray(random_bytes(32))
        
        # Encrypt device_key with master_key.
        # OS keychain/TPM wrapping remains a separate device_key_protection_v1
        # layer; this patch only strengthens passphrases and online unlock rate limits.
        blob = encrypt(master_key, device_key, aad=b"paracci.device_key.v1")
        
        # Save
        db.set_device_meta("pin_salt", pin_salt)
        db.set_device_meta("encrypted_device_key", blob.nonce + blob.ciphertext)
        
        return device_key
    finally:
        # Wipe master_key from memory
        if 'master_key' in locals():
            wipe(master_key)


def unlock_device(db: BurnDB, pin: str) -> bytearray:
    """
    Unlocks the device key with the passphrase.
    """
    pin_salt = db.get_device_meta("pin_salt")
    enc_data = db.get_device_meta("encrypted_device_key")
    
    if not pin_salt or not enc_data:
        raise DeviceError("Device not set up yet.")

    db.assert_unlock_allowed()
    master_key = derive_master_key(pin, pin_salt)
    
    try:
        # enc_data: nonce(12) + ciphertext
        nonce = enc_data[:12]
        ciphertext = enc_data[12:]
        blob = EncryptedBlob(nonce=nonce, ciphertext=ciphertext)
        
        device_key = bytearray(decrypt(master_key, blob, aad=b"paracci.device_key.v1"))
    except Exception:
        state = db.record_unlock_failure()
        if state["retry_after_seconds"] > 0 and state["failed_attempts"] >= UNLOCK_MAX_FAILED_ATTEMPTS:
            raise DeviceLockedError(state["retry_after_seconds"])
        raise DeviceError("Incorrect passphrase.")
    else:
        db.reset_unlock_failures()
        return device_key
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
    """Error related to device key or passphrase."""


class DeviceLockedError(DeviceError):
    """Unlock is temporarily locked because of repeated failed attempts."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = max(1, int(retry_after_seconds))
        super().__init__(
            f"Too many failed attempts. Try again in {self.retry_after_seconds} seconds."
        )
