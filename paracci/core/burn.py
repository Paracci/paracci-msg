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
import subprocess
import sys
import hashlib
import json
import getpass
import logging
import math
import re
import threading
import time
from contextlib import contextmanager
from pathlib import Path

MIGRATION_CONTEXT = threading.local()
MIGRATION_CONTEXT.device_key = None
MIGRATION_CONTEXT.is_encrypting = False

try:
    import sqlcipher3.dbapi2 as sqlcipher
    _original_sqlite3_connect = sqlcipher.connect
    def _patched_sqlite3_connect(database, **kwargs):
        conn = _original_sqlite3_connect(database, **kwargs)
        key = getattr(MIGRATION_CONTEXT, "device_key", None)
        if key and not getattr(MIGRATION_CONTEXT, "is_encrypting", False):
            if "sessions.db" in str(database) and not str(database).endswith(".meta"):
                conn.execute(f"PRAGMA key = \"x'{key.hex()}'\"")
        return conn
    sqlcipher.connect = _patched_sqlite3_connect
    sys.modules["sqlite3"] = sqlcipher
    import sqlite3
except ImportError:
    import sqlite3

from yoyo import read_migrations, get_backend
from .shields import shield
from .constants import BURN_OPENING_STALE_SECONDS

from .crypto import (
    message_id_fingerprint,
    secure_hash,
    encrypt, 
    decrypt, 
    derive_master_key, 
    EncryptedBlob,
    KEY_LEN,
    NONCE_LEN,
    random_bytes,
    wipe
)

logger = logging.getLogger(__name__)

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
UNLOCK_EVER_SUCCEEDED_KEY = "unlock_ever_succeeded"
UNLOCK_EVER_SUCCEEDED_VALUE = b"1"
UNLOCK_MAX_FAILED_ATTEMPTS = 5
UNLOCK_LOCKOUT_SECONDS = 300
UNLOCK_FAILURE_DELAYS = {
    2: 2,
    3: 5,
    4: 15,
}
_UNLOCK_ATTEMPT_LOCK = threading.Lock()
TWO_FA_SECRET_KEY = "2fa_secret"
TWO_FA_SECRET_AAD = b"paracci.2fa_secret.v1"
TWO_FA_SECRET_NONCE_LEN = 12
TWO_FA_SECRET_TAG_LEN = 16
TWO_FA_SECRET_MIN_CIPHERTEXT_LEN = TWO_FA_SECRET_TAG_LEN + 1
LEGACY_TOTP_SECRET_RE = re.compile(r"^[A-Z2-7]{16,128}$")

PROTECTED_VALUE_PREFIX = b"paracci.burndb.field.v1:"
PROTECTED_VALUE_AAD_PREFIX = b"paracci.burndb.field.v1\x00"
PROTECTED_VALUE_TAG_LEN = 16
STORAGE_MIGRATION_KEY = "protected_fields_v1"
STORAGE_MIGRATION_V2_KEY = "protected_fields_v2"
STORAGE_MIGRATION_PENDING = b"pending_scrub"
STORAGE_MIGRATION_COMPLETE = b"complete"
BOOTSTRAP_DEVICE_META_KEYS = frozenset(
    {
        "pin_salt",
        "encrypted_device_key",
        "dpapi_blob",
        "platform_binding_profile_id_v1",
        "platform_binding_kind_v1",
        UNLOCK_RATE_LIMIT_KEY,
        UNLOCK_EVER_SUCCEEDED_KEY,
    }
)

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


@contextmanager
def _serialized_unlock_attempt():
    """Serialize one unlock attempt through reservation and final outcome."""
    with _UNLOCK_ATTEMPT_LOCK:
        yield


class _ConnectionProxy:
    """A proxy that delegates database operations but ignores close()."""

    def __init__(self, conn: sqlite3.Connection):
        object.__setattr__(self, "_conn", conn)

    def __getattr__(self, name):
        return getattr(self._conn, name)

    def __setattr__(self, name, value):
        setattr(self._conn, name, value)

    def close(self):
        pass

    def __enter__(self):
        self._conn.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return self._conn.__exit__(exc_type, exc_val, exc_tb)


# ---------------------------------------------------------------------------
# Directory and File Permission Security Helpers
# ---------------------------------------------------------------------------

def _secure_dir_permissions(dir_path: str | Path) -> None:
    """Restrict directory permissions to owner only.

    POSIX: sets mode 0o700 (rwx------).
    Windows: disables inheritance and grants Full Control to the owner via icacls.
    """
    path = Path(dir_path).resolve()
    try:
        path.mkdir(parents=True, exist_ok=True)
        if sys.platform == "win32":
            username = os.environ.get("USERNAME")
            if not username:
                try:
                    import getpass
                    username = getpass.getuser()
                except Exception:
                    pass
            if not username:
                logger.warning(
                    "Could not restrict directory permissions on %s: USERNAME is empty.",
                    path,
                )
                return
            result = subprocess.run(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{username}:(OI)(CI)F",
                ],
                check=False,
                capture_output=True,
            )
            if result.returncode != 0:
                logger.warning(
                    "icacls could not restrict permissions on directory %s (rc=%d): %s",
                    path,
                    result.returncode,
                    result.stderr.decode(errors="replace").strip(),
                )
        else:
            os.chmod(path, 0o700)
    except Exception as exc:
        logger.warning("Could not restrict directory permissions on %s: %s", path, exc)


def _secure_file_permissions(file_path: str | Path) -> None:
    """Restrict file permissions to owner only.

    POSIX: sets mode 0o600 (rw-------).
    Windows: disables inheritance and grants Full Control to the owner via icacls.
    """
    path = Path(file_path).resolve()
    try:
        if not path.exists():
            return
        if sys.platform == "win32":
            username = os.environ.get("USERNAME")
            if not username:
                try:
                    import getpass
                    username = getpass.getuser()
                except Exception:
                    pass
            if not username:
                logger.warning(
                    "Could not restrict file permissions on %s: USERNAME is empty.",
                    path,
                )
                return
            result = subprocess.run(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{username}:F",
                ],
                check=False,
                capture_output=True,
            )
            if result.returncode != 0:
                logger.warning(
                    "icacls could not restrict permissions on file %s (rc=%d): %s",
                    path,
                    result.returncode,
                    result.stderr.decode(errors="replace").strip(),
                )
        else:
            os.chmod(path, 0o600)
    except Exception as exc:
        logger.warning("Could not restrict file permissions on %s: %s", path, exc)


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

    def __init__(
        self,
        db_path: str | Path,
        device_key: bytes | bytearray | None = None,
    ):
        """Initializes storage in locked bootstrap mode or keyed protected mode."""
        self.db_path = str(db_path)
        self.meta_db_path = str(db_path) + ".meta"
        self._local = threading.local()
        self._device_key: bytearray | None = None
        if device_key is not None:
            if len(device_key) != KEY_LEN:
                raise DeviceError("Invalid device key.")
            self._device_key = bytearray(device_key)
        self._init_db()
        if self._device_key is not None:
            try:
                self._migrate_protected_fields()
            except Exception:
                self.release_device_key()
                raise

    @property
    def _meta_prefix(self) -> str:
        return "meta." if self._device_key else ""

    @property
    def has_device_key(self) -> bool:
        """Return whether protected database values may be opened."""
        return self._device_key is not None

    def with_device_key(self, device_key: bytes | bytearray) -> "BurnDB":
        """Open the same database with a lifetime-scoped protected-field key."""
        db = BurnDB(self.db_path, device_key=device_key)
        db._ensure_sqlcipher_encryption()
        return db

    def _ensure_sqlcipher_encryption(self):
        """Detects if sessions.db is plaintext, and exports it to SQLCipher if so."""
        is_plaintext = False
        import sqlite3 as std_sqlite3
        try:
            conn = std_sqlite3.connect(self.db_path)
            conn.execute("SELECT count(*) FROM sqlite_master")
            is_plaintext = True
        except std_sqlite3.DatabaseError:
            pass
        finally:
            conn.close()
            
        if not is_plaintext:
            return

        logger.info("Migrating sessions.db to SQLCipher...")
        temp_db_path = self.db_path + ".enc"
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)
            
        # Perform sqlcipher export using the patched sqlite3 with is_encrypting = True
        MIGRATION_CONTEXT.is_encrypting = True
        try:
            import sqlite3
            conn = sqlite3.connect(self.db_path)
            try:
                conn.execute(f"ATTACH DATABASE '{temp_db_path}' AS encrypted KEY \"x'{self._device_key.hex()}'\"")
                conn.execute("SELECT sqlcipher_export('encrypted')")
                conn.execute("DETACH DATABASE encrypted")
            except sqlite3.OperationalError as exc:
                if "no such function: sqlcipher_export" in str(exc):
                    logger.error("SQLCipher not installed; cannot encrypt database. Falling back to plaintext.")
                    conn.close()
                    if os.path.exists(temp_db_path):
                        os.remove(temp_db_path)
                    return
                raise
            conn.close()
            
            # Strip device_meta tables from the new encrypted DB
            conn_enc = sqlite3.connect(temp_db_path)
            conn_enc.execute(f"PRAGMA key = \"x'{self._device_key.hex()}'\"")
            conn_enc.execute("DROP TABLE IF EXISTS device_meta")
            conn_enc.execute("DROP TABLE IF EXISTS burn_internal_meta")
            conn_enc.execute("VACUUM")
            conn_enc.close()
            
            import shutil
            shutil.move(temp_db_path, self.db_path)
        finally:
            MIGRATION_CONTEXT.is_encrypting = False

    def release_device_key(self) -> None:
        """Best-effort zeroing for the protected-field key owned by this object."""
        self.close()
        if self._device_key is not None:
            wipe(self._device_key)
            self._device_key = None

    def close(self) -> None:
        """Closes the cached database connection for the current thread."""
        conn = getattr(self._local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
            self._local.conn = None

    def _connect(self) -> sqlite3.Connection:
        """Connects to the SQLite database in WAL mode with optimized settings, reusing per-thread connections."""
        conn = getattr(self._local, "conn", None)
        if conn is None:
            if self._device_key is None:
                conn = sqlite3.connect(self.meta_db_path, check_same_thread=False)
                conn.execute("PRAGMA journal_mode=WAL")
            else:
                conn = sqlite3.connect(self.db_path, check_same_thread=False)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute(f"ATTACH DATABASE '{self.meta_db_path}' AS meta KEY ''")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA secure_delete=ON")
            conn.execute("PRAGMA cache_size=64")
            self._local.conn = conn
        return _ConnectionProxy(conn)

    @staticmethod
    def _secure_db_permissions(db_path: str) -> None:
        """Restrict the database file and WAL sidecar permissions to the owner only."""
        targets = [db_path] + [
            db_path + suffix
            for suffix in ("-wal", "-shm")
            if os.path.exists(db_path + suffix)
        ]
        for target in targets:
            _secure_file_permissions(target)

    def _init_db(self):
        """Creates the database tables via yoyo structural migrations."""
        _secure_dir_permissions(Path(self.db_path).parent)
        
        v1_migration_needed = os.path.exists(self.db_path) and not os.path.exists(self.meta_db_path)
        
        _old_mask = None
        if sys.platform != "win32":
            _old_mask = os.umask(0o177)
            
        try:
            import sqlite3
            migrations_dir = Path(__file__).parent / "migrations" / "schema"
            migrations = read_migrations(str(migrations_dir))
            
            # 1. Run migrations on meta.db
            conn = sqlite3.connect(self.meta_db_path)
            conn.execute("PRAGMA journal_mode=WAL")
            conn.close()
            backend_meta = get_backend(f"sqlite:///{self.meta_db_path}")
            with backend_meta.lock():
                backend_meta.apply_migrations(backend_meta.to_apply(migrations))
            if backend_meta.connection:
                backend_meta.connection.close()
                
            # 2. Extract V1 metadata if needed
            if v1_migration_needed:
                conn = sqlite3.connect(self.meta_db_path)
                conn.execute(f"ATTACH DATABASE '{self.db_path}' AS old KEY ''")
                try:
                    conn.execute("INSERT OR IGNORE INTO device_meta SELECT * FROM old.device_meta")
                    conn.execute("INSERT OR IGNORE INTO burn_internal_meta SELECT * FROM old.burn_internal_meta")
                    conn.commit()
                except sqlite3.OperationalError:
                    pass
                conn.close()
                
            # 3. Run migrations on sessions.db if unlocked
            if self._device_key is not None:
                conn = sqlite3.connect(self.db_path)
                conn.execute("PRAGMA journal_mode=WAL")
                conn.close()
                
                MIGRATION_CONTEXT.device_key = self._device_key
                try:
                    backend_sessions = get_backend(f"sqlite:///{self.db_path}")
                    with backend_sessions.lock():
                        backend_sessions.apply_migrations(backend_sessions.to_apply(migrations))
                    if backend_sessions.connection:
                        backend_sessions.connection.close()
                finally:
                    MIGRATION_CONTEXT.device_key = None
        finally:
            if _old_mask is not None:
                os.umask(_old_mask)

        self._secure_db_permissions(self.db_path)
        self._secure_db_permissions(self.meta_db_path)

    def _require_device_key(self) -> bytearray:
        if self._device_key is None:
            raise DeviceError("Device is locked; protected metadata is unavailable.")
        return self._device_key

    @staticmethod
    def _row_identifier(value: bytes | bytearray | str) -> bytes:
        if isinstance(value, str):
            return value.encode("utf-8")
        return bytes(value)

    def _protected_aad(
        self,
        table: str,
        column: str,
        row_identifier: bytes | bytearray | str,
    ) -> bytes:
        return (
            PROTECTED_VALUE_AAD_PREFIX
            + table.encode("ascii")
            + b"\x00"
            + column.encode("ascii")
            + b"\x00"
            + self._row_identifier(row_identifier)
        )

    @staticmethod
    def _logical_bytes(value: bytes | bytearray | str) -> bytes:
        if isinstance(value, str):
            return value.encode("utf-8")
        if isinstance(value, (bytes, bytearray)):
            return bytes(value)
        raise DeviceError("Invalid protected metadata.")

    def _encrypt_protected_value(
        self,
        table: str,
        column: str,
        row_identifier: bytes | bytearray | str,
        value: bytes | bytearray | str,
    ) -> bytes:
        key = self._require_device_key()
        blob = encrypt(
            key,
            self._logical_bytes(value),
            aad=self._protected_aad(table, column, row_identifier),
        )
        return PROTECTED_VALUE_PREFIX + blob.nonce + blob.ciphertext

    def _decrypt_protected_value(
        self,
        table: str,
        column: str,
        row_identifier: bytes | bytearray | str,
        value,
    ) -> bytes:
        key = self._require_device_key()
        if not isinstance(value, bytes) or not value.startswith(PROTECTED_VALUE_PREFIX):
            raise DeviceError("Invalid protected metadata.")
        encoded = value[len(PROTECTED_VALUE_PREFIX):]
        if len(encoded) < NONCE_LEN + PROTECTED_VALUE_TAG_LEN:
            raise DeviceError("Invalid protected metadata.")
        blob = EncryptedBlob(nonce=encoded[:NONCE_LEN], ciphertext=encoded[NONCE_LEN:])
        try:
            return decrypt(
                key,
                blob,
                aad=self._protected_aad(table, column, row_identifier),
            )
        except Exception as exc:
            raise DeviceError("Invalid protected metadata.") from exc

    def _decrypt_protected_text(
        self,
        table: str,
        column: str,
        row_identifier: bytes | bytearray | str,
        value,
    ) -> str:
        try:
            return self._decrypt_protected_value(
                table,
                column,
                row_identifier,
                value,
            ).decode("utf-8")
        except DeviceError:
            raise
        except UnicodeDecodeError as exc:
            raise DeviceError("Invalid protected metadata.") from exc

    def _migration_state(self, conn: sqlite3.Connection, key: str = STORAGE_MIGRATION_KEY) -> bytes | None:
        row = conn.execute(f"SELECT value FROM {self._meta_prefix}burn_internal_meta WHERE key=?",
            (key,),
        ).fetchone()
        if row is None:
            return None
        state = self._decrypt_protected_value(
            "burn_internal_meta",
            "value",
            key,
            row[0],
        )
        if state not in {STORAGE_MIGRATION_PENDING, STORAGE_MIGRATION_COMPLETE}:
            raise DeviceError("Invalid protected metadata migration state.")
        return state

    def _write_migration_state(self, conn: sqlite3.Connection, state: bytes, key: str = STORAGE_MIGRATION_KEY) -> None:
        conn.execute(f"INSERT OR REPLACE INTO {self._meta_prefix}burn_internal_meta (key, value) VALUES (?, ?)",
            (
                key,
                self._encrypt_protected_value(
                    "burn_internal_meta",
                    "value",
                    key,
                    state,
                ),
            ),
        )

    def _migrate_protected_fields(self) -> None:
        """Encrypt existing plaintext cells atomically, then scrub SQLite residue."""
        # Key validation check: try to decrypt migration status markers to verify key correctness
        # if the database has already been migrated.
        conn = self._connect()
        try:
            for key in (STORAGE_MIGRATION_KEY, STORAGE_MIGRATION_V2_KEY):
                row = conn.execute(f"SELECT value FROM {self._meta_prefix}burn_internal_meta WHERE key=?",
                    (key,),
                ).fetchone()
                if row is not None:
                    self._decrypt_protected_value("burn_internal_meta", "value", key, row[0])
        finally:
            conn.close()

        import sys
        sys._paracci_migration_db = self
        try:
            backend = get_backend(f"sqlite:///{self.db_path}")
            migrations_dir = Path(__file__).parent / "migrations" / "encryption"
            migrations = read_migrations(str(migrations_dir))
            
            to_run = backend.to_apply(migrations)
            if to_run:
                backend.apply_migrations(to_run)
                
                # Checkpoint and scrub residue
                scrub_conn = self._connect()
                try:
                    checkpoint = scrub_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                    if checkpoint and checkpoint[0] != 0:
                        raise DeviceError("Could not scrub protected metadata migration residue.")
                    scrub_conn.execute("VACUUM")
                    checkpoint = scrub_conn.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone()
                    if checkpoint and checkpoint[0] != 0:
                        raise DeviceError("Could not scrub protected metadata migration residue.")
                finally:
                    scrub_conn.close()
            if backend.connection:
                backend.connection.close()
        finally:
            if hasattr(sys, "_paracci_migration_db"):
                del sys._paracci_migration_db

        # Clean up stale opening reservations now that the database is unlocked
        cleanup_conn = self._connect()
        try:
            cleanup_conn.execute("BEGIN IMMEDIATE")
            self._cleanup_stale_opening(cleanup_conn)
            cleanup_conn.commit()
        except Exception:
            if cleanup_conn.in_transaction:
                cleanup_conn.rollback()
        finally:
            cleanup_conn.close()

    def _cleanup_stale_opening(self, conn: sqlite3.Connection) -> None:
        """Deletes abandoned opening reservations left by a prior process."""
        stale_before = int(time.time()) - BURN_OPENING_STALE_SECONDS
        try:
            rows = conn.execute(
                "SELECT fingerprint, status, reserved_at FROM burned_messages"
            ).fetchall()
        except sqlite3.OperationalError:
            return

        to_delete = []
        for fingerprint, enc_status, enc_reserved_at in rows:
            try:
                if isinstance(enc_status, bytes) and enc_status.startswith(PROTECTED_VALUE_PREFIX):
                    status = self._decrypt_protected_text("burned_messages", "status", fingerprint, enc_status)
                else:
                    status = enc_status

                if isinstance(enc_reserved_at, bytes) and enc_reserved_at.startswith(PROTECTED_VALUE_PREFIX):
                    reserved_at_str = self._decrypt_protected_text("burned_messages", "reserved_at", fingerprint, enc_reserved_at)
                    reserved_at = int(reserved_at_str)
                else:
                    reserved_at = int(enc_reserved_at) if enc_reserved_at is not None else 0

                if status == BURN_STATUS_OPENING and reserved_at < stale_before:
                    to_delete.append(fingerprint)
            except Exception:
                continue

        for fingerprint in to_delete:
            conn.execute("DELETE FROM burned_messages WHERE fingerprint=?", (fingerprint,))

    def register_pending_deletion(self, file_path: str | Path) -> None:
        """Saves a file path for secure deletion retry."""
        path_str = str(Path(file_path).resolve())
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO pending_deletions (file_path) VALUES (?)",
                (path_str,)
            )
            conn.commit()
        except Exception as exc:
            logger.error("Failed to register pending deletion path: %s", exc)
        finally:
            conn.close()

    def remove_pending_deletion(self, file_path: str | Path) -> None:
        """Removes a file path from the pending deletions list."""
        path_str = str(Path(file_path).resolve())
        conn = self._connect()
        try:
            conn.execute(
                "DELETE FROM pending_deletions WHERE file_path = ?",
                (path_str,)
            )
            conn.commit()
        except Exception as exc:
            logger.error("Failed to remove pending deletion path: %s", exc)
        finally:
            conn.close()

    def retry_pending_deletions(self) -> None:
        """Attempts to securely delete all registered pending deletions."""
        conn = self._connect()
        try:
            rows = conn.execute("SELECT file_path FROM pending_deletions").fetchall()
        except Exception as exc:
            logger.error("Failed to query pending deletions: %s", exc)
            return
        finally:
            conn.close()

        for (path_str,) in rows:
            path = Path(path_str)
            if not path.exists():
                self.remove_pending_deletion(path_str)
                continue
            if secure_delete(path):
                logger.info("Successfully cleaned up pending sensitive file: %s", path_str)
                self.remove_pending_deletion(path_str)
            else:
                logger.warning("Retry secure deletion failed for pending sensitive file: %s", path_str)

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
            if not row:
                return None
            val = row[0]
            if isinstance(val, bytes) and val.startswith(PROTECTED_VALUE_PREFIX):
                return self._decrypt_protected_text("burned_messages", "status", fingerprint, val)
            return val
        finally:
            conn.close()

    def burn(self, msg_id: bytes, session_id: bytes, direction: int):
        """Registers the MSG_ID as burned in one terminal transaction."""
        fingerprint = message_id_fingerprint(msg_id)
        now = int(time.time())

        # Encrypt metadata fields using fingerprint as row_identifier
        enc_status = self._encrypt_protected_value("burned_messages", "status", fingerprint, BURN_STATUS_BURNED)
        enc_reserved_at = self._encrypt_protected_value("burned_messages", "reserved_at", fingerprint, str(now))
        enc_burned_at = self._encrypt_protected_value("burned_messages", "burned_at", fingerprint, str(now))
        enc_session_id = self._encrypt_protected_value("burned_messages", "session_id", fingerprint, session_id)
        enc_direction = self._encrypt_protected_value("burned_messages", "direction", fingerprint, str(direction))

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
                (fingerprint, enc_status, enc_reserved_at, enc_burned_at, enc_session_id, enc_direction)
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

            enc_opening_status = self._encrypt_protected_value("burned_messages", "status", fingerprint, BURN_STATUS_OPENING)
            enc_now = self._encrypt_protected_value("burned_messages", "reserved_at", fingerprint, str(now))

            try:
                conn.execute(
                    """
                    INSERT INTO burned_messages
                        (fingerprint, status, reserved_at, burned_at, failed_at, session_id, direction, failure_reason)
                    VALUES (?, ?, ?, NULL, NULL, NULL, NULL, NULL)
                    """,
                    (fingerprint, enc_opening_status, enc_now),
                )
            except sqlite3.IntegrityError:
                row = conn.execute(
                    "SELECT status, reserved_at, failure_reason FROM burned_messages WHERE fingerprint=?",
                    (fingerprint,),
                ).fetchone()
                if row:
                    enc_status, enc_reserved_at, enc_reason = row
                    
                    if isinstance(enc_status, bytes) and enc_status.startswith(PROTECTED_VALUE_PREFIX):
                        status = self._decrypt_protected_text("burned_messages", "status", fingerprint, enc_status)
                    else:
                        status = enc_status

                    if isinstance(enc_reserved_at, bytes) and enc_reserved_at.startswith(PROTECTED_VALUE_PREFIX):
                        reserved_at = int(self._decrypt_protected_text("burned_messages", "reserved_at", fingerprint, enc_reserved_at))
                    else:
                        reserved_at = int(enc_reserved_at) if enc_reserved_at is not None else 0

                    if status == BURN_STATUS_FAILED:
                        if enc_reason is not None:
                            self._decrypt_protected_text(
                                "burned_messages",
                                "failure_reason",
                                fingerprint,
                                enc_reason,
                            )
                        updated = conn.execute(
                            """
                            UPDATE burned_messages
                            SET status=?, reserved_at=?, burned_at=NULL, failed_at=NULL,
                                session_id=NULL, direction=NULL, failure_reason=NULL
                            WHERE fingerprint=?
                            """,
                            (enc_opening_status, enc_now, fingerprint),
                        )
                        if updated.rowcount != 1:
                            conn.rollback()
                            raise AlreadyBurnedError(
                                "This message is already being opened or has been burned."
                            )
                    elif status == BURN_STATUS_OPENING and reserved_at < stale_before:
                        updated = conn.execute(
                            """
                            UPDATE burned_messages
                            SET status=?, reserved_at=?, burned_at=NULL, failed_at=NULL,
                                session_id=NULL, direction=NULL, failure_reason=NULL
                            WHERE fingerprint=?
                            """,
                            (enc_opening_status, enc_now, fingerprint),
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

        # Encrypt the fields we are setting
        enc_status_burned = self._encrypt_protected_value("burned_messages", "status", fingerprint, BURN_STATUS_BURNED)
        enc_burned_at = self._encrypt_protected_value("burned_messages", "burned_at", fingerprint, str(now))
        enc_session_id = self._encrypt_protected_value("burned_messages", "session_id", fingerprint, session_id)
        enc_direction = self._encrypt_protected_value("burned_messages", "direction", fingerprint, str(direction))

        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")

            # Fetch status to check if it's currently opening
            row = conn.execute(
                "SELECT status FROM burned_messages WHERE fingerprint=?",
                (fingerprint,)
            ).fetchone()
            if not row:
                raise AlreadyBurnedError(
                    "This message was already opened and burned. It cannot be opened again."
                )
            enc_status = row[0]
            if isinstance(enc_status, bytes) and enc_status.startswith(PROTECTED_VALUE_PREFIX):
                status = self._decrypt_protected_text("burned_messages", "status", fingerprint, enc_status)
            else:
                status = enc_status

            if status != BURN_STATUS_OPENING:
                raise AlreadyBurnedError(
                    "This message was already opened and burned. It cannot be opened again."
                )

            updated = conn.execute(
                """
                UPDATE burned_messages
                SET status=?, burned_at=?, failed_at=NULL, session_id=?, direction=?, failure_reason=NULL
                WHERE fingerprint=?
                """,
                (enc_status_burned, enc_burned_at, enc_session_id, enc_direction, fingerprint),
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

        enc_status_failed = self._encrypt_protected_value("burned_messages", "status", fingerprint, BURN_STATUS_FAILED)
        enc_failed_at = self._encrypt_protected_value("burned_messages", "failed_at", fingerprint, str(now))
        failure_reason = self._encrypt_protected_value(
            "burned_messages",
            "failure_reason",
            fingerprint,
            (reason or "")[:512],
        )
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")

            row = conn.execute(
                "SELECT status FROM burned_messages WHERE fingerprint=?",
                (fingerprint,)
            ).fetchone()
            if not row:
                raise DeviceError("Opening reservation not found.")
            enc_status = row[0]
            if isinstance(enc_status, bytes) and enc_status.startswith(PROTECTED_VALUE_PREFIX):
                status = self._decrypt_protected_text("burned_messages", "status", fingerprint, enc_status)
            else:
                status = enc_status

            if status != BURN_STATUS_OPENING:
                raise DeviceError("Cannot mark a non-opening message as failed.")

            conn.execute(
                """
                UPDATE burned_messages
                SET status=?, failed_at=?, failure_reason=?
                WHERE fingerprint=?
                """,
                (enc_status_failed, enc_failed_at, failure_reason, fingerprint),
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
        protected_label = self._encrypt_protected_value(
            "sessions",
            "label",
            session_id,
            label,
        )
        protected_state = self._encrypt_protected_value(
            "sessions",
            "state",
            session_id,
            state,
        )
        protected_created_at = self._encrypt_protected_value(
            "sessions",
            "created_at",
            session_id,
            str(created_at),
        )
        now = int(time.time())
        protected_updated_at = self._encrypt_protected_value(
            "sessions",
            "updated_at",
            session_id,
            str(now),
        )
        conn = self._connect()
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
                (session_id, protected_label, protected_state, encrypted_meta, protected_created_at, protected_updated_at)
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
            if row is None:
                return None
            
            enc_label, enc_state, encrypted_meta, enc_created_at = row

            if isinstance(enc_label, bytes) and enc_label.startswith(PROTECTED_VALUE_PREFIX):
                label = self._decrypt_protected_text("sessions", "label", session_id, enc_label)
            else:
                label = enc_label

            if isinstance(enc_state, bytes) and enc_state.startswith(PROTECTED_VALUE_PREFIX):
                state = self._decrypt_protected_text("sessions", "state", session_id, enc_state)
            else:
                state = enc_state

            if isinstance(enc_created_at, bytes) and enc_created_at.startswith(PROTECTED_VALUE_PREFIX):
                created_at_str = self._decrypt_protected_text("sessions", "created_at", session_id, enc_created_at)
                created_at = int(created_at_str)
            else:
                created_at = int(enc_created_at) if enc_created_at is not None else 0

            return (label, state, encrypted_meta, created_at)
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
                "SELECT session_id, label, state, created_at, updated_at FROM sessions"
            ).fetchall()
            sessions = []
            for row in rows:
                session_id = row[0]
                enc_label = row[1]
                enc_state = row[2]
                enc_created_at = row[3]
                enc_updated_at = row[4]

                if isinstance(enc_label, bytes) and enc_label.startswith(PROTECTED_VALUE_PREFIX):
                    label = self._decrypt_protected_text("sessions", "label", session_id, enc_label)
                else:
                    label = enc_label

                if isinstance(enc_state, bytes) and enc_state.startswith(PROTECTED_VALUE_PREFIX):
                    state = self._decrypt_protected_text("sessions", "state", session_id, enc_state)
                else:
                    state = enc_state

                if isinstance(enc_created_at, bytes) and enc_created_at.startswith(PROTECTED_VALUE_PREFIX):
                    created_at = int(self._decrypt_protected_text("sessions", "created_at", session_id, enc_created_at))
                else:
                    created_at = int(enc_created_at) if enc_created_at is not None else 0

                if isinstance(enc_updated_at, bytes) and enc_updated_at.startswith(PROTECTED_VALUE_PREFIX):
                    updated_at = int(self._decrypt_protected_text("sessions", "updated_at", session_id, enc_updated_at))
                else:
                    updated_at = int(enc_updated_at) if enc_updated_at is not None else 0

                sessions.append({
                    "session_id": session_id,
                    "label": label,
                    "state": state,
                    "created_at": created_at,
                    "updated_at": updated_at,
                })
            sessions.sort(key=lambda s: s["updated_at"], reverse=True)
            return sessions
        finally:
            conn.close()

    def update_session_state(self, session_id: bytes, state: str, encrypted_meta: bytes):
        """Updates session state."""
        protected_state = self._encrypt_protected_value(
            "sessions",
            "state",
            session_id,
            state,
        )
        now = int(time.time())
        protected_updated_at = self._encrypt_protected_value(
            "sessions",
            "updated_at",
            session_id,
            str(now),
        )
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE sessions SET state=?, encrypted_meta=?, updated_at=? WHERE session_id=?",
                (protected_state, encrypted_meta, protected_updated_at, session_id)
            )
            conn.commit()
        finally:
            conn.close()

    # --- Device Metadata ---

    def get_device_meta(self, key: str) -> bytes | None:
        """Returns the specified key from device metadata (e.g., pin_salt)."""
        if key not in BOOTSTRAP_DEVICE_META_KEYS:
            self._require_device_key()
        conn = self._connect()
        try:
            row = conn.execute(f"SELECT value FROM {self._meta_prefix}device_meta WHERE key=?", (key,)
            ).fetchone()
            if row is None:
                return None
            if key in BOOTSTRAP_DEVICE_META_KEYS:
                return row[0]
            return self._decrypt_protected_value("device_meta", "value", key, row[0])
        finally:
            conn.close()

    def set_device_meta(self, key: str, value: bytes | bytearray | str):
        """Registers or updates a new key-value pair in device metadata."""
        encoded = self._logical_bytes(value)
        if key not in BOOTSTRAP_DEVICE_META_KEYS:
            encoded = self._encrypt_protected_value("device_meta", "value", key, encoded)
        conn = self._connect()
        try:
            conn.execute(f"INSERT OR REPLACE INTO {self._meta_prefix}device_meta (key, value) VALUES (?, ?)",
                (key, encoded)
            )
            conn.commit()
        finally:
            conn.close()

    def set_device_meta_batch(self, values: dict[str, bytes | bytearray | str]) -> None:
        """Stores metadata atomically while applying protected-value policy."""
        encoded_values = []
        for key, value in values.items():
            encoded = self._logical_bytes(value)
            if key not in BOOTSTRAP_DEVICE_META_KEYS:
                encoded = self._encrypt_protected_value("device_meta", "value", key, encoded)
            encoded_values.append((key, encoded))
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.executemany(
                "INSERT OR REPLACE INTO {self._meta_prefix}device_meta (key, value) VALUES (?, ?)",
                encoded_values,
            )
            conn.commit()
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def delete_device_meta(self, key: str):
        """Deletes the specified key from device metadata if it exists."""
        if key not in BOOTSTRAP_DEVICE_META_KEYS:
            self._require_device_key()
        conn = self._connect()
        try:
            conn.execute(f"DELETE FROM {self._meta_prefix}device_meta WHERE key=?", (key,))
            conn.commit()
        finally:
            conn.close()

    def _get_or_create_rate_limit_key(self) -> bytes:
        """Retrieve or generate a persistent 32-byte key for rate-limit signatures."""
        key_path = Path(self.db_path).parent / ".rate_limit.key"
        if key_path.exists():
            try:
                key = key_path.read_bytes()
                if len(key) == 32:
                    return key
            except Exception as exc:
                logger.error("Failed to read rate limit signing key: %s", exc)

        # Generate a new 32-byte key
        from .crypto import random_bytes
        new_key = random_bytes(32)
        try:
            # Create file with owner-only read/write permissions (0o600)
            fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(new_key)
            return new_key
        except Exception as exc:
            logger.error("Failed to save rate limit signing key: %s", exc)
            return new_key

    def _encode_unlock_rate_limit(self, state: dict) -> bytes:
        stored = {
            "failed_attempts": state["failed_attempts"],
            "locked_until": state["locked_until"],
            "last_failed_at": state["last_failed_at"],
        }
        raw_json = json.dumps(stored, sort_keys=True, separators=(",", ":")).encode("utf-8")

        # Try to protect with Windows DPAPI if on Windows
        import sys
        if sys.platform == "win32":
            try:
                from desktop.dpapi_win import wrap_with_dpapi
                return b"dpapi:" + wrap_with_dpapi(raw_json)
            except Exception as exc:
                logger.error("DPAPI rate-limit wrapping failed: %s", exc)

        # Fallback to HMAC-SHA256 signature for Unix/other platforms
        import hmac
        import hashlib
        key = self._get_or_create_rate_limit_key()
        sig = hmac.new(key, raw_json, hashlib.sha256).digest()
        return b"hmac:" + sig + raw_json

    def _write_unlock_rate_limit(self, conn: sqlite3.Connection, state: dict) -> None:
        conn.execute(f"INSERT OR REPLACE INTO {self._meta_prefix}device_meta (key, value) VALUES (?, ?)",
            (UNLOCK_RATE_LIMIT_KEY, self._encode_unlock_rate_limit(state)),
        )

    def _load_unlock_rate_limit(
        self,
        conn: sqlite3.Connection,
        now: int,
    ) -> tuple[dict, bool]:
        row = conn.execute(f"SELECT value FROM {self._meta_prefix}device_meta WHERE key=?",
            (UNLOCK_RATE_LIMIT_KEY,),
        ).fetchone()
        raw = row[0] if row is not None else None
        unlock_ever_succeeded = False
        has_sessions = False
        if row is None:
            unlock_ever_succeeded = conn.execute(f"SELECT 1 FROM {self._meta_prefix}device_meta WHERE key=? LIMIT 1",
                (UNLOCK_EVER_SUCCEEDED_KEY,),
            ).fetchone() is not None
            has_sessions = (
                conn.execute("SELECT 1 FROM sessions LIMIT 1").fetchone() is not None
            )
        state = self._decode_unlock_rate_limit(
            raw,
            now,
            unlock_ever_succeeded=unlock_ever_succeeded,
            has_sessions=has_sessions,
        )
        return state, row is None and (unlock_ever_succeeded or has_sessions)

    def _decode_unlock_rate_limit(
        self,
        raw: bytes | None,
        now: int | None = None,
        *,
        unlock_ever_succeeded: bool = False,
        has_sessions: bool = False,
    ) -> dict:
        now = int(time.time()) if now is None else int(now)
        state = {"failed_attempts": 0, "locked_until": 0, "last_failed_at": 0}
        if raw is None and (unlock_ever_succeeded or has_sessions):
            failed_attempts = UNLOCK_MAX_FAILED_ATTEMPTS - 1
            delay = UNLOCK_FAILURE_DELAYS[failed_attempts]
            state = {
                "failed_attempts": failed_attempts,
                "locked_until": now + delay,
                "last_failed_at": now,
            }
        elif raw:
            try:
                if raw.startswith(b"dpapi:"):
                    from desktop.dpapi_win import unwrap_with_dpapi
                    decrypted = unwrap_with_dpapi(raw[6:])
                    parsed = json.loads(decrypted.decode("utf-8"))
                elif raw.startswith(b"hmac:"):
                    import hmac
                    import hashlib
                    if len(raw) < 5 + 32:
                        raise ValueError("Rate limit record is truncated.")
                    stored_sig = raw[5:5+32]
                    payload = raw[5+32:]
                    key = self._get_or_create_rate_limit_key()
                    computed_sig = hmac.new(key, payload, hashlib.sha256).digest()
                    if not hmac.compare_digest(stored_sig, computed_sig):
                        raise ValueError("Tampering detected (HMAC mismatch).")
                    parsed = json.loads(payload.decode("utf-8"))
                else:
                    raise ValueError("Tampering detected (missing signature prefix).")

                state["failed_attempts"] = max(0, int(parsed.get("failed_attempts", 0)))
                state["locked_until"] = max(0, int(parsed.get("locked_until", 0)))
                state["last_failed_at"] = max(0, int(parsed.get("last_failed_at", 0)))
            except Exception as exc:
                logger.error("Rate limit verification/decryption failed: %s", exc)
                # Tamper protection fallback: force complete device lockout
                state = {
                    "failed_attempts": UNLOCK_MAX_FAILED_ATTEMPTS,
                    "locked_until": now + UNLOCK_LOCKOUT_SECONDS,
                    "last_failed_at": now,
                }
        state["retry_after_seconds"] = max(0, state["locked_until"] - now)
        return state

    def get_unlock_rate_limit(self, now: int | None = None) -> dict:
        """Returns durable unlock failure and lockout state."""
        now = int(time.time()) if now is None else int(now)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            state, recovered_missing_record = self._load_unlock_rate_limit(conn, now)
            if recovered_missing_record:
                self._write_unlock_rate_limit(conn, state)
            conn.commit()
            return state
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def assert_unlock_allowed(self, now: int | None = None) -> None:
        """Raises when the durable unlock lockout window is still active."""
        state = self.get_unlock_rate_limit(now)
        if state["retry_after_seconds"] > 0:
            raise DeviceLockedError(state["retry_after_seconds"])

    def reserve_unlock_attempt(self, now: int | None = None) -> dict:
        """Claims one unlock attempt before expensive verification begins."""
        now = int(time.time()) if now is None else int(now)
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            state, _recovered_missing_record = self._load_unlock_rate_limit(conn, now)
            if state["retry_after_seconds"] > 0:
                self._write_unlock_rate_limit(conn, state)
                conn.commit()
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
            self._write_unlock_rate_limit(conn, updated)
            conn.commit()
            updated["retry_after_seconds"] = delay
            return updated
        except Exception:
            if conn.in_transaction:
                conn.rollback()
            raise
        finally:
            conn.close()

    def record_unlock_failure(self, now: int | None = None) -> dict:
        """Compatibility helper for recording an already-known failed attempt."""
        return self.reserve_unlock_attempt(now)

    def reset_unlock_failures(self) -> None:
        """Clears failures and records that this device has unlocked successfully."""
        conn = self._connect()
        try:
            conn.execute("BEGIN IMMEDIATE")
            self._write_unlock_rate_limit(
                conn,
                {"failed_attempts": 0, "locked_until": 0, "last_failed_at": 0},
            )
            conn.execute(f"INSERT OR IGNORE INTO {self._meta_prefix}device_meta (key, value) VALUES (?, ?)",
                (UNLOCK_EVER_SUCCEEDED_KEY, UNLOCK_EVER_SUCCEEDED_VALUE),
            )
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

def secure_delete(file_path: str | Path, passes: int = 3) -> bool:
    """
    Requests the platform shield's best-effort deletion hygiene for a file.
    """
    try:
        deleted = shield.secure_delete(str(file_path))
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        logger.exception("Unexpected secure deletion failure for a sensitive source file.")
        return False
    if not deleted:
        logger.error("Secure deletion failed for a sensitive source file.")
        return False
    return True


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
    ) -> bool:
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
            succeeded = secure_delete(file_path)
            if not succeeded:
                logger.critical(
                    "SECURITY EVENT: Secure deletion failed for sensitive file at: %s. Registering for retry cleanup.",
                    file_path
                )
                self.db.register_pending_deletion(file_path)
            return succeeded
        return True

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
            succeeded = secure_delete(file_path)
            if not succeeded:
                logger.critical(
                    "SECURITY EVENT: Secure deletion failed during force burn for file at: %s. Registering for retry cleanup.",
                    file_path
                )
                self.db.register_pending_deletion(file_path)
                raise SecureDeleteError(
                    "The message was burned, but its source file could not be securely deleted."
                )


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

def validate_passphrase_strength(passphrase: str):
    """
    Validates passphrase strength.

    Criteria:
    - 12 to 128 characters
    - Numeric-only passphrases require at least 20 digits
    - Must have enough character diversity and estimated entropy
    - Must not be obvious sequences, common weak phrases, or repeated tokens
    """
    passphrase = passphrase or ""
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


def init_device(db: BurnDB, passphrase: str) -> bytearray:
    """
    Sets up the device for the first time:
    1. Produces a new passphrase_salt.
    2. Derives master_key from the passphrase.
    3. Produces a random device_key.
    4. Encrypts and saves the device_key with the master_key.
    """
    validate_passphrase_strength(passphrase)
    
    if is_device_initialized(db):
        raise DeviceError("Device already set up.")
    
    passphrase_salt = random_bytes(16)
    master_key = derive_master_key(passphrase, passphrase_salt)
    
    try:
        device_key = bytearray(random_bytes(32))
        
        # Encrypt device_key with master_key.
        # OS keychain/TPM wrapping remains a separate device_key_protection_v1
        # layer; this patch only strengthens passphrases and online unlock rate limits.
        blob = encrypt(master_key, device_key, aad=b"paracci.device_key.v1")
        
        # Save
        # "pin_salt" is retained in device metadata keys to avoid breaking database compatibility
        db.set_device_meta("pin_salt", passphrase_salt)
        db.set_device_meta("encrypted_device_key", blob.nonce + blob.ciphertext)
        
        return device_key
    finally:
        # Wipe master_key from memory
        if 'master_key' in locals():
            wipe(master_key)


def unlock_device(db: BurnDB, passphrase: str) -> bytearray:
    """
    Unlocks the device key with the passphrase.
    """
    # "pin_salt" is retained in device metadata keys to avoid breaking database compatibility
    passphrase_salt = db.get_device_meta("pin_salt")
    enc_data = db.get_device_meta("encrypted_device_key")
    
    if not passphrase_salt or not enc_data:
        raise DeviceError("Device not set up yet.")

    with _serialized_unlock_attempt():
        state = db.reserve_unlock_attempt()
        master_key = derive_master_key(passphrase, passphrase_salt)

        try:
            # enc_data: nonce(12) + ciphertext
            nonce = enc_data[:12]
            ciphertext = enc_data[12:]
            blob = EncryptedBlob(nonce=nonce, ciphertext=ciphertext)

            device_key = bytearray(decrypt(master_key, blob, aad=b"paracci.device_key.v1"))
        except Exception:
            if state["retry_after_seconds"] > 0 and state["failed_attempts"] >= UNLOCK_MAX_FAILED_ATTEMPTS:
                raise DeviceLockedError(state["retry_after_seconds"])
            raise DeviceError("Incorrect passphrase.")
        else:
            db.reset_unlock_failures()
            return device_key
        finally:
            # Wipe master_key from memory
            wipe(master_key)


# ---------------------------------------------------------------------------
# Error Classes
# ---------------------------------------------------------------------------

class AlreadyBurnedError(Exception):
    """Message has been opened and burned before."""


class TTLExpiredError(Exception):
    """Message TTL has expired."""


class SecureDeleteError(Exception):
    """A burned message source file could not be securely deleted."""


class DeviceError(Exception):
    """Error related to device key or passphrase."""


class DeviceLockedError(DeviceError):
    """Unlock is temporarily locked because of repeated failed attempts."""

    def __init__(self, retry_after_seconds: int):
        self.retry_after_seconds = max(1, int(retry_after_seconds))
        super().__init__(
            f"Too many failed attempts. Try again in {self.retry_after_seconds} seconds."
        )
