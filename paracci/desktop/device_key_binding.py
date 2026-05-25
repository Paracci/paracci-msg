"""Desktop-layer device key binding.

Core burn storage remains passphrase-only for compatibility. This adapter adds
platform current-user binding at the desktop and Flask entrypoints.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import logging
import sqlite3
import sys
import threading

from cryptography.exceptions import InvalidTag

from core.burn import (
    UNLOCK_MAX_FAILED_ATTEMPTS,
    BurnDB,
    DeviceError,
    DeviceLockedError,
    _serialized_unlock_attempt,
    init_device as legacy_init_device,
    is_device_initialized,
    unlock_device as legacy_unlock_device,
    validate_pin_strength,
)
from core.crypto import EncryptedBlob, decrypt, derive_master_key, encrypt, random_bytes, wipe

from .dpapi_win import DPAPIError, unwrap_with_dpapi, wrap_with_dpapi
from .keychain_mac import KeychainError, delete_from_keychain, unwrap_with_keychain, wrap_with_keychain
from .secret_service_linux import (
    SecretServiceError,
    delete_from_secret_service,
    unwrap_with_secret_service,
    wrap_with_secret_service,
)


logger = logging.getLogger(__name__)
_warning_state = threading.local()

DPAPI_BLOB_META_KEY = "dpapi_blob"
DPAPI_BLOB_PREFIX = b"paracci.dpapi.device_key.v1:"
BOUND_DEVICE_KEY_AAD = b"paracci.device_key.dpapi.v1"
BOUND_STORAGE_KEY_LABEL = b"paracci.device_key.binding.storage.v1"

PLATFORM_BINDING_PROFILE_ID_META_KEY = "platform_binding_profile_id_v1"
PLATFORM_BINDING_KIND_META_KEY = "platform_binding_kind_v1"
PLATFORM_BOUND_DEVICE_KEY_AAD = b"paracci.device_key.platform_binding.v1"
MACOS_KEYCHAIN_KIND = b"macos_keychain"
LINUX_SECRET_SERVICE_KIND = b"linux_secret_service"

DEVICE_KEY_NONCE_LEN = 12
KEY_LEN = 32

DPAPI_DIFFERENT_ACCOUNT_CODE = "dpapi_different_account"
DPAPI_KEYFILE_DAMAGED_CODE = "dpapi_keyfile_damaged"
DPAPI_DIFFERENT_ACCOUNT_I18N = "auth.dpapi_different_account"
DPAPI_KEYFILE_DAMAGED_I18N = "auth.dpapi_keyfile_damaged"
DPAPI_DIFFERENT_ACCOUNT_MESSAGE = (
    "This profile was created on a different Windows account and cannot be opened here."
)
DPAPI_KEYFILE_DAMAGED_MESSAGE = (
    "Device binding verification failed. The local key file may be damaged."
)

KEYCHAIN_MISSING_CODE = "keychain_missing"
KEYCHAIN_FAILED_CODE = "keychain_failed"
KEYCHAIN_MISSING_I18N = "auth.keychain_missing"
KEYCHAIN_FAILED_I18N = "auth.keychain_failed"
KEYCHAIN_MISSING_MESSAGE = (
    "This profile's device binding could not be found in the macOS Keychain. "
    "The profile may have been created on a different Mac."
)
KEYCHAIN_FAILED_MESSAGE = (
    "Keychain access failed. Ensure Paracci is allowed in System Settings "
    "\u2192 Privacy & Security."
)

SECRET_SERVICE_UNAVAILABLE_CODE = "secret_service_unavailable"
SECRET_SERVICE_MISSING_CODE = "secret_service_missing"
SECRET_SERVICE_FAILED_CODE = "secret_service_failed"
SECRET_SERVICE_UNAVAILABLE_I18N = "auth.secret_service_unavailable"
SECRET_SERVICE_MISSING_I18N = "auth.secret_service_missing"
SECRET_SERVICE_FAILED_I18N = "auth.secret_service_failed"
SECRET_SERVICE_UNAVAILABLE_MESSAGE = (
    "No keyring daemon is running. Install and unlock GNOME Keyring or KWallet "
    "to enable device binding. Falling back to passphrase-only mode."
)
SECRET_SERVICE_MISSING_MESSAGE = (
    "This profile's device binding could not be found in the system keyring."
)
SECRET_SERVICE_FAILED_MESSAGE = "System keyring access failed. Unlock the keyring and try again."


@dataclass(frozen=True)
class DeviceBindingWarning:
    """Nonfatal device-binding warning for UI surfacing."""

    code: str
    i18n_key: str
    message: str


class DeviceBindingError(DeviceError):
    """User-visible failure from the device binding layer."""

    def __init__(self, code: str, i18n_key: str, message: str):
        self.code = code
        self.i18n_key = i18n_key
        super().__init__(message)


def consume_device_binding_warning() -> DeviceBindingWarning | None:
    """Return and clear the latest nonfatal binding warning for this thread."""
    warning = getattr(_warning_state, "warning", None)
    _warning_state.warning = None
    return warning


def initialize_device_with_binding(db: BurnDB, pin: str) -> bytearray:
    """Initialize the profile, adding platform binding when available."""
    _clear_device_binding_warning()
    if sys.platform == "win32":
        return _initialize_windows_device_with_binding(db, pin)
    if sys.platform == "darwin":
        return _initialize_platform_bound_device(
            db,
            pin,
            MACOS_KEYCHAIN_KIND,
            _store_keychain_factor,
            _keychain_failed_error,
        )
    if sys.platform.startswith("linux"):
        return _initialize_linux_bound_or_fallback(db, pin)
    return legacy_init_device(db, pin)


def unlock_device_with_binding(db: BurnDB, pin: str) -> bytearray:
    """Unlock the profile, requiring platform binding when available."""
    _clear_device_binding_warning()
    if sys.platform == "win32":
        dpapi_blob = db.get_device_meta(DPAPI_BLOB_META_KEY)
        if not dpapi_blob:
            return _unlock_legacy_and_bind(db, pin)
        return _unlock_bound_device(db, pin, dpapi_blob)
    if sys.platform == "darwin":
        return _unlock_macos_bound_device(db, pin)
    if sys.platform.startswith("linux"):
        return _unlock_linux_bound_or_fallback(db, pin)
    return legacy_unlock_device(db, pin)


def delete_device_binding_for_profile(db: BurnDB) -> None:
    """Delete platform keychain/keyring binding state for the current profile."""
    profile_id = _read_profile_id(db)
    kind = _read_binding_kind(db)
    if not profile_id or not kind:
        return

    if kind == MACOS_KEYCHAIN_KIND:
        try:
            delete_from_keychain(profile_id)
        except KeychainError as exc:
            raise _keychain_failed_error() from exc
    elif kind == LINUX_SECRET_SERVICE_KIND:
        try:
            delete_from_secret_service(profile_id)
        except SecretServiceError as exc:
            raise _secret_service_failed_error() from exc
    else:
        return

    db.delete_device_meta(PLATFORM_BINDING_PROFILE_ID_META_KEY)
    db.delete_device_meta(PLATFORM_BINDING_KIND_META_KEY)


def _initialize_windows_device_with_binding(db: BurnDB, pin: str) -> bytearray:
    validate_pin_strength(pin)
    if is_device_initialized(db):
        raise DeviceError("Device already set up.")

    pin_salt = random_bytes(16)
    master_key = derive_master_key(pin, pin_salt)
    dpapi_factor = None
    storage_key = None

    try:
        dpapi_factor = bytearray(random_bytes(KEY_LEN))
        stored_dpapi_blob = _protect_dpapi_factor(dpapi_factor)
        storage_key = _derive_bound_storage_key(master_key, dpapi_factor)
        device_key = bytearray(random_bytes(KEY_LEN))
        encrypted = encrypt(storage_key, device_key, aad=BOUND_DEVICE_KEY_AAD)
        _set_device_meta_batch(
            db,
            {
                "pin_salt": pin_salt,
                "encrypted_device_key": encrypted.nonce + encrypted.ciphertext,
                DPAPI_BLOB_META_KEY: stored_dpapi_blob,
            },
        )
        return device_key
    finally:
        wipe(master_key)
        if dpapi_factor is not None:
            wipe(dpapi_factor)
        if storage_key is not None:
            wipe(storage_key)


def _unlock_bound_device(db: BurnDB, pin: str, stored_dpapi_blob: bytes) -> bytearray:
    pin_salt = db.get_device_meta("pin_salt")
    encrypted_device_key = db.get_device_meta("encrypted_device_key")
    if not pin_salt or not encrypted_device_key:
        raise DeviceError("Device not set up yet.")

    with _serialized_unlock_attempt():
        master_key = None
        dpapi_factor = None
        storage_key = None

        try:
            raw_dpapi_blob = _decode_dpapi_blob(stored_dpapi_blob)
            try:
                dpapi_factor = _as_mutable_secret(unwrap_with_dpapi(raw_dpapi_blob))
            except DPAPIError as exc:
                raise _different_account_error() from exc

            if len(dpapi_factor) != KEY_LEN:
                raise _keyfile_damaged_error()

            state = db.reserve_unlock_attempt()
            master_key = derive_master_key(pin, pin_salt)
            storage_key = _derive_bound_storage_key(master_key, dpapi_factor)
            try:
                device_key = _decrypt_stored_device_key(
                    storage_key,
                    encrypted_device_key,
                    BOUND_DEVICE_KEY_AAD,
                    _keyfile_damaged_error,
                )
            except DeviceBindingError:
                raise
            except InvalidTag:
                _raise_incorrect_passphrase(state)
        except DeviceError:
            raise
        except sqlite3.Error:
            raise
        except (DPAPIError, KeychainError, SecretServiceError, ValueError, TypeError) as exc:
            raise _keyfile_damaged_error() from exc
        else:
            db.reset_unlock_failures()
            return device_key
        finally:
            if master_key is not None:
                wipe(master_key)
            if dpapi_factor is not None:
                wipe(dpapi_factor)
            if storage_key is not None:
                wipe(storage_key)


def _unlock_legacy_and_bind(db: BurnDB, pin: str) -> bytearray:
    device_key = legacy_unlock_device(db, pin)
    pin_salt = db.get_device_meta("pin_salt")
    if not pin_salt:
        raise DeviceError("Device not set up yet.")

    master_key = derive_master_key(pin, pin_salt)
    dpapi_factor = None
    storage_key = None
    try:
        dpapi_factor = bytearray(random_bytes(KEY_LEN))
        storage_key = _derive_bound_storage_key(master_key, dpapi_factor)
        encrypted = encrypt(storage_key, device_key, aad=BOUND_DEVICE_KEY_AAD)
        _set_device_meta_batch(
            db,
            {
                "encrypted_device_key": encrypted.nonce + encrypted.ciphertext,
                DPAPI_BLOB_META_KEY: _protect_dpapi_factor(dpapi_factor),
            },
        )
    finally:
        wipe(master_key)
        if dpapi_factor is not None:
            wipe(dpapi_factor)
        if storage_key is not None:
            wipe(storage_key)
    return device_key


def _initialize_linux_bound_or_fallback(db: BurnDB, pin: str) -> bytearray:
    try:
        return _initialize_platform_bound_device(
            db,
            pin,
            LINUX_SECRET_SERVICE_KIND,
            _store_secret_service_factor,
            _secret_service_failed_error,
        )
    except DeviceBindingError as exc:
        if exc.code != SECRET_SERVICE_UNAVAILABLE_CODE:
            raise
        logger.warning("Linux Secret Service unavailable during initialization; using passphrase-only mode.")
        _set_device_binding_warning(_secret_service_unavailable_warning())
        return legacy_init_device(db, pin)


def _unlock_macos_bound_device(db: BurnDB, pin: str) -> bytearray:
    profile_id = _read_profile_id(db)
    kind = _read_binding_kind(db)
    if not profile_id and not kind:
        device_key = legacy_unlock_device(db, pin)
        return _bind_legacy_device_with_platform_factor(
            db,
            pin,
            device_key,
            MACOS_KEYCHAIN_KIND,
            _store_keychain_factor,
            _keychain_failed_error,
        )
    if kind != MACOS_KEYCHAIN_KIND or not profile_id:
        raise _keychain_missing_error()
    return _unlock_platform_bound_device(
        db,
        pin,
        MACOS_KEYCHAIN_KIND,
        _load_keychain_factor,
        _keychain_failed_error,
    )


def _unlock_linux_bound_or_fallback(db: BurnDB, pin: str) -> bytearray:
    profile_id = _read_profile_id(db)
    kind = _read_binding_kind(db)
    if not profile_id and not kind:
        device_key = legacy_unlock_device(db, pin)
        try:
            return _bind_legacy_device_with_platform_factor(
                db,
                pin,
                device_key,
                LINUX_SECRET_SERVICE_KIND,
                _store_secret_service_factor,
                _secret_service_failed_error,
            )
        except DeviceBindingError as exc:
            if exc.code != SECRET_SERVICE_UNAVAILABLE_CODE:
                raise
            logger.warning("Linux Secret Service unavailable during unlock migration; using passphrase-only mode.")
            _set_device_binding_warning(_secret_service_unavailable_warning())
            return device_key
    if kind != LINUX_SECRET_SERVICE_KIND or not profile_id:
        raise _secret_service_missing_error()
    return _unlock_platform_bound_device(
        db,
        pin,
        LINUX_SECRET_SERVICE_KIND,
        _load_secret_service_factor,
        _secret_service_failed_error,
    )


def _initialize_platform_bound_device(
    db: BurnDB,
    pin: str,
    kind: bytes,
    store_factor,
    damaged_error_factory,
) -> bytearray:
    validate_pin_strength(pin)
    if is_device_initialized(db):
        raise DeviceError("Device already set up.")

    pin_salt = random_bytes(16)
    master_key = derive_master_key(pin, pin_salt)
    binding_factor = None
    storage_key = None
    profile_id = _new_profile_id()
    stored = False

    try:
        binding_factor = bytearray(random_bytes(KEY_LEN))
        store_factor(profile_id, binding_factor)
        stored = True
        storage_key = _derive_bound_storage_key(master_key, binding_factor)
        device_key = bytearray(random_bytes(KEY_LEN))
        encrypted = encrypt(storage_key, device_key, aad=PLATFORM_BOUND_DEVICE_KEY_AAD)
        try:
            _set_device_meta_batch(
                db,
                {
                    "pin_salt": pin_salt,
                    "encrypted_device_key": encrypted.nonce + encrypted.ciphertext,
                    PLATFORM_BINDING_PROFILE_ID_META_KEY: profile_id.encode("ascii"),
                    PLATFORM_BINDING_KIND_META_KEY: kind,
                },
            )
        except Exception:
            if stored:
                _best_effort_delete_platform_factor(kind, profile_id)
            raise
        return device_key
    except DeviceBindingError:
        raise
    except Exception as exc:
        raise damaged_error_factory() from exc
    finally:
        wipe(master_key)
        if binding_factor is not None:
            wipe(binding_factor)
        if storage_key is not None:
            wipe(storage_key)


def _unlock_platform_bound_device(
    db: BurnDB,
    pin: str,
    kind: bytes,
    load_factor,
    damaged_error_factory,
) -> bytearray:
    pin_salt = db.get_device_meta("pin_salt")
    encrypted_device_key = db.get_device_meta("encrypted_device_key")
    profile_id = _read_profile_id(db)
    stored_kind = _read_binding_kind(db)
    if not pin_salt or not encrypted_device_key:
        raise DeviceError("Device not set up yet.")
    if not profile_id or stored_kind != kind:
        raise damaged_error_factory()

    with _serialized_unlock_attempt():
        master_key = None
        binding_factor = None
        storage_key = None

        try:
            binding_factor = _as_mutable_secret(load_factor(profile_id))
            if len(binding_factor) != KEY_LEN:
                raise damaged_error_factory()

            state = db.reserve_unlock_attempt()
            master_key = derive_master_key(pin, pin_salt)
            storage_key = _derive_bound_storage_key(master_key, binding_factor)
            try:
                device_key = _decrypt_stored_device_key(
                    storage_key,
                    encrypted_device_key,
                    PLATFORM_BOUND_DEVICE_KEY_AAD,
                    damaged_error_factory,
                )
            except DeviceBindingError:
                raise
            except Exception:
                _raise_incorrect_passphrase(state)
        except DeviceError:
            raise
        except sqlite3.Error:
            raise
        except Exception as exc:
            raise damaged_error_factory() from exc
        else:
            db.reset_unlock_failures()
            return device_key
        finally:
            if master_key is not None:
                wipe(master_key)
            if binding_factor is not None:
                wipe(binding_factor)
            if storage_key is not None:
                wipe(storage_key)


def _bind_legacy_device_with_platform_factor(
    db: BurnDB,
    pin: str,
    device_key: bytes | bytearray,
    kind: bytes,
    store_factor,
    damaged_error_factory,
) -> bytes | bytearray:
    pin_salt = db.get_device_meta("pin_salt")
    if not pin_salt:
        raise DeviceError("Device not set up yet.")

    master_key = derive_master_key(pin, pin_salt)
    binding_factor = None
    storage_key = None
    profile_id = _new_profile_id()
    stored = False
    try:
        binding_factor = bytearray(random_bytes(KEY_LEN))
        store_factor(profile_id, binding_factor)
        stored = True
        storage_key = _derive_bound_storage_key(master_key, binding_factor)
        encrypted = encrypt(storage_key, device_key, aad=PLATFORM_BOUND_DEVICE_KEY_AAD)
        try:
            _set_device_meta_batch(
                db,
                {
                    "encrypted_device_key": encrypted.nonce + encrypted.ciphertext,
                    PLATFORM_BINDING_PROFILE_ID_META_KEY: profile_id.encode("ascii"),
                    PLATFORM_BINDING_KIND_META_KEY: kind,
                },
            )
        except Exception:
            if stored:
                _best_effort_delete_platform_factor(kind, profile_id)
            raise
        return device_key
    except DeviceBindingError:
        raise
    except Exception as exc:
        raise damaged_error_factory() from exc
    finally:
        wipe(master_key)
        if binding_factor is not None:
            wipe(binding_factor)
        if storage_key is not None:
            wipe(storage_key)


def _protect_dpapi_factor(dpapi_factor: bytes | bytearray) -> bytes:
    try:
        return _encode_dpapi_blob(wrap_with_dpapi(dpapi_factor))
    except DPAPIError as exc:
        raise _keyfile_damaged_error() from exc


def _store_keychain_factor(profile_id: str, binding_factor: bytes | bytearray) -> None:
    try:
        wrap_with_keychain(profile_id, binding_factor)
    except KeychainError as exc:
        raise _keychain_failed_error() from exc


def _load_keychain_factor(profile_id: str) -> bytearray:
    try:
        return _as_mutable_secret(unwrap_with_keychain(profile_id))
    except KeychainError as exc:
        if exc.code == "missing":
            raise _keychain_missing_error() from exc
        raise _keychain_failed_error() from exc


def _store_secret_service_factor(profile_id: str, binding_factor: bytes | bytearray) -> None:
    try:
        wrap_with_secret_service(profile_id, binding_factor)
    except SecretServiceError as exc:
        if exc.code == "unavailable":
            raise _secret_service_unavailable_error() from exc
        raise _secret_service_failed_error() from exc


def _load_secret_service_factor(profile_id: str) -> bytearray:
    try:
        return _as_mutable_secret(unwrap_with_secret_service(profile_id))
    except SecretServiceError as exc:
        if exc.code == "missing":
            raise _secret_service_missing_error() from exc
        raise _secret_service_failed_error() from exc


def _best_effort_delete_platform_factor(kind: bytes, profile_id: str) -> None:
    try:
        if kind == MACOS_KEYCHAIN_KIND:
            delete_from_keychain(profile_id)
        elif kind == LINUX_SECRET_SERVICE_KIND:
            delete_from_secret_service(profile_id)
    except Exception:
        logger.warning("Failed to clean up orphaned platform binding factor.", exc_info=True)


def _decrypt_stored_device_key(
    storage_key: bytes | bytearray,
    encrypted_device_key: bytes,
    aad: bytes,
    damaged_error_factory=None,
) -> bytearray:
    if damaged_error_factory is None:
        damaged_error_factory = _keyfile_damaged_error
    if len(encrypted_device_key) <= DEVICE_KEY_NONCE_LEN:
        raise damaged_error_factory()
    blob = EncryptedBlob(
        nonce=encrypted_device_key[:DEVICE_KEY_NONCE_LEN],
        ciphertext=encrypted_device_key[DEVICE_KEY_NONCE_LEN:],
    )
    return bytearray(decrypt(storage_key, blob, aad=aad))


def _derive_bound_storage_key(
    master_key: bytes | bytearray,
    binding_factor: bytes | bytearray,
) -> bytearray:
    digest = hmac.new(master_key, digestmod=hashlib.sha256)
    digest.update(BOUND_STORAGE_KEY_LABEL)
    digest.update(binding_factor)
    return bytearray(digest.digest())


def _as_mutable_secret(value: bytes | bytearray) -> bytearray:
    """Keep owned secret buffers mutable so their final wipe is effective."""
    if isinstance(value, bytearray):
        return value
    return bytearray(value)


def _raise_incorrect_passphrase(state: dict) -> None:
    if state["retry_after_seconds"] > 0 and state["failed_attempts"] >= UNLOCK_MAX_FAILED_ATTEMPTS:
        raise DeviceLockedError(state["retry_after_seconds"])
    raise DeviceError("Incorrect passphrase.")


def _new_profile_id() -> str:
    return random_bytes(16).hex()


def _read_profile_id(db: BurnDB) -> str | None:
    raw = db.get_device_meta(PLATFORM_BINDING_PROFILE_ID_META_KEY)
    if not raw:
        return None
    try:
        profile_id = raw.decode("ascii")
    except UnicodeDecodeError:
        return None
    return profile_id or None


def _read_binding_kind(db: BurnDB) -> bytes | None:
    return db.get_device_meta(PLATFORM_BINDING_KIND_META_KEY)


def _encode_dpapi_blob(raw_blob: bytes) -> bytes:
    if not raw_blob:
        raise _keyfile_damaged_error()
    return DPAPI_BLOB_PREFIX + raw_blob


def _decode_dpapi_blob(stored_blob: bytes) -> bytes:
    if not stored_blob.startswith(DPAPI_BLOB_PREFIX):
        raise _keyfile_damaged_error()
    raw_blob = stored_blob[len(DPAPI_BLOB_PREFIX):]
    if not raw_blob:
        raise _keyfile_damaged_error()
    return raw_blob


def _set_device_meta_batch(db: BurnDB, values: dict[str, bytes]) -> None:
    db.set_device_meta_batch(values)


def _set_device_binding_warning(warning: DeviceBindingWarning) -> None:
    _warning_state.warning = warning


def _clear_device_binding_warning() -> None:
    _warning_state.warning = None


def _different_account_error() -> DeviceBindingError:
    return DeviceBindingError(
        DPAPI_DIFFERENT_ACCOUNT_CODE,
        DPAPI_DIFFERENT_ACCOUNT_I18N,
        DPAPI_DIFFERENT_ACCOUNT_MESSAGE,
    )


def _keyfile_damaged_error() -> DeviceBindingError:
    return DeviceBindingError(
        DPAPI_KEYFILE_DAMAGED_CODE,
        DPAPI_KEYFILE_DAMAGED_I18N,
        DPAPI_KEYFILE_DAMAGED_MESSAGE,
    )


def _keychain_missing_error() -> DeviceBindingError:
    return DeviceBindingError(
        KEYCHAIN_MISSING_CODE,
        KEYCHAIN_MISSING_I18N,
        KEYCHAIN_MISSING_MESSAGE,
    )


def _keychain_failed_error() -> DeviceBindingError:
    return DeviceBindingError(
        KEYCHAIN_FAILED_CODE,
        KEYCHAIN_FAILED_I18N,
        KEYCHAIN_FAILED_MESSAGE,
    )


def _secret_service_unavailable_error() -> DeviceBindingError:
    return DeviceBindingError(
        SECRET_SERVICE_UNAVAILABLE_CODE,
        SECRET_SERVICE_UNAVAILABLE_I18N,
        SECRET_SERVICE_UNAVAILABLE_MESSAGE,
    )


def _secret_service_missing_error() -> DeviceBindingError:
    return DeviceBindingError(
        SECRET_SERVICE_MISSING_CODE,
        SECRET_SERVICE_MISSING_I18N,
        SECRET_SERVICE_MISSING_MESSAGE,
    )


def _secret_service_failed_error() -> DeviceBindingError:
    return DeviceBindingError(
        SECRET_SERVICE_FAILED_CODE,
        SECRET_SERVICE_FAILED_I18N,
        SECRET_SERVICE_FAILED_MESSAGE,
    )


def _secret_service_unavailable_warning() -> DeviceBindingWarning:
    return DeviceBindingWarning(
        SECRET_SERVICE_UNAVAILABLE_CODE,
        SECRET_SERVICE_UNAVAILABLE_I18N,
        SECRET_SERVICE_UNAVAILABLE_MESSAGE,
    )
