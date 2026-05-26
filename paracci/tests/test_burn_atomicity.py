import logging
import sys
from pathlib import Path
from queue import Queue
from threading import Barrier, Thread

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

import core.burn as burn_module
from core.burn import (
    BURN_STATUS_BURNED,
    BURN_STATUS_OPENING,
    AlreadyBurnedError,
    BurnDB,
    BurnGuard,
    SecureDeleteError,
)
from core.constants import BURN_OPENING_STALE_SECONDS
from core.crypto import new_message_id


def test_single_use_reservation_is_atomic(tmp_path):
    import os
    device_key = os.urandom(32)
    db_path = tmp_path / "sessions.db"
    db_a = BurnDB(db_path, device_key=device_key)
    db_b = BurnDB(db_path, device_key=device_key)
    guard_a = BurnGuard(db_a)
    guard_b = BurnGuard(db_b)
    msg_id = new_message_id()
    session_id = new_message_id()
    barrier = Barrier(2)
    results = Queue()

    def attempt_open(name, guard):
        try:
            barrier.wait(timeout=5)
            reserved = guard.pre_open_check(msg_id, expire_at=0, single_use=True)
            results.put((name, "reserved", reserved))
        except AlreadyBurnedError:
            results.put((name, "already_burned", None))
        except Exception as exc:
            results.put((name, "error", repr(exc)))

    threads = [
        Thread(target=attempt_open, args=("a", guard_a)),
        Thread(target=attempt_open, args=("b", guard_b)),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
        assert not thread.is_alive()

    observed = [results.get_nowait() for _ in threads]
    states = [state for _name, state, _value in observed]
    assert states.count("reserved") == 1
    assert states.count("already_burned") == 1
    assert "error" not in states
    assert db_a.get_burn_status(msg_id) == BURN_STATUS_OPENING

    guard_a.post_open_burn(msg_id, session_id, direction=1, single_use=True, file_path=None)
    assert db_b.get_burn_status(msg_id) == BURN_STATUS_BURNED


def test_stale_opening_reservation_is_reclaimed_on_retry(tmp_path, monkeypatch):
    import os
    device_key = os.urandom(32)
    now = [1_700_000_000]
    monkeypatch.setattr(burn_module.time, "time", lambda: now[0])
    db = BurnDB(tmp_path / "sessions.db", device_key=device_key)
    msg_id = new_message_id()

    assert db.reserve_open(msg_id) is True
    now[0] += BURN_OPENING_STALE_SECONDS + 1

    assert db.reserve_open(msg_id) is True
    assert db.get_burn_status(msg_id) == BURN_STATUS_OPENING
    with pytest.raises(AlreadyBurnedError):
        db.reserve_open(msg_id)


def test_fresh_opening_reservation_survives_initialization_and_is_rejected(
    tmp_path, monkeypatch
):
    import os
    device_key = os.urandom(32)
    now = [1_700_000_000]
    monkeypatch.setattr(burn_module.time, "time", lambda: now[0])
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path, device_key=device_key)
    msg_id = new_message_id()

    assert db.reserve_open(msg_id) is True
    now[0] += BURN_OPENING_STALE_SECONDS - 1

    restarted = BurnDB(db_path, device_key=device_key)
    assert restarted.get_burn_status(msg_id) == BURN_STATUS_OPENING
    with pytest.raises(AlreadyBurnedError):
        restarted.reserve_open(msg_id)


def test_startup_sweep_removes_stale_opening_reservation(tmp_path, monkeypatch):
    import os
    device_key = os.urandom(32)
    now = [1_700_000_000]
    monkeypatch.setattr(burn_module.time, "time", lambda: now[0])
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path, device_key=device_key)
    msg_id = new_message_id()

    assert db.reserve_open(msg_id) is True
    now[0] += BURN_OPENING_STALE_SECONDS + 1

    restarted = BurnDB(db_path, device_key=device_key)
    assert restarted.get_burn_status(msg_id) is None
    assert restarted.reserve_open(msg_id) is True
    assert restarted.get_burn_status(msg_id) == BURN_STATUS_OPENING


def test_post_open_burn_calls_secure_delete_and_reports_success(tmp_path, monkeypatch):
    import os
    device_key = os.urandom(32)
    db = BurnDB(tmp_path / "sessions.db", device_key=device_key)
    guard = BurnGuard(db)
    msg_id = new_message_id()
    session_id = new_message_id()
    source = tmp_path / "message.paracci"
    deleted = []
    monkeypatch.setattr(
        burn_module.shield,
        "secure_delete",
        lambda path: deleted.append(path) or True,
    )

    assert guard.pre_open_check(msg_id, expire_at=0, single_use=True) is True
    assert guard.post_open_burn(msg_id, session_id, 1, True, source) is True

    assert deleted == [str(source)]
    assert db.get_burn_status(msg_id) == BURN_STATUS_BURNED


def test_post_open_burn_logs_failed_secure_delete_without_unburning(
    tmp_path, monkeypatch, caplog
):
    import os
    device_key = os.urandom(32)
    db = BurnDB(tmp_path / "sessions.db", device_key=device_key)
    guard = BurnGuard(db)
    msg_id = new_message_id()
    session_id = new_message_id()
    monkeypatch.setattr(burn_module.shield, "secure_delete", lambda _path: False)

    assert guard.pre_open_check(msg_id, expire_at=0, single_use=True) is True
    with caplog.at_level(logging.ERROR, logger=burn_module.__name__):
        deleted = guard.post_open_burn(
            msg_id,
            session_id,
            direction=1,
            single_use=True,
            file_path=tmp_path / "message.paracci",
        )

    assert deleted is False
    assert db.get_burn_status(msg_id) == BURN_STATUS_BURNED
    assert "Secure deletion failed for a sensitive source file." in caplog.text


def test_force_burn_raises_when_secure_delete_fails(tmp_path, monkeypatch, caplog):
    import os
    device_key = os.urandom(32)
    db = BurnDB(tmp_path / "sessions.db", device_key=device_key)
    guard = BurnGuard(db)
    msg_id = new_message_id()
    session_id = new_message_id()
    monkeypatch.setattr(burn_module.shield, "secure_delete", lambda _path: False)

    with caplog.at_level(logging.ERROR, logger=burn_module.__name__):
        with pytest.raises(SecureDeleteError):
            guard.force_burn(
                msg_id,
                session_id,
                direction=1,
                file_path=tmp_path / "message.paracci",
            )

    assert db.get_burn_status(msg_id) == BURN_STATUS_BURNED
    assert "Secure deletion failed for a sensitive source file." in caplog.text


def test_secure_delete_failure_registers_retry_and_cleans_up(tmp_path, monkeypatch, caplog):
    import os
    device_key = os.urandom(32)
    db = BurnDB(tmp_path / "sessions.db", device_key=device_key)
    guard = BurnGuard(db)
    msg_id = new_message_id()
    session_id = new_message_id()

    sensitive_file = tmp_path / "sensitive.paracci"
    sensitive_file.write_bytes(b"sensitive content")
    assert sensitive_file.exists()

    should_fail = [True]
    original_secure_delete = burn_module.shield.secure_delete
    def mock_secure_delete(path):
        if should_fail[0]:
            return False
        return original_secure_delete(path)

    monkeypatch.setattr(burn_module.shield, "secure_delete", mock_secure_delete)

    assert guard.pre_open_check(msg_id, expire_at=0, single_use=True) is True

    with caplog.at_level(logging.CRITICAL, logger=burn_module.__name__):
        deleted = guard.post_open_burn(
            msg_id,
            session_id,
            direction=1,
            single_use=True,
            file_path=sensitive_file,
        )

    assert deleted is False
    conn = db._connect()
    rows = conn.execute("SELECT file_path FROM pending_deletions").fetchall()
    conn.close()
    assert len(rows) == 1
    assert rows[0][0] == str(sensitive_file.resolve())

    assert "SECURITY EVENT: Secure deletion failed" in caplog.text

    should_fail[0] = False
    db.retry_pending_deletions()

    assert not sensitive_file.exists()
    conn = db._connect()
    rows = conn.execute("SELECT file_path FROM pending_deletions").fetchall()
    conn.close()
    assert len(rows) == 0


def test_startup_and_lock_integration(tmp_path, monkeypatch):
    import os
    import app as ag_app
    from desktop.services import NativeServices

    flask_data_dir = tmp_path / "flask_data"
    flask_data_dir.mkdir()
    desktop_data_dir = tmp_path / "desktop_data"
    desktop_data_dir.mkdir()

    flask_file = flask_data_dir / "flask_failed.paracci"
    flask_file.write_bytes(b"content")
    desktop_file = desktop_data_dir / "desktop_failed.paracci"
    desktop_file.write_bytes(b"content")

    flask_db = BurnDB(flask_data_dir / "sessions.db")
    flask_db.register_pending_deletion(flask_file)

    desktop_db = BurnDB(desktop_data_dir / "sessions.db")
    desktop_db.register_pending_deletion(desktop_file)

    conn = flask_db._connect()
    assert len(conn.execute("SELECT file_path FROM pending_deletions").fetchall()) == 1
    conn.close()

    conn = desktop_db._connect()
    assert len(conn.execute("SELECT file_path FROM pending_deletions").fetchall()) == 1
    conn.close()

    monkeypatch.setattr(ag_app, "DATA_DIR", flask_data_dir)
    monkeypatch.setattr(ag_app, "db", None)

    from app import create_app
    monkeypatch.setenv("PARACCI_LOOPBACK_PORT", "12345")
    monkeypatch.setenv("PARACCI_LOOPBACK_HOST", "127.0.0.1")
    app_instance = create_app(loopback_auth_token="test_token")

    assert not flask_file.exists()
    conn = ag_app.db._connect()
    assert len(conn.execute("SELECT file_path FROM pending_deletions").fetchall()) == 0
    conn.close()

    flask_file_lock = flask_data_dir / "flask_failed_lock.paracci"
    flask_file_lock.write_bytes(b"content")
    ag_app.db.register_pending_deletion(flask_file_lock)

    from app import lock_device
    lock_device()

    assert not flask_file_lock.exists()
    conn = ag_app.db._connect()
    assert len(conn.execute("SELECT file_path FROM pending_deletions").fetchall()) == 0
    conn.close()

    services = NativeServices(desktop_data_dir)
    assert not desktop_file.exists()
    conn = services.device.db._connect()
    assert len(conn.execute("SELECT file_path FROM pending_deletions").fetchall()) == 0
    conn.close()

    desktop_file_lock = desktop_data_dir / "desktop_failed_lock.paracci"
    desktop_file_lock.write_bytes(b"content")
    services.device.db.register_pending_deletion(desktop_file_lock)

    services.device.lock()
    assert not desktop_file_lock.exists()
    conn = services.device.db._connect()
    assert len(conn.execute("SELECT file_path FROM pending_deletions").fetchall()) == 0
    conn.close()


def test_burn_db_connection_caching_and_threading(tmp_path):
    from threading import Thread
    from queue import Queue

    db = BurnDB(tmp_path / "sessions.db")

    conn1 = db._connect()
    conn2 = db._connect()

    assert conn1._conn is conn2._conn

    q = Queue()
    def check_thread():
        try:
            conn_t = db._connect()
            q.put(conn_t._conn)
        except Exception as exc:
            q.put(exc)

    t = Thread(target=check_thread)
    t.start()
    t.join()

    conn_thread = q.get()
    assert not isinstance(conn_thread, Exception)
    assert conn_thread is not conn1._conn

    db.close()
    conn3 = db._connect()
    assert conn3._conn is not conn1._conn

