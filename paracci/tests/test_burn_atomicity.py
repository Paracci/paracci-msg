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
    db_path = tmp_path / "sessions.db"
    db_a = BurnDB(db_path)
    db_b = BurnDB(db_path)
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
    now = [1_700_000_000]
    monkeypatch.setattr(burn_module.time, "time", lambda: now[0])
    db = BurnDB(tmp_path / "sessions.db")
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
    now = [1_700_000_000]
    monkeypatch.setattr(burn_module.time, "time", lambda: now[0])
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path)
    msg_id = new_message_id()

    assert db.reserve_open(msg_id) is True
    now[0] += BURN_OPENING_STALE_SECONDS - 1

    restarted = BurnDB(db_path)
    assert restarted.get_burn_status(msg_id) == BURN_STATUS_OPENING
    with pytest.raises(AlreadyBurnedError):
        restarted.reserve_open(msg_id)


def test_startup_sweep_removes_stale_opening_reservation(tmp_path, monkeypatch):
    now = [1_700_000_000]
    monkeypatch.setattr(burn_module.time, "time", lambda: now[0])
    db_path = tmp_path / "sessions.db"
    db = BurnDB(db_path)
    msg_id = new_message_id()

    assert db.reserve_open(msg_id) is True
    now[0] += BURN_OPENING_STALE_SECONDS + 1

    restarted = BurnDB(db_path)
    assert restarted.get_burn_status(msg_id) is None
    assert restarted.reserve_open(msg_id) is True
    assert restarted.get_burn_status(msg_id) == BURN_STATUS_OPENING


def test_post_open_burn_calls_secure_delete_and_reports_success(tmp_path, monkeypatch):
    db = BurnDB(tmp_path / "sessions.db")
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
    db = BurnDB(tmp_path / "sessions.db")
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
    db = BurnDB(tmp_path / "sessions.db")
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
