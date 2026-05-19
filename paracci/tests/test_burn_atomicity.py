import sys
from pathlib import Path
from queue import Queue
from threading import Barrier, Thread

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.burn import (
    BURN_STATUS_BURNED,
    BURN_STATUS_OPENING,
    AlreadyBurnedError,
    BurnDB,
    BurnGuard,
)
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
