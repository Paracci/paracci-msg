import io
import json
import os
import socket
import struct
import sys
import threading
from types import SimpleNamespace
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE_ROOT = REPO_ROOT / "paracci"
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(PACKAGE_ROOT))

import run
from core.burn import BurnDB
from core.crypto import random_bytes
from core.envelope import (
    DIR_X_TO_Y,
    FILE_VERSION,
    HEADER_SIZE,
    MAGIC_BYTES,
    TYPE_MESSAGE,
)
from desktop.file_activation import (
    FileActivationBroker,
    inspect_launch_file,
    install_macos_file_open_handler,
)


def seed_locked_session_db(db_path):
    keyed_db = BurnDB(db_path, device_key=random_bytes(32))
    keyed_db.save_session(SESSION_ID, "opaque", "active", b"encrypted-metadata", 1)
    keyed_db.release_device_key()
    return BurnDB(db_path)


SESSION_ID = bytes.fromhex("00112233445566778899aabbccddeeff")


def message_header(
    session_id: bytes = SESSION_ID,
    *,
    magic: bytes = MAGIC_BYTES,
    file_type: int = TYPE_MESSAGE,
) -> bytes:
    return (
        magic
        + bytes([FILE_VERSION, file_type])
        + session_id
        + (b"m" * 16)
        + bytes([DIR_X_TO_Y, 0])
        + struct.pack(">I", 0)
        + struct.pack(">Q", 0)
    )


def write_message(path: Path, session_id: bytes = SESSION_ID) -> Path:
    path.write_bytes(message_header(session_id) + b"encrypted-body-is-not-needed")
    return path


def test_inspect_launch_file_reads_header_only(tmp_path, monkeypatch):
    message_path = write_message(tmp_path / "incoming.paracci")
    message_bytes = message_path.read_bytes()
    reads = []
    original_open = Path.open

    class RecordingReader(io.BytesIO):
        def read(self, size=-1):
            reads.append(size)
            return super().read(size)

    def guarded_open(path, mode="r", *args, **kwargs):
        if path == message_path and mode == "rb":
            return RecordingReader(message_bytes)
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", guarded_open)

    candidate = inspect_launch_file(str(message_path))

    assert candidate is not None
    assert candidate.path == message_path
    assert candidate.session_id == SESSION_ID
    assert reads == [HEADER_SIZE]


@pytest.mark.parametrize(
    "filename,content",
    [
        ("wrong.txt", message_header()),
        ("bad.paracci", b"NOPE" + message_header()[4:]),
        ("short.paracci", message_header()[:20]),
        ("handshake.paracci", message_header(file_type=0x10)),
    ],
)
def test_inspect_launch_file_rejects_invalid_inputs(tmp_path, filename, content):
    path = tmp_path / filename
    path.write_bytes(content)

    assert inspect_launch_file(str(path)) is None


def test_inspect_launch_file_rejects_relative_missing_and_unreadable_paths(tmp_path, monkeypatch):
    unreadable = write_message(tmp_path / "blocked.paracci")
    original_open = Path.open

    def deny_open(path, mode="r", *args, **kwargs):
        if path == unreadable and mode == "rb":
            raise PermissionError("denied")
        return original_open(path, mode, *args, **kwargs)

    monkeypatch.setattr(Path, "open", deny_open)

    assert inspect_launch_file("relative.paracci") is None
    assert inspect_launch_file(str(tmp_path / "missing.paracci")) is None
    assert inspect_launch_file(str(unreadable)) is None


def test_session_exists_is_available_while_metadata_is_locked(tmp_path):
    db = seed_locked_session_db(tmp_path / "sessions.db")

    assert db.session_exists(SESSION_ID) is True
    assert db.session_exists(b"\xff" * 16) is False


def test_startup_cleanup_preserves_valid_activated_file(tmp_path, monkeypatch):
    from core.config import ParacciConfig

    downloads = tmp_path / "downloads"
    downloads.mkdir()
    activated = write_message(downloads / "activated.paracci")
    unrelated = write_message(downloads / "unrelated.paracci")
    old_time = 1
    os.utime(activated, (old_time, old_time))
    os.utime(unrelated, (old_time, old_time))

    def configure(instance):
        instance.full_downloads_path = str(downloads)
        instance.get = lambda key: 1 if key == "auto_cleanup_hours" else None

    monkeypatch.setattr(ParacciConfig, "__init__", configure)

    run.run_auto_cleanup(activated)

    assert activated.exists()
    assert not unrelated.exists()


def test_known_activation_builds_opaque_session_url(tmp_path):
    import app.routes as routes

    routes.NATIVE_FILE_REF_CACHE.clear()
    message_path = write_message(tmp_path / "private message.paracci")
    candidate = inspect_launch_file(str(message_path))
    db = seed_locked_session_db(tmp_path / "sessions.db")

    target = run._file_activation_target(candidate, db)

    assert target.startswith(f"/session/{SESSION_ID.hex()}?native_file_id=")
    assert str(message_path) not in target
    ref_id = target.split("native_file_id=", 1)[1]
    assert routes._resolve_native_file_ref(ref_id)["path"] == str(message_path)
    routes.NATIVE_FILE_REF_CACHE.clear()


def test_unknown_activation_targets_generic_home_error_without_caching_path(tmp_path):
    import app.routes as routes

    routes.NATIVE_FILE_REF_CACHE.clear()
    message_path = write_message(tmp_path / "unknown.paracci")
    candidate = inspect_launch_file(str(message_path))
    db = BurnDB(tmp_path / "sessions.db")

    target = run._file_activation_target(candidate, db)

    assert target == "/?file_activation_error=1"
    assert SESSION_ID.hex() not in target
    assert routes.NATIVE_FILE_REF_CACHE == {}


class FakeWindow:
    def __init__(self):
        self.calls = []
        self.urls = []

    def restore(self):
        self.calls.append("restore")

    def show(self):
        self.calls.append("show")

    def load_url(self, url):
        self.urls.append(url)


def test_window_activation_foregrounds_and_navigates_only_for_valid_files(tmp_path):
    message_path = write_message(tmp_path / "known.paracci")
    db = seed_locked_session_db(tmp_path / "sessions.db")
    window = FakeWindow()

    target = run._activate_main_window(window, str(message_path), db, "127.0.0.1", 18080)
    invalid_target = run._activate_main_window(
        window,
        str(tmp_path / "missing.paracci"),
        db,
        "127.0.0.1",
        18080,
    )

    assert target.startswith(f"/session/{SESSION_ID.hex()}?native_file_id=")
    assert invalid_target is None
    assert window.calls == ["restore", "show", "restore", "show"]
    assert len(window.urls) == 1
    assert str(message_path) not in window.urls[0]


def test_macos_file_open_delegate_forwards_finder_paths_to_activation_callback():
    class BaseDelegate:
        pass

    class BrowserView:
        AppDelegate = BaseDelegate

    class FakeApplication:
        def __init__(self):
            self.replies = []

        def replyToOpenOrPrint_(self, reply):
            self.replies.append(reply)

    cocoa = SimpleNamespace(
        BrowserView=BrowserView,
        AppKit=SimpleNamespace(
            NSApplicationDelegateReplySuccess=7,
            NSApplicationDelegateReplyFailure=8,
        ),
    )
    received = []

    assert install_macos_file_open_handler(received.append, cocoa) is True

    application = FakeApplication()
    delegate = cocoa.BrowserView.AppDelegate()
    delegate.application_openFiles_(application, ["/Inbox/first.paracci", "/Inbox/second.paracci"])

    assert received == ["/Inbox/first.paracci", "/Inbox/second.paracci"]
    assert application.replies == [7]
    assert issubclass(cocoa.BrowserView.AppDelegate, BaseDelegate)


def test_macos_file_open_delegate_reports_failed_activation():
    class BaseDelegate:
        pass

    class BrowserView:
        AppDelegate = BaseDelegate

    application = SimpleNamespace(replies=[])
    application.replyToOpenOrPrint_ = application.replies.append
    cocoa = SimpleNamespace(
        BrowserView=BrowserView,
        AppKit=SimpleNamespace(
            NSApplicationDelegateReplySuccess=7,
            NSApplicationDelegateReplyFailure=8,
        ),
    )

    def reject(_path):
        raise RuntimeError("invalid activation")

    assert install_macos_file_open_handler(reject, cocoa) is True
    cocoa.BrowserView.AppDelegate().application_openFiles_(application, ["/Inbox/bad.paracci"])

    assert application.replies == [8]


def test_activation_broker_forwards_to_existing_instance(tmp_path):
    received = []
    notified = threading.Event()

    def receive(path):
        received.append(path)
        notified.set()

    data_dir = tmp_path / "profile"
    broker, forwarded = FileActivationBroker.claim_or_forward(data_dir, None, receive)
    assert broker is not None
    assert forwarded is False
    try:
        second, forwarded = FileActivationBroker.claim_or_forward(
            data_dir,
            r"C:\Inbox\message.paracci",
            lambda _path: pytest.fail("secondary must not become the receiver"),
        )
        assert second is None
        assert forwarded is True
        assert notified.wait(1.0)
        assert received == [r"C:\Inbox\message.paracci"]
    finally:
        broker.close()


def test_activation_broker_rejects_wrong_token_and_recovers_stale_descriptor(tmp_path):
    data_dir = tmp_path / "profile"
    data_dir.mkdir()
    (data_dir / ".file_activation.json").write_text(
        json.dumps({"host": "127.0.0.1", "port": 9, "token": "stale"}),
        encoding="utf-8",
    )
    received = []
    broker, forwarded = FileActivationBroker.claim_or_forward(data_dir, None, received.append)
    assert broker is not None
    assert forwarded is False
    try:
        descriptor = FileActivationBroker._read_descriptor(broker.descriptor_path)
        descriptor["token"] = "wrong"
        assert FileActivationBroker._send_activation(descriptor, None) is False
        with socket.create_connection(("127.0.0.1", broker.port), timeout=0.5) as client:
            client.sendall(b"not-json\n")
            malformed_response = json.loads(client.recv(512).decode("utf-8"))
        assert malformed_response == {"ok": False}
        assert received == []
    finally:
        broker.close()


def test_activation_broker_survives_callback_failure(tmp_path):
    callbacks = []

    def fail_once(path):
        callbacks.append(path)
        if len(callbacks) == 1:
            raise RuntimeError("window is closing")

    data_dir = tmp_path / "profile"
    broker, forwarded = FileActivationBroker.claim_or_forward(data_dir, None, fail_once)
    assert broker is not None
    assert forwarded is False
    try:
        descriptor = FileActivationBroker._read_descriptor(broker.descriptor_path)
        assert FileActivationBroker._send_activation(descriptor, None) is False
        assert FileActivationBroker._send_activation(descriptor, None) is True
        assert callbacks == [None, None]
    finally:
        broker.close()
