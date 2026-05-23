"""Desktop activation support for opening associated .paracci message files."""

from __future__ import annotations

import hmac
import json
import logging
import os
import secrets
import socket
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from core.envelope import (
    HEADER_SIZE,
    MAGIC_BYTES,
    TYPE_MESSAGE,
    EnvelopeError,
    _parse_header,
)

logger = logging.getLogger(__name__)

_DESCRIPTOR_FILENAME = ".file_activation.json"
_LOCK_FILENAME = ".file_activation.lock"
_MAX_REQUEST_BYTES = 64 * 1024
_MAX_PATH_CHARS = 32768


@dataclass(frozen=True)
class LaunchFileCandidate:
    """A structurally valid message file inspected without decryption."""

    path: Path
    session_id: bytes


def inspect_launch_file(argument: str | None) -> LaunchFileCandidate | None:
    """Validate an associated-file argument and read only its plaintext header."""
    if not isinstance(argument, str) or not argument or "\x00" in argument:
        return None

    path = Path(argument)
    if not path.is_absolute() or path.suffix.casefold() != ".paracci":
        return None

    try:
        if not path.is_file():
            return None
        with path.open("rb") as source:
            header_bytes = source.read(HEADER_SIZE)
        if len(header_bytes) != HEADER_SIZE or header_bytes[:4] != MAGIC_BYTES:
            return None
        header = _parse_header(header_bytes)
    except (OSError, EnvelopeError, ValueError):
        return None

    if header.msg_type != TYPE_MESSAGE:
        return None
    return LaunchFileCandidate(path=path, session_id=header.session_id)


class FileActivationBroker:
    """Authenticated single-instance activation transport over local loopback."""

    def __init__(self, data_dir: Path, on_activation: Callable[[str | None], None]):
        self.data_dir = Path(data_dir)
        self.on_activation = on_activation
        self.descriptor_path = self.data_dir / _DESCRIPTOR_FILENAME
        self.lock_path = self.data_dir / _LOCK_FILENAME
        self.token = ""
        self.port: int | None = None
        self._lock_handle = None
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    @classmethod
    def claim_or_forward(
        cls,
        data_dir: Path,
        activation_path: str | None,
        on_activation: Callable[[str | None], None],
    ) -> tuple["FileActivationBroker | None", bool]:
        """Start the primary broker or forward activation to its existing owner."""
        broker = cls(Path(data_dir), on_activation)
        broker.data_dir.mkdir(parents=True, exist_ok=True)
        if broker._claim_lock():
            broker._start_server()
            return broker, False

        if cls._forward_existing(broker.descriptor_path, activation_path):
            return None, True

        # A held lock means another process owns the profile. Avoid launching a
        # competing window even when its startup endpoint is not yet responsive.
        logger.warning("Existing Paracci instance did not accept activation.")
        return None, True

    @staticmethod
    def _forward_existing(descriptor_path: Path, activation_path: str | None) -> bool:
        deadline = time.monotonic() + 1.5
        while time.monotonic() < deadline:
            descriptor = FileActivationBroker._read_descriptor(descriptor_path)
            if descriptor and FileActivationBroker._send_activation(descriptor, activation_path):
                return True
            time.sleep(0.05)
        return False

    @staticmethod
    def _read_descriptor(descriptor_path: Path) -> dict | None:
        try:
            descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
            port = descriptor.get("port")
            token = descriptor.get("token")
            if (
                descriptor.get("host") != "127.0.0.1"
                or not isinstance(port, int)
                or not 0 < port < 65536
                or not isinstance(token, str)
                or not token
                or len(token) > 128
            ):
                return None
            return {"host": "127.0.0.1", "port": port, "token": token}
        except (OSError, ValueError, TypeError):
            return None

    @staticmethod
    def _send_activation(descriptor: dict, activation_path: str | None) -> bool:
        action = "open_file" if activation_path is not None else "focus"
        request_data = {
            "token": descriptor["token"],
            "action": action,
        }
        if action == "open_file":
            request_data["path"] = activation_path
        raw = json.dumps(request_data, separators=(",", ":")).encode("utf-8") + b"\n"
        if len(raw) > _MAX_REQUEST_BYTES:
            return False
        try:
            with socket.create_connection(
                (descriptor["host"], descriptor["port"]),
                timeout=0.5,
            ) as client:
                client.settimeout(0.5)
                client.sendall(raw)
                response = client.recv(512)
            payload = json.loads(response.decode("utf-8"))
            return payload.get("ok") is True
        except (OSError, ValueError, TypeError):
            return False

    def _claim_lock(self) -> bool:
        handle = self.lock_path.open("a+b")
        handle.seek(0, os.SEEK_END)
        if handle.tell() == 0:
            handle.write(b"0")
            handle.flush()
        handle.seek(0)
        try:
            if os.name == "nt":
                import msvcrt

                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl

                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            handle.close()
            return False
        self._lock_handle = handle
        return True

    def _start_server(self) -> None:
        self.token = secrets.token_urlsafe(32)
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("127.0.0.1", 0))
        server.listen(4)
        server.settimeout(0.25)
        self._server = server
        self.port = int(server.getsockname()[1])
        self._write_descriptor()
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _write_descriptor(self) -> None:
        descriptor = {
            "host": "127.0.0.1",
            "port": self.port,
            "token": self.token,
        }
        temporary = self.descriptor_path.with_name(
            f"{self.descriptor_path.name}.{os.getpid()}.tmp"
        )
        temporary.write_text(
            json.dumps(descriptor, separators=(",", ":")),
            encoding="utf-8",
        )
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, self.descriptor_path)

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                client, _address = self._server.accept() if self._server else (None, None)
            except TimeoutError:
                continue
            except OSError:
                break
            if client is None:
                continue
            with client:
                client.settimeout(0.5)
                accepted = self._receive_request(client)
                response = json.dumps({"ok": accepted}, separators=(",", ":")).encode("ascii")
                try:
                    client.sendall(response + b"\n")
                except OSError:
                    pass

    def _receive_request(self, client: socket.socket) -> bool:
        raw = bytearray()
        try:
            while len(raw) <= _MAX_REQUEST_BYTES:
                chunk = client.recv(4096)
                if not chunk:
                    break
                raw.extend(chunk)
                if b"\n" in chunk:
                    break
        except OSError:
            return False
        if not raw or len(raw) > _MAX_REQUEST_BYTES:
            return False
        try:
            payload = json.loads(bytes(raw).split(b"\n", 1)[0].decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return False
        if not isinstance(payload, dict) or not hmac.compare_digest(
            str(payload.get("token", "")),
            self.token,
        ):
            return False

        action = payload.get("action")
        if action == "focus":
            return self._dispatch_activation(None)
        path = payload.get("path")
        if (
            action != "open_file"
            or not isinstance(path, str)
            or not path
            or "\x00" in path
            or len(path) > _MAX_PATH_CHARS
        ):
            return False
        return self._dispatch_activation(path)

    def _dispatch_activation(self, path: str | None) -> bool:
        try:
            self.on_activation(path)
            return True
        except (MemoryError, KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            logger.exception("Desktop file activation callback failed.")
            return False

    def close(self) -> None:
        """Stop accepting activation messages and release the instance lock."""
        self._stop.set()
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=0.5)
            self._thread = None
        descriptor = self._read_descriptor(self.descriptor_path)
        if descriptor and hmac.compare_digest(descriptor["token"], self.token):
            try:
                self.descriptor_path.unlink()
            except OSError:
                pass
        if self._lock_handle is not None:
            try:
                self._lock_handle.seek(0)
                if os.name == "nt":
                    import msvcrt

                    msvcrt.locking(self._lock_handle.fileno(), msvcrt.LK_UNLCK, 1)
                else:
                    import fcntl

                    fcntl.flock(self._lock_handle.fileno(), fcntl.LOCK_UN)
            finally:
                self._lock_handle.close()
                self._lock_handle = None
