import concurrent.futures
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.preview_store import NativeSaveGrantStore, PreviewStore


def test_generate_token_returns_64_char_hex_string():
    store = PreviewStore()

    token = store.generate_token(b"preview-bytes", "note.txt", "text/plain")

    assert len(token) == 64
    int(token, 16)


def test_get_returns_entry_for_valid_token():
    store = PreviewStore()

    token = store.generate_token(b"preview-bytes", "note.txt", "text/plain")
    entry = store.get(token)

    assert entry is not None
    assert entry.token == token
    assert entry.filename == "note.txt"
    assert entry.mime_type == "text/plain"
    assert entry.allow_download is True


def test_generate_token_preserves_download_permission():
    store = PreviewStore()

    token = store.generate_token(
        b"preview-bytes",
        "note.txt",
        "text/plain",
        allow_download=False,
    )
    entry = store.get(token)

    assert entry is not None
    assert entry.allow_download is False


def test_get_returns_none_for_expired_token():
    now = [100.0]
    store = PreviewStore(ttl_seconds=5, clock=lambda: now[0])

    token = store.generate_token(b"preview-bytes", "note.txt", "text/plain")
    now[0] = 106.0

    assert store.get(token) is None


def test_get_returns_none_for_unknown_token():
    store = PreviewStore()

    assert store.get("0" * 64) is None


def test_revoke_removes_token_immediately():
    store = PreviewStore()

    token = store.generate_token(b"preview-bytes", "note.txt", "text/plain")
    store.revoke(token)

    assert store.get(token) is None


def test_cleanup_expired_removes_only_expired_entries():
    now = [100.0]
    store = PreviewStore(ttl_seconds=5, clock=lambda: now[0])

    expired = store.generate_token(b"expired", "expired.txt", "text/plain")
    now[0] = 102.0
    current = store.generate_token(b"current", "current.txt", "text/plain")
    now[0] = 106.0

    store.cleanup_expired()

    assert store.get(expired) is None
    assert store.get(current) is not None


def test_concurrent_generates_do_not_corrupt_store():
    store = PreviewStore()

    def generate(index):
        return store.generate_token(
            f"preview-{index}".encode("ascii"),
            f"file-{index}.txt",
            "text/plain",
        )

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        tokens = list(executor.map(generate, range(100)))

    assert len(set(tokens)) == 100
    assert all(store.get(token) is not None for token in tokens)


def test_file_bytes_are_stored_and_retrieved_correctly():
    store = PreviewStore()
    file_bytes = b"\x00\x01paracci-preview\xff"

    token = store.generate_token(file_bytes, "blob.bin", "application/octet-stream")
    entry = store.get(token)

    assert entry is not None
    assert entry.file_bytes == file_bytes


def test_native_save_grant_is_opaque_and_one_shot():
    store = NativeSaveGrantStore()

    token = store.issue(b"download-bytes", "message.paracci")
    entry = store.consume(token)

    assert len(token) == 64
    int(token, 16)
    assert entry is not None
    assert entry.file_bytes == b"download-bytes"
    assert entry.filename == "message.paracci"
    assert store.consume(token) is None


def test_native_save_grant_expires_before_consumption():
    now = [100.0]
    store = NativeSaveGrantStore(ttl_seconds=5, clock=lambda: now[0])

    token = store.issue(b"download-bytes", "message.paracci")
    now[0] = 106.0

    assert store.consume(token) is None


def test_native_save_grant_rejects_unsafe_filename():
    store = NativeSaveGrantStore()

    with pytest.raises(ValueError, match="Invalid download filename"):
        store.issue(b"download-bytes", "../message.paracci")


def test_native_save_grant_rejects_oversized_bytes(monkeypatch):
    import core.preview_store as preview_store_module

    monkeypatch.setattr(preview_store_module, "MAX_NATIVE_SAVE_BYTES", 2)
    store = NativeSaveGrantStore()

    with pytest.raises(ValueError, match="size limit"):
        store.issue(b"too-large", "message.paracci")
