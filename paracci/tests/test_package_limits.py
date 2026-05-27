import io
import json
import random
import string
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core import package as package_module
from core.package import (
    Attachment,
    Package,
    PackageLimitError,
    create_package,
    extract_package,
    package_to_template_data,
)


def _zip_bytes(entries, compression=zipfile.ZIP_DEFLATED):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression) as zf:
        for name, content in entries:
            zf.writestr(name, content)
    return buffer.getvalue()


def _metadata(attachments=None, allow_download=False, include_allow_download=True):
    metadata = {"attachments": attachments or []}
    if include_allow_download:
        metadata["allow_download"] = allow_download
    return json.dumps(metadata).encode("utf-8")


def test_extract_package_round_trips_normal_package_with_limits():
    blob = create_package("hello", [("note.txt", b"attachment text")], allow_download=True)

    package = extract_package(blob)

    assert package.text == "hello"
    assert package.allow_download is True
    assert len(package.attachments) == 1
    assert package.attachments[0].filename == "note.txt"
    assert package.attachments[0].content == b"attachment text"


def test_extract_package_missing_download_policy_uses_explicit_default_only():
    blob = _zip_bytes([
        ("message.md", b"legacy"),
        ("metadata.json", _metadata(include_allow_download=False)),
    ])

    assert extract_package(blob).allow_download is False
    assert extract_package(blob, default_allow_download=True).allow_download is True


@pytest.mark.parametrize("allow_download", [False, True])
def test_extract_package_explicit_download_policy_overrides_legacy_default(allow_download):
    blob = _zip_bytes([
        ("message.md", b"legacy"),
        ("metadata.json", _metadata(allow_download=allow_download)),
    ])

    package = extract_package(blob, default_allow_download=not allow_download)

    assert package.allow_download is allow_download


def test_extract_package_rejects_metadata_over_limit_before_parsing():
    rng = random.Random(1337)
    payload = "".join(rng.choice(string.ascii_letters + string.digits) for _ in range(
        package_module.MAX_PACKAGE_METADATA_BYTES + 1024
    ))
    blob = _zip_bytes([
        ("message.md", b"hello"),
        ("metadata.json", json.dumps({"payload": payload}).encode("utf-8")),
    ])

    with pytest.raises(PackageLimitError):
        extract_package(blob)


def test_extract_package_rejects_too_many_metadata_attachments():
    attachments = []
    entries = [("message.md", b"hello")]
    for index in range(package_module.MAX_PACKAGE_ATTACHMENT_COUNT + 1):
        path = f"attachments/{index}_note.txt"
        entries.append((path, b"x"))
        attachments.append({
            "original_name": "note.txt",
            "internal_path": path,
            "size": 1,
        })
    entries.append(("metadata.json", _metadata(attachments)))

    with pytest.raises(PackageLimitError):
        extract_package(_zip_bytes(entries, compression=zipfile.ZIP_STORED))


def test_extract_package_rejects_too_many_zip_entries():
    entries = [("message.md", b"hello"), ("metadata.json", _metadata())]
    for index in range(package_module.MAX_PACKAGE_ZIP_ENTRY_COUNT - 1):
        entries.append((f"extra-{index}.bin", b"x"))

    with pytest.raises(PackageLimitError):
        extract_package(_zip_bytes(entries, compression=zipfile.ZIP_STORED))


def test_extract_package_rejects_high_compression_ratio_attachment():
    path = "attachments/0_payload.txt"
    blob = _zip_bytes([
        ("message.md", b"hello"),
        (path, b"A" * 200_000),
        ("metadata.json", _metadata([{
            "original_name": "payload.txt",
            "internal_path": path,
            "size": 200_000,
        }])),
    ])

    with pytest.raises(PackageLimitError):
        extract_package(blob)


def test_extract_package_rejects_compressed_size_before_streaming(monkeypatch):
    monkeypatch.setattr(package_module, "MAX_PACKAGE_ENTRY_COMPRESSED_BYTES", 200)
    path = "attachments/0_payload.bin"
    blob = _zip_bytes([
        ("message.md", b"ok"),
        (path, b"x" * 201),
        ("metadata.json", _metadata([{
            "original_name": "payload.bin",
            "internal_path": path,
            "size": 201,
        }])),
    ], compression=zipfile.ZIP_STORED)

    with pytest.raises(PackageLimitError):
        extract_package(blob)


def test_extract_package_rejects_total_attachment_limit(monkeypatch):
    monkeypatch.setattr(package_module, "MAX_PACKAGE_ATTACHMENT_BYTES", 10)
    monkeypatch.setattr(package_module, "MAX_PACKAGE_TOTAL_ATTACHMENT_BYTES", 5)
    paths = ["attachments/0_a.txt", "attachments/1_b.txt"]
    blob = _zip_bytes([
        ("message.md", b"ok"),
        (paths[0], b"aaaa"),
        (paths[1], b"bbbb"),
        ("metadata.json", _metadata([
            {"original_name": "a.txt", "internal_path": paths[0], "size": 4},
            {"original_name": "b.txt", "internal_path": paths[1], "size": 4},
        ])),
    ], compression=zipfile.ZIP_STORED)

    with pytest.raises(PackageLimitError):
        extract_package(blob)


def test_streaming_read_aborts_when_actual_bytes_exceed_limit(monkeypatch):
    blob = _zip_bytes([("message.md", b"abcdef")], compression=zipfile.ZIP_STORED)
    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        info = zf.getinfo("message.md")
        monkeypatch.setattr(package_module, "_validate_zip_entry_info", lambda *args: None)
        with pytest.raises(PackageLimitError):
            package_module._read_zip_entry_limited(zf, info, 3, "Package message")


def test_package_to_template_data_rejects_constructed_over_limits(monkeypatch):
    too_many = Package(
        text="hello",
        attachments=[
            Attachment(filename=f"{index}.txt", content=b"x")
            for index in range(package_module.MAX_PACKAGE_ATTACHMENT_COUNT + 1)
        ],
        allow_download=False,
    )

    with pytest.raises(PackageLimitError):
        package_to_template_data(too_many)

    monkeypatch.setattr(package_module, "MAX_PACKAGE_TOTAL_ATTACHMENT_BYTES", 3)
    too_large = Package(
        text="hello",
        attachments=[Attachment(filename="payload.txt", content=b"xxxx")],
        allow_download=False,
    )

    with pytest.raises(PackageLimitError):
        package_to_template_data(too_large)


def test_package_to_template_data_does_not_emit_attachment_base64():
    package = Package(
        text="hello",
        attachments=[Attachment(filename="image.png", content=b"plaintext-image-bytes", mime_type="image/png")],
        allow_download=True,
    )

    data = package_to_template_data(package)

    assert data["attachments"][0]["is_media"] is True
    assert data["attachments"][0]["data_b64"] == ""
    assert data["attachments"][0]["full_b64"] == ""
    assert "plaintext-image-bytes" not in str(data)


def test_extract_package_still_skips_unsafe_attachment_paths():
    blob = _zip_bytes([
        ("message.md", b"hello"),
        ("../escape.txt", b"payload"),
        ("metadata.json", _metadata([{
            "original_name": "safe.txt",
            "internal_path": "../escape.txt",
            "size": 7,
        }])),
    ])

    package = extract_package(blob)

    assert package.text == "hello"
    assert package.attachments == []


def test_extract_package_cleans_up_temp_files_on_error(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    temp_dir = tmp_path / "temp"
    
    monkeypatch.setattr(package_module, "MAX_PACKAGE_ATTACHMENT_BYTES", 5)
    
    blob = _zip_bytes([
        ("message.md", b"hello"),
        ("attachments/0_safe.txt", b"safe"),
        ("attachments/1_unsafe.txt", b"unsafe"),
        ("metadata.json", _metadata([
            {"original_name": "safe.txt", "internal_path": "attachments/0_safe.txt", "size": 4},
            {"original_name": "unsafe.txt", "internal_path": "attachments/1_unsafe.txt", "size": 6},
        ])),
    ], compression=zipfile.ZIP_STORED)
    
    assert not list(temp_dir.glob("extracted_*.bin"))
    
    with pytest.raises(PackageLimitError):
        extract_package(blob)
        
    assert not list(temp_dir.glob("extracted_*.bin"))


def test_extract_package_cleans_up_temp_files_on_total_limit_error(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    temp_dir = tmp_path / "temp"
    
    monkeypatch.setattr(package_module, "MAX_PACKAGE_ATTACHMENT_BYTES", 10)
    monkeypatch.setattr(package_module, "MAX_PACKAGE_TOTAL_ATTACHMENT_BYTES", 5)
    
    blob = _zip_bytes([
        ("message.md", b"hello"),
        ("attachments/0_a.txt", b"aaaa"),
        ("attachments/1_b.txt", b"bbbb"),
        ("metadata.json", _metadata([
            {"original_name": "a.txt", "internal_path": "attachments/0_a.txt", "size": 4},
            {"original_name": "b.txt", "internal_path": "attachments/1_b.txt", "size": 4},
        ])),
    ], compression=zipfile.ZIP_STORED)
    
    assert not list(temp_dir.glob("extracted_*.bin"))
    
    with pytest.raises(PackageLimitError):
        extract_package(blob)
        
    assert not list(temp_dir.glob("extracted_*.bin"))
