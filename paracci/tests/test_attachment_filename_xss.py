import io
import json
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.package import (
    Attachment,
    Package,
    create_package,
    extract_package,
    package_to_template_data,
    sanitize_attachment_filename,
)


PROJECT_ROOT = Path(__file__).parent.parent.parent


def test_sanitize_attachment_filename_removes_xss_and_path_chars():
    unsafe = '..\\<img src=x onerror=alert(1)>/"evil\r\n.js'
    sanitized = sanitize_attachment_filename(unsafe)

    assert sanitized.endswith("evil.js")
    assert "<" not in sanitized
    assert ">" not in sanitized
    assert '"' not in sanitized
    assert "'" not in sanitized
    assert "/" not in sanitized
    assert "\\" not in sanitized
    assert "\r" not in sanitized
    assert "\n" not in sanitized
    assert sanitize_attachment_filename('<>"\x00') == "attachment.bin"


def test_create_package_stores_only_sanitized_attachment_names():
    unsafe = '../<svg onload=alert(1)> "quote".txt'
    blob = create_package("hello", [(unsafe, b"payload")], allow_download=True)

    with zipfile.ZipFile(io.BytesIO(blob), "r") as zf:
        names = zf.namelist()
        metadata = json.loads(zf.read("metadata.json").decode("utf-8"))

    attachment = metadata["attachments"][0]
    assert attachment["original_name"] == sanitize_attachment_filename(unsafe)
    assert unsafe not in json.dumps(metadata)
    assert all("<" not in name and ">" not in name and '"' not in name for name in names)
    assert attachment["internal_path"].startswith("attachments/")


def test_extract_package_sanitizes_malicious_peer_metadata():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("message.md", b"hello")
        zf.writestr("attachments/0_payload.txt", b"payload")
        zf.writestr(
            "metadata.json",
            json.dumps({
                "allow_download": True,
                "attachments": [{
                    "original_name": '<img src=x onerror=alert(1)>.txt',
                    "internal_path": "attachments/0_payload.txt",
                    "size": 7,
                }],
            }).encode("utf-8"),
        )

    package = extract_package(buffer.getvalue())

    assert len(package.attachments) == 1
    filename = package.attachments[0].filename
    assert filename == sanitize_attachment_filename('<img src=x onerror=alert(1)>.txt')
    assert "<" not in filename
    assert ">" not in filename
    assert "onerror=" not in filename


def test_extract_package_skips_unsafe_attachment_paths():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("message.md", b"hello")
        zf.writestr("../escape.txt", b"payload")
        zf.writestr(
            "metadata.json",
            json.dumps({
                "attachments": [{
                    "original_name": "safe.txt",
                    "internal_path": "../escape.txt",
                    "size": 7,
                }],
            }).encode("utf-8"),
        )

    package = extract_package(buffer.getvalue())

    assert package.attachments == []


def test_package_to_template_data_sanitizes_constructed_attachments():
    package = Package(
        text="hello",
        attachments=[Attachment(filename='<script>alert(1)</script>.png', content=b"")],
        allow_download=True,
    )

    data = package_to_template_data(package)
    filename = data["attachments"][0]["filename"]

    assert "<" not in filename
    assert ">" not in filename
    assert "script" in filename


def test_session_js_no_attachment_filename_html_or_inline_handlers():
    session_js = (PROJECT_ROOT / "paracci" / "app" / "static" / "js" / "session.js").read_text(encoding="utf-8")

    assert "item.innerHTML" not in session_js
    assert "onclick=\"handleAttachment" not in session_js
    assert "handleAttachmentDownload('${att.pid}', '${att.filename}')" not in session_js
    assert "${att.filename}" not in session_js


def test_routes_script_csp_rejects_inline_and_eval():
    routes = (PROJECT_ROOT / "paracci" / "app" / "routes.py").read_text(encoding="utf-8")
    script_policy_lines = [
        line for line in routes.splitlines()
        if '"script-src ' in line or "'script-src " in line or "script-src-attr" in line
    ]
    script_policy = "\n".join(script_policy_lines)

    assert "'unsafe-inline'" not in script_policy
    assert "'unsafe-eval'" not in script_policy
    assert "script-src-attr 'none'" in routes
