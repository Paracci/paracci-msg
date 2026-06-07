import json
import re
from pathlib import Path

from jinja2 import Environment, FileSystemLoader


PACKAGE_ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_ROOT = PACKAGE_ROOT / "app" / "templates"
STATIC_ROOT = PACKAGE_ROOT / "app" / "static"
I18N_ROOT = PACKAGE_ROOT / "app" / "i18n"

SETUP_TEMPLATE = (TEMPLATE_ROOT / "setup.html").read_text(encoding="utf-8")
SESSION_TEMPLATE = (TEMPLATE_ROOT / "session.html").read_text(encoding="utf-8")
BASE_TEMPLATE = (TEMPLATE_ROOT / "base.html").read_text(encoding="utf-8")
CARRIER_JS = (STATIC_ROOT / "js" / "carrier.js").read_text(encoding="utf-8")
SETUP_JS = (STATIC_ROOT / "js" / "setup.js").read_text(encoding="utf-8")
SESSION_JS = (STATIC_ROOT / "js" / "session.js").read_text(encoding="utf-8")
APP_JS = (STATIC_ROOT / "js" / "app.js").read_text(encoding="utf-8")

EXPECTED_CARRIER_KEYS = {
    "panel_title",
    "panel_optional",
    "outer_wrapper_note",
    "recompression_warning",
    "capacity_hint",
    "cover_file_label",
    "carrier_file_label",
    "extract_setup",
    "extract_responder",
    "extract_message",
    "export_setup",
    "export_responder",
    "export_message",
    "generic_error",
    "processing",
}


def test_carrier_templates_compile():
    env = Environment(loader=FileSystemLoader(TEMPLATE_ROOT))
    env.filters["expires_at"] = lambda value: value
    env.filters["time_left"] = lambda value: value

    env.get_template("setup.html")
    env.get_template("session.html")


def test_carrier_controls_are_collapsed_secondary_and_explicit():
    combined = SETUP_TEMPLATE + SESSION_TEMPLATE

    assert "<details class=\"carrier-panel" in combined
    assert not re.search(r"<details[^>]*carrier-panel[^>]*\sopen(?:\s|=|>)", combined)
    assert 'class="btn btn-secondary"' in combined
    assert "carrier.recompression_warning" in SETUP_TEMPLATE
    assert "carrier.recompression_warning" in SESSION_TEMPLATE
    assert "carrier.panel_optional" in combined

    for endpoint in (
        "main.session_import_carrier",
        "main.session_import_responder_carrier",
        "main.session_open_carrier",
        "main.session_export_carrier",
        "main.session_seal_carrier",
    ):
        assert endpoint in combined


def test_normal_paracci_flows_and_drop_targets_remain_primary():
    assert "url_for('main.session_import')" in SETUP_TEMPLATE
    assert 'name="paracci_file" id="fileInput" accept=".paracci" required' in SETUP_TEMPLATE
    assert 'data-drop-target="import"' in SETUP_TEMPLATE
    assert 'class="btn btn-primary btn-lg px-12" id="importBtn"' in SETUP_TEMPLATE

    assert "url_for('main.session_import_responder', sid=sid)" in SESSION_TEMPLATE
    assert 'name="paracci_file" id="responder-input" accept=".paracci"' in SESSION_TEMPLATE
    assert 'data-drop-target="finalize"' in SESSION_TEMPLATE
    assert "url_for('main.session_seal', sid=sid)" in SESSION_TEMPLATE
    assert 'id="seal-submit"' in SESSION_TEMPLATE
    assert 'id="paracci_file" name="paracci_file" accept=".paracci"' in SESSION_TEMPLATE
    assert 'data-drop-target="open"' in SESSION_TEMPLATE
    assert "url_for('main.session_export', sid=sid)" in SESSION_TEMPLATE


def test_carrier_inputs_are_explicit_png_pickers_without_path_or_drop_fields():
    combined = SETUP_TEMPLATE + SESSION_TEMPLATE + SETUP_JS + SESSION_JS

    assert 'accept="image/png,.png"' in SETUP_TEMPLATE
    assert 'accept="image/png,.png"' in SESSION_TEMPLATE
    assert "formData.set('carrier_png'" in SETUP_JS
    assert "formData.set('carrier_png'" in SESSION_JS
    assert "formData.set('cover_png'" in SESSION_JS
    assert "png_lossless_v1" in CARRIER_JS
    assert "carrier_native_file_id" not in combined
    assert "cover_native_file_id" not in combined
    assert 'name="carrier_png"' not in combined
    assert 'name="cover_png"' not in combined

    carrier_input = re.search(r'<input type="file"[^>]+data-carrier-file[^>]*>', SESSION_TEMPLATE)
    assert carrier_input
    assert "data-drop-target" not in carrier_input.group(0)


def test_normal_drop_resolver_does_not_detect_png_carriers():
    resolver = re.search(
        r"function resolveDropIntent\(fileInfo = \{\}\) \{(?P<body>.*?)\n\}",
        APP_JS,
        re.DOTALL,
    )
    assert resolver
    body = resolver.group("body")
    assert ".paracci" in body
    assert ".png" not in body
    assert "carrier" not in body.lower()


def test_carrier_frontend_uses_safe_generic_errors_and_managed_downloads():
    combined = CARRIER_JS + SETUP_JS + SESSION_JS

    assert "alert.textContent = genericErrorText();" in CARRIER_JS
    assert "response.text(" not in CARRIER_JS
    assert "data.error" not in CARRIER_JS
    assert "console." not in CARRIER_JS
    assert "save_file_silent" in CARRIER_JS
    assert re.search(r"\.save_file\(", combined) is None
    for forbidden in ("FileReader", "readAsDataURL", "readAsArrayBuffer", "btoa(", "atob("):
        assert forbidden not in combined
    assert "qr_matrix_v1" not in combined
    assert "carrier_generic_error" in BASE_TEMPLATE
    assert "carrier_processing" in BASE_TEMPLATE


def test_all_locales_define_conservative_carrier_strings():
    locale_files = sorted(I18N_ROOT.glob("*.json"))
    assert {path.stem for path in locale_files} == {"de", "en", "es", "fr", "ru", "tr"}

    for locale_file in locale_files:
        payload = json.loads(locale_file.read_text(encoding="utf-8"))
        carrier = payload["carrier"]
        assert set(carrier) == EXPECTED_CARRIER_KEYS
        assert all(isinstance(value, str) and value.strip() for value in carrier.values())
        combined = " ".join(carrier.values()).lower()
        assert "undetect" not in combined
        assert "tamper-proof" not in combined
        assert "authenticated carrier" not in combined

    english = json.loads((I18N_ROOT / "en.json").read_text(encoding="utf-8"))["carrier"]
    assert "file/document" in english["recompression_warning"]
    assert "recompress" in english["recompression_warning"]
    assert "resize" in english["recompression_warning"]
    assert "convert" in english["recompression_warning"]
    assert "outer transport wrapper" in english["outer_wrapper_note"]
