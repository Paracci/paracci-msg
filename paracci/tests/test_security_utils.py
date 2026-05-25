import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.security_utils import has_bidi_controls, is_homograph_attack, scan_text_for_security


@pytest.mark.parametrize(
    "text",
    [
        "https://example.com",
        "https://\u043f\u0440\u0438\u043c\u0435\u0440.\u0440\u0444",
        "https://\u0430\u0440\u0440\u04cf\u0435.com",
        "Hello \u043c\u0438\u0440",
        "Hello \u043c\u0438\u0440 https://example.com",
        "https://example.com/\u043c\u0438\u0440",
        "https://\u043f\u0440\u0438\u043c\u0435\u0440.com",
    ],
)
def test_safe_text_and_domains_are_not_flagged(text):
    assert is_homograph_attack(text) is False
    assert scan_text_for_security(text)["is_safe"] is True


def test_mixed_script_label_is_flagged_and_reported():
    url = "https://\u0440\u0430ypal.com"
    text = f"Open this link: {url}"

    assert is_homograph_attack(text) is True
    assert scan_text_for_security(text) == {
        "is_safe": False,
        "risks": [{"type": "homograph", "target": url}],
    }


def test_punycode_preserves_single_and_mixed_script_decisions():
    pure_cyrillic = "\u043f\u0440\u0438\u043c\u0435\u0440".encode("idna").decode("ascii")
    mixed_script = "\u0440\u0430ypal".encode("idna").decode("ascii")

    assert is_homograph_attack(f"https://{pure_cyrillic}.com") is False
    assert is_homograph_attack(f"https://{mixed_script}.com") is True


def test_www_url_form_is_checked_without_examining_other_text():
    assert is_homograph_attack("See www.\u0440\u0430ypal.com/\u043c\u0438\u0440") is True
    assert is_homograph_attack("See www.example.com/\u043c\u0438\u0440") is False


def test_bidi_control_reporting_is_unchanged():
    text = "safe text\u202e"

    assert has_bidi_controls(text) is True
    assert scan_text_for_security(text) == {
        "is_safe": False,
        "risks": [{"type": "rtl_override", "target": "General text"}],
    }
