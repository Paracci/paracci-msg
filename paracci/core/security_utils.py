import re
import unicodedata
from urllib.parse import urlparse

_URL_PATTERN = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
_IDN_DOT_TRANSLATION = str.maketrans({
    '\u3002': '.',
    '\uff0e': '.',
    '\uff61': '.',
})


def _extract_urls(text: str) -> list[str]:
    return _URL_PATTERN.findall(text)


def _script_for_letter(char: str) -> str | None:
    if not unicodedata.category(char).startswith('L'):
        return None
    name = unicodedata.name(char, '')
    return name.split()[0] if name else None


def _decoded_label(label: str) -> str:
    if label.lower().startswith('xn--'):
        try:
            return label.encode('ascii').decode('idna')
        except UnicodeError:
            return label
    return label


def _url_has_mixed_script_label(url: str) -> bool:
    parse_target = f'//{url}' if url.startswith('www.') else url
    try:
        hostname = urlparse(parse_target).hostname
    except ValueError:
        return False
    if not hostname:
        return False

    hostname = hostname.translate(_IDN_DOT_TRANSLATION)
    for label in hostname.split('.'):
        scripts = {
            script
            for char in _decoded_label(label)
            if (script := _script_for_letter(char)) is not None
        }
        if len(scripts) > 1:
            return True
    return False


def is_homograph_attack(text: str) -> bool:
    """
    Return True if a URL in text has a domain label containing mixed scripts.
    """
    return any(_url_has_mixed_script_label(url) for url in _extract_urls(text))

def has_bidi_controls(text: str) -> bool:
    """
    Checks all dangerous Bidi (Bidirectional) control characters.
    These characters are used to hide file extensions or display misleading 
    links.
    """
    bidi_chars = [
        '\u202A', '\u202B', '\u202C', '\u202D', '\u202E', # LRE, RLE, PDF, LRO, RLO
        '\u2066', '\u2067', '\u2068', '\u2069',          # LRI, RLI, FSI, PDI
        '\u200E', '\u200F',                              # LRM, RLM
        '\u061C'                                         # ALM
    ]
    return any(c in text for c in bidi_chars)

def scan_text_for_security(text: str) -> dict:
    """
    Scans text for security risks.
    """
    risks = []
    for url in _extract_urls(text):
        if _url_has_mixed_script_label(url):
            risks.append({"type": "homograph", "target": url})
            
    if has_bidi_controls(text):
        risks.append({"type": "rtl_override", "target": "General text"})
        
    return {
        "is_safe": len(risks) == 0,
        "risks": risks
    }
