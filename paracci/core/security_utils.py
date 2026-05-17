import unicodedata
import re

def is_homograph_attack(text: str) -> bool:
    """
    Simple homograph attack detection. 
    Returns True if there are mixed scripts (like Latin + Cyrillic) in the text.
    """
    scripts = set()
    for char in text:
        cat = unicodedata.category(char)
        if cat.startswith('L'): # Letter
            try:
                # Get script name (e.g., 'LATIN', 'CYRILLIC')
                script = unicodedata.name(char).split()[0]
                scripts.add(script)
            except:
                pass
    
    # If there are multiple scripts and one of them is Latin, consider it suspicious
    return len(scripts) > 1 and 'LATIN' in scripts

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
    # Find URLs
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)
    
    risks = []
    for url in urls:
        if is_homograph_attack(url):
            risks.append({"type": "homograph", "target": url})
            
    if has_bidi_controls(text):
        risks.append({"type": "rtl_override", "target": "General text"})
        
    return {
        "is_safe": len(risks) == 0,
        "risks": risks
    }
