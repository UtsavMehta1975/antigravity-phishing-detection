"""
Strict Unicode, IDNA, Homoglyph, and Zero-Width / Tag-Block Normalization Layer.
Prevents evasion techniques such as invisible character insertions, tag smuggling,
bidirectional overrides, and Cyrillic/Greek homoglyph substitutions.
"""
import re
import unicodedata
from typing import Dict, List, Tuple

# Set of invisible and zero-width characters commonly used to split keywords
ZERO_WIDTH_CHARS = {
    '\u200B',  # Zero Width Space
    '\u200C',  # Zero Width Non-Joiner
    '\u200D',  # Zero Width Joiner
    '\u200E',  # Left-to-Right Mark
    '\u200F',  # Right-to-Left Mark
    '\uFEFF',  # Zero Width No-Break Space (BOM)
    '\u2060',  # Word Joiner
    '\u00AD',  # Soft Hyphen
    '\u2000',  # En Quad
    '\u2001',  # Em Quad
    '\u2002',  # En Space
    '\u2003',  # Em Space
    '\u2004',  # Three-Per-Em Space
    '\u2005',  # Four-Per-Em Space
    '\u2006',  # Six-Per-Em Space
    '\u2007',  # Figure Space
    '\u2008',  # Punctuation Space
    '\u2009',  # Thin Space
    '\u200A',  # Hair Space
    '\u202F',  # Narrow No-Break Space
    '\u205F',  # Medium Mathematical Space
    '\u3000',  # Ideographic Space
}

# Bidirectional overrides (used to visually reverse filenames or URLs)
BIDI_OVERRIDES = {
    '\u202A',  # LRE
    '\u202B',  # RLE
    '\u202C',  # PDF
    '\u202D',  # LRO
    '\u202E',  # RLO
    '\u2066',  # LRI
    '\u2067',  # RLI
    '\u2068',  # FSI
    '\u2069',  # PDI
}

# High-frequency Cyrillic and Greek homoglyphs targeting Latin alphabet
HOMOGLYPH_MAP = {
    # Cyrillic
    '\u0430': 'a', '\u0410': 'A',  # Cyrillic small/cap A
    '\u0441': 'c', '\u0421': 'C',  # Cyrillic small/cap Es
    '\u0435': 'e', '\u0415': 'E',  # Cyrillic small/cap Ie
    '\u0456': 'i', '\u0406': 'I',  # Cyrillic small/cap Byelorussian-Ukrainian I
    '\u0458': 'j', '\u0408': 'J',  # Cyrillic small/cap Je
    '\u043E': 'o', '\u041E': 'O',  # Cyrillic small/cap O
    '\u0440': 'p', '\u0420': 'P',  # Cyrillic small/cap Er
    '\u0455': 's', '\u0405': 'S',  # Cyrillic small/cap Dze
    '\u0445': 'x', '\u0425': 'X',  # Cyrillic small/cap Kha
    '\u0443': 'y', '\u0423': 'Y',  # Cyrillic small/cap U
    '\u0432': 'b', '\u0412': 'B',  # Cyrillic small/cap Ve
    '\u043D': 'h', '\u041D': 'H',  # Cyrillic small/cap En
    '\u043C': 'm', '\u041C': 'M',  # Cyrillic small/cap Em
    '\u0442': 't', '\u0422': 'T',  # Cyrillic small/cap Te
    # Greek
    '\u03B1': 'a', '\u0391': 'A',  # Greek alpha
    '\u03BF': 'o', '\u039F': 'O',  # Greek omicron
    '\u03BD': 'v', '\u039D': 'N',  # Greek nu
    '\u03C1': 'p', '\u03A1': 'P',  # Greek rho
    '\u03BA': 'k', '\u039A': 'K',  # Greek kappa
}


class NormalizationResult:
    def __init__(self, original: str, normalized: str, anomalies: List[Dict[str, str]]):
        self.original = original
        self.normalized = normalized
        self.anomalies = anomalies

    @property
    def has_evasion(self) -> bool:
        return len(self.anomalies) > 0

    def to_dict(self) -> dict:
        return {
            "original": self.original,
            "normalized": self.normalized,
            "anomalies": self.anomalies,
            "has_evasion": self.has_evasion,
        }


def normalize_text(text: str) -> NormalizationResult:
    """
    Normalizes arbitrary text by:
    1. Detecting and stripping Plane 14 tag-smuggling characters (U+E0000 - U+E007F).
    2. Detecting and stripping zero-width and invisible control characters.
    3. Detecting and stripping bidirectional override characters.
    4. Canonical Unicode decomposition & recomposition (NFKC).
    5. Transliterating known homoglyphs into their ASCII counterparts for NLP matching.
    """
    if not text:
        return NormalizationResult("", "", [])

    anomalies: List[Dict[str, str]] = []
    chars = []

    for idx, ch in enumerate(text):
        cp = ord(ch)

        # 1. Plane 14 Tag Smuggling Detection (U+E0000 to U+E007F)
        if 0xE0000 <= cp <= 0xE007F:
            anomalies.append({
                "type": "TAG_SMUGGLING",
                "char": f"U+{cp:05X}",
                "position": idx,
                "description": "Unicode Plane 14 tag smuggling character detected and removed"
            })
            continue

        # 2. Bidirectional Overrides Detection
        if ch in BIDI_OVERRIDES:
            anomalies.append({
                "type": "BIDI_OVERRIDE",
                "char": f"U+{cp:04X}",
                "position": idx,
                "description": f"Bidirectional override character '{unicodedata.name(ch, 'BIDI')}' detected"
            })
            continue

        # 3. Zero-width and invisible characters
        if ch in ZERO_WIDTH_CHARS:
            anomalies.append({
                "type": "ZERO_WIDTH_CHARACTER",
                "char": f"U+{cp:04X}",
                "position": idx,
                "description": f"Zero-width or invisible character '{unicodedata.name(ch, 'ZERO_WIDTH')}' stripped"
            })
            continue

        # 4. Homoglyphs
        if ch in HOMOGLYPH_MAP:
            mapped = HOMOGLYPH_MAP[ch]
            anomalies.append({
                "type": "HOMOGLYPH_LOOKALIKE",
                "char": f"U+{cp:04X} ({ch})",
                "position": idx,
                "replacement": mapped,
                "description": f"Non-Latin homoglyph '{ch}' replaced with Latin '{mapped}'"
            })
            chars.append(mapped)
            continue

        chars.append(ch)

    reconstructed = "".join(chars)
    # Apply NFKC normalization
    nfkc_text = unicodedata.normalize("NFKC", reconstructed)

    return NormalizationResult(text, nfkc_text, anomalies)


def normalize_domain(domain_str: str) -> Tuple[str, List[Dict[str, str]]]:
    """
    Normalizes domain names, handling Punycode (IDNA) and homograph attacks.
    Returns (ascii_domain, list_of_anomalies).
    """
    if not domain_str:
        return "", []

    domain_str = domain_str.strip().lower()
    anomalies: List[Dict[str, str]] = []

    # Check for Punycode
    if "xn--" in domain_str:
        try:
            decoded = domain_str.encode("ascii").decode("idna")
            anomalies.append({
                "type": "PUNYCODE_IDNA",
                "char": domain_str,
                "description": f"Punycode encoded domain decoded to internationalized domain: {decoded}"
            })
            # Also test the decoded representation for homoglyphs
            norm_res = normalize_text(decoded)
            if norm_res.has_evasion:
                anomalies.extend(norm_res.anomalies)
            return domain_str, anomalies
        except Exception:
            anomalies.append({
                "type": "MALFORMED_PUNYCODE",
                "char": domain_str,
                "description": "Failed to decode Punycode domain"
            })

    # Direct normalization of domain string
    norm_res = normalize_text(domain_str)
    if norm_res.has_evasion:
        anomalies.extend(norm_res.anomalies)

    return norm_res.normalized, anomalies
