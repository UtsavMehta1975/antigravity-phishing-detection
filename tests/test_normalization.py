"""
Unit tests for Unicode, IDNA, Homoglyph, and Zero-Width / Tag-Block Normalization.
"""
import pytest
from backend.normalization import normalize_text, normalize_domain

def test_zero_width_character_stripping():
    # Insert Zero-Width Space (\u200B) and Zero-Width Non-Joiner (\u200C)
    evasive_text = "p\u200Ba\u200Cy\u200Dp\u200Ea\u200Fl"
    result = normalize_text(evasive_text)

    assert result.has_evasion is True
    assert result.normalized == "paypal"
    assert any(a["type"] == "ZERO_WIDTH_CHARACTER" for a in result.anomalies)

def test_tag_smuggling_plane_14_removal():
    # Insert Plane 14 tag characters (U+E0001, U+E0041)
    tag_smuggled = "m\U000E0001i\U000E0041crosoft"
    result = normalize_text(tag_smuggled)

    assert result.has_evasion is True
    assert result.normalized == "microsoft"
    assert any(a["type"] == "TAG_SMUGGLING" for a in result.anomalies)

def test_bidi_override_detection():
    # Right-to-Left Override (\u202E)
    bidi_str = "invoice_\u202Excod.exe"
    result = normalize_text(bidi_str)

    assert result.has_evasion is True
    assert any(a["type"] == "BIDI_OVERRIDE" for a in result.anomalies)

def test_homoglyph_cyrillic_transliteration():
    # Cyrillic small 'о' (U+043E) and 'а' (U+0430) inside "gооgle"
    homoglyph_domain = "g\u043E\u043Egle.com"
    norm_domain, anomalies = normalize_domain(homoglyph_domain)

    assert norm_domain == "google.com"
    assert len(anomalies) > 0
    assert any(a["type"] == "HOMOGLYPH_LOOKALIKE" for a in anomalies)

def test_punycode_decoding():
    # Punycode representation of apple.com with Cyrillic 'а' -> xn--pple-43a.com
    punycode_domain = "xn--pple-43a.com"
    norm_domain, anomalies = normalize_domain(punycode_domain)

    assert any(a["type"] == "PUNYCODE_IDNA" for a in anomalies)
