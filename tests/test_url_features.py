"""
Unit tests for URL feature extraction, Shannon entropy, brand impersonation, and IP evasions.
"""
import pytest
from backend.parsers.url_extractor import (
    calculate_shannon_entropy, levenshtein_ratio, is_ip_address,
    URLAnalysisResult
)

def test_shannon_entropy_calculation():
    # Low entropy regular text
    low_entropy = calculate_shannon_entropy("google.com")
    # High entropy DGA domain
    high_entropy = calculate_shannon_entropy("x8q9w2z7p1k4m0v.top")

    assert high_entropy > low_entropy
    assert high_entropy > 3.5

def test_ip_address_detection():
    assert is_ip_address("192.168.1.1") is True
    assert is_ip_address("10.0.0.1") is True
    assert is_ip_address("0x7f000001") is True
    assert is_ip_address("microsoft.com") is False

def test_brand_impersonation_detection():
    # Typosquatting of Microsoft and PayPal
    ms_spoof = URLAnalysisResult("http://login-microsoft-security-verify.top/auth")
    res1 = ms_spoof.analyze()
    assert any(a["category"] == "BRAND_IMPERSONATION" for a in res1["anomalies"])
    assert res1["risk_score"] >= 40.0

    pp_spoof = URLAnalysisResult("http://paypa1-account-update.xyz/signin")
    res2 = pp_spoof.analyze()
    assert res2["risk_score"] >= 35.0

def test_benign_url():
    clean_url = URLAnalysisResult("https://www.google.com/search?q=cybersecurity")
    res = clean_url.analyze()
    assert res["risk_score"] < 25.0
