"""
Security Middleware Tests — SSRF Guard, Input Validation, Rate Limiter, PII Scrubber.
Covers the security controls added for hackathon judging criteria.
All tests use controlled, non-destructive inputs (no live network calls).
"""
import pytest
from backend.middleware.validators import (
    validate_scan_url, validate_email_upload, validate_attachment_upload,
    MAX_URL_LENGTH
)
from backend.middleware.pii_scrubber import (
    hash_pii_body, mask_email_address, truncate_url, scrub_target
)
from backend.cache import LRUCache


# ===========================================================================
# SSRF Guard Tests
# ===========================================================================
class TestSSRFGuard:

    def test_blocks_rfc1918_10_network(self):
        """10.x.x.x (RFC 1918) must be blocked."""
        err = validate_scan_url("http://10.0.0.1/admin")
        assert err is not None
        assert "SSRF" in err

    def test_blocks_rfc1918_192_168(self):
        """192.168.x.x (RFC 1918) must be blocked."""
        err = validate_scan_url("http://192.168.1.1/login")
        assert err is not None
        assert "SSRF" in err

    def test_blocks_rfc1918_172_16(self):
        """172.16.x.x (RFC 1918) must be blocked."""
        err = validate_scan_url("http://172.16.0.1/secret")
        assert err is not None
        assert "SSRF" in err

    def test_blocks_loopback(self):
        """127.0.0.1 loopback must be blocked."""
        err = validate_scan_url("http://127.0.0.1:8080/api")
        assert err is not None
        assert "SSRF" in err

    def test_blocks_localhost_hostname(self):
        """localhost must be blocked."""
        err = validate_scan_url("http://localhost/admin")
        # Note: 'localhost' resolves to 127.0.0.1 — SSRF guard catches by name too
        assert err is not None  # Either SSRF or invalid host

    def test_blocks_aws_metadata(self):
        """AWS EC2 metadata endpoint must be blocked."""
        err = validate_scan_url("http://169.254.169.254/latest/meta-data/")
        assert err is not None

    def test_blocks_file_scheme(self):
        """file:// scheme must be blocked."""
        err = validate_scan_url("file:///etc/passwd")
        assert err is not None
        assert "file" in err.lower() or "scheme" in err.lower()

    def test_blocks_ftp_scheme(self):
        """ftp:// scheme must be blocked."""
        err = validate_scan_url("ftp://malware.example.com/payload.zip")
        assert err is not None

    def test_allows_public_https_url(self):
        """Valid public HTTPS URL must pass."""
        err = validate_scan_url("https://google.com")
        assert err is None

    def test_allows_public_http_url(self):
        """Valid public HTTP URL must pass."""
        err = validate_scan_url("http://example.com/page")
        assert err is None

    def test_allows_phishing_url_for_analysis(self):
        """Phishing URLs (public) must be allowed through for scanning."""
        err = validate_scan_url("http://login-microsoft-secure.top/auth")
        assert err is None

    def test_rejects_too_long_url(self):
        """URL exceeding MAX_URL_LENGTH must be rejected."""
        long_url = "http://example.com/" + "a" * (MAX_URL_LENGTH + 100)
        err = validate_scan_url(long_url)
        assert err is not None
        assert "length" in err.lower() or "exceed" in err.lower()

    def test_rejects_empty_url(self):
        """Empty URL must be rejected."""
        err = validate_scan_url("")
        assert err is not None

    def test_rejects_whitespace_only_url(self):
        """Whitespace-only URL must be rejected."""
        err = validate_scan_url("   ")
        assert err is not None


# ===========================================================================
# File Upload Validation Tests
# ===========================================================================
class TestFileUploadValidation:

    def test_accepts_eml_extension(self):
        """Valid .eml file must be accepted."""
        err = validate_email_upload("test.eml", b"From: a@b.com\n\nBody")
        assert err is None

    def test_accepts_msg_extension(self):
        """Valid .msg file must be accepted."""
        err = validate_email_upload("test.msg", b"content")
        assert err is None

    def test_rejects_exe_as_email(self):
        """Executable disguised as email must be rejected."""
        err = validate_email_upload("malware.exe", b"MZ...")
        assert err is not None

    def test_rejects_oversized_email(self):
        """Email file over 10MB must be rejected."""
        big_content = b"X" * (11 * 1024 * 1024)
        err = validate_email_upload("big.eml", big_content)
        assert err is not None
        assert "size" in err.lower() or "MB" in err

    def test_accepts_pdf_attachment(self):
        """PDF attachment must be accepted."""
        err = validate_attachment_upload("invoice.pdf", b"%PDF-1.4 content")
        assert err is None

    def test_accepts_exe_attachment_for_analysis(self):
        """EXE attachment must be accepted for malware analysis."""
        err = validate_attachment_upload("payload.exe", b"MZ payload")
        assert err is None

    def test_rejects_oversized_attachment(self):
        """Attachment over 5MB must be rejected."""
        big = b"X" * (6 * 1024 * 1024)
        err = validate_attachment_upload("big.pdf", big)
        assert err is not None


# ===========================================================================
# PII Scrubber Tests
# ===========================================================================
class TestPIIScrubber:

    def test_hash_pii_body_deterministic(self):
        """Same input always produces same SHA-256 hash."""
        text = "Sensitive email body"
        assert hash_pii_body(text) == hash_pii_body(text)

    def test_hash_pii_body_is_64_chars(self):
        """SHA-256 hex digest is always 64 characters."""
        result = hash_pii_body("test content")
        assert len(result) == 64

    def test_mask_email_address(self):
        """Email address is masked correctly."""
        masked = mask_email_address("alice@example.com")
        assert "alice" not in masked
        assert "@example.com" in masked
        assert "a" in masked  # First char preserved

    def test_truncate_url(self):
        """URL longer than max_len is truncated."""
        long_url = "https://example.com/" + "a" * 300
        result = truncate_url(long_url, max_len=100)
        assert len(result) <= 100 + len("...[truncated]")
        assert "truncated" in result

    def test_short_url_not_truncated(self):
        """Short URL is not modified."""
        url = "https://example.com/page"
        assert truncate_url(url) == url

    def test_scrub_target_email(self):
        """Email address target gets masked."""
        result = scrub_target("victim@company.com")
        assert "victim" not in result

    def test_scrub_target_url(self):
        """Long URL target gets truncated."""
        result = scrub_target("https://example.com/" + "x" * 300)
        assert "truncated" in result


# ===========================================================================
# LRU Cache Tests
# ===========================================================================
class TestLRUCache:

    def test_cache_set_and_get(self):
        """Basic set and get works."""
        cache = LRUCache(max_size=10, ttl_seconds=60)
        cache.set("url1", {"verdict": "PHISHING"})
        result = cache.get("url1")
        assert result is not None
        assert result["verdict"] == "PHISHING"

    def test_cache_miss_returns_none(self):
        """Missing key returns None."""
        cache = LRUCache(max_size=10, ttl_seconds=60)
        assert cache.get("nonexistent") is None

    def test_cache_evicts_lru_at_capacity(self):
        """LRU entry is evicted when cache is full."""
        cache = LRUCache(max_size=3, ttl_seconds=60)
        cache.set("a", 1)
        cache.set("b", 2)
        cache.set("c", 3)
        cache.set("d", 4)  # Evicts "a"
        assert cache.get("a") is None  # Evicted
        assert cache.get("d") == 4     # Still present

    def test_cache_expiry(self):
        """Entries expire after TTL."""
        import time
        cache = LRUCache(max_size=10, ttl_seconds=0)  # Instant TTL
        cache.set("key", "value")
        time.sleep(0.01)
        assert cache.get("key") is None  # Expired

    def test_cache_stats(self):
        """Stats correctly track hits and misses."""
        cache = LRUCache(max_size=10, ttl_seconds=60)
        cache.set("k", "v")
        cache.get("k")     # hit
        cache.get("miss")  # miss
        stats = cache.stats()
        assert stats["cache_hits"] == 1
        assert stats["cache_misses"] == 1
        assert stats["hit_rate_percent"] == 50.0
