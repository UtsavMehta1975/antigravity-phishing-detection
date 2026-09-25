"""
PII Protection & Data Scrubbing Utilities.

All scan results stored in the database pass through this module first.
Scrubs sensitive personal data before persistence:
  - Email body text → SHA-256 hash only (body never stored)
  - URLs → truncated to 200 chars in storage
  - Email addresses in 'target' field → masked (user@domain → u***@domain)
  - Auto-prune: scans older than DATA_RETENTION_DAYS are purged on startup
"""
import re
import hashlib
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

DATA_RETENTION_DAYS = 30


def hash_pii_body(text: str) -> str:
    """Returns SHA-256 hex digest of text. Never store raw email bodies."""
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def mask_email_address(email: str) -> str:
    """Masks email address: alice@example.com → a***@example.com"""
    if "@" not in email:
        return email
    local, domain = email.split("@", 1)
    if len(local) <= 1:
        return f"{local}***@{domain}"
    return f"{local[0]}{'*' * min(len(local) - 1, 4)}@{domain}"


def truncate_url(url: str, max_len: int = 200) -> str:
    """Truncates URL for log storage to prevent unbounded DB growth."""
    if len(url) > max_len:
        return url[:max_len] + "...[truncated]"
    return url


def scrub_target(target: str) -> str:
    """
    Scrubs a scan target string for safe storage:
    - Truncates URLs
    - Masks email addresses
    """
    target = target.strip()

    # Check if it looks like an email address
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", target):
        return mask_email_address(target)

    # URL — truncate
    if target.startswith(("http://", "https://", "ftp://")):
        return truncate_url(target)

    return truncate_url(target)


def scrub_scan_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """
    Scrubs a complete scan record before DB storage.
    Modifies in-place and returns the scrubbed dict.
    """
    # Scrub target
    if "target" in record:
        record["target"] = scrub_target(str(record["target"]))

    # Scrub summary — remove any raw email body fragments
    if "summary" in record and isinstance(record["summary"], str):
        # Replace anything that looks like base64-encoded content (email body chunks)
        record["summary"] = re.sub(
            r"[A-Za-z0-9+/]{60,}={0,2}",
            "[base64-content-redacted]",
            record["summary"]
        )

    return record


def purge_old_scans(db_path: str) -> int:
    """
    Deletes scan records older than DATA_RETENTION_DAYS from the SQLite database.
    Returns the number of rows deleted.
    Called on application startup.
    """
    import sqlite3
    cutoff = datetime.utcnow() - timedelta(days=DATA_RETENTION_DAYS)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    try:
        conn = sqlite3.connect(db_path, timeout=10.0)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM scans WHERE created_at < ?", (cutoff_str,))
        deleted = cursor.rowcount
        conn.commit()
        conn.close()
        return deleted
    except Exception:
        return 0
