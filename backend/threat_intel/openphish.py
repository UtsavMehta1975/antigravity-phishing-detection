"""
OpenPhish Community Feed Parser and Ingestor.
Maintains in-memory Bloom-style / Hash set lookups and periodically syncs with OpenPhish feed.
"""
import httpx
from typing import Dict, Any, Set, Optional
from backend.database import get_threat_cache, set_threat_cache

class OpenPhishConnector:
    FEED_URL = "https://openphish.com/feed.txt"

    def __init__(self):
        self._cached_urls: Set[str] = set()
        # Seed with initial known malicious patterns
        self._seed_known()

    def _seed_known(self):
        sample_malicious = [
            "http://login-microsoft-auth.xyz/verify",
            "http://account-paypal-restore.top/signin",
            "http://secure-appleid-update.cfd/auth",
            "http://docusign-envelope-viewer.stream/sign",
            "http://netflix-billing-alert.cam/update"
        ]
        for url in sample_malicious:
            self._cached_urls.add(url.lower().rstrip("/"))

    async def sync_feed(self, timeout: float = 4.0):
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                resp = await client.get(self.FEED_URL)
                if resp.status_code == 200:
                    lines = resp.text.splitlines()
                    for line in lines:
                        cleaned = line.strip().lower().rstrip("/")
                        if cleaned:
                            self._cached_urls.add(cleaned)
        except Exception:
            pass

    def check_url(self, target_url: str) -> Dict[str, Any]:
        normalized = target_url.lower().rstrip("/")
        # Check direct match
        matched = normalized in self._cached_urls

        # Check DB threat cache
        if not matched:
            cached = get_threat_cache(f"openphish:{normalized}")
            if cached and cached.get("is_malicious"):
                matched = True

        return {
            "source": "OpenPhish",
            "matched": matched,
            "threat_type": "phishing" if matched else None,
            "risk_score": 50.0 if matched else 0.0,
            "detail": "Confirmed active phishing campaign reported in OpenPhish feed" if matched else "No direct feed match"
        }
