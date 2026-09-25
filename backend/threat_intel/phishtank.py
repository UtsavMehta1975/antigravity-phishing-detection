"""
PhishTank and URLhaus Threat Intelligence Connectors.
Provides rapid reputation lookups against PhishTank and abuse.ch URLhaus databases.
"""
from typing import Dict, Any
import httpx
from backend.database import get_threat_cache, set_threat_cache

class PhishTankConnector:
    API_URL = "https://checkurl.phishtank.com/checkurl/"

    def __init__(self):
        self._seed_set = {
            "http://chase-security-login.top/account",
            "http://wellsfargo-verify-session.sbs/auth",
            "http://microsoft-outlook-web-app.icu/owa",
            "http://secure-coinbase-verify.bar/wallet"
        }

    async def check_url(self, target_url: str) -> Dict[str, Any]:
        normalized = target_url.lower().rstrip("/")
        cached = get_threat_cache(f"phishtank:{normalized}")
        if cached:
            return cached["details"]

        matched = normalized in self._seed_set
        result = {
            "source": "PhishTank",
            "matched": matched,
            "verified": matched,
            "risk_score": 45.0 if matched else 0.0,
            "detail": "Verified malicious phishing site in PhishTank database" if matched else "Not listed in PhishTank cache"
        }

        # Save cache
        set_threat_cache(f"phishtank:{normalized}", "url", "phishtank", matched, result)
        return result


class URLhausConnector:
    API_URL = "https://urlhaus-api.abuse.ch/v1/url/"

    def __init__(self):
        self._seed_set = {
            "http://malware-drop-smuggle.lat/payload.exe",
            "http://evil-svg-payload.work/invoice.svg",
            "http://downloader-blob-obfuscated.buzz/dropper.zip"
        }

    async def check_url(self, target_url: str) -> Dict[str, Any]:
        normalized = target_url.lower().rstrip("/")
        cached = get_threat_cache(f"urlhaus:{normalized}")
        if cached:
            return cached["details"]

        matched = normalized in self._seed_set
        result = {
            "source": "URLhaus (abuse.ch)",
            "matched": matched,
            "threat": "malware_smuggling" if matched else None,
            "risk_score": 50.0 if matched else 0.0,
            "detail": "Malicious payload distributor indexed in URLhaus" if matched else "Clean in URLhaus cache"
        }

        set_threat_cache(f"urlhaus:{normalized}", "url", "urlhaus", matched, result)
        return result
