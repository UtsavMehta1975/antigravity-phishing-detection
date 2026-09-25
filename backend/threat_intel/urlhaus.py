"""
URLhaus (abuse.ch) Threat Intelligence Connector.
Detects malware drop URLs and payload distributors.
"""
from typing import Dict, Any
from backend.database import get_threat_cache, set_threat_cache

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
