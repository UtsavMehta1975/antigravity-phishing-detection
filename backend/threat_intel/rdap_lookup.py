"""
ICANN RDAP Domain Registration Context Lookup Wrapper.
Queries ICANN RDAP endpoints to discover:
- Domain creation date and domain age in days
- Registrar identity
- Newly Registered Domain (NRD) status (< 30 days old)
"""
import re
from datetime import datetime, timezone
from typing import Dict, Any, Optional
import httpx
from backend.config import NEW_DOMAIN_AGE_DAYS_THRESHOLD
from backend.database import get_threat_cache, set_threat_cache

class RDAPLookup:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    async def lookup_domain(self, domain: str) -> Dict[str, Any]:
        domain = domain.lower().strip()
        if not domain or "." not in domain:
            return {"domain": domain, "status": "INVALID", "age_days": None}

        # Check local DB cache first
        cached = get_threat_cache(f"rdap:{domain}")
        if cached:
            return cached["details"]

        result = {
            "domain": domain,
            "registrar": "Unknown",
            "registration_date": None,
            "age_days": None,
            "is_newly_registered": False,
            "risk_score": 0.0,
            "anomalies": []
        }

        # Query public ICANN RDAP bootstrap
        rdap_url = f"https://rdap.org/domain/{domain}"
        try:
            async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as client:
                resp = await client.get(rdap_url)
                if resp.status_code == 200:
                    data = resp.json()

                    # Extract registrar
                    entities = data.get("entities", [])
                    for entity in entities:
                        roles = entity.get("roles", [])
                        if "registrar" in roles:
                            vcard = entity.get("vcardArray", [])
                            if len(vcard) > 1:
                                for item in vcard[1]:
                                    if item[0] == "fn":
                                        result["registrar"] = item[3]
                                        break

                    # Extract registration event
                    events = data.get("events", [])
                    for ev in events:
                        if ev.get("eventAction") in ["registration", "created"]:
                            date_str = ev.get("eventDate")
                            result["registration_date"] = date_str
                            try:
                                # Parse ISO date
                                dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                                now = datetime.now(timezone.utc)
                                age_days = (now - dt).days
                                result["age_days"] = age_days

                                if age_days < NEW_DOMAIN_AGE_DAYS_THRESHOLD:
                                    result["is_newly_registered"] = True
                                    result["risk_score"] = 35.0
                                    result["anomalies"].append({
                                        "category": "NEWLY_REGISTERED_DOMAIN",
                                        "detail": f"Domain registered only {age_days} days ago (< {NEW_DOMAIN_AGE_DAYS_THRESHOLD} days threshold), typical of disposable attack infrastructure",
                                        "severity": "HIGH",
                                        "weight": 35.0
                                    })
                            except Exception:
                                pass
                            break
        except Exception:
            # Offline or timeout fallback: Heuristic estimation
            pass

        # Cache result
        set_threat_cache(
            indicator=f"rdap:{domain}",
            indicator_type="domain_rdap",
            source="icann_rdap",
            is_malicious=result["is_newly_registered"],
            details=result
        )

        return result
