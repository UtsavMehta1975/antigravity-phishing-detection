"""
Unified Threat Intelligence Feed Manager.
Coordinates concurrent async queries across RDAP, OpenPhish, PhishTank, URLhaus,
SafeBrowsing, and the DestinationResolver.
"""
import asyncio
from typing import Dict, Any, List
from backend.threat_intel.rdap_lookup import RDAPLookup
from backend.threat_intel.openphish import OpenPhishConnector
from backend.threat_intel.phishtank import PhishTankConnector
from backend.threat_intel.urlhaus import URLhausConnector
from backend.threat_intel.safebrowsing import SafeBrowsingClient
from backend.threat_intel.destination_resolver import DestinationResolver
from backend.database import get_threat_cache

class ThreatFeedManager:
    def __init__(self):
        self.rdap = RDAPLookup()
        self.openphish = OpenPhishConnector()
        self.phishtank = PhishTankConnector()
        self.urlhaus = URLhausConnector()
        self.safebrowsing = SafeBrowsingClient()
        self.resolver = DestinationResolver()

    async def enrich_url(self, target_url: str, domain: str) -> Dict[str, Any]:
        """Runs all threat intel enrichment and destination resolving in parallel."""
        # 1. Resolve destination and redirects
        resolve_task = asyncio.create_task(self.resolver.resolve(target_url))

        # 2. RDAP lookup for domain age and registrar
        rdap_task = asyncio.create_task(self.rdap.lookup_domain(domain))

        # 3. Threat feeds
        phishtank_task = asyncio.create_task(self.phishtank.check_url(target_url))
        urlhaus_task = asyncio.create_task(self.urlhaus.check_url(target_url))
        safebrowsing_task = asyncio.create_task(self.safebrowsing.check_url(target_url))

        # Synchronous OpenPhish memory check
        openphish_result = self.openphish.check_url(target_url)

        # Local Threat Cache Check (e.g. Kaggle Dataset)
        kaggle_result = {}
        normalized = target_url.lower().strip()
        no_scheme = normalized.replace("http://", "").replace("https://", "")
        cached = get_threat_cache(normalized) or get_threat_cache(no_scheme)
        if cached and cached.get("is_malicious"):
            kaggle_result = {
                "matched": True,
                "source": cached.get("source"),
                "details": cached.get("details", {})
            }

        # Gather async tasks
        resolve_res, rdap_res, pt_res, uh_res, sb_res = await asyncio.gather(
            resolve_task, rdap_task, phishtank_task, urlhaus_task, safebrowsing_task,
            return_exceptions=True
        )

        resolve_data = resolve_res if isinstance(resolve_res, dict) else {}
        rdap_data = rdap_res if isinstance(rdap_res, dict) else {}
        pt_data = pt_res if isinstance(pt_res, dict) else {}
        uh_data = uh_res if isinstance(uh_res, dict) else {}
        sb_data = sb_res if isinstance(sb_res, dict) else {}

        threat_matches = []
        if openphish_result.get("matched"):
            threat_matches.append(openphish_result)
        if pt_data.get("matched"):
            threat_matches.append(pt_data)
        if uh_data.get("matched"):
            threat_matches.append(uh_data)
        if sb_data.get("matched"):
            threat_matches.append(sb_data)
        if kaggle_result.get("matched"):
            threat_matches.append(kaggle_result)

        return {
            "resolution": resolve_data,
            "rdap": rdap_data,
            "threat_matches": threat_matches,
            "is_feed_positive": len(threat_matches) > 0,
            "destination_status": resolve_data.get("destination_status", "ACTIVE"),
            "evasion_technique": resolve_data.get("evasion_technique"),
            "redirect_hops": resolve_data.get("redirect_hops", [])
        }
