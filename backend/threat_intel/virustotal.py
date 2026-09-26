import httpx
import base64
from typing import Dict, Any
from backend.config import VIRUSTOTAL_API_KEY

class VirusTotalClient:
    def __init__(self):
        self.api_key = VIRUSTOTAL_API_KEY
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "x-apikey": self.api_key
        }

    async def check_url(self, target_url: str) -> Dict[str, Any]:
        if not self.api_key:
            return {"matched": False, "source": "VirusTotal", "error": "No API key"}

        url_id = base64.urlsafe_b64encode(target_url.encode()).decode().strip("=")
        endpoint = f"{self.base_url}/urls/{url_id}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                response = await client.get(endpoint, headers=self.headers)
                
                if response.status_code == 200:
                    data = response.json()
                    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0)
                    suspicious = stats.get("suspicious", 0)
                    
                    if malicious > 0 or suspicious > 2:
                        return {
                            "matched": True,
                            "source": "VirusTotal",
                            "details": {
                                "malicious_engines": malicious,
                                "suspicious_engines": suspicious,
                                "vt_link": f"https://www.virustotal.com/gui/url/{url_id}"
                            }
                        }
        except Exception as e:
            pass
            
        return {"matched": False, "source": "VirusTotal"}
