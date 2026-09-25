"""
AI Social Engineering & Semantic Pretext Analyzer (AI Security Copilot).
Analyzes psychological coercion, authority impersonation, urgency levers,
and generates structured forensic incident response recommendations.
Supports optional Google Gemini LLM API integration with automatic offline fallback.
"""
import os
import re
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

class AISecurityAdvisor:
    def __init__(self):
        self.gemini_api_key = os.environ.get("GEMINI_API_KEY", "")

    def analyze_social_engineering(self, text: str, indicators: List[str]) -> Dict[str, Any]:
        """Analyzes text for social engineering, urgency, and cognitive manipulation."""
        # Try live Gemini LLM if API key is provided
        if self.gemini_api_key:
            llm_res = self._call_gemini_llm(text, indicators)
            if llm_res:
                return llm_res

        # Fallback: High-speed local cognitive heuristic engine (works offline with 0 latency)
        return self._heuristic_analysis(text, indicators)

    def _call_gemini_llm(self, text: str, indicators: List[str]) -> Optional[Dict[str, Any]]:
        """Invokes Google Gemini 1.5 Flash via REST API for deep generative threat analysis."""
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={self.gemini_api_key}"
            prompt = (
                "You are an elite Cybersecurity Incident Response AI Copilot. Analyze the following target text/URL "
                f"and detected indicators: {indicators}.\nTarget: {text[:500]}\n\n"
                "Return a valid JSON object ONLY with the following exact keys:\n"
                "- manipulation_score: integer from 0 to 100\n"
                "- primary_pretext_category: string (e.g. 'Corporate IT Impersonation', 'Urgent Financial Coercion', 'Quishing Mobile Evasion', 'Credential Harvesting')\n"
                "- coercion_tactics_detected: list of strings (up to 4 short bullet tactics)\n"
                "- ai_behavioral_insight: string (2 sentences describing psychological manipulation)\n"
                "- ai_recommended_playbook: list of 4 actionable SOC containment steps"
            )
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.2, "response_mime_type": "application/json"}
            }
            req = urllib.request.Request(
                url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST"
            )
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    text_out = data["candidates"][0]["content"]["parts"][0]["text"]
                    parsed = json.loads(text_out)
                    parsed["ai_copilot_enabled"] = True
                    parsed["llm_provider"] = "Google Gemini 1.5 Flash (Cloud LLM)"
                    return parsed
        except Exception:
            pass
        return None

    def _heuristic_analysis(self, text: str, indicators: List[str]) -> Dict[str, Any]:
        """Local cognitive behavioral engine."""
        clean_text = text.lower()

        # Psychological Levers
        urgency_score = 0
        authority_score = 0
        financial_score = 0
        coercion_tactics = []

        # 1. Fear & Artificial Urgency
        urgency_terms = ["immediate", "24 hours", "suspended", "expired", "urgent", "terminate", "final notice", "critical", "compromised"]
        for term in urgency_terms:
            if term in clean_text:
                urgency_score += 15
                coercion_tactics.append(f"Artificial Time Constraint ('{term}')")

        # 2. Authority Impersonation
        authority_terms = ["microsoft", "it support", "security team", "administrator", "system alert", "bank", "compliance", "law enforcement", "docusign", "corporate", "it department"]
        for term in authority_terms:
            if term in clean_text:
                authority_score += 20
                coercion_tactics.append(f"Impersonation of Authority Figure ('{term}')")

        # 3. Financial & Scarcity Traps
        financial_terms = ["invoice", "wire transfer", "payment", "bank", "selectedbank", "payroll", "refund", "billing", "cryptocurrency", "wallet"]
        for term in financial_terms:
            if term in clean_text:
                financial_score += 20
                coercion_tactics.append(f"Financial / Billing Coercion ('{term}')")

        total_manipulation = min(98.0, max(10.0, float(urgency_score + authority_score + financial_score)))

        # Categorize Pretext
        if (authority_score >= 20 and urgency_score >= 15) or (authority_score >= 40):
            pretext_type = "Corporate Authority & IT Impersonation"
            explanation = "The communication leverages institutional authority combined with time pressure to trigger cognitive overload and force credential disclosure."
        elif financial_score >= 20:
            pretext_type = "Financial & Billing Coercion"
            explanation = "The attacker simulates a critical invoice or banking action to exploit financial anxiety and prompt impulsive authorization."
        elif any("QUISHING" in ind for ind in indicators):
            pretext_type = "Multi-Modal Quishing Evasion"
            explanation = "The attack steers the victim from protected workstation endpoints to personal mobile devices via QR codes."
        elif any("SMUGGLING" in ind for ind in indicators):
            pretext_type = "Client-Side In-Memory Payload Smuggling"
            explanation = "Malware delivery masked inside vector graphics to bypass network edge firewalls."
        else:
            pretext_type = "Standard Phishing Pretext"
            explanation = "Deceptive communication designed to guide the recipient toward unverified landing pages."

        # SOC Incident Response Playbook
        playbook = [
            "Isolate the endpoint if payload download was triggered.",
            "Revoke existing session tokens and enforce mandatory MFA re-authentication.",
            "Add sender domain and target host to firewall perimeter blocklist.",
            "Search mail logs across enterprise for identical subject and sender hashes."
        ]

        return {
            "ai_copilot_enabled": True,
            "llm_provider": "Built-in Cognitive AI Engine (Offline / Zero-Latency)",
            "manipulation_score": total_manipulation,
            "primary_pretext_category": pretext_type,
            "coercion_tactics_detected": list(set(coercion_tactics))[:4],
            "ai_behavioral_insight": explanation,
            "ai_recommended_playbook": playbook
        }

