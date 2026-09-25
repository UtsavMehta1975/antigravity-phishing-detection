"""
Explainable AI (XAI) Engine matching NIST Four Principles of Explainable AI:
1. Explanation: Evidence-backed reasoning detailing why the alert triggered.
2. Meaningfulness: Clear, understandable presentation for both end-users and SOC analysts.
3. Accuracy: Factually reflective of the features, graph provenance, and signatures observed.
4. Knowledge Limits: Explicit disclosure of boundary conditions (e.g., CAPTCHA evasion preventing crawler inspection).
"""
from typing import Dict, Any, List, Optional

class XAIEngine:
    @staticmethod
    def generate_explanation(
        scan_type: str,
        total_risk_score: float,
        all_anomalies: List[Dict[str, Any]],
        critical_path: List[str],
        destination_status: str = "ACTIVE",
        evasion_techniques: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        evasions = evasion_techniques or []

        # Determine overall verdict
        if destination_status == "UNKNOWN" or any("CAPTCHA" in ev for ev in evasions):
            if total_risk_score >= 35.0:
                verdict = "UNKNOWN_GUARDED"
                verdict_label = "High Risk - Guarded Target"
            else:
                verdict = "UNKNOWN"
                verdict_label = "Unresolved Evasion Wall"
        elif total_risk_score >= 70.0:
            verdict = "PHISHING"
            verdict_label = "Malicious Phishing Attack"
        elif total_risk_score >= 35.0:
            verdict = "CAUTION"
            verdict_label = "Suspicious Pretext / Caution"
        else:
            verdict = "BENIGN"
            verdict_label = "Legitimate / Low Risk"

        confidence_score = min(100.0, max(15.0, total_risk_score))

        # Top contributing risk factors
        sorted_anomalies = sorted(all_anomalies, key=lambda x: x.get("weight", 0.0), reverse=True)
        top_factors = [a.get("detail", "") for a in sorted_anomalies[:4]]

        # Construct NIST Four Principles Payload
        # Principle 1: Explanation
        explanation_summary = f"The automated engine assessed a risk score of {confidence_score:.1f}/100. "
        if top_factors:
            explanation_summary += "Key findings: " + "; ".join(top_factors) + "."
        else:
            explanation_summary += "No anomalous obfuscation, homoglyphs, or feed indicators detected."

        # Principle 2: Meaningfulness (Recipient-focused translation)
        if verdict in ["PHISHING", "UNKNOWN_GUARDED"]:
            meaningful_text = "This communication appears deceptive. It uses urgency or disguises destination links to trick you into submitting passwords or downloading malicious files."
        elif verdict == "CAUTION":
            meaningful_text = "This item has unusual attributes (such as a recently registered domain or mismatched sender headers) that warrant extra scrutiny before clicking."
        else:
            meaningful_text = "Standard domain security protocols (SPF/DKIM) and known reputation checks were satisfied without evasion signatures."

        # Principle 3: Accuracy
        accuracy_telemetry = {
            "evaluated_features_count": len(all_anomalies),
            "critical_path_length": len(critical_path),
            "highest_severity_anomaly": sorted_anomalies[0].get("category") if sorted_anomalies else "NONE",
            "evasion_techniques_flagged": evasions
        }

        # Principle 4: Knowledge Limits
        knowledge_limits = []
        if destination_status == "UNKNOWN":
            knowledge_limits.append(
                "Landing page is protected by a CAPTCHA or Cloudflare challenge wall; automated crawler could not render post-challenge DOM."
            )
        if any(a.get("category") == "NEWLY_REGISTERED_DOMAIN" for a in all_anomalies):
            knowledge_limits.append(
                "Domain was registered within the last 30 days, limiting historical reputation data."
            )
        if not knowledge_limits:
            knowledge_limits.append(
                "Assessment is bounded by current threat intelligence feeds and static attachment heuristics."
            )

        # Dual-Layer: Recipient View (Simplified human-first card)
        recipient_view = {
            "verdict": verdict,
            "badge_color": "crimson" if verdict in ["PHISHING", "UNKNOWN_GUARDED"] else ("amber" if verdict == "CAUTION" else "emerald"),
            "headline": verdict_label,
            "plain_reason": meaningful_text,
            "bullet_reasons": top_factors[:3] if top_factors else ["Authentication headers aligned with standard policies."],
            "recommended_action": "Do NOT click links, download attachments, or enter credentials. Report and isolate." if verdict != "BENIGN" else "Safe to proceed under standard organizational hygiene."
        }

        # Dual-Layer: Analyst View (Deep technical forensics)
        analyst_view = {
            "verdict": verdict,
            "confidence_score": confidence_score,
            "destination_status": destination_status,
            "evasion_techniques": evasions,
            "all_anomalies": sorted_anomalies,
            "critical_evidence_path": critical_path,
            "nist_evaluation": {
                "principle_1_explanation": explanation_summary,
                "principle_2_meaningfulness": meaningful_text,
                "principle_3_accuracy": accuracy_telemetry,
                "principle_4_knowledge_limits": knowledge_limits
            }
        }

        return {
            "verdict": verdict,
            "verdict_label": verdict_label,
            "confidence_score": confidence_score,
            "summary": explanation_summary,
            "recipient_view": recipient_view,
            "analyst_view": analyst_view
        }
