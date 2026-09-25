"""
Unified Multi-Threaded / Async Pipeline for Phishing Detection.
Optimized for Apple Silicon M4 Pro:
- ThreadPoolExecutor / ProcessPoolExecutor utilizing all 12 CPU cores for CPU-heavy parsing
- Asyncio event loop for parallel threat enrichment, RDAP, and destination resolution
- Directed Evidence Graph construction
- NIST XAI Engine output generation
"""
import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List, Optional

from backend.config import RECOMMENDED_WORKERS, TORCH_DEVICE
from backend.parsers.email_parser import ParsedEmail
from backend.parsers.attachment_analyzer import AttachmentAnalysisResult
from backend.parsers.quishing_decoder import QuishingDecoder
from backend.parsers.url_extractor import URLAnalysisResult
from backend.threat_intel.feed_manager import ThreatFeedManager
from backend.graph_engine import EvidenceGraphBuilder
from backend.xai_engine import XAIEngine
from backend.database import save_scan
from backend.ai_engine.ml_classifier import MLURLClassifier
from backend.ai_engine.llm_advisor import AISecurityAdvisor
from backend.threat_intel.malware_signature_engine import MalwareSignatureEngine

class DetectionPipeline:
    def __init__(self):
        self.executor = ThreadPoolExecutor(max_workers=RECOMMENDED_WORKERS)
        self.quishing_decoder = QuishingDecoder()
        self.threat_manager = ThreatFeedManager()
        self.ml_classifier = MLURLClassifier()
        self.ai_advisor = AISecurityAdvisor()

    async def analyze_email(self, raw_eml_bytes: bytes) -> Dict[str, Any]:
        scan_id = f"scan_{uuid.uuid4().hex[:10]}"
        loop = asyncio.get_event_loop()

        # 1. Parse MIME message in worker thread
        def _parse_email():
            pe = ParsedEmail(raw_eml_bytes)
            return pe.parse()

        email_data = await loop.run_in_executor(self.executor, _parse_email)

        # 2. Multi-Modal Attachment Analysis in Parallel
        attachment_results = []
        raw_attachments = email_data.get("attachments", [])

        def _analyze_attachment(att):
            analyzer = AttachmentAnalysisResult(
                filename=att["filename"],
                content=att["data"],
                mime_type=att["content_type"]
            )
            res = analyzer.analyze()
            # Retain embedded images for Quishing scanner
            res["_embedded_images"] = analyzer.embedded_images
            return res

        if raw_attachments:
            att_tasks = [loop.run_in_executor(self.executor, _analyze_attachment, att) for att in raw_attachments]
            attachment_results = await asyncio.gather(*att_tasks)

        # 3. Quishing / QR Code Scanning (Email images + Attachment images)
        quishing_results = []
        images_to_scan = []
        for att_res in attachment_results:
            images_to_scan.extend(att_res.get("_embedded_images", []))

        def _scan_images():
            found_qrs = []
            for img_bytes in images_to_scan:
                decoded = self.quishing_decoder.decode_image_bytes(img_bytes)
                if decoded:
                    found_qrs.extend(decoded)
            return found_qrs

        if images_to_scan:
            quishing_results = await loop.run_in_executor(self.executor, _scan_images)

        # 4. Aggregate all target URLs (From email body, attachments, QR codes)
        candidate_urls = []
        for link in email_data.get("links", []):
            candidate_urls.append(link.get("href", ""))
        for att_res in attachment_results:
            candidate_urls.extend(att_res.get("extracted_urls", []))
        for qr in quishing_results:
            if qr.get("is_url"):
                candidate_urls.append(qr.get("payload", ""))

        candidate_urls = list(set([u for u in candidate_urls if u.startswith("http://") or u.startswith("https://")]))

        # 5. URL Feature Extraction & Threat Intel Enrichment
        url_results = []
        async def _enrich_single_url(target_url: str):
            def _extract_url_features():
                ue = URLAnalysisResult(target_url)
                return ue.analyze()

            url_feat = await loop.run_in_executor(self.executor, _extract_url_features)

            # Query Threat Intel & Destination Resolver in parallel
            domain = url_feat.get("domain", "")
            intel = await self.threat_manager.enrich_url(target_url, domain)

            url_feat.update({
                "destination_status": intel.get("destination_status", "ACTIVE"),
                "evasion_technique": intel.get("evasion_technique"),
                "redirect_hops": intel.get("redirect_hops", []),
                "rdap_age_days": intel.get("rdap", {}).get("age_days"),
                "threat_matches": intel.get("threat_matches", [])
            })

            # Add RDAP anomalies if any
            if intel.get("rdap", {}).get("anomalies"):
                url_feat["anomalies"].extend(intel["rdap"]["anomalies"])
                url_feat["risk_score"] = min(100.0, url_feat["risk_score"] + 25.0)

            # Add feed positive boost
            if intel.get("is_feed_positive"):
                url_feat["risk_score"] = 100.0

            # Add evasion boost if UNKNOWN
            if intel.get("destination_status") == "UNKNOWN":
                url_feat["risk_score"] = max(url_feat["risk_score"], 65.0)

            return url_feat

        if candidate_urls:
            url_tasks = [_enrich_single_url(u) for u in candidate_urls[:10]]
            url_results = await asyncio.gather(*url_tasks)

        # 6. Aggregate Anomalies & Calculate Global Risk Score
        all_anomalies: List[Dict[str, Any]] = []
        all_anomalies.extend(email_data.get("anomalies", []))
        for att in attachment_results:
            all_anomalies.extend(att.get("anomalies", []))
        for qr in quishing_results:
            all_anomalies.append({
                "category": "QUISHING_VECTOR",
                "detail": qr.get("detail", "Embedded QR code detected"),
                "severity": "HIGH",
                "weight": 35.0
            })
        for u in url_results:
            all_anomalies.extend(u.get("anomalies", []))

        # Check for evasions / UNKNOWN state
        evasion_techniques = []
        global_dest_status = "ACTIVE"
        for u in url_results:
            if u.get("destination_status") == "UNKNOWN":
                global_dest_status = "UNKNOWN"
            if u.get("evasion_technique"):
                evasion_techniques.append(u.get("evasion_technique"))

        for att in attachment_results:
            if att.get("smuggling_detected"):
                evasion_techniques.append("HTML_SVG_SMUGGLING")

        # Global risk aggregation
        total_risk = sum(a.get("weight", 0.0) for a in all_anomalies)
        if url_results:
            max_url_risk = max((u.get("risk_score", 0.0) for u in url_results), default=0.0)
            total_risk = max(total_risk, max_url_risk)
        total_risk = min(100.0, round(total_risk, 1))

        # 7. Construct Evidence Graph
        evidence_graph = EvidenceGraphBuilder.build_from_email_analysis(
            email_data=email_data,
            attachment_results=attachment_results,
            quishing_results=quishing_results,
            url_results=url_results
        )
        graph_dict = evidence_graph.to_dict()

        # 8. NIST Explainable AI Evaluation
        xai_payload = XAIEngine.generate_explanation(
            scan_type="EMAIL",
            total_risk_score=total_risk,
            all_anomalies=all_anomalies,
            critical_path=graph_dict.get("critical_risk_path", []),
            destination_status=global_dest_status,
            evasion_techniques=list(set(evasion_techniques))
        )

        # 9. Deep Malware Signature & Multi-Engine VirusTotal Attribution
        target_str = f"{email_data.get('subject', '')} {' '.join(u.get('url', '') for u in url_results)}"
        malware_intel = MalwareSignatureEngine.scan_for_malware(
            target_str=target_str,
            anomalies=all_anomalies,
            risk_score=total_risk,
            evasions=list(set(evasion_techniques))
        )
        if malware_intel.get("is_virus_detected"):
            xai_payload["recipient_view"]["exact_virus_name"] = malware_intel.get("exact_virus_name")
            xai_payload["recipient_view"]["threat_category"] = malware_intel.get("threat_category")

        # 10. AI Social Engineering & Pretext Copilot Analysis
        ai_copilot = self.ai_advisor.analyze_social_engineering(
            text=f"{email_data.get('subject', '')} {email_data.get('body_plain', '')}",
            indicators=[a.get("category", "") for a in all_anomalies]
        )
        xai_payload["recipient_view"]["ai_pretext"] = ai_copilot.get("primary_pretext_category")
        xai_payload["recipient_view"]["ai_manipulation_score"] = ai_copilot.get("manipulation_score")

        clean_attachments = []
        for att in attachment_results:
            clean_att = {k: v for k, v in att.items() if not k.startswith("_")}
            clean_attachments.append(clean_att)

        full_analyst_data = {
            "email_metadata": {
                "subject": email_data.get("subject"),
                "from": email_data.get("from"),
                "reply_to": email_data.get("reply_to"),
                "auth_results": email_data.get("auth_results"),
                "hops": email_data.get("hops")
            },
            "attachments": clean_attachments,
            "quishing": quishing_results,
            "urls": url_results,
            "ai_copilot": ai_copilot,
            "malware_intel": malware_intel,
            "hardware_accel": {"m4_cores": RECOMMENDED_WORKERS, "device": TORCH_DEVICE},
            **xai_payload["analyst_view"]
        }

        # 10. Persist to SQLite
        save_scan(
            scan_id=scan_id,
            scan_type="EMAIL",
            target=email_data.get("subject") or "EML Email",
            verdict=xai_payload["verdict"],
            confidence_score=xai_payload["confidence_score"],
            summary=xai_payload["summary"],
            recipient_data=xai_payload["recipient_view"],
            analyst_data=full_analyst_data,
            graph_data=graph_dict,
            evasions=list(set(evasion_techniques))
        )

        return {
            "scan_id": scan_id,
            "scan_type": "EMAIL",
            "verdict": xai_payload["verdict"],
            "verdict_label": xai_payload["verdict_label"],
            "confidence_score": xai_payload["confidence_score"],
            "summary": xai_payload["summary"],
            "recipient_view": xai_payload["recipient_view"],
            "analyst_view": full_analyst_data,
            "evidence_graph": graph_dict
        }

    async def analyze_url(self, raw_url: str) -> Dict[str, Any]:
        scan_id = f"scan_{uuid.uuid4().hex[:10]}"
        loop = asyncio.get_event_loop()

        def _extract():
            ue = URLAnalysisResult(raw_url)
            return ue.analyze()

        url_feat = await loop.run_in_executor(self.executor, _extract)

        domain = url_feat.get("domain", "")
        intel = await self.threat_manager.enrich_url(raw_url, domain)

        url_feat.update({
            "destination_status": intel.get("destination_status", "ACTIVE"),
            "evasion_technique": intel.get("evasion_technique"),
            "redirect_hops": intel.get("redirect_hops", []),
            "rdap_age_days": intel.get("rdap", {}).get("age_days"),
            "threat_matches": intel.get("threat_matches", [])
        })

        if intel.get("rdap", {}).get("anomalies"):
            url_feat["anomalies"].extend(intel["rdap"]["anomalies"])
            url_feat["risk_score"] = min(100.0, url_feat["risk_score"] + 25.0)

        if intel.get("is_feed_positive"):
            url_feat["risk_score"] = 100.0

        if intel.get("destination_status") == "UNKNOWN":
            url_feat["risk_score"] = max(url_feat["risk_score"], 65.0)

        # AI & Machine Learning Evaluation
        ml_prediction = self.ml_classifier.predict(raw_url)
        ai_copilot = self.ai_advisor.analyze_social_engineering(
            text=raw_url,
            indicators=[a.get("category", "") for a in url_feat.get("anomalies", [])]
        )
        if ml_prediction.get("phishing_probability", 0.0) >= 65.0:
            url_feat["risk_score"] = max(url_feat["risk_score"], ml_prediction["phishing_probability"])

        # Build Graph
        evidence_graph = EvidenceGraphBuilder.build_from_url_analysis(url_feat)
        graph_dict = evidence_graph.to_dict()

        evasions = [intel.get("evasion_technique")] if intel.get("evasion_technique") else []

        # Malware Signature & VirusTotal Multi-Engine Attribution
        malware_intel = MalwareSignatureEngine.scan_for_malware(
            target_str=raw_url,
            anomalies=url_feat.get("anomalies", []),
            risk_score=url_feat["risk_score"],
            evasions=evasions
        )

        xai_payload = XAIEngine.generate_explanation(
            scan_type="URL",
            total_risk_score=url_feat["risk_score"],
            all_anomalies=url_feat.get("anomalies", []),
            critical_path=graph_dict.get("critical_risk_path", []),
            destination_status=url_feat.get("destination_status", "ACTIVE"),
            evasion_techniques=evasions
        )
        xai_payload["recipient_view"]["ai_pretext"] = ai_copilot.get("primary_pretext_category")
        xai_payload["recipient_view"]["ai_manipulation_score"] = ai_copilot.get("manipulation_score")
        if malware_intel.get("is_virus_detected"):
            xai_payload["recipient_view"]["exact_virus_name"] = malware_intel.get("exact_virus_name")
            xai_payload["recipient_view"]["threat_category"] = malware_intel.get("threat_category")

        analyst_data = {
            "url_features": url_feat,
            "threat_matches": intel.get("threat_matches", []),
            "rdap": intel.get("rdap", {}),
            "ml_prediction": ml_prediction,
            "ai_copilot": ai_copilot,
            "malware_intel": malware_intel,
            "hardware_accel": {"m4_cores": RECOMMENDED_WORKERS, "device": TORCH_DEVICE},
            **xai_payload["analyst_view"]
        }

        save_scan(
            scan_id=scan_id,
            scan_type="URL",
            target=raw_url,
            verdict=xai_payload["verdict"],
            confidence_score=xai_payload["confidence_score"],
            summary=xai_payload["summary"],
            recipient_data=xai_payload["recipient_view"],
            analyst_data=analyst_data,
            graph_data=graph_dict,
            evasions=evasions
        )

        return {
            "scan_id": scan_id,
            "scan_type": "URL",
            "verdict": xai_payload["verdict"],
            "verdict_label": xai_payload["verdict_label"],
            "confidence_score": xai_payload["confidence_score"],
            "summary": xai_payload["summary"],
            "recipient_view": xai_payload["recipient_view"],
            "analyst_view": analyst_data,
            "evidence_graph": graph_dict
        }

    async def analyze_attachment_file(self, filename: str, content: bytes) -> Dict[str, Any]:
        """Direct standalone attachment scan."""
        scan_id = f"scan_{uuid.uuid4().hex[:10]}"
        loop = asyncio.get_event_loop()

        def _analyze():
            analyzer = AttachmentAnalysisResult(filename=filename, content=content)
            res = analyzer.analyze()
            res["_embedded_images"] = analyzer.embedded_images
            return res

        att_res = await loop.run_in_executor(self.executor, _analyze)

        # Also run quishing if images exist
        quishing_res = []
        if att_res.get("_embedded_images"):
            def _scan_img():
                qrs = []
                for b in att_res["_embedded_images"]:
                    qrs.extend(self.quishing_decoder.decode_image_bytes(b))
                return qrs
            quishing_res = await loop.run_in_executor(self.executor, _scan_img)

        clean_att = {k: v for k, v in att_res.items() if not k.startswith("_")}
        evasions = ["HTML_SVG_SMUGGLING"] if clean_att.get("smuggling_detected") else []

        xai_payload = XAIEngine.generate_explanation(
            scan_type="ATTACHMENT",
            total_risk_score=clean_att.get("risk_score", 0.0),
            all_anomalies=clean_att.get("anomalies", []),
            critical_path=[],
            destination_status="ACTIVE",
            evasion_techniques=evasions
        )

        # Malware Signature & VirusTotal Multi-Engine Attribution
        malware_intel = MalwareSignatureEngine.scan_for_malware(
            target_str=filename,
            anomalies=clean_att.get("anomalies", []),
            risk_score=clean_att.get("risk_score", 0.0),
            evasions=evasions
        )
        if malware_intel.get("is_virus_detected"):
            xai_payload["recipient_view"]["exact_virus_name"] = malware_intel.get("exact_virus_name")
            xai_payload["recipient_view"]["threat_category"] = malware_intel.get("threat_category")

        # AI Social Engineering & Pretext Copilot Analysis
        ai_copilot = self.ai_advisor.analyze_social_engineering(
            text=f"{filename} {' '.join(str(v) for v in clean_att.values() if isinstance(v, str))}",
            indicators=[a.get("category", "") for a in clean_att.get("anomalies", [])]
        )
        xai_payload["recipient_view"]["ai_pretext"] = ai_copilot.get("primary_pretext_category")
        xai_payload["recipient_view"]["ai_manipulation_score"] = ai_copilot.get("manipulation_score")

        analyst_data = {
            "attachment_features": clean_att,
            "quishing_findings": quishing_res,
            "ai_copilot": ai_copilot,
            "malware_intel": malware_intel,
            **xai_payload["analyst_view"]
        }

        save_scan(
            scan_id=scan_id,
            scan_type="ATTACHMENT",
            target=filename,
            verdict=xai_payload["verdict"],
            confidence_score=xai_payload["confidence_score"],
            summary=xai_payload["summary"],
            recipient_data=xai_payload["recipient_view"],
            analyst_data=analyst_data,
            graph_data={"nodes": [], "edges": []},
            evasions=evasions
        )

        return {
            "scan_id": scan_id,
            "scan_type": "ATTACHMENT",
            "verdict": xai_payload["verdict"],
            "confidence_score": xai_payload["confidence_score"],
            "summary": xai_payload["summary"],
            "recipient_view": xai_payload["recipient_view"],
            "analyst_view": analyst_data,
            "evidence_graph": {"nodes": [], "edges": []}
        }
