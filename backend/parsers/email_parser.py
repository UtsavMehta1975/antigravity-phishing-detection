"""
MIME Email Parser & Header Authentication Engine.
Extracts:
- Multi-hop Received headers and origin IP provenance
- SPF, DKIM, DMARC authentication verdicts
- Display-Name / From / Reply-To spoofing & mismatches
- Body extraction (Plain & HTML) with Zero-Width / Tag-Smuggling normalization
- Anchor text vs actual href destination discrepancies
- Embedded attachments for multi-modal analysis
"""
import re
import email
from email import policy
from email.parser import BytesParser
from typing import Dict, Any, List, Optional, Tuple
from bs4 import BeautifulSoup
from backend.normalization import normalize_text, normalize_domain

# Pretext urgency & credential harvest indicators
URGENCY_PATTERNS = [
    r"\b(account\s+suspended|suspended\s+temporarily|action\s+required)\b",
    r"\b(password\s+expired|reset\s+password|verify\s+your\s+identity)\b",
    r"\b(unauthorized\s+login|security\s+alert|compromised)\b",
    r"\b(immediate\s+action|within\s+24\s+hours|final\s+warning)\b",
    r"\b(wire\s+transfer|invoice\s+overdue|payment\s+declined)\b",
    r"\b(mfa\s+request|two-factor\s+authentication|one-time\s+code)\b"
]

class ParsedEmail:
    def __init__(self, raw_eml_bytes: bytes):
        self.raw_bytes = raw_eml_bytes
        self.msg = BytesParser(policy=policy.default).parsebytes(raw_eml_bytes)
        self.headers: Dict[str, str] = {}
        self.subject: str = ""
        self.from_header: str = ""
        self.reply_to: str = ""
        self.return_path: str = ""
        self.body_plain: str = ""
        self.body_html: str = ""
        self.links: List[Dict[str, str]] = []
        self.attachments: List[Dict[str, Any]] = []
        self.anomalies: List[Dict[str, Any]] = []
        self.hops: List[Dict[str, str]] = []
        self.auth_results: Dict[str, str] = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
        self.risk_score: float = 0.0

    def parse(self) -> Dict[str, Any]:
        # 1. Parse Headers
        for key, val in self.msg.items():
            self.headers[key.lower()] = str(val)

        raw_subject = self.headers.get("subject", "")
        norm_subj = normalize_text(raw_subject)
        self.subject = norm_subj.normalized
        if norm_subj.has_evasion:
            for anom in norm_subj.anomalies:
                self.anomalies.append({
                    "category": "EVASION_SUBJECT_NORMALIZATION",
                    "detail": f"Subject line contains evasion: {anom['description']}",
                    "severity": "HIGH",
                    "weight": 20.0
                })
                self.risk_score += 20.0

        self.from_header = self.headers.get("from", "")
        self.reply_to = self.headers.get("reply-to", "")
        self.return_path = self.headers.get("return-path", "")

        # 2. Authentication Results & Spoofing Analysis
        self._analyze_auth_headers()
        self._analyze_sender_mismatch()
        self._extract_received_hops()

        # 3. Body Parsing & Normalization
        self._extract_bodies_and_attachments()

        # 4. Link & Anchor Discrepancy Analysis
        self._analyze_links()

        # 5. Pretext & Urgency Analysis
        self._analyze_pretext()

        normalized_risk = min(100.0, round(self.risk_score, 1))

        return {
            "subject": self.subject,
            "from": self.from_header,
            "reply_to": self.reply_to,
            "return_path": self.return_path,
            "auth_results": self.auth_results,
            "hops": self.hops,
            "body_plain": self.body_plain,
            "body_html": self.body_html,
            "links": self.links,
            "attachments": self.attachments,
            "anomalies": self.anomalies,
            "risk_score": normalized_risk,
        }

    def _analyze_auth_headers(self):
        auth_header = self.headers.get("authentication-results", "").lower()
        rec_spf = self.headers.get("received-spf", "").lower()

        # SPF
        if "spf=pass" in auth_header or rec_spf.startswith("pass"):
            self.auth_results["spf"] = "PASS"
        elif "spf=fail" in auth_header or rec_spf.startswith("fail"):
            self.auth_results["spf"] = "FAIL"
            self.anomalies.append({
                "category": "AUTH_SPF_FAIL",
                "detail": "SPF validation explicitly FAILED: sending IP not authorized by domain policy",
                "severity": "CRITICAL",
                "weight": 35.0
            })
            self.risk_score += 35.0
        elif "spf=softfail" in auth_header or rec_spf.startswith("softfail"):
            self.auth_results["spf"] = "SOFTFAIL"
            self.anomalies.append({
                "category": "AUTH_SPF_SOFTFAIL",
                "detail": "SPF validation softfailed",
                "severity": "MEDIUM",
                "weight": 15.0
            })
            self.risk_score += 15.0

        # DKIM
        if "dkim=pass" in auth_header:
            self.auth_results["dkim"] = "PASS"
        elif "dkim=fail" in auth_header:
            self.auth_results["dkim"] = "FAIL"
            self.anomalies.append({
                "category": "AUTH_DKIM_FAIL",
                "detail": "DKIM cryptographic signature verification FAILED or tampered",
                "severity": "CRITICAL",
                "weight": 35.0
            })
            self.risk_score += 35.0

        # DMARC
        if "dmarc=pass" in auth_header:
            self.auth_results["dmarc"] = "PASS"
        elif "dmarc=fail" in auth_header:
            self.auth_results["dmarc"] = "FAIL"
            self.anomalies.append({
                "category": "AUTH_DMARC_FAIL",
                "detail": "DMARC policy alignment FAILED",
                "severity": "CRITICAL",
                "weight": 35.0
            })
            self.risk_score += 35.0

    def _analyze_sender_mismatch(self):
        from_email_match = re.search(r"[\w\.-]+@([\w\.-]+)", self.from_header)
        from_domain = from_email_match.group(1).lower() if from_email_match else ""

        # Display name spoofing (e.g., "Microsoft Support <attacker@evil.com>")
        display_name = ""
        if "<" in self.from_header:
            display_name = self.from_header.split("<")[0].replace('"', '').strip()
            for brand in ["microsoft", "paypal", "apple", "google", "chase", "docusign", "netflix"]:
                if brand in display_name.lower() and brand not in from_domain:
                    self.anomalies.append({
                        "category": "DISPLAY_NAME_SPOOFING",
                        "detail": f"Display name pretends to be '{display_name}' but sender domain is '{from_domain}'",
                        "severity": "CRITICAL",
                        "weight": 35.0
                    })
                    self.risk_score += 35.0

        # Reply-To mismatch
        if self.reply_to:
            reply_match = re.search(r"[\w\.-]+@([\w\.-]+)", self.reply_to)
            reply_domain = reply_match.group(1).lower() if reply_match else ""
            if from_domain and reply_domain and from_domain != reply_domain:
                self.anomalies.append({
                    "category": "REPLY_TO_MISMATCH",
                    "detail": f"Reply-To domain '{reply_domain}' differs from From domain '{from_domain}'",
                    "severity": "HIGH",
                    "weight": 25.0
                })
                self.risk_score += 25.0

    def _extract_received_hops(self):
        rec_headers = self.msg.get_all("received", [])
        for rh in rec_headers:
            rh_str = str(rh)
            ip_match = re.search(r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]", rh_str)
            ip = ip_match.group(1) if ip_match else "unknown"
            from_match = re.search(r"from\s+([^\s]+)", rh_str, re.IGNORECASE)
            from_host = from_match.group(1) if from_match else "unknown"
            self.hops.append({"ip": ip, "from": from_host, "raw": rh_str[:120]})

    def _extract_bodies_and_attachments(self):
        if self.msg.is_multipart():
            for part in self.msg.walk():
                content_disposition = str(part.get("Content-Disposition", ""))
                content_type = part.get_content_type()
                filename = part.get_filename()

                if filename or "attachment" in content_disposition:
                    data = part.get_payload(decode=True)
                    if data:
                        self.attachments.append({
                            "filename": filename or "unnamed_attachment",
                            "content_type": content_type,
                            "size": len(data),
                            "data": data
                        })
                elif content_type == "text/plain":
                    try:
                        self.body_plain += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                    except Exception:
                        pass
                elif content_type == "text/html":
                    try:
                        self.body_html += part.get_payload(decode=True).decode(part.get_content_charset() or "utf-8", errors="ignore")
                    except Exception:
                        pass
        else:
            ctype = self.msg.get_content_type()
            try:
                payload = self.msg.get_payload(decode=True).decode(self.msg.get_content_charset() or "utf-8", errors="ignore")
                if ctype == "text/html":
                    self.body_html = payload
                else:
                    self.body_plain = payload
            except Exception:
                pass

        # Normalize bodies
        norm_plain = normalize_text(self.body_plain)
        if norm_plain.has_evasion:
            for anom in norm_plain.anomalies:
                self.anomalies.append({
                    "category": "EVASION_BODY_NORMALIZATION",
                    "detail": f"Body text contains obfuscation: {anom['description']}",
                    "severity": "HIGH",
                    "weight": 20.0
                })
                self.risk_score += 20.0
        self.body_plain = norm_plain.normalized

    def _analyze_links(self):
        # 1. Links from HTML body
        if self.body_html:
            try:
                soup = BeautifulSoup(self.body_html, "html.parser")
                for a_tag in soup.find_all("a", href=True):
                    href = a_tag["href"].strip()
                    anchor_text = a_tag.get_text().strip()
                    self.links.append({"href": href, "anchor": anchor_text})

                    # Critical Check: Anchor text shows a legitimate domain, but href points elsewhere
                    anchor_url_match = re.search(r"https?://([\w\.-]+)", anchor_text)
                    if anchor_url_match and (href.startswith("http://") or href.startswith("https://")):
                        expected_domain = anchor_url_match.group(1).lower()
                        actual_match = re.search(r"https?://([\w\.-]+)", href)
                        actual_domain = actual_match.group(1).lower() if actual_match else ""
                        if expected_domain != actual_domain and not actual_domain.endswith(f".{expected_domain}"):
                            self.anomalies.append({
                                "category": "ANCHOR_DESTINATION_MISMATCH",
                                "detail": f"Anchor text presents '{expected_domain}' but hyperlink navigates to '{actual_domain}'",
                                "severity": "CRITICAL",
                                "weight": 40.0
                            })
                            self.risk_score += 40.0
            except Exception:
                pass

        # 2. Regex fallback for plain text links
        plain_links = re.findall(r"https?://[^\s<>\"]+", self.body_plain)
        for pl in plain_links:
            self.links.append({"href": pl, "anchor": pl})

    def _analyze_pretext(self):
        full_text = f"{self.subject} {self.body_plain}"
        matched_pretexts = []
        for pattern in URGENCY_PATTERNS:
            found = re.findall(pattern, full_text, re.IGNORECASE)
            if found:
                matched_pretexts.extend([f[0] if isinstance(f, tuple) else f for f in found])

        if matched_pretexts:
            self.anomalies.append({
                "category": "PSYCHOLOGICAL_URGENCY_PRETEXT",
                "detail": f"Urgency & credential harvest triggers detected: {', '.join(set(matched_pretexts[:5]))}",
                "severity": "HIGH",
                "weight": 25.0
            })
            self.risk_score += 25.0
