"""
Attachment Analyzer with Dedicated HTML/SVG Smuggling, PDF, and DOCX Parsers.
Specifically detects:
- HTML/SVG smuggling (Blob URLs, Base64 payload reconstruction, automated download clicks, eval/atob)
- Malicious PDF structures (Embedded JavaScript, OpenAction triggers, URI annotations)
- High-risk DOCX features (Remote template injection, macros, external relationships)
"""
import os
import re
import base64
import zipfile
from io import BytesIO
from typing import Dict, Any, List, Optional
from bs4 import BeautifulSoup

# Regex patterns for HTML / SVG Smuggling Detection
SMUGGLING_PATTERNS = [
    (r"URL\.createObjectURL\s*\(", "BLOB_URL_CREATION", "Dynamic Blob URL creation used to construct malicious files in-memory", "HIGH", 30.0),
    (r"window\.webkitURL\.createObjectURL\s*\(", "BLOB_URL_CREATION", "Webkit Blob URL creation detected", "HIGH", 30.0),
    (r"new\s+Blob\s*\(", "IN_MEMORY_BLOB_CONSTRUCTION", "In-memory binary Blob assembly detected, typical of smuggling payloads", "HIGH", 25.0),
    (r"window\.atob\s*\(|atob\s*\(", "BASE64_ATOB_DECODING", "Base64 decoding via atob() for obfuscated script/executable unpack", "HIGH", 25.0),
    (r"document\.createElement\s*\(\s*['\"]a['\"]\s*\)", "DYNAMIC_ANCHOR_INJECTION", "Dynamic <a> link element creation for programmatic download triggering", "MEDIUM", 20.0),
    (r"\.download\s*=\s*", "AUTOMATED_DOWNLOAD_TRIGGER", "Automated HTML5 download attribute injection to bypass perimeter firewalls", "HIGH", 30.0),
    (r"\.click\s*\(\s*\)", "AUTOMATED_CLICK_EXECUTION", "Automated click() invocation triggering covert download", "MEDIUM", 15.0),
    (r"eval\s*\(", "EVAL_EXECUTION", "Dynamic code execution via eval()", "HIGH", 25.0),
    (r"unescape\s*\(|decodeURI\s*\(", "OBFUSCATED_URL_DECODING", "String unescaping/decoding used for heuristic evasion", "MEDIUM", 15.0),
    (r"String\.fromCharCode\s*\(", "CHARCODE_OBFUSCATION", "String assembly via fromCharCode to hide keywords", "MEDIUM", 15.0),
    (r"msSaveOrOpenBlob\s*\(", "MS_BLOB_SAVE", "Direct Internet Explorer/Edge binary payload save API", "HIGH", 30.0),
]

class AttachmentAnalysisResult:
    def __init__(self, filename: str, content: bytes, mime_type: Optional[str] = None):
        self.filename = filename
        self.content = content
        self.mime_type = mime_type or "application/octet-stream"
        self.size = len(content)
        self.extracted_urls: List[str] = []
        self.anomalies: List[Dict[str, Any]] = []
        self.risk_score: float = 0.0
        self.smuggling_detected: bool = False
        self.embedded_images: List[bytes] = []

    def analyze(self) -> Dict[str, Any]:
        ext = os.path.splitext(self.filename)[1].lower()

        if ext in [".svg", ".html", ".htm", ".xhtml"]:
            self._analyze_html_svg_smuggling()
        elif ext == ".pdf":
            self._analyze_pdf()
        elif ext in [".docx", ".docm", ".dotm"]:
            self._analyze_docx()
        elif ext in [".png", ".jpg", ".jpeg", ".webp", ".bmp"]:
            self.embedded_images.append(self.content)
        else:
            # General binary inspection for embedded smuggling keywords
            self._analyze_raw_binary()

        # Clamp risk score
        normalized_risk = min(100.0, round(self.risk_score, 1))

        return {
            "filename": self.filename,
            "size": self.size,
            "extension": ext,
            "risk_score": normalized_risk,
            "smuggling_detected": self.smuggling_detected,
            "extracted_urls": list(set(self.extracted_urls)),
            "anomalies": self.anomalies,
            "embedded_image_count": len(self.embedded_images)
        }

    def _analyze_html_svg_smuggling(self):
        """Deep inspection of SVG and HTML files for smuggling artifacts."""
        try:
            text = self.content.decode("utf-8", errors="ignore")
        except Exception:
            text = str(self.content)

        # 1. Smuggling Pattern Regex Matches
        for pattern, category, description, severity, weight in SMUGGLING_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                self.smuggling_detected = True
                self.anomalies.append({
                    "category": f"SMUGGLING_{category}",
                    "detail": f"{description} (matches: {len(matches)})",
                    "severity": severity,
                    "weight": weight
                })
                self.risk_score += weight

        # 2. BeautifulSoup DOM Inspection
        try:
            soup = BeautifulSoup(text, "html.parser")

            # Check for <script> tags inside SVG or HTML
            scripts = soup.find_all("script")
            if scripts:
                self.anomalies.append({
                    "category": "EMBEDDED_SCRIPT",
                    "detail": f"Detected {len(scripts)} embedded executable <script> tags inside {self.filename}",
                    "severity": "HIGH",
                    "weight": 25.0
                })
                self.risk_score += 25.0

            # SVG specific evasion elements: <foreignObject>, <animate>, etc.
            foreign_objects = soup.find_all(["foreignobject", "foreignObject"])
            if foreign_objects:
                self.smuggling_detected = True
                self.anomalies.append({
                    "category": "SVG_FOREIGNOBJECT_SMUGGLING",
                    "detail": "SVG contains <foreignObject> container, commonly abused to embed HTML/JS in vector images",
                    "severity": "CRITICAL",
                    "weight": 35.0
                })
                self.risk_score += 35.0

            # Check for inline event handlers (onload, onerror, onbegin, etc.)
            event_handlers = re.findall(r"\b(onload|onerror|onclick|onmouseover|onbegin)\s*=", text, re.IGNORECASE)
            if event_handlers:
                self.anomalies.append({
                    "category": "INLINE_EVENT_HANDLER",
                    "detail": f"Suspicious inline event handlers detected: {', '.join(set(event_handlers))}",
                    "severity": "HIGH",
                    "weight": 25.0
                })
                self.risk_score += 25.0

            # Extract URLs from <a> tags and <form> actions
            for tag in soup.find_all(["a", "link", "iframe", "embed", "form"]):
                href = tag.get("href") or tag.get("src") or tag.get("action")
                if href:
                    if href.startswith("http://") or href.startswith("https://"):
                        self.extracted_urls.append(href)
                    elif href.startswith("data:"):
                        self.anomalies.append({
                            "category": "DATA_URI_PAYLOAD",
                            "detail": f"Embedded data: URI payload ({href[:40]}...)",
                            "severity": "HIGH",
                            "weight": 25.0
                        })
                        self.risk_score += 25.0

            # Check for large base64 chunks
            b64_matches = re.findall(r"([A-Za-z0-9+/=]{100,})", text)
            if b64_matches:
                self.anomalies.append({
                    "category": "OBFUSCATED_BASE64_PAYLOAD",
                    "detail": f"Detected {len(b64_matches)} large base64-encoded binary string(s) indicative of packed payload",
                    "severity": "HIGH",
                    "weight": 30.0
                })
                self.risk_score += 30.0

        except Exception as e:
            self.anomalies.append({
                "category": "PARSER_WARNING",
                "detail": f"DOM parsing error: {str(e)}",
                "severity": "LOW",
                "weight": 5.0
            })

    def _analyze_pdf(self):
        """Analyzes PDF files for embedded JavaScript, launch actions, URI annotations, and extracts images."""
        # 1. Structural search in raw bytes for fast, evasion-resilient signature detection
        raw_str = self.content.decode("latin1", errors="ignore")
        if "/JavaScript" in raw_str or "/JS" in raw_str:
            self.anomalies.append({
                "category": "PDF_EMBEDDED_JAVASCRIPT",
                "detail": "PDF contains embedded /JavaScript or /JS stream object",
                "severity": "CRITICAL",
                "weight": 40.0
            })
            self.risk_score += 40.0

        if "/Launch" in raw_str:
            self.anomalies.append({
                "category": "PDF_LAUNCH_ACTION",
                "detail": "PDF contains /Launch action to execute local commands or applications",
                "severity": "CRITICAL",
                "weight": 45.0
            })
            self.risk_score += 45.0

        if "/OpenAction" in raw_str:
            self.anomalies.append({
                "category": "PDF_OPENACTION_TRIGGER",
                "detail": "PDF contains /OpenAction trigger to execute commands immediately upon opening",
                "severity": "HIGH",
                "weight": 30.0
            })
            self.risk_score += 30.0

        # Extract regex URLs from raw stream
        urls = re.findall(r"https?://[^\s<>\"]+", raw_str)
        self.extracted_urls.extend(urls)

        # 2. Extract structured pages, annotations, and embedded images
        try:
            from pypdf import PdfReader
            reader = PdfReader(BytesIO(self.content))
            for page_num, page in enumerate(reader.pages):
                if "/Annots" in page:
                    for annot in page["/Annots"]:
                        obj = annot.get_object()
                        if "/A" in obj and "/URI" in obj["/A"]:
                            uri = obj["/A"]["/URI"]
                            if isinstance(uri, str):
                                self.extracted_urls.append(uri)

                # Extract images for QR code / Quishing analysis
                try:
                    for img_name, img_file in page.images.items():
                        self.embedded_images.append(img_file.data)
                except Exception:
                    pass
        except Exception:
            pass

    def _analyze_docx(self):
        """Analyzes DOCX/DOCM files for external relationship injection and VBA macros."""
        try:
            with zipfile.ZipFile(BytesIO(self.content)) as zf:
                namelist = zf.namelist()

                # Check for VBA Macro
                if any("vbaProject.bin" in name for name in namelist):
                    self.anomalies.append({
                        "category": "DOCX_EMBEDDED_VBA_MACRO",
                        "detail": "Office document contains embedded vbaProject.bin macro code",
                        "severity": "CRITICAL",
                        "weight": 40.0
                    })
                    self.risk_score += 40.0

                # Check relationships for remote template injection
                rel_files = [n for n in namelist if n.endswith(".rels")]
                for rel_file in rel_files:
                    xml_content = zf.read(rel_file).decode("utf-8", errors="ignore")
                    urls = re.findall(r'Target\s*=\s*["\'](https?://[^"\']+)["\']', xml_content)
                    for url in urls:
                        self.extracted_urls.append(url)
                        if "attachedTemplate" in xml_content or "external" in xml_content.lower():
                            self.anomalies.append({
                                "category": "DOCX_REMOTE_TEMPLATE_INJECTION",
                                "detail": f"Remote template injection pointing to external URL: {url}",
                                "severity": "CRITICAL",
                                "weight": 45.0
                            })
                            self.risk_score += 45.0

                # Extract embedded media images for quishing
                media_files = [n for n in namelist if n.startswith("word/media/")]
                for mf in media_files:
                    self.embedded_images.append(zf.read(mf))

        except Exception as e:
            self.anomalies.append({
                "category": "DOCX_PARSE_ERROR",
                "detail": f"Failed to parse document structure: {str(e)}",
                "severity": "LOW",
                "weight": 5.0
            })

    def _analyze_raw_binary(self):
        """Scans arbitrary binary content for embedded URLs and evasion signatures."""
        raw_text = self.content.decode("utf-8", errors="ignore")
        urls = re.findall(r"https?://[^\s<>\"]+", raw_text)
        self.extracted_urls.extend(urls[:10])
