# AntiGravity: Phishing Email & URL Provenance Detection Platform (Problem P12)

A production-grade, end-to-end Phishing Email, URL, and Smuggled Payload Detection Platform designed for high-throughput cyber defense, featuring **Directed Evidence Graph Provenance**, **NIST-Compliant Explainable AI (XAI)**, and a **Dual-Layer Interface** (Executive Recipient View & SOC Analyst Forensics).

Engineered specifically for **Apple Silicon (MacBook M4 Pro)** with parallelized execution across all 12 CPU cores, unified memory caching, and MPS neural acceleration.

---

## 🚀 Key Architectural Capabilities

### 1. Hardware-Optimized Performance (Apple Silicon M4 Pro)
- **12-Core Multi-Threaded Worker Pool**: CPU-intensive tasks (MIME extraction, computer vision QR decoding, SVG/HTML DOM parsing, and Shannon entropy calculations) are distributed concurrently using `concurrent.futures.ThreadPoolExecutor` and Python's `asyncio` event loop.
- **24 GB Unified Memory Cache**: High-speed in-memory lookups for OpenPhish, PhishTank, and URLhaus threat indicators, backed by an ACID SQLite WAL (Write-Ahead Logging) database.
- **Metal Performance Shaders (MPS)**: PyTorch/HuggingFace hardware acceleration hooks configured for Apple Silicon (`device="mps"`).

### 2. Ingestion & Evasion-Resilient Normalization Layer
- **Unicode Plane 14 Tag Smuggling Stripping**: Removes invisible Plane 14 tag characters (`U+E0000` - `U+E007F`) used to hide malicious URLs from perimeter inspection filters.
- **Zero-Width & Invisible Control Removal**: Strips ZWSP (`\u200B`), ZWNJ (`\u200C`), ZWJ (`\u200D`), and BOM (`\uFEFF`) embedded to break keyword tokens.
- **Bidirectional Override (Bidi) Neutralization**: Detects and neutralizes RLO (`\u202E`) and other bidi markers used to spoof file extensions.
- **Homoglyph & Punycode (IDNA) Transliteration**: Identifies Cyrillic (`а`, `о`, `р`, `е`) and Greek lookalikes targeting Latin alphabets with Levenshtein distance metrics.

### 3. Multi-Modal Parsers & Extractors
- **Attachment Analyzer (HTML & SVG Smuggling)**:
  - Detects in-memory Blob URL generation (`URL.createObjectURL(blob)`).
  - Flags obfuscated Base64 unpacking (`window.atob(...)`).
  - Detects programmatic download execution (`<a download>`, dynamic element injection, `.click()`).
  - Identifies SVG `<foreignObject>` and inline script containers.
  - PDF: Uncovers embedded `/JavaScript`, `/Launch` actions, and `/OpenAction` triggers.
  - DOCX: Identifies external template injection and embedded VBA macros.
- **Computer Vision Quishing (QR Code) Decoder**:
  - Scans image attachments and embedded PDF graphics using OpenCV (`cv2.QRCodeDetector`) with adaptive contrast enhancement and sharpening to resolve hidden target URLs.
- **Deep URL Feature Extractor**:
  - Shannon entropy computation of host and path components.
  - Digit-to-letter ratios, host depth, and suspicious TLD patterns (`.xyz`, `.top`, `.stream`, `.buzz`, `.cfd`, etc.).
  - Obfuscated IP host detection (IPv4, hex, and integer representations).
  - Open-redirect parameter detection and credential pre-fill query parameters.

### 4. Directed Evidence Graph Engine
Constructs a complete provenance chain using `networkx`:
```
[MIME Message] 
      ├──> [Attachment: invoice.svg] ──> [Smuggled Payload URL] ──┐
      ├──> [Embedded QR Code] ─────────> [Target URL] ───────────┼──> [Intermediate Hops] ──> [Landing Page] ──> [Requested Action]
      └──> [Body Link (Anchor Spoof)] ───────────────────────────┘
```
- **Critical Risk Path Highlight**: Computes the highest-risk trajectory through the provenance chain.
- **Interactive Graph Visualizer**: HTML5 Canvas visualizer with physics repulsion, node dragging, and click-to-inspect attributes.

### 5. Threat Intel & Handling the "Unknown" State
- **Threat Feeds**: Live integrations and cached connectors for OpenPhish, PhishTank, URLhaus (abuse.ch), and Google Safe Browsing / Web Risk.
- **ICANN RDAP Context Wrapper**: Evaluates domain age in days; flags Newly Registered Domains (NRDs < 30 days old).
- **The "Unknown" State (Evasion Challenge Walls)**:
  - If a destination is protected by an unresolved CAPTCHA, Cloudflare Turnstile, or bot challenge wall, the platform explicitly classifies the destination status as **UNKNOWN** (rather than benignly trusting it) and triggers the `EVASION_CAPTCHA_VERIFICATION_WALL` flag.

### 6. NIST-Compliant Explainable AI (XAI)
Adheres to the **NIST SP 1270 Four Principles of Explainable AI**:
1. **Explanation**: Clear rationale detailing why the communication was flagged.
2. **Meaningfulness**: Understandable, context-appropriate language tailored to end-users and SOC analysts.
3. **Accuracy**: Factually reflective of observed features, graph provenance, and threat feeds.
4. **Knowledge Limits**: Explicit boundaries (disclosing unreached pages due to CAPTCHA walls or limited WHOIS history).

### 7. Dual-Layer Interface
- **Recipient View**: Clean, visual risk card with simple security badges (Crimson / Amber / Emerald / Purple), plain-English explanations, and one-click Safe Report / Quarantine buttons.
- **Analyst View**: Deep SOC workbench exposing the interactive Evidence Graph, MIME authentication headers (SPF, DKIM, DMARC), decoded QR contents, redirect hops, threat feed matches, and auditable override management.
- **Feedback Loop**: "Report False Positive / False Negative" modal recording analyst notes into an auditable SQLite table.

---

## 📁 Project Structure

```
/
├── backend/
│   ├── config.py                 # Apple Silicon M4 Pro hardware configuration
│   ├── database.py               # SQLite WAL persistence for scans & overrides
│   ├── normalization.py          # Unicode, IDNA, homoglyphs, zero-width stripping
│   ├── graph_engine.py           # Directed Evidence Graph & critical path builder
│   ├── xai_engine.py             # NIST 4 Principles Explainable AI rationale
│   ├── pipeline.py               # 12-core concurrent detection pipeline
│   ├── main.py                   # FastAPI REST backend and static file server
│   ├── parsers/
│   │   ├── email_parser.py       # MIME parser & SPF/DKIM/DMARC authentication
│   │   ├── attachment_analyzer.py # SVG/HTML smuggling, PDF JS, DOCX templates
│   │   ├── quishing_decoder.py   # Computer vision OpenCV QR code scanner
│   │   └── url_extractor.py      # Shannon entropy & brand typosquatting
│   └── threat_intel/
│       ├── feed_manager.py       # Async orchestrator for all feeds
│       ├── rdap_lookup.py        # ICANN RDAP domain registration age lookup
│       ├── openphish.py          # OpenPhish feed parser & cache
│       ├── phishtank.py          # PhishTank connector
│       ├── urlhaus.py            # URLhaus abuse.ch connector
│       ├── safebrowsing.py       # Google Safe Browsing / Web Risk client
│       └── destination_resolver.py # Evasion wall detector & UNKNOWN state handler
├── frontend/
│   ├── index.html                # Modern Dual-Layer UI
│   ├── css/
│   │   └── styles.css            # Dark cyberpunk glassmorphic design system
│   └── js/
│       ├── app.js                # Dual-layer controller & view switcher
│       ├── graph_viz.js          # Interactive canvas Evidence Graph visualizer
│       └── api.js                # API client & sample test fixtures
├── datasets/
│   └── sample_data/
│       ├── phishing_urls_benchmark.csv
│       └── email_corpus_benchmark.json
├── scripts/
│   └── ingest_datasets.py        # Kaggle & benchmark dataset ingestion utility
├── tests/                        # 19 Unit & Integration Tests (100% Passing)
│   ├── test_normalization.py
│   ├── test_attachment_smuggling.py
│   ├── test_quishing.py
│   ├── test_url_features.py
│   ├── test_evidence_graph.py
│   └── test_pipeline_e2e.py
├── run.py                        # Unified one-command bootstrap launcher
└── requirements.txt
```

---

## 🛠️ Quick Start & Execution (MacBook M4 Pro)

### 1. Activate Environment & Dependencies
```bash
# From workspace root
source .venv/bin/activate
pip install -r requirements.txt
```

### 2. Run the Full Test Suite
Verify all multi-modal parsers, SVG smuggling detectors, and evidence graph linkers:
```bash
pytest -v
```
*(All 19 tests pass in < 0.6 seconds).*

### 3. Ingest Kaggle / Security Benchmark Datasets
Bootstrap baseline heuristic rules and threat caches:
```bash
python scripts/ingest_datasets.py
```

### 4. Launch the Platform
Start the unified FastAPI backend and Dual-Layer Dashboard:
```bash
python run.py
```

Open your browser to:
- **Web Dashboard**: [http://localhost:8000](http://localhost:8000)
- **API Documentation (Swagger)**: [http://localhost:8000/docs](http://localhost:8000/docs)

---

## 🧪 Testing 1-Click Attack Scenarios

Once the dashboard is open, use the **1-Click Test Scenarios** at the top of the scanner console:
1. **SVG Smuggling Attack**: Simulates an incoming email with an attached `.svg` file containing an obfuscated Blob URL and automated executable download trigger.
2. **Microsoft Typosquatting**: Analyzes a brand impersonation attack (`login-microsoft-security-verify.top`).
3. **High-Entropy DGA Domain**: Tests Shannon entropy thresholds on algorithmically generated domains.
4. **Cloudflare Evasion Wall**: Demonstrates the platform's handling of the **UNKNOWN** state when an automated crawler encounters a CAPTCHA challenge.
5. **Legitimate Email**: Verifies benign classification with aligned SPF/DKIM authentication.
