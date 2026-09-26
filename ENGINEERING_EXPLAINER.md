# ShieldCheck: Engineering & Logic Breakdown (For SWEs)

ShieldCheck is a multi-modal, highly scalable phishing and malware detection engine. Unlike standard email gateways that rely purely on text-based heuristics, this platform handles modern evasion tactics (like Quishing and HTML Smuggling) by piping inputs through a concurrent AI, Computer Vision, and Threat Intelligence pipeline.

Here is the technical logic and stack breakdown of how the system processes an incoming threat in under 1 second.

---

## 💻 1. The Tech Stack Overview

1. **Backend API:** FastAPI (Python 3.9+)
   - Chosen for its native asynchronous capabilities (`asyncio`) to handle concurrent API calls to 8 different threat feeds and LLM services without blocking the main event loop.
2. **Frontend UI:** Vanilla JS + CSS3 + HTML5
   - Purposefully framework-less to ensure a zero-dependency, ultra-fast initial load time. It uses a dual-view controller (Simple/Analyst modes) driven by DOM state toggles.
3. **Machine Learning:** Scikit-Learn (Random Forest)
   - A lightweight structural classifier trained on 2,847 labeled samples (benign vs. phishing URLs). It computes features like Shannon entropy, digit ratios, and brand impersonation distance in `<2ms`.
4. **Computer Vision:** OpenCV (`cv2`)
   - Used to extract hidden destination URLs from QR codes inside email attachments (Quishing) before the payload can hit a mobile device.
5. **Generative AI:** Google Gemini 1.5 Flash
   - Acts as the Social Engineering behavioral analyzer. It doesn't look at code; it looks at the psychology of the text (e.g., detecting artificial urgency or coercion).
6. **Data Storage:** SQLite (WAL Mode)
   - Configured with Write-Ahead Logging to prevent database locking during high-throughput batch scans.

---

## ⚙️ 2. The Core Execution Logic

When a payload (URL, EML, or File) hits the Edge Router, the following pipeline executes:

### Step 1: Security Gateway (Pre-Processing)
* **Rate Limiting:** A sliding-window rate limiter (in-memory) caps requests per IP to prevent DDoS or API abuse.
* **SSRF Guard:** Before making any outbound requests, the URL is parsed. If the resolved IP belongs to an RFC 1918 private block (`10.x`, `192.168.x`) or loopback (`127.x`), the request is aggressively dropped with a `422 Unprocessable Entity`.
* **PII Scrubbing:** If an email is uploaded, the body is stripped of PII and hashed (SHA-256) before storage.

### Step 2: The Multi-Engine Fan-out
The backend uses `asyncio.gather()` to execute three distinct analysis layers concurrently:

1. **Static Analysis & Heuristics:**
   * Uses AST/Regex to detect HTML smuggling indicators (e.g., in-memory Blob assembly using `createObjectURL()` or `atob()`).
2. **Machine Learning Feature Extraction:**
   * Calculates structural anomalies (e.g., high Shannon entropy in the domain name indicating a DGA - Domain Generation Algorithm).
3. **Threat Intelligence Consensus:**
   * Polls 8 enterprise AV engines (simulated/cached via VirusTotal paradigms) to achieve a deterministic verdict based on signature matching (e.g., identifying a specific threat family like *LummaStealer* mapped to MITRE ATT&CK `T1566`).

### Step 3: Synthesis & XAI Generation
Once the async tasks resolve, the data is passed to the **NIST SP 1270 Explainable AI (XAI)** module. 
Instead of returning an opaque "Risk Score = 95", the system maps the outputs into 4 human-readable pillars:
1. **Explanation:** Why was it flagged? (e.g., *Computer Vision decoded a hidden QR code redirecting to a known credential harvester.*)
2. **Meaningfulness:** What does this mean for the user?
3. **Accuracy:** What is the confidence interval?
4. **Knowledge Limits:** What couldn't the model verify? (e.g., *Site hidden behind a Cloudflare CAPTCHA wall.*)

### Step 4: Batch Processing & Caching
To handle enterprise-scale loads (e.g., an entire SOC team dumping logs), the `/api/scan/batch` endpoint processes up to 100 URLs in parallel. 
* To prevent duplicate processing overhead, results are stored in an **LRU (Least Recently Used) Cache** with a 5-minute TTL. 
* Subsequent hits for the same threat hash return in `<10ms`.

---

## 🎯 Why This Architecture Wins

Standard security tools fail at the presentation layer—they output JSON walls or generic "Blocked" screens. 
This architecture decouples the complex, highly-concurrent detection backend from a presentation layer that can dynamically cast the exact same underlying JSON payload into an Emoji-driven interface (for non-technical users) or a full Forensic Evidence Graph (for SOC analysts). 
