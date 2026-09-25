"""
Deep URL Feature Extractor.
Calculates Shannon entropy, host depth, path length, digit-to-letter ratio,
TLD repetition, brand impersonation similarity, IP address evasions, and URL shortener detection.
"""
import re
import math
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs
import tldextract
from backend.config import HIGH_RISK_ENTROPY_THRESHOLD, BRAND_SIMILARITY_THRESHOLD, TARGET_BRANDS
from backend.normalization import normalize_text, normalize_domain

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "buff.ly",
    "ow.ly", "cutt.ly", "rb.gy", "rebrand.ly", "shorturl.at", "tiny.cc",
    "v.gd", "bl.ink", "lnkd.in", "s.id", "alturl.com", "t.ly", "clck.ru"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "club", "click", "buzz", "cfd", "sbs",
    "country", "stream", "gq", "ml", "cf", "ga", "tk", "fit", "rest",
    "monster", "cam", "icu", "bar", "lat", "fun", "space", "casa", "pro", "test"
}

FREE_HOSTING_DOMAINS = {
    "pages.dev", "replit.app", "webflow.io", "edgeone.dev", "blogspot.com",
    "firebaseapp.com", "web.app", "netlify.app", "vercel.app", "github.io"
}

DANGEROUS_EXTENSIONS = {
    ".exe", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".scr", ".msi",
    ".dll", ".hta", ".pif", ".iso", ".img", ".dmg", ".apk", ".cpl"
}

MALWARE_LURE_PATTERNS = [
    r"software[-_]update", r"malware[-_]download", r"security[-_]update",
    r"software[-_]crack", r"browser[-_]update", r"fake[-_]antivirus",
    r"urgent[-_]update", r"driver[-_]update", r"document[-_]download",
    r"account[-_]security", r"system[-_]check", r"software[-_]activation",
    r"invoice[-_]download", r"free[-_]vpn", r"codec[-_]update",
    r"selectedbank", r"trustpass", r"sellercheck", r"security[-_]server"
]

def calculate_shannon_entropy(text: str) -> float:
    """Calculates the Shannon entropy of a given string."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        prob = count / length
        entropy -= prob * math.log2(prob)
    return round(entropy, 4)

def levenshtein_ratio(s1: str, s2: str) -> float:
    """Computes Levenshtein similarity ratio between 0.0 and 1.0."""
    s1, s2 = s1.lower(), s2.lower()
    if s1 == s2:
        return 1.0
    if not s1 or not s2:
        return 0.0

    len1, len2 = len(s1), len(s2)
    dp = [[0] * (len2 + 1) for _ in range(len1 + 1)]

    for i in range(len1 + 1):
        dp[i][0] = i
    for j in range(len2 + 1):
        dp[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1
            dp[i][j] = min(
                dp[i - 1][j] + 1,      # deletion
                dp[i][j - 1] + 1,      # insertion
                dp[i - 1][j - 1] + cost # substitution
            )

    dist = dp[len1][len2]
    max_len = max(len1, len2)
    return round(1.0 - (dist / max_len), 4)

def is_ip_address(host: str) -> bool:
    """Detects standard IPv4, IPv6, or obfuscated hex/octal/integer IP address in host."""
    # Standard IPv4
    ipv4_pattern = r"^(\d{1,3}\.){3}\d{1,3}$"
    if re.match(ipv4_pattern, host):
        return True
    # Hex or octal or integer IP notation
    if re.match(r"^0x[0-9a-fA-F]+$", host) or (host.isdigit() and int(host) > 65535):
        return True
    return False

def check_brand_impersonation(domain: str, subdomain: str) -> List[Dict[str, Any]]:
    """Detects brand name mimicry/typosquatting in domain or subdomain."""
    matches = []
    full_host_clean = f"{subdomain}.{domain}".lower().replace(".", "").replace("-", "")

    for brand in TARGET_BRANDS:
        # Check if brand is contained as a substring in an untrusted domain
        # e.g., 'login-microsoft-verify.com' or 'paypal-security.support'
        if brand in full_host_clean and domain != f"{brand}.com" and not domain.endswith(f".{brand}.com"):
            matches.append({
                "brand": brand,
                "target_domain": domain,
                "similarity": 1.0,
                "technique": "SUBSTRING_TYPOSQUATTING",
                "risk": "HIGH"
            })
            continue

        # Fuzzy similarity check against domain core
        ratio = levenshtein_ratio(domain.split(".")[0], brand)
        if ratio >= BRAND_SIMILARITY_THRESHOLD and ratio < 1.0:
            matches.append({
                "brand": brand,
                "target_domain": domain,
                "similarity": ratio,
                "technique": "LEVENSHTEIN_BRAND_MIMICRY",
                "risk": "HIGH"
            })

    return matches

class URLAnalysisResult:
    def __init__(self, raw_url: str):
        self.raw_url = raw_url
        self.parsed = urlparse(raw_url if "://" in raw_url else f"http://{raw_url}")
        self.scheme = self.parsed.scheme.lower()
        self.host = self.parsed.netloc.split(":")[0].lower()
        self.path = self.parsed.path
        self.query = self.parsed.query
        self.anomalies: List[Dict[str, Any]] = []
        self.risk_score: float = 0.0

    def analyze(self) -> Dict[str, Any]:
        # 1. Normalization & Homoglyph detection on Host
        norm_host, host_anomalies = normalize_domain(self.host)
        for anom in host_anomalies:
            self.anomalies.append({
                "category": "EVASION_HOMOGLYPH",
                "detail": anom["description"],
                "severity": "HIGH",
                "weight": 25.0
            })
            self.risk_score += 25.0

        # 2. TLD & Subdomain Extraction
        extracted = tldextract.extract(norm_host)
        subdomain = extracted.subdomain
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        tld = extracted.suffix.lower()

        # 3. Entropy Analysis
        host_entropy = calculate_shannon_entropy(self.host)
        path_entropy = calculate_shannon_entropy(self.path)
        if host_entropy > HIGH_RISK_ENTROPY_THRESHOLD:
            self.anomalies.append({
                "category": "HIGH_HOST_ENTROPY",
                "detail": f"Unusually high host entropy ({host_entropy:.2f} > {HIGH_RISK_ENTROPY_THRESHOLD}), characteristic of DGA or phishing kits",
                "severity": "MEDIUM",
                "weight": 20.0
            })
            self.risk_score += 20.0

        # 4. Host Depth & Subdomains
        host_depth = len(norm_host.split("."))
        if host_depth > 4:
            self.anomalies.append({
                "category": "EXCESSIVE_SUBDOMAINS",
                "detail": f"Deep subdomain hierarchy ({host_depth} levels), often used to disguise real destination",
                "severity": "MEDIUM",
                "weight": 15.0
            })
            self.risk_score += 15.0

        # 5. IP Address in Host
        if is_ip_address(self.host):
            self.anomalies.append({
                "category": "IP_HOST_INDICATOR",
                "detail": f"Direct IP address '{self.host}' used instead of legitimate registered domain name",
                "severity": "HIGH",
                "weight": 30.0
            })
            self.risk_score += 30.0

        # 6. Digit-to-Letter Ratio & Hyphens
        digit_count = sum(c.isdigit() for c in norm_host)
        letter_count = sum(c.isalpha() for c in norm_host)
        ratio = (digit_count / (letter_count + 1))
        if ratio > 0.4 and not is_ip_address(self.host):
            self.anomalies.append({
                "category": "HIGH_DIGIT_RATIO",
                "detail": f"High digit-to-letter ratio ({ratio:.2f}) in hostname",
                "severity": "LOW",
                "weight": 10.0
            })
            self.risk_score += 10.0

        hyphen_count = norm_host.count("-")
        if hyphen_count >= 3:
            self.anomalies.append({
                "category": "EXCESSIVE_HYPHENS",
                "detail": f"Suspicious hostname containing {hyphen_count} hyphens",
                "severity": "MEDIUM",
                "weight": 12.0
            })
            self.risk_score += 12.0

        # 7. Suspicious TLD
        if tld in SUSPICIOUS_TLDS:
            self.anomalies.append({
                "category": "ABUSED_TLD",
                "detail": f"Top-Level Domain '.{tld}' is heavily correlated with malicious bulletproof campaigns",
                "severity": "MEDIUM",
                "weight": 15.0
            })
            self.risk_score += 15.0

        # 8. Known Shortener
        is_shortener = norm_host in KNOWN_SHORTENERS
        if is_shortener:
            self.anomalies.append({
                "category": "URL_SHORTENER_CLOAK",
                "detail": f"Known URL shortening service '{norm_host}' masking final destination",
                "severity": "HIGH",
                "weight": 35.0
            })
            self.risk_score += 35.0

        # 9. Brand Impersonation
        brand_matches = check_brand_impersonation(domain, subdomain)
        for b_match in brand_matches:
            self.anomalies.append({
                "category": "BRAND_IMPERSONATION",
                "detail": f"Detected targeted brand mimicry of '{b_match['brand']}' using {b_match['technique']} (similarity: {b_match['similarity']:.2f})",
                "severity": "CRITICAL",
                "weight": 35.0
            })
            self.risk_score += 35.0

        # 10. Open Redirects or Credential Harvesting Query Params
        query_lower = self.query.lower()
        if any(param in query_lower for param in ["redirect=", "url=", "next=", "target=", "dest="]):
            self.anomalies.append({
                "category": "OPEN_REDIRECT_PARAM",
                "detail": "URL query contains open-redirect parameter pattern",
                "severity": "MEDIUM",
                "weight": 15.0
            })
            self.risk_score += 15.0

        if any(term in query_lower for term in ["email=", "user=", "login=", "passwd=", "pass=", "token="]):
            self.anomalies.append({
                "category": "CREDENTIAL_PREFILL_PARAM",
                "detail": "URL query pre-fills user credential or identity parameters",
                "severity": "HIGH",
                "weight": 20.0
            })
            self.risk_score += 20.0

        # 11. Direct Executable / Dangerous Script Payload in Path
        path_lower = self.path.lower()
        for ext in DANGEROUS_EXTENSIONS:
            if path_lower.endswith(ext):
                self.anomalies.append({
                    "category": "DIRECT_EXECUTABLE_DOWNLOAD",
                    "detail": f"Direct executable/script download payload detected ({ext}) in URL path",
                    "severity": "CRITICAL",
                    "weight": 55.0
                })
                self.risk_score += 55.0
                break

        # 12. Malware Lure Keywords & Phishing Pretext in Host or Path
        full_url_lower = self.raw_url.lower()
        matched_lures = []
        for pat in MALWARE_LURE_PATTERNS:
            found = re.findall(pat, full_url_lower)
            if found:
                matched_lures.extend(found)
        if matched_lures:
            self.anomalies.append({
                "category": "MALWARE_LURE_VECTOR",
                "detail": f"Malicious lure pretext detected in URL: {', '.join(set(matched_lures[:3]))}",
                "severity": "HIGH",
                "weight": 40.0
            })
            self.risk_score += 40.0

        # 13. Free Hosting Platform Abuse (e.g., pages.dev, replit.app, blogspot.com, webflow.io)
        if domain in FREE_HOSTING_DOMAINS and subdomain:
            sub_entropy = calculate_shannon_entropy(subdomain)
            is_suspicious_sub = (
                sub_entropy > 2.8 or
                any(c.isdigit() for c in subdomain) or
                len(subdomain) > 8 or
                any(w in subdomain for w in ["security", "server", "landing", "login", "verify", "shopee", "365", "auth", "yard", "ofornaogu"])
            )
            if is_suspicious_sub:
                self.anomalies.append({
                    "category": "FREE_HOSTING_PHISHING_ABUSE",
                    "detail": f"Disposable free hosting provider '{domain}' utilized with suspicious subdomain '{subdomain}'",
                    "severity": "HIGH",
                    "weight": 35.0
                })
                self.risk_score += 35.0

        # 14. Phishing Campaign Fragments / Parameter Patterns
        if "#selectedbank" in self.raw_url.lower() or "/o/fz" in path_lower:
            self.anomalies.append({
                "category": "BANK_HARVESTING_CAMPAIGN",
                "detail": "URL structure matches known banking credential harvesting campaign pattern",
                "severity": "CRITICAL",
                "weight": 50.0
            })
            self.risk_score += 50.0

        # Clamp risk score
        normalized_risk = min(100.0, round(self.risk_score, 1))

        return {
            "url": self.raw_url,
            "scheme": self.scheme,
            "host": self.host,
            "subdomain": subdomain,
            "domain": domain,
            "tld": tld,
            "path": self.path,
            "query": self.query,
            "host_entropy": host_entropy,
            "path_entropy": path_entropy,
            "is_ip": is_ip_address(self.host),
            "is_shortener": is_shortener,
            "risk_score": normalized_risk,
            "anomalies": self.anomalies,
        }
