"""
SSRF Guard & Input Validation Middleware.
Blocks Server-Side Request Forgery (SSRF) attacks and enforces strict input constraints.

Security controls:
- RFC 1918 / loopback / link-local IP blocklist (prevents internal network scanning)
- Cloud metadata endpoint blocking (AWS 169.254.169.254, GCP, Azure)
- Dangerous URL scheme blocking (file://, ftp://, gopher://)
- URL length cap (2048 chars per RFC 3986 recommendation)
- File size and content-type enforcement for uploads
"""
import re
import ipaddress
from typing import Optional
from urllib.parse import urlparse


# ---------------------------------------------------------------------------
# SSRF Block Lists
# ---------------------------------------------------------------------------
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918
    ipaddress.ip_network("172.16.0.0/12"),     # RFC 1918
    ipaddress.ip_network("192.168.0.0/16"),    # RFC 1918
    ipaddress.ip_network("127.0.0.0/8"),       # Loopback
    ipaddress.ip_network("::1/128"),           # IPv6 loopback
    ipaddress.ip_network("169.254.0.0/16"),    # Link-local / AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),         # Unspecified
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT
    ipaddress.ip_network("fc00::/7"),          # IPv6 private
    ipaddress.ip_network("fe80::/10"),         # IPv6 link-local
]

_BLOCKED_SCHEMES = {"file", "ftp", "gopher", "ldap", "dict", "sftp", "tftp", "jar"}

_CLOUD_METADATA_HOSTS = {
    "169.254.169.254",           # AWS EC2 metadata
    "metadata.google.internal",  # GCP
    "169.254.170.2",             # ECS task metadata
    "fd00:ec2::254",             # AWS IPv6 metadata
}

# Internal hostnames blocked by name (before DNS resolution)
_BLOCKED_HOSTNAMES = {
    "localhost",
    "localhost.localdomain",
    "broadcasthost",
    "local",
    "ip6-localhost",
    "ip6-loopback",
}

# Max constraints
MAX_URL_LENGTH = 2048
MAX_EMAIL_FILE_BYTES = 10 * 1024 * 1024   # 10 MB
MAX_ATTACHMENT_FILE_BYTES = 5 * 1024 * 1024  # 5 MB

ALLOWED_EMAIL_EXTENSIONS = {".eml", ".msg", ".txt", ".mbox"}
ALLOWED_ATTACHMENT_EXTENSIONS = {
    ".html", ".htm", ".pdf", ".docx", ".doc",
    ".zip", ".xlsx", ".xls", ".exe", ".ps1",
    ".bat", ".scr", ".msi", ".dll", ".vbs",
    ".js", ".svg", ".png", ".jpg", ".jpeg", ".gif"
}


def _is_private_ip(host: str) -> bool:
    """Returns True if host resolves to an RFC-1918 or otherwise blocked IP range."""
    # Strip port if present
    host = host.split(":")[0]
    # IPv6 brackets
    host = host.strip("[]")
    try:
        addr = ipaddress.ip_address(host)
        for net in _PRIVATE_NETWORKS:
            if addr in net:
                return True
    except ValueError:
        pass  # Not an IP; domain will be checked by name
    return False


def validate_scan_url(url: str) -> Optional[str]:
    """
    Validates a URL submitted for scanning.
    Returns None if valid, or an error message string if invalid.

    Checks:
      1. Length cap
      2. Dangerous scheme (file://, ftp://, etc.)
      3. SSRF: Private/loopback IP hosts
      4. Cloud metadata host blocking
    """
    if not url or not url.strip():
        return "URL cannot be empty."

    if len(url) > MAX_URL_LENGTH:
        return f"URL exceeds maximum allowed length of {MAX_URL_LENGTH} characters."

    # Ensure scheme exists for parsing
    normalized = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", normalized):
        normalized = "http://" + normalized

    try:
        parsed = urlparse(normalized)
    except Exception:
        return "Malformed URL: unable to parse."

    scheme = parsed.scheme.lower()
    if scheme in _BLOCKED_SCHEMES:
        return f"URL scheme '{scheme}://' is not permitted for scanning. Only http/https are accepted."

    if scheme not in ("http", "https"):
        return f"Only http:// and https:// URLs are accepted. Received scheme: '{scheme}'."

    host = parsed.hostname or ""

    if not host:
        return "URL must contain a valid hostname."

    # Block internal hostnames by name (before any DNS lookup)
    if host.lower() in _BLOCKED_HOSTNAMES:
        return (
            f"SSRF Blocked: '{host}' is an internal hostname and cannot be scanned. "
            "Only public internet URLs are accepted."
        )

    # Block cloud metadata endpoints
    if host.lower() in _CLOUD_METADATA_HOSTS:
        return "Access to cloud metadata endpoints is blocked for security reasons."

    # Block private/internal IP addresses (SSRF)
    if _is_private_ip(host):
        return (
            "SSRF Blocked: The submitted URL resolves to a private or internal network address. "
            "Only public internet URLs may be scanned."
        )

    return None  # ✅ Valid


def validate_email_upload(filename: str, content: bytes) -> Optional[str]:
    """Validates an uploaded email file. Returns error string or None."""
    if len(content) > MAX_EMAIL_FILE_BYTES:
        return f"Email file exceeds maximum allowed size of {MAX_EMAIL_FILE_BYTES // (1024*1024)} MB."

    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_EMAIL_EXTENSIONS:
        return (
            f"File type '{ext}' is not accepted for email analysis. "
            f"Allowed types: {', '.join(sorted(ALLOWED_EMAIL_EXTENSIONS))}"
        )
    return None


def validate_attachment_upload(filename: str, content: bytes) -> Optional[str]:
    """Validates an uploaded attachment file. Returns error string or None."""
    if len(content) > MAX_ATTACHMENT_FILE_BYTES:
        return f"Attachment exceeds maximum allowed size of {MAX_ATTACHMENT_FILE_BYTES // (1024*1024)} MB."

    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    if ext not in ALLOWED_ATTACHMENT_EXTENSIONS:
        return (
            f"File type '{ext}' is not in the supported attachment list. "
            f"Supported: {', '.join(sorted(ALLOWED_ATTACHMENT_EXTENSIONS))}"
        )
    return None
