"""
Hardware & System Configuration for Phishing Detection Platform.
Optimized specifically for Apple Silicon M4 Pro (12 CPU Cores, 24 GB Unified RAM, MPS).
"""
import os
import platform
import multiprocessing
from pydantic import BaseModel

# Hardware Profiling
IS_MACOS = platform.system() == "Darwin"
IS_ARM = platform.machine() in ("arm64", "aarch64")
TOTAL_CPU_CORES = multiprocessing.cpu_count() or 12
RECOMMENDED_WORKERS = max(4, TOTAL_CPU_CORES)

# MPS (Metal Performance Shaders) acceleration check
def get_torch_device() -> str:
    try:
        import torch
        if torch.backends.mps.is_available():
            return "mps"
        elif torch.cuda.is_available():
            return "cuda"
    except ImportError:
        pass
    return "cpu"

TORCH_DEVICE = get_torch_device()

# Paths & Settings
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(BASE_DIR, "datasets")
DB_PATH = os.path.join(BASE_DIR, "detection_platform.db")
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

# Memory Cache Configuration (Optimized for 24 GB RAM)
MAX_CACHE_ENTRIES = 50_000
DNS_CACHE_TTL_SECONDS = 3600
THREAT_FEED_REFRESH_INTERVAL_HOURS = 4

# Threat Intel Thresholds
HIGH_RISK_ENTROPY_THRESHOLD = 4.2
NEW_DOMAIN_AGE_DAYS_THRESHOLD = 30
BRAND_SIMILARITY_THRESHOLD = 0.82

# Target High-Value Brands for Impersonation Detection
TARGET_BRANDS = [
    "microsoft", "office365", "outlook", "azure", "google", "gmail",
    "apple", "icloud", "amazon", "netflix", "paypal", "chase",
    "bankofamerica", "wellsfargo", "docusign", "adobe", "dropbox",
    "facebook", "instagram", "meta", "linkedin", "twitter", "x",
    "github", "coinbase", "binance", "metamask", "dhl", "fedex", "usps",
    "shopee", "lazada", "tokopedia", "walmart", "steam", "aliexpress",
    "ebay", "spotify", "telegram", "whatsapp"
]
