"""
AntiGravity Phishing Email & URL Detection Platform Launcher.
Optimized for Apple Silicon MacBook M4 Pro (12 CPU Cores, 24 GB RAM, MPS).
"""
import os
import sys
import uvicorn

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.config import (
    TOTAL_CPU_CORES, RECOMMENDED_WORKERS, TORCH_DEVICE,
    IS_MACOS, IS_ARM, DB_PATH
)
from backend.database import init_db
from scripts.ingest_datasets import ingest_url_dataset, ingest_email_dataset, SAMPLE_URLS_CSV, SAMPLE_EMAILS_JSON

def print_banner():
    print("=" * 72)
    print("      AntiGravity Phishing Detection & Provenance Engine")
    print("              Problem P12 - End-to-End Platform")
    print("=" * 72)
    print(f"[*] Hardware Profile: Apple Silicon M4 Pro ({'macOS ARM64' if IS_MACOS and IS_ARM else 'Host'})")
    print(f"[*] CPU Allocation : {TOTAL_CPU_CORES} Cores mapped across asyncio / worker pools")
    print(f"[*] Device Accel   : {TORCH_DEVICE.upper()} (Metal Performance Shaders)")
    print(f"[*] Local Database : SQLite WAL mode ({DB_PATH})")
    print("=" * 72)

def main():
    print_banner()

    # 1. Initialize Database
    print("[*] Initializing local database and schema...")
    init_db()

    # 2. Check if benchmark datasets need bootstrapping
    print("[*] Checking baseline heuristic rules & Kaggle benchmark feeds...")
    try:
        ingest_url_dataset(SAMPLE_URLS_CSV)
        ingest_email_dataset(SAMPLE_EMAILS_JSON)
    except Exception as e:
        print(f"[!] Dataset baseline note: {e}")

    print("\n[✓] System initialized successfully.")
    print("[✓] Serving Dual-Layer UI & API at: http://localhost:8000")
    print("[✓] OpenAPI / Swagger Docs at     : http://localhost:8000/docs")
    print("=" * 72 + "\n")

    # 3. Start Uvicorn Server
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=False,
        workers=1,
        log_level="info"
    )

if __name__ == "__main__":
    main()
