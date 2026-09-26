"""
Automated Kaggle & Benchmark Dataset Ingestion Utility.
Structures and imports phishing URL datasets and email corpora into local SQLite storage
to bootstrap baseline model weights, regex pattern matchers, and threat caches.
"""
import os
import sys
import csv
import json
import argparse
from typing import Dict, Any

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.database import init_db, get_db_connection, set_threat_cache
from backend.config import TOTAL_CPU_CORES, TORCH_DEVICE

SAMPLE_URLS_CSV = os.path.join(BASE_DIR, "datasets", "sample_data", "phishing_urls_benchmark.csv")
SAMPLE_EMAILS_JSON = os.path.join(BASE_DIR, "datasets", "sample_data", "email_corpus_benchmark.json")

def ingest_url_dataset(csv_path: str) -> int:
    """Ingests Kaggle or benchmark URL CSV file into SQLite threat_cache and rules."""
    if not os.path.exists(csv_path):
        print(f"[!] File not found: {csv_path}")
        return 0

    conn = get_db_connection()
    cursor = conn.cursor()
    ingested_count = 0

    print(f"[*] Ingesting URL Benchmark Dataset from: {csv_path}")
    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row.get("url", "").strip()
            label = int(row.get("label", 0))
            category = row.get("category", "general")
            source = row.get("source", "kaggle_dataset")

            if not url:
                continue

            is_malicious = (label == 1)
            details = {
                "benchmark_category": category,
                "label": "phishing" if is_malicious else "benign",
                "source": source
            }

            # Ingest into threat cache using current cursor
            cursor.execute("""
            INSERT OR REPLACE INTO threat_cache (indicator, indicator_type, source, is_malicious, details, updated_at)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
            """, (url.lower(), "url", f"benchmark_{source}", 1 if is_malicious else 0, json.dumps(details)))

            # Store rule
            if is_malicious:
                cursor.execute("""
                INSERT INTO benchmark_rules (rule_type, pattern, weight, description)
                VALUES (?, ?, ?, ?)
                """, ("URL_BENCHMARK_FLAG", url, 40.0, f"Known Kaggle phishing sample ({category})"))

            ingested_count += 1

    conn.commit()
    conn.close()
    return ingested_count

def ingest_email_dataset(json_path: str) -> int:
    """Ingests email benchmark JSON into database."""
    if not os.path.exists(json_path):
        print(f"[!] File not found: {json_path}")
        return 0

    conn = get_db_connection()
    cursor = conn.cursor()
    ingested_count = 0

    print(f"[*] Ingesting Email Corpus Dataset from: {json_path}")
    with open(json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
        for item in data:
            subject = item.get("subject", "")
            target_url = item.get("target_url", "")
            label = item.get("label", "benign")
            indicators = item.get("indicators", [])

            is_phish = (label != "benign")
            if target_url:
                cursor.execute("""
                INSERT OR REPLACE INTO threat_cache (indicator, indicator_type, source, is_malicious, details, updated_at)
                VALUES (?, ?, ?, ?, ?, datetime('now'))
                """, (target_url.lower(), "url", "email_corpus_benchmark", 1 if is_phish else 0, json.dumps({"email_subject": subject, "indicators": indicators})))

            cursor.execute("""
            INSERT INTO benchmark_rules (rule_type, pattern, weight, description)
            VALUES (?, ?, ?, ?)
            """, ("EMAIL_CORPUS_PRETEXT", subject, 35.0 if is_phish else 0.0, f"Benchmark sample ({label})"))

            ingested_count += 1

    conn.commit()
    conn.close()
    return ingested_count

def main():
    parser = argparse.ArgumentParser(description="Ingest Kaggle Security Datasets & Benchmark Rules")
    parser.add_argument("--urls", type=str, default=SAMPLE_URLS_CSV, help="Path to URL dataset CSV")
    parser.add_argument("--emails", type=str, default=SAMPLE_EMAILS_JSON, help="Path to Email corpus JSON")
    args = parser.parse_args()

    print("=" * 65)
    print("ShieldCheck Dataset Ingestion & Heuristic Initialization")
    print(f"Host Profile: Apple Silicon M4 Pro ({TOTAL_CPU_CORES} Cores, Torch: {TORCH_DEVICE})")
    print("=" * 65)

    init_db()

    url_count = ingest_url_dataset(args.urls)
    email_count = ingest_email_dataset(args.emails)

    print(f"[✓] Successfully ingested {url_count} URL indicators and {email_count} email pretext records.")
    print("[✓] Baseline heuristic tables and threat cache populated.")

if __name__ == "__main__":
    main()
