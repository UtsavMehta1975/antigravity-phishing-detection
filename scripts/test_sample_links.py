"""
Automated Batch Tester for Malicious Sample Links.
Safely analyzes links from sampledetectionlinks.md WITHOUT opening or clicking them.
Outputs a structured threat verdict report with NIST XAI rationales and attack categories.
"""
import os
import sys
import asyncio
from typing import List, Dict, Any

# Ensure project root is in sys.path
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.pipeline import DetectionPipeline

SAMPLE_FILE = os.path.join(BASE_DIR, "sampledetectionlinks.md")

def extract_links_from_file(file_path: str) -> List[Dict[str, Any]]:
    links = []
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return links

    current_group = "1"
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            clean = line.strip()
            if not clean:
                continue
            if clean.startswith("1)"):
                current_group = "Phishing / Credential Harvesting"
                url_part = clean[2:].strip()
                if url_part:
                    links.append({"url": url_part, "group": current_group})
                continue
            elif clean.startswith("2)"):
                current_group = "Malware / Direct Executable Drops"
                url_part = clean[2:].strip()
                if url_part:
                    links.append({"url": url_part, "group": current_group})
                continue

            if clean.startswith("http://") or clean.startswith("https://"):
                links.append({"url": clean, "group": current_group})

    return links

async def run_batch_evaluation():
    links = extract_links_from_file(SAMPLE_FILE)
    if not links:
        print("[!] No links found in sample file.")
        return

    print("=" * 86)
    print("ShieldCheck Batch Detection & Security Evaluation")
    print(f"Target File: {SAMPLE_FILE} ({len(links)} total malicious test links)")
    print("SAFETY RULE: Outbound payload execution and browser opening are STRICTLY DISABLED.")
    print("=" * 86 + "\n")

    pipeline = DetectionPipeline()

    results = []
    for idx, item in enumerate(links, 1):
        url = item["url"]
        group = item["group"]
        
        # Analyze via pipeline without opening browser
        res = await pipeline.analyze_url(url)
        results.append({
            "index": idx,
            "url": url,
            "group": group,
            "verdict": res.get("verdict"),
            "confidence": res.get("confidence_score"),
            "risk_score": res.get("analyst_view", {}).get("url_features", {}).get("risk_score", 0.0),
            "anomalies": res.get("analyst_view", {}).get("all_anomalies", []),
            "summary": res.get("summary")
        })

    # Print Summary Table
    print(f"{'#':<3} | {'GROUP':<25} | {'VERDICT':<10} | {'SCORE':<6} | {'URL':<42}")
    print("-" * 92)

    flagged_count = 0
    for r in results:
        is_threat = r["verdict"] in ["PHISHING", "CAUTION", "UNKNOWN_GUARDED", "UNKNOWN"]
        if is_threat or r["confidence"] >= 35.0:
            flagged_count += 1

        verdict_str = r["verdict"]
        score_str = f"{r['confidence']:.0f}%"
        url_disp = r["url"][:40] + ("..." if len(r["url"]) > 40 else "")
        group_disp = r["group"][:24]
        print(f"{r['index']:<3} | {group_disp:<25} | {verdict_str:<10} | {score_str:<6} | {url_disp:<42}")

    print("-" * 92)
    detection_rate = (flagged_count / len(results)) * 100
    print(f"\n[✓] Batch Analysis Complete: {flagged_count}/{len(results)} Flagged ({detection_rate:.1f}% Detection Rate)")

    # Print Key Attack Vectors Identified
    print("\n[+] Top Attack Vectors Identified:")
    vector_counts: Dict[str, int] = {}
    for r in results:
        for anom in r["anomalies"]:
            cat = anom.get("category", "UNKNOWN")
            vector_counts[cat] = vector_counts.get(cat, 0) + 1

    for cat, count in sorted(vector_counts.items(), key=lambda x: x[1], reverse=True)[:8]:
        print(f"    • {cat:<32}: {count} occurrences")

    print("\n" + "=" * 86)

if __name__ == "__main__":
    asyncio.run(run_batch_evaluation())
