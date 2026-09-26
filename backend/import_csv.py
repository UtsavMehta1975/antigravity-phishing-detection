import csv
import json
import sqlite3
import sys
from datetime import datetime
from backend.config import DB_PATH

def import_csv(csv_path):
    print(f"Connecting to database at {DB_PATH}...")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print(f"Reading CSV file from {csv_path}...")
    
    count = 0
    batch_size = 10000
    records = []
    
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            url = row['url'].lower()
            url_type = row['type']
            
            is_malicious = 0 if url_type == 'benign' else 1
            details = json.dumps({"type": url_type})
            
            records.append((
                url,
                'url',
                'kaggle_malicious_phish',
                is_malicious,
                details,
                datetime.utcnow().isoformat()
            ))
            
            count += 1
            if len(records) >= batch_size:
                cursor.executemany("""
                INSERT OR IGNORE INTO threat_cache (indicator, indicator_type, source, is_malicious, details, updated_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """, records)
                conn.commit()
                records = []
                print(f"Inserted {count} records...")
                
    if records:
        cursor.executemany("""
        INSERT OR IGNORE INTO threat_cache (indicator, indicator_type, source, is_malicious, details, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """, records)
        conn.commit()
        print(f"Inserted {count} records...")
        
    conn.close()
    print("Import complete.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python import_csv.py <path_to_csv>")
        sys.exit(1)
    import_csv(sys.argv[1])
