"""
SQLite Persistence Engine for Phishing Detection Platform.
Stores scan provenance history, NIST XAI rationales, Evidence Graph snapshots,
threat cache, and auditable false-positive/negative override logs.
"""
import os
import json
import sqlite3
from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.config import DB_PATH

def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # 1. Scans Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        scan_type TEXT NOT NULL,
        target TEXT NOT NULL,
        verdict TEXT NOT NULL,
        confidence_score REAL NOT NULL,
        summary TEXT NOT NULL,
        recipient_data TEXT NOT NULL,
        analyst_data TEXT NOT NULL,
        graph_data TEXT NOT NULL,
        evasions TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 2. Auditable Override & Feedback Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS overrides (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id TEXT NOT NULL,
        target TEXT NOT NULL,
        feedback_type TEXT NOT NULL,
        override_verdict TEXT NOT NULL,
        analyst_notes TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id)
    );
    """)

    # 3. Threat Intel Heuristic & Feed Cache Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS threat_cache (
        indicator TEXT PRIMARY KEY,
        indicator_type TEXT NOT NULL,
        source TEXT NOT NULL,
        is_malicious INTEGER NOT NULL,
        details TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 4. Benchmark Dataset Storage for Heuristic Rules & Baselines
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS benchmark_rules (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rule_type TEXT NOT NULL,
        pattern TEXT NOT NULL,
        weight REAL NOT NULL,
        description TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()

def save_scan(scan_id: str, scan_type: str, target: str, verdict: str,
              confidence_score: float, summary: str, recipient_data: Dict[str, Any],
              analyst_data: Dict[str, Any], graph_data: Dict[str, Any], evasions: List[str]):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO scans (
        id, scan_type, target, verdict, confidence_score, summary,
        recipient_data, analyst_data, graph_data, evasions, created_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        scan_id, scan_type, target, verdict, confidence_score, summary,
        json.dumps(recipient_data), json.dumps(analyst_data),
        json.dumps(graph_data), json.dumps(evasions),
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()

def get_scan(scan_id: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "scan_type": row["scan_type"],
        "target": row["target"],
        "verdict": row["verdict"],
        "confidence_score": row["confidence_score"],
        "summary": row["summary"],
        "recipient_data": json.loads(row["recipient_data"]),
        "analyst_data": json.loads(row["analyst_data"]),
        "graph_data": json.loads(row["graph_data"]),
        "evasions": json.loads(row["evasions"]),
        "created_at": row["created_at"],
    }

def list_recent_scans(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, scan_type, target, verdict, confidence_score, summary, created_at FROM scans ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def save_override(scan_id: str, target: str, feedback_type: str, override_verdict: str, analyst_notes: str) -> int:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO overrides (scan_id, target, feedback_type, override_verdict, analyst_notes, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (scan_id, target, feedback_type, override_verdict, analyst_notes, datetime.utcnow().isoformat()))
    override_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return override_id

def list_overrides(limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM overrides ORDER BY created_at DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_threat_cache(indicator: str) -> Optional[Dict[str, Any]]:
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM threat_cache WHERE indicator = ?", (indicator.lower(),))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return {
        "indicator": row["indicator"],
        "indicator_type": row["indicator_type"],
        "source": row["source"],
        "is_malicious": bool(row["is_malicious"]),
        "details": json.loads(row["details"]),
        "updated_at": row["updated_at"]
    }

def set_threat_cache(indicator: str, indicator_type: str, source: str, is_malicious: bool, details: Dict[str, Any]):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO threat_cache (indicator, indicator_type, source, is_malicious, details, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (indicator.lower(), indicator_type, source, 1 if is_malicious else 0, json.dumps(details), datetime.utcnow().isoformat()))
    conn.commit()
    conn.close()
