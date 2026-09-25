"""
FastAPI Backend Application for Phishing Email and URL Detection Platform.
Provides REST endpoints for email parsing, URL extraction, attachment smuggling analysis,
Evidence Graph generation, NIST XAI evaluation, and auditable feedback override tracking.
"""
import os
import psutil
from fastapi import FastAPI, File, UploadFile, Form, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Optional, List, Dict, Any

from backend.config import (
    TOTAL_CPU_CORES, RECOMMENDED_WORKERS, TORCH_DEVICE,
    FRONTEND_DIR, IS_MACOS, IS_ARM
)
from backend.database import (
    init_db, list_recent_scans, get_scan,
    save_override, list_overrides
)
from backend.pipeline import DetectionPipeline

# Initialize FastAPI app
app = FastAPI(
    title="AntiGravity Phishing Detection Engine",
    description="Apple Silicon M4 Pro Optimized Phishing Email & URL Provenance Engine with NIST XAI",
    version="1.0.0"
)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Pipeline Instance
pipeline = DetectionPipeline()

# Ensure Database is initialized and baseline feeds seeded on startup
@app.on_event("startup")
async def startup_event():
    init_db()
    try:
        from scripts.ingest_datasets import ingest_url_dataset, ingest_email_dataset, SAMPLE_URLS_CSV, SAMPLE_EMAILS_JSON
        ingest_url_dataset(SAMPLE_URLS_CSV)
        ingest_email_dataset(SAMPLE_EMAILS_JSON)
    except Exception:
        pass

# Models
class URLScanRequest(BaseModel):
    url: str

class FeedbackRequest(BaseModel):
    scan_id: str
    target: str
    feedback_type: str  # 'false_positive' or 'false_negative'
    override_verdict: str  # 'BENIGN' or 'PHISHING'
    analyst_notes: str

# 1. System Health & Hardware Telemetry
@app.get("/api/health")
async def health_check():
    mem = psutil.virtual_memory()
    return {
        "status": "HEALTHY",
        "hardware": {
            "platform": "Apple Silicon (macOS)" if IS_MACOS and IS_ARM else "Standard Host",
            "cpu_cores": TOTAL_CPU_CORES,
            "worker_threads": RECOMMENDED_WORKERS,
            "total_ram_gb": round(mem.total / (1024**3), 2),
            "ram_used_percent": mem.percent,
            "torch_acceleration_device": TORCH_DEVICE,
            "mps_available": TORCH_DEVICE == "mps"
        }
    }

# 2. Email (.eml) Scan Endpoint
@app.post("/api/scan/email")
async def scan_email(file: UploadFile = File(...)):
    if not file.filename.lower().endswith((".eml", ".msg", ".txt")):
        # Still attempt to parse as MIME
        pass
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty email file uploaded")

    result = await pipeline.analyze_email(content)
    return result

# 3. URL Scan Endpoint
@app.post("/api/scan/url")
async def scan_url(req: URLScanRequest):
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    result = await pipeline.analyze_url(req.url.strip())
    return result

# 4. Standalone Attachment Scan Endpoint
@app.post("/api/scan/attachment")
async def scan_attachment(file: UploadFile = File(...)):
    content = await file.read()
    if not content:
        raise HTTPException(status_code=400, detail="Empty file uploaded")
    result = await pipeline.analyze_attachment_file(file.filename, content)
    return result

# 5. History & Audit Endpoints
@app.get("/api/scans")
async def get_scans(limit: int = 50):
    return list_recent_scans(limit=limit)

@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str):
    scan = get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

# 6. Feedback & Auditable Allow-Override Endpoints
@app.post("/api/feedback")
async def submit_feedback(req: FeedbackRequest):
    override_id = save_override(
        scan_id=req.scan_id,
        target=req.target,
        feedback_type=req.feedback_type,
        override_verdict=req.override_verdict,
        analyst_notes=req.analyst_notes
    )
    return {
        "status": "RECORDED",
        "override_id": override_id,
        "message": f"Auditable override recorded for scan '{req.scan_id}'"
    }

@app.get("/api/overrides")
async def get_overrides(limit: int = 50):
    return list_overrides(limit=limit)

# 7. Serve Frontend Dashboard
if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
