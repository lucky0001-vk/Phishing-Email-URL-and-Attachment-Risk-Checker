"""
SafeX FastAPI Web Application
Provides high-performance REST APIs and serves the mesmerizing Cyber Defense UI.
"""

import os
from typing import List, Optional
from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from safex.core.analyzer import analyze_email
from safex.core.test_samples import get_test_samples

app = FastAPI(
    title="SafeX Threat Defense Engine",
    description="Static Email, URL, and Attachment Phishing & Malware Decision-Support Tool",
    version="2.0.0"
)

import time

START_TIME = time.time()

# Enable CORS for file:// and cross-origin access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_security_headers(request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


# Current file directory
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
if not os.path.exists(STATIC_DIR):
    root_public = os.path.join(os.path.dirname(os.path.dirname(BASE_DIR)), "public")
    if os.path.exists(root_public):
        STATIC_DIR = root_public

# Mount static files safely if directory exists
if os.path.exists(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/api/health")
@app.get("/health")
async def health_check():
    """Engine health status and static security telemetry."""
    return {
        "status": "healthy",
        "service": "SafeX Threat Defense Engine",
        "version": "2.0.0",
        "uptime_seconds": round(time.time() - START_TIME, 2),
        "execution_mode": "strictly_static_in_memory",
        "live_dns_lookups": False,
        "active_heuristic_rules": 48,
        "max_attachment_size_mb": 25
    }


@app.get("/", response_class=HTMLResponse)
@app.get("/index.html", response_class=HTMLResponse)
async def serve_index():
    index_path = os.path.join(STATIC_DIR, "index.html")
    with open(index_path, "r", encoding="utf-8") as f:
        return f.read()


@app.get("/app.js")
async def serve_app_js():
    from fastapi.responses import FileResponse
    return FileResponse(os.path.join(STATIC_DIR, "app.js"))


@app.get("/styles.css")
async def serve_styles_css():
    from fastapi.responses import FileResponse
    return FileResponse(os.path.join(STATIC_DIR, "styles.css"))


@app.get("/api/samples")
@app.get("/samples")
async def list_samples():
    """Returns catalog of pre-configured test scenarios."""
    samples = get_test_samples()
    catalog = []
    for k, v in samples.items():
        catalog.append({
            "key": k,
            "id": v["id"],
            "title": v["title"],
            "description": v["description"],
            "expected_verdict": v["expected_verdict"],
            "has_attachments": len(v["attachments"]) > 0,
            "attachment_names": [att[0] for att in v["attachments"]]
        })
    return catalog


@app.get("/api/sample/{sample_id}")
@app.get("/sample/{sample_id}")
async def run_sample_analysis(sample_id: int):
    """Run static analysis on one of the 9 pre-configured test scenarios."""
    samples = get_test_samples()
    target_sample = None
    for k, v in samples.items():
        if v["id"] == sample_id:
            target_sample = v
            break

    if not target_sample:
        raise HTTPException(status_code=404, detail=f"Sample #{sample_id} not found.")

    result = analyze_email(target_sample["email_text"], target_sample["attachments"])
    return {
        "sample_meta": {
            "id": target_sample["id"],
            "title": target_sample["title"],
            "description": target_sample["description"],
            "expected_verdict": target_sample["expected_verdict"],
        },
        "analysis": result.model_dump()
    }


@app.post("/api/analyze")
@app.post("/analyze")
async def analyze_custom_input(
    email_text: Optional[str] = Form(None),
    eml_file: Optional[UploadFile] = File(None),
    attachments: Optional[List[UploadFile]] = File(None)
):
    """
    Analyze custom email input:
    - Text pasted in textarea, or
    - Uploaded .eml RFC822 file, and/or
    - Multiple standalone uploaded attachment files.
    """
    raw_content = b""
    if eml_file and eml_file.filename:
        raw_content = await eml_file.read()
    elif email_text:
        raw_content = email_text.encode("utf-8")

    external_atts = []
    if attachments:
        for att in attachments:
            if att.filename:
                att_bytes = await att.read()
                external_atts.append((
                    att.filename,
                    att_bytes,
                    att.content_type or "application/octet-stream"
                ))

    if not raw_content and not external_atts:
        raise HTTPException(status_code=400, detail="Please provide either email text, an .eml file, or attachment files.")

    result = analyze_email(raw_content, external_atts)
    return {
        "analysis": result.model_dump()
    }


@app.post("/api/analyze-link")
@app.post("/analyze-link")
async def analyze_standalone_url(
    url: str = Form(...),
    anchor_text: Optional[str] = Form("")
):
    """
    Dedicated endpoint to analyze any standalone URL or link statically
    without requiring an entire email container.
    """
    from safex.core.url_analyzer import _analyze_single_link
    clean_url = url.strip()
    if not clean_url.startswith(("http://", "https://")):
        clean_url = "http://" + clean_url
    la = _analyze_single_link(clean_url, anchor_text.strip() if anchor_text else "")
    return {
        "link_analysis": la.model_dump()
    }


@app.get("/api/benchmark")
@app.get("/benchmark")
async def get_benchmark_comparison():
    """
    Evaluates rule-based engine vs simulated ML classifier on 20 benchmark test samples.
    Returns confusion matrices, precision, recall, f1-score, and side-by-side predictions.
    """
    from safex.core.evaluation_engine import evaluate_benchmark
    results = evaluate_benchmark()
    return results


@app.get("/api/feedback")
@app.get("/feedback")
async def get_user_feedback():
    """Get aggregated feedback statistics and recent submissions."""
    from safex.core.feedback_store import get_feedback_stats
    return get_feedback_stats()


@app.post("/api/feedback")
@app.post("/feedback")
async def submit_user_feedback(
    sample_id: str = Form("custom"),
    sample_name: str = Form("User Ingestion"),
    user_verdict: str = Form("ACCURATE"),
    notes: Optional[str] = Form(""),
    assigned_score: int = Form(0),
    assigned_rating: str = Form("LOW")
):
    """
    Submit user feedback to report incorrect classifications, false positives, or confirm accuracy.
    """
    from safex.core.feedback_store import record_feedback
    record = record_feedback({
        "sample_id": sample_id,
        "sample_name": sample_name,
        "user_verdict": user_verdict,
        "notes": notes or "",
        "assigned_score": assigned_score,
        "assigned_rating": assigned_rating,
    })
    return {
        "status": "success",
        "message": "Feedback recorded successfully for continuous evaluation.",
        "record": record
    }


def start_server(host="127.0.0.1", port=8000):
    """Entry point for starting the web server."""
    import uvicorn
    print(f"🚀 SafeX Cyber Defense Platform starting on http://{host}:{port}")
    uvicorn.run("safex.web.app:app", host=host, port=port, reload=False)


if __name__ == "__main__":
    start_server()
