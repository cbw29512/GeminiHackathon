import subprocess
import sys
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, PlainTextResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import logging
import uvicorn

from services.schemas import NetworkAnomaly, SecurityAlert, IncidentReport
from services.llm_analyzer import (
    analyze_traffic_with_gemma,
    analyze_logs_with_gemma,
    GemmaError,
)

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "templates"))

MAX_LOG_CHARS = 50_000

app = FastAPI(title="NetGuard AI Analysis API", version="0.4.1")


class LogAutopsyRequest(BaseModel):
    logs: str
    time_window: Optional[str] = None


@app.get("/")
def read_root():
    return {
        "status": "online",
        "engine": "Gemma 4 E4B (Q8_0)",
        "endpoints": ["/analyze", "/analyze-logs", "/ui", "/sample-logs"],
        "max_log_chars": MAX_LOG_CHARS,
    }


@app.get("/ui", response_class=HTMLResponse)
def ui(request: Request):
    """Single-page log autopsy UI."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/sample-logs", response_class=PlainTextResponse)
def sample_logs():
    """Return sanitized sample eve.json for the UI demo."""
    sanitizer = PROJECT_ROOT / "scripts" / "sanitize_logs.py"
    sample = PROJECT_ROOT / "scripts" / "sample_eve.json"

    if not sanitizer.exists() or not sample.exists():
        raise HTTPException(status_code=500, detail="Sample assets missing.")

    try:
        result = subprocess.run(
            [sys.executable, str(sanitizer), "--input", str(sample), "--seed", "42"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return result.stdout
    except subprocess.TimeoutExpired as exc:
        logger.exception("Sanitizer timed out.")
        raise HTTPException(status_code=500, detail="Sample sanitizer timed out.") from exc
    except subprocess.CalledProcessError as exc:
        logger.exception("Sanitizer failed.")
        raise HTTPException(status_code=500, detail="Sample sanitizer failed.") from exc


@app.post("/analyze", response_model=SecurityAlert)
async def analyze_threat(anomaly: NetworkAnomaly):
    """Single-anomaly analysis."""
    try:
        logger.info("Analyzing anomaly from %s", anomaly.source_ip)
        return await analyze_traffic_with_gemma(anomaly)
    except GemmaError as exc:
        logger.exception("Inference failure.")
        raise HTTPException(status_code=502, detail="Local Gemma inference failed.") from exc


@app.post("/analyze-logs", response_model=IncidentReport)
async def analyze_logs(request: LogAutopsyRequest):
    """Long-context log autopsy. The hero feature."""
    logs = request.logs.strip()

    if not logs:
        raise HTTPException(status_code=400, detail="Empty log block.")

    if len(logs) > MAX_LOG_CHARS:
        raise HTTPException(
            status_code=413,
            detail=f"Log block too large. Max allowed characters: {MAX_LOG_CHARS}.",
        )

    char_count = len(logs)
    logger.info("Log autopsy: %s chars (~%s tokens estimate)", char_count, char_count // 4)

    try:
        return await analyze_logs_with_gemma(logs, request.time_window)
    except GemmaError as exc:
        logger.exception("Inference failure.")
        raise HTTPException(status_code=502, detail="Local Gemma inference failed.") from exc


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)