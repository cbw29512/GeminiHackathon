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

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(PROJECT_ROOT / "templates"))

app = FastAPI(title="NetGuard AI Analysis API", version="0.4.0")


class LogAutopsyRequest(BaseModel):
    logs: str
    time_window: Optional[str] = None


@app.get("/")
def read_root():
    return {
        "status": "online",
        "engine": "Gemma 4 E4B (Q8_0)",
        "endpoints": ["/analyze", "/analyze-logs", "/ui", "/sample-logs"],
    }


@app.get("/ui", response_class=HTMLResponse)
def ui(request: Request):
    """Single-page log autopsy UI."""
    return templates.TemplateResponse("index.html", {"request": request})


@app.get("/sample-logs", response_class=PlainTextResponse)
def sample_logs():
    """Returns the sanitized sample eve.json. Used by the UI's 'Load sample' button."""
    sanitizer = PROJECT_ROOT / "scripts" / "sanitize_logs.py"
    sample = PROJECT_ROOT / "scripts" / "sample_eve.json"
    if not sanitizer.exists() or not sample.exists():
        raise HTTPException(status_code=500, detail="Sample assets missing")
    try:
        result = subprocess.run(
            [sys.executable, str(sanitizer), "--input", str(sample), "--seed", "42"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise HTTPException(status_code=500, detail=f"Sanitizer failed: {e.stderr}") from e


@app.post("/analyze", response_model=SecurityAlert)
async def analyze_threat(anomaly: NetworkAnomaly):
    """Single-anomaly analysis."""
    try:
        logger.info(f"Analyzing anomaly from {anomaly.source_ip}")
        return await analyze_traffic_with_gemma(anomaly)
    except GemmaError as e:
        logger.error(f"Inference failure: {e}")
        raise HTTPException(status_code=502, detail=str(e))


@app.post("/analyze-logs", response_model=IncidentReport)
async def analyze_logs(request: LogAutopsyRequest):
    """Long-context log autopsy. The hero feature."""
    if not request.logs.strip():
        raise HTTPException(status_code=400, detail="Empty log block")
    char_count = len(request.logs)
    logger.info(f"Log autopsy: {char_count} chars (~{char_count // 4} tokens estimate)")
    try:
        return await analyze_logs_with_gemma(request.logs, request.time_window)
    except GemmaError as e:
        logger.error(f"Inference failure: {e}")
        raise HTTPException(status_code=502, detail=str(e))


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)