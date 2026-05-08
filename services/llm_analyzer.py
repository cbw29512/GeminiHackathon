import logging
import httpx
from typing import Optional
from pydantic import ValidationError

from services.schemas import NetworkAnomaly, SecurityAlert, IncidentReport

logger = logging.getLogger(__name__)

OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODEL_NAME = "gemma4"
TIMEOUT_SECONDS = 300.0


class GemmaError(RuntimeError):
    """Raised when local inference fails or returns unparseable output."""


async def _call_gemma(prompt: str, system: Optional[str] = None) -> str:
    """POST to Ollama with format=json. Returns the raw response string."""
    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "format": "json",
    }
    if system:
        payload["system"] = system

    async with httpx.AsyncClient(timeout=TIMEOUT_SECONDS) as client:
        try:
            response = await client.post(OLLAMA_URL, json=payload)
            response.raise_for_status()
        except httpx.HTTPError as e:
            raise GemmaError(f"Ollama request failed: {e}") from e

    body = response.json()
    raw = body.get("response", "")
    if not raw.strip():
        raise GemmaError("Ollama returned empty response")
    return raw


async def analyze_traffic_with_gemma(anomaly: NetworkAnomaly) -> SecurityAlert:
    """Single-anomaly analysis. Used by POST /analyze."""
    system = (
        "You are a senior cybersecurity analyst. Respond with valid JSON only. "
        "No commentary, no markdown fences."
    )
    prompt = (
        "Analyze this single network anomaly and return JSON matching the schema below.\n\n"
        f"Timestamp: {anomaly.timestamp.isoformat()}\n"
        f"Source IP: {anomaly.source_ip}\n"
        f"Destination IP: {anomaly.destination_ip}\n"
        f"Protocol: {anomaly.protocol}\n"
        f"Flagged reason: {anomaly.flagged_reason}\n"
        f"Payload snippet: {anomaly.payload_snippet or '(none)'}\n\n"
        'Schema: {"severity": "CRITICAL|HIGH|MEDIUM|LOW", '
        '"analysis": "2-3 sentence explanation", '
        '"mitigation_steps": ["actionable step", ...]}'
    )
    raw = await _call_gemma(prompt, system=system)
    try:
        return SecurityAlert.model_validate_json(raw)
    except ValidationError as e:
        raise GemmaError(
            f"Gemma returned invalid SecurityAlert JSON: {e}\nRaw output: {raw[:500]}"
        ) from e


async def analyze_logs_with_gemma(logs: str, time_window: Optional[str] = None) -> IncidentReport:
    """Long-context log autopsy. Used by POST /analyze-logs. The hero feature."""
    system = (
        "You are a senior SOC analyst conducting a post-incident review. "
        "You read the entire log block before responding. You correlate events "
        "across many lines to find multi-stage attack patterns that line-by-line "
        "SIEMs miss. Respond with valid JSON only."
    )
    window_label = f" (window: {time_window})" if time_window else ""
    prompt = (
        f"Below is a sanitized block of security logs{window_label}. "
        "Read every line. Look for related events that span the whole window: "
        "reconnaissance followed by exploitation, privilege escalation, lateral movement, "
        "data exfiltration, persistence. Do not just match patterns line by line. "
        "Reason about the sequence and explain the attack chain.\n\n"
        "Return a single JSON object matching this schema:\n"
        "{\n"
        '  "incident_summary": "2-3 sentences describing what happened",\n'
        '  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",\n'
        '  "confidence": "HIGH|MEDIUM|LOW",\n'
        '  "attack_chain": ["stage1", "stage2", ...],\n'
        '  "timeline": [\n'
        '    {"timestamp": "...", "actor": "...", "target": "...", "action": "...", "significance": "..."}\n'
        '  ],\n'
        '  "iocs": ["ip:...", "user:...", "domain:..."],\n'
        '  "triage_recommendations": ["actionable next step", ...]\n'
        "}\n\n"
        "If nothing suspicious is present, return severity INFO, empty timeline, "
        "and an incident_summary explaining the window looks clean.\n\n"
        "--- LOGS ---\n"
        f"{logs}\n"
        "--- END LOGS ---"
    )
    raw = await _call_gemma(prompt, system=system)
    try:
        return IncidentReport.model_validate_json(raw)
    except ValidationError as e:
        raise GemmaError(
            f"Gemma returned invalid IncidentReport JSON: {e}\nRaw output: {raw[:500]}"
        ) from e