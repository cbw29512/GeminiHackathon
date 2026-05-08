from datetime import datetime
from typing import List, Optional, Literal

from pydantic import BaseModel, Field

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
AlertSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]


class NetworkAnomaly(BaseModel):
    """Input: a single flagged network event."""
    timestamp: datetime
    source_ip: str
    destination_ip: str
    protocol: str
    flagged_reason: str = Field(..., description="The heuristic that triggered the flag")
    payload_snippet: Optional[str] = Field(default=None, description="Sanitized truncated payload")


class SecurityAlert(BaseModel):
    """Output of single-anomaly analysis. Returned by POST /analyze."""
    severity: AlertSeverity = Field(..., description="CRITICAL | HIGH | MEDIUM | LOW")
    analysis: str = Field(..., description="2-3 sentence explanation")
    mitigation_steps: List[str] = Field(..., description="Actionable next steps")


class TimelineEvent(BaseModel):
    """One ordered step inside an incident timeline."""
    timestamp: str
    actor: str
    target: str
    action: str
    significance: str


class IncidentReport(BaseModel):
    """Output of long-context log autopsy. Returned by POST /analyze-logs."""
    incident_summary: str = Field(..., description="2-3 sentence overview")
    severity: Severity = Field(..., description="CRITICAL | HIGH | MEDIUM | LOW | INFO")
    confidence: Confidence = Field(..., description="HIGH | MEDIUM | LOW")
    attack_chain: List[str] = Field(..., description="Ordered kill-chain stages observed")
    timeline: List[TimelineEvent] = Field(..., description="Chronological events with reasoning")
    iocs: List[str] = Field(..., description="Indicators of compromise")
    triage_recommendations: List[str] = Field(..., description="Actionable next steps")