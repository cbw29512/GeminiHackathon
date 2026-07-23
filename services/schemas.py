"""Validated input and output schemas for local security analysis."""

from datetime import datetime
from ipaddress import IPv4Address, IPv6Address
from typing import List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field

Severity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
AlertSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
Confidence = Literal["HIGH", "MEDIUM", "LOW"]
IPAddress = Union[IPv4Address, IPv6Address]


class StrictModel(BaseModel):
    """Reject unexpected fields so API and model contracts stay explicit."""

    model_config = ConfigDict(extra="forbid")


class NetworkAnomaly(StrictModel):
    """A single bounded, sanitized network event."""

    timestamp: datetime
    source_ip: IPAddress
    destination_ip: IPAddress
    protocol: str = Field(min_length=1, max_length=32)
    flagged_reason: str = Field(min_length=1, max_length=1_000)
    payload_snippet: Optional[str] = Field(default=None, max_length=4_000)


class SecurityAlert(StrictModel):
    """Validated result of single-anomaly analysis."""

    severity: AlertSeverity
    analysis: str = Field(min_length=1, max_length=4_000)
    mitigation_steps: List[str] = Field(min_length=1, max_length=20)


class TimelineEvent(StrictModel):
    """One bounded step in an incident timeline."""

    timestamp: str = Field(min_length=1, max_length=100)
    actor: str = Field(min_length=1, max_length=500)
    target: str = Field(min_length=1, max_length=500)
    action: str = Field(min_length=1, max_length=1_000)
    significance: str = Field(min_length=1, max_length=2_000)


class IncidentReport(StrictModel):
    """Validated result of long-context log analysis."""

    incident_summary: str = Field(min_length=1, max_length=6_000)
    severity: Severity
    confidence: Confidence
    attack_chain: List[str] = Field(max_length=30)
    timeline: List[TimelineEvent] = Field(max_length=200)
    iocs: List[str] = Field(max_length=500)
    triage_recommendations: List[str] = Field(max_length=50)
