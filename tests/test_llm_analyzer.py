"""Tests for Gemma response parsing without calling Ollama.

Big picture:
- These tests do not call the real local model.
- They monkeypatch the Ollama helper so we can test parsing and schema validation.
- asyncio.run() lets plain pytest execute async production functions without pytest-asyncio.
"""
from __future__ import annotations

import asyncio

import pytest

from services import llm_analyzer
from services.llm_analyzer import (
    GemmaError,
    analyze_logs_with_gemma,
    analyze_traffic_with_gemma,
)
from services.schemas import NetworkAnomaly


def test_analyze_logs_valid_json(monkeypatch):
    """A valid Gemma incident report should parse into IncidentReport."""

    async def fake_call(prompt: str, system: str | None = None) -> str:
        return """
        {
          "incident_summary": "A multi-stage intrusion was observed.",
          "severity": "CRITICAL",
          "confidence": "HIGH",
          "attack_chain": ["scan", "credential access", "execution"],
          "timeline": [
            {
              "timestamp": "2026-05-07T14:00:01Z",
              "actor": "ip:198.51.100.42",
              "target": "host:203.0.113.10",
              "action": "scanned exposed services",
              "significance": "Reconnaissance preceded later activity."
            }
          ],
          "iocs": ["ip:198.51.100.42"],
          "triage_recommendations": ["Disable compromised accounts."]
        }
        """

    monkeypatch.setattr(llm_analyzer, "_call_gemma", fake_call)

    report = asyncio.run(analyze_logs_with_gemma("demo logs", "demo window"))

    assert report.severity == "CRITICAL"
    assert report.confidence == "HIGH"
    assert report.attack_chain[0] == "scan"


def test_analyze_logs_invalid_severity_rejected(monkeypatch):
    """Strict schema should reject invalid model labels."""

    async def fake_call(prompt: str, system: str | None = None) -> str:
        return """
        {
          "incident_summary": "Bad severity label.",
          "severity": "URGENT",
          "confidence": "HIGH",
          "attack_chain": [],
          "timeline": [],
          "iocs": [],
          "triage_recommendations": []
        }
        """

    monkeypatch.setattr(llm_analyzer, "_call_gemma", fake_call)

    with pytest.raises(GemmaError):
        asyncio.run(analyze_logs_with_gemma("demo logs"))


def test_analyze_single_anomaly_valid_json(monkeypatch):
    """A valid single-anomaly response should parse into SecurityAlert."""

    async def fake_call(prompt: str, system: str | None = None) -> str:
        return """
        {
          "severity": "HIGH",
          "analysis": "The payload resembles SQL injection.",
          "mitigation_steps": ["Review web logs.", "Block the source IP."]
        }
        """

    monkeypatch.setattr(llm_analyzer, "_call_gemma", fake_call)

    anomaly = NetworkAnomaly(
        timestamp="2026-05-07T14:00:00Z",
        source_ip="198.51.100.42",
        destination_ip="10.0.0.5",
        protocol="HTTP",
        flagged_reason="SQL injection attempt",
        payload_snippet="' OR 1=1 --",
    )

    alert = asyncio.run(analyze_traffic_with_gemma(anomaly))

    assert alert.severity == "HIGH"
    assert "SQL injection" in alert.analysis