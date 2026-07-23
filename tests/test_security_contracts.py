import pytest
from pydantic import ValidationError

from main import LogAutopsyRequest, MAX_LOG_CHARS
from services.schemas import NetworkAnomaly


def test_log_request_rejects_oversized_input() -> None:
    with pytest.raises(ValidationError):
        LogAutopsyRequest(logs="x" * (MAX_LOG_CHARS + 1))


def test_log_request_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        LogAutopsyRequest(logs="sanitized", unexpected="value")


def test_network_anomaly_validates_ip_addresses() -> None:
    with pytest.raises(ValidationError):
        NetworkAnomaly(
            timestamp="2026-07-23T12:00:00Z",
            source_ip="not-an-ip",
            destination_ip="192.0.2.10",
            protocol="HTTP",
            flagged_reason="test",
        )


def test_network_anomaly_bounds_payload() -> None:
    with pytest.raises(ValidationError):
        NetworkAnomaly(
            timestamp="2026-07-23T12:00:00Z",
            source_ip="192.0.2.9",
            destination_ip="192.0.2.10",
            protocol="HTTP",
            flagged_reason="test",
            payload_snippet="x" * 4_001,
        )
