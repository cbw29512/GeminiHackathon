import random
from services.schemas import NetworkAnomaly

def generate_synthetic_anomalies(count=1):
    anomalies = []
    for _ in range(count):
        anomalies.append(NetworkAnomaly(
            timestamp="2026-05-07T19:30:00",
            source_ip=f"192.0.2.{random.randint(1, 254)}",
            destination_ip="10.0.0.5",
            protocol="TCP",
            flagged_reason="Synthetic Test Anomaly",
            payload_snippet="DEBUG: Manual trigger"
        ))
    return anomalies
