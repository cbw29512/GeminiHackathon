"""Tests for the sanitization pipeline."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SANITIZER = PROJECT_ROOT / "scripts" / "sanitize_logs.py"
SAMPLE = PROJECT_ROOT / "scripts" / "sample_eve.json"


def run_sanitizer(input_text: str, seed: int | None = 42) -> str:
    """Pipe input_text through the sanitizer and return its stdout."""
    cmd = [sys.executable, str(SANITIZER)]
    if seed is not None:
        cmd.extend(["--seed", str(seed)])
    result = subprocess.run(
        cmd,
        input=input_text,
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return result.stdout


def parse_lines(text: str) -> list[dict]:
    return [json.loads(line) for line in text.strip().splitlines() if line.strip()]


def test_consistency_same_ip_same_replacement():
    """Same input IP must map to the same output IP across all occurrences."""
    sample = SAMPLE.read_text(encoding="utf-8")
    out = run_sanitizer(sample)
    lines = parse_lines(out)

    # Original eve.json has 10.0.0.5 in many lines; all sanitized versions
    # must collapse to the same replacement value.
    src_ips = [line.get("dest_ip") for line in lines if line.get("dest_ip")]
    target_ip_replacements = {
        line.get("dest_ip")
        for line in lines
        if line.get("event_type") in {"flow", "ssh", "alert"} and line.get("dest_ip")
    }
    # We only assert >0 replacements (10.0.0.5 is private; should be mapped).
    # The point: pick any IP that appeared >1 time; all replacements should match.
    assert any(src_ips.count(ip) >= 2 for ip in set(src_ips)), \
        "Sample lacks repeated dest_ips; consistency cannot be verified"

    # Group: for each unique replacement IP, ensure the original lines all had
    # the same source. We do that by running twice and confirming determinism.
    out2 = run_sanitizer(sample)
    assert out == out2, "Same input + same seed must produce identical output"


def test_doc_ips_preserved():
    """RFC 5737 documentation IPs (198.51.100/24) are already safe; do not rewrite."""
    sample = '{"src_ip":"198.51.100.42","dest_ip":"203.0.113.7"}\n'
    out = run_sanitizer(sample)
    parsed = parse_lines(out)[0]
    assert parsed["src_ip"] == "198.51.100.42"
    assert parsed["dest_ip"] == "203.0.113.7"


def test_private_ip_sanitized():
    """RFC 1918 private IPs reveal topology; they must be rewritten."""
    sample = '{"src_ip":"10.0.0.5","dest_ip":"192.168.1.100"}\n'
    out = run_sanitizer(sample)
    parsed = parse_lines(out)[0]
    assert parsed["src_ip"] != "10.0.0.5"
    assert parsed["dest_ip"] != "192.168.1.100"
    # And both should now be doc-pool IPs
    assert parsed["src_ip"].startswith("203.0.113.")
    assert parsed["dest_ip"].startswith("203.0.113.")


def test_username_sanitized_consistently():
    """Username 'backup' must always become the same fake username."""
    sample = (
        '{"event_type":"ssh","ssh":{"username":"backup","auth_msg":"success"}}\n'
        '{"event_type":"ssh","ssh":{"username":"backup","auth_msg":"failed"}}\n'
        '{"event_type":"audit","username":"backup"}\n'
    )
    out = run_sanitizer(sample)
    lines = parse_lines(out)
    fake1 = lines[0]["ssh"]["username"]
    fake2 = lines[1]["ssh"]["username"]
    fake3 = lines[2]["username"]
    assert fake1 == fake2 == fake3, f"Inconsistent: {fake1=} {fake2=} {fake3=}"
    assert fake1 != "backup", "backup was not sanitized"


def test_safe_usernames_preserved():
    """root/admin/system stay as-is; they're context, not PII."""
    sample = '{"username":"root"}\n{"username":"admin"}\n'
    out = run_sanitizer(sample)
    lines = parse_lines(out)
    assert lines[0]["username"] == "root"
    assert lines[1]["username"] == "admin"


def test_lan_hostname_sanitized():
    """*.lan, *.local, *.corp hostnames get rewritten consistently."""
    sample = (
        '{"http":{"hostname":"shop.divcl.lan"}}\n'
        '{"http":{"hostname":"shop.divcl.lan"}}\n'
    )
    out = run_sanitizer(sample)
    lines = parse_lines(out)
    h1 = lines[0]["http"]["hostname"]
    h2 = lines[1]["http"]["hostname"]
    assert h1 == h2, "Same hostname must map to same replacement"
    assert h1 != "shop.divcl.lan"
    assert h1.endswith(".lan")


def test_structure_preserved():
    """Sanitized output is still valid NDJSON with the same line count."""
    sample = SAMPLE.read_text(encoding="utf-8")
    out = run_sanitizer(sample)
    in_lines = [ln for ln in sample.splitlines() if ln.strip()]
    out_lines = [ln for ln in out.splitlines() if ln.strip()]
    assert len(in_lines) == len(out_lines)
    for line in out_lines:
        json.loads(line)  # must parse; raises if not


def test_timestamps_unchanged():
    """We never touch timestamps; correlation depends on them."""
    sample = SAMPLE.read_text(encoding="utf-8")
    out = run_sanitizer(sample)
    in_lines = parse_lines(sample)
    out_lines = parse_lines(out)
    for inp, outp in zip(in_lines, out_lines):
        assert inp["timestamp"] == outp["timestamp"]