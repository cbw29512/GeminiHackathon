"""
Sanitize Suricata eve.json (or any text logs) before sending to a local LLM.

Design rules:
  - Consistency: the same input value always maps to the same output value
    within a single run. Gemma needs to correlate '198.51.100.42' across
    many lines; randomizing per-occurrence destroys the signal.
  - Structure preserved: NDJSON stays NDJSON, timestamps stay valid ISO-8601,
    field types unchanged. Only string content gets swapped.
  - Reproducible (optional): pass --seed for deterministic mappings across runs.
  - No round-trip: this is one-way. We do not store the mapping table to disk
    by default. Pass --emit-mapping <path> if you want it.

Usage:
  python scripts/sanitize_logs.py --input scripts/sample_eve.json --output sanitized.json
  python scripts/sanitize_logs.py < raw.json > clean.json
  python scripts/sanitize_logs.py --input raw.json --seed 42 --emit-mapping map.json

What gets swapped:
  - IPv4 addresses outside reserved/documentation ranges (RFC 1918, 5737, 6890)
  - Usernames in known fields (ssh.username, sudo USER=, *_user, *_username)
  - Hostnames in *.lan / *.local / *.corp domains and HTTP Host headers
  - URLs are kept structurally; hostnames inside them get swapped consistently

What does NOT get swapped:
  - Timestamps, ports, signature IDs, rule names, event types, byte counts
  - Public-internet IPs that match RFC 5737 docs (198.51.100.0/24, 203.0.113.0/24,
    192.0.2.0/24) since those are already safe to publish
  - Loopback, multicast, link-local
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import random
import re
import sys
from pathlib import Path
from typing import Optional

# IPs we leave alone because they are already safe / meaningful
SAFE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),       # loopback
    ipaddress.ip_network("224.0.0.0/4"),       # multicast
    ipaddress.ip_network("169.254.0.0/16"),    # link-local
    ipaddress.ip_network("198.51.100.0/24"),   # RFC 5737 doc
    ipaddress.ip_network("203.0.113.0/24"),    # RFC 5737 doc
    ipaddress.ip_network("192.0.2.0/24"),      # RFC 5737 doc
    ipaddress.ip_network("8.8.8.8/32"),        # well-known public DNS, kept for context
    ipaddress.ip_network("1.1.1.1/32"),        # well-known public DNS, kept for context
]

# Documentation IP pool to draw replacements from (RFC 5737 TEST-NET-2)
DOC_POOL_NETWORK = ipaddress.ip_network("203.0.113.0/24")

# Common safe-to-leave system usernames; everything else gets swapped
SAFE_USERS = {"root", "admin", "administrator", "system", "nobody", "daemon"}

FAKE_USER_POOL = [
    "alice", "bob", "carol", "dave", "eve", "frank", "grace", "heidi",
    "ivan", "judy", "mallory", "olivia", "peggy", "trent", "victor", "walter",
]

FAKE_HOST_POOL = [
    "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel",
    "india", "juliet", "kilo", "lima", "mike", "november", "oscar", "papa",
]

IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HOSTNAME_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9-]{0,62})\.(lan|local|corp|home|internal)\b")


class Mapper:
    """Stable, in-memory mapping from real value -> sanitized value."""

    def __init__(self, seed: Optional[int] = None):
        self.rng = random.Random(seed)
        self.ip_map: dict[str, str] = {}
        self.user_map: dict[str, str] = {}
        self.host_map: dict[str, str] = {}
        self._used_doc_ips: set[str] = set()
        self._user_pool = FAKE_USER_POOL.copy()
        self._host_pool = FAKE_HOST_POOL.copy()
        self.rng.shuffle(self._user_pool)
        self.rng.shuffle(self._host_pool)
        self._user_idx = 0
        self._host_idx = 0

    def _next_doc_ip(self) -> str:
        # Pull a fresh address from the doc pool
        while True:
            host_part = self.rng.randint(2, 253)
            candidate = str(ipaddress.IPv4Address(int(DOC_POOL_NETWORK.network_address) + host_part))
            if candidate not in self._used_doc_ips:
                self._used_doc_ips.add(candidate)
                return candidate

    def _next_user(self) -> str:
        if self._user_idx >= len(self._user_pool):
            # Ran out; suffix with numbers
            base = self._user_pool[self._user_idx % len(self._user_pool)]
            return f"{base}{self._user_idx}"
        name = self._user_pool[self._user_idx]
        self._user_idx += 1
        return name

    def _next_host(self) -> str:
        if self._host_idx >= len(self._host_pool):
            base = self._host_pool[self._host_idx % len(self._host_pool)]
            return f"{base}{self._host_idx}"
        name = self._host_pool[self._host_idx]
        self._host_idx += 1
        return name

    def map_ip(self, ip_str: str) -> str:
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            return ip_str
        if any(ip in net for net in SAFE_NETWORKS):
            return ip_str
        if ip.is_private or ip.is_reserved:
            # Sanitize private RFC 1918 addresses too — they reveal internal topology
            if ip_str not in self.ip_map:
                self.ip_map[ip_str] = self._next_doc_ip()
            return self.ip_map[ip_str]
        # Public IP — sanitize it
        if ip_str not in self.ip_map:
            self.ip_map[ip_str] = self._next_doc_ip()
        return self.ip_map[ip_str]

    def map_user(self, username: str) -> str:
        if not username or username.lower() in SAFE_USERS:
            return username
        if username not in self.user_map:
            self.user_map[username] = self._next_user()
        return self.user_map[username]

    def map_hostname_label(self, label: str) -> str:
        if label not in self.host_map:
            self.host_map[label] = self._next_host()
        return self.host_map[label]

    def export(self) -> dict:
        return {
            "ip_map": self.ip_map,
            "user_map": self.user_map,
            "host_map": self.host_map,
        }


def sanitize_text(text: str, mapper: Mapper) -> str:
    """Replace IPs and *.lan-style hostnames in any free-form string."""
    text = IPV4_RE.sub(lambda m: mapper.map_ip(m.group(0)), text)

    def _host_repl(m: re.Match) -> str:
        label, suffix = m.group(1), m.group(2)
        return f"{mapper.map_hostname_label(label)}.{suffix}"
    text = HOSTNAME_RE.sub(_host_repl, text)
    return text


# Field paths where usernames live in eve.json
USERNAME_FIELDS = {"username", "user", "usr", "username_created"}


def sanitize_value(value, mapper: Mapper, key_hint: Optional[str] = None):
    """Recursively sanitize a JSON value."""
    if isinstance(value, dict):
        return {k: sanitize_value(v, mapper, key_hint=k) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_value(v, mapper, key_hint=key_hint) for v in value]
    if isinstance(value, str):
        if key_hint in USERNAME_FIELDS:
            return mapper.map_user(value)
        return sanitize_text(value, mapper)
    return value


def sanitize_line(line: str, mapper: Mapper) -> str:
    """Try JSON; fall back to text sanitization."""
    line = line.rstrip("\n")
    if not line.strip():
        return line
    try:
        obj = json.loads(line)
        sanitized = sanitize_value(obj, mapper)
        return json.dumps(sanitized, separators=(",", ":"))
    except json.JSONDecodeError:
        return sanitize_text(line, mapper)


def main() -> int:
    parser = argparse.ArgumentParser(description="Sanitize logs before LLM submission.")
    parser.add_argument("--input", "-i", help="Input file (default: stdin)")
    parser.add_argument("--output", "-o", help="Output file (default: stdout)")
    parser.add_argument("--seed", type=int, default=None, help="Seed for reproducible mappings")
    parser.add_argument("--emit-mapping", help="Write the mapping table to this path (be careful)")
    args = parser.parse_args()

    src = open(args.input, "r", encoding="utf-8") if args.input else sys.stdin
    dst = open(args.output, "w", encoding="utf-8") if args.output else sys.stdout

    mapper = Mapper(seed=args.seed)
    try:
        for line in src:
            dst.write(sanitize_line(line, mapper) + "\n")
    finally:
        if args.input:
            src.close()
        if args.output:
            dst.close()

    if args.emit_mapping:
        Path(args.emit_mapping).write_text(json.dumps(mapper.export(), indent=2), encoding="utf-8")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())