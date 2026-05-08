# NetGuard Gemma 4 Hackathon Contest Packet

## Project Name

NetGuard Gemma 4 Local SOC Analyst

## Repository

https://github.com/cbw29512/GeminiHackathon

## One-Sentence Pitch

NetGuard uses a local Gemma 4 model as a SOC analyst that reads sanitized Suricata/Wazuh-style telemetry and returns a structured incident report.

## What The Project Does

This project adds a local AI analysis layer to a security monitoring workflow.

The core endpoint is:

`POST /analyze-logs`

It accepts a sanitized block of security logs and returns:

- incident summary
- severity
- confidence
- attack chain
- timeline
- indicators of compromise
- triage recommendations

## Why Gemma 4 Is Central

Gemma 4 is not decorative in this project.

Gemma 4 performs the core reasoning task: reading a multi-event log window, correlating events across time, and turning noisy telemetry into an analyst-style incident report.

The project does not use Gemma 4 only for copywriting, chat, or a generic explanation. The model is the security reasoning engine behind the hero feature.

## Demo Scenario

The demo uses a sanitized event window shaped like real SOC telemetry.

The sequence includes:

1. network scan
2. web attack probe
3. SSH brute force attempts
4. successful login
5. privileged command execution
6. payload retrieval
7. outbound shell behavior
8. persistence indicator

The value of the demo is that these events are not treated as isolated alerts. Gemma 4 is asked to connect them into one coherent incident.

## Privacy Boundary

Security logs can expose internal IPs, usernames, hostnames, and traffic patterns.

The public demo uses sanitized data. The sanitizer preserves useful event structure while replacing sensitive values. This keeps the demonstration realistic without exposing private telemetry.

## Local-First Design

The project is designed to run locally:

- FastAPI serves the local API.
- Ollama runs the local Gemma 4 model.
- Pydantic validates model output.
- Sanitization happens before logs are submitted for analysis.
- The API binds to `127.0.0.1`.

## Current Stable State

The stable code checkpoint includes:

- `/analyze`
- `/analyze-logs`
- `/ui`
- `/sample-logs`
- `max_log_chars` guard on `/analyze-logs`
- committed UI template
- stricter schema validation
- test harness that does not require `pytest-asyncio`
- 11 passing tests

## Submission Assets

Use these documents for final contest work:

- `docs/DEVTO_SUBMISSION_OUTLINE.md`
- `docs/DEMO_SCRIPT.md`
- `docs/SCREENSHOT_CHECKLIST.md`
- `docs/HACKATHON_DEMO_LOCK.md`

## Definition Of Done

The submission is ready when:

- GitHub repo is public or accessible as required by the contest.
- README accurately describes the working demo.
- Demo recording shows `/ui` or `/analyze-logs`.
- Screenshots show the endpoint, model output, and local-first design.
- Dev.to article explains why Gemma 4 is central to the project.
- No model binary, secrets, raw captures, or private logs are committed.