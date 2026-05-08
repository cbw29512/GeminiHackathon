# Demo Script

## Goal

Record a clean 2-4 minute demo showing Gemma 4 doing the central project task: analyzing sanitized SOC logs and returning a structured incident report.

## Demo Setup

Use two terminals.

Terminal 1 starts the API:

`cd "C:\Users\divcl\OneDrive\Desktop\HackathonProject"`

`python main.py`

Expected server line:

`Uvicorn running on http://127.0.0.1:8000`

Terminal 2 verifies the API:

`Invoke-RestMethod http://127.0.0.1:8000/`

Expected proof:

- status is online
- engine is Gemma 4 E4B Q8_0
- endpoints include `/analyze-logs`
- `max_log_chars` is present

## Scene 1 — Project Intro

Show the GitHub repo:

https://github.com/cbw29512/GeminiHackathon

Say:

NetGuard Gemma 4 is a local-first SOC analyst demo. It uses Gemma 4 through Ollama to read sanitized security telemetry and produce a structured incident report.

## Scene 2 — API Health

Show the health response from:

`http://127.0.0.1:8000/`

Point out:

- local API
- Gemma 4 engine
- `/analyze-logs`
- `/ui`
- `max_log_chars`

Say:

The model runs locally and the API is bound to loopback. This is designed for sensitive telemetry workflows where cloud inference may not be acceptable.

## Scene 3 — UI

Open:

`http://127.0.0.1:8000/ui`

Click:

`Load sample logs`

Then click:

`Analyze logs`

Say:

The UI loads sanitized SOC-shaped sample logs. The logs are then submitted to the local `/analyze-logs` endpoint.

## Scene 4 — Result

Show the output JSON.

Point out:

- incident summary
- severity
- confidence
- attack chain
- timeline
- IOCs
- triage recommendations

Say:

This is the core of the project. Gemma 4 is not just generating prose. It is reading the event window and producing an analyst-style incident report.

## Scene 5 — Sanitization

Show:

`scripts/sanitize_logs.py`

Say:

The sanitizer preserves event structure while replacing sensitive values. This makes the demo realistic without exposing private logs.

## Scene 6 — Safety Guard

Show the oversized log guard if desired:

`max_log_chars: 50000`

Say:

The API also rejects oversized log blocks so the demo cannot accidentally send huge inputs into local inference.

## Closing Line

This project gives a small SOC workflow a local analyst brain: one that can read noisy telemetry, connect related events, and produce a usable incident report without sending logs to a hosted model.

## Do Not Show

Do not show:

- raw private logs
- secrets
- tokens
- model binary contents
- private capture files
- ignored local folders