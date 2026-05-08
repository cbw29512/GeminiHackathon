# Dev.to Submission Outline

## Working Title

I Gave My Home SOC a Local Gemma 4 Analyst

## Subtitle

A local-first cybersecurity demo where Gemma 4 reads sanitized SOC telemetry and produces a structured incident report.

## Opening Hook

Most dashboards tell you what fired.

They do not always tell you what happened.

This project uses Gemma 4 as a local SOC analyst. It reads a sanitized log window, connects related security events, and returns a structured incident report with severity, confidence, attack chain, timeline, IOCs, and triage recommendations.

## The Problem

Security telemetry is noisy.

A real incident may not look like one obvious alert. It may look like a scan, a suspicious request, failed logins, one successful login, a payload download, a reverse shell, and a persistence event.

Rules can flag the pieces. A human analyst still has to connect them.

## The Solution

NetGuard Gemma 4 adds a local analysis endpoint:

`POST /analyze-logs`

The endpoint sends sanitized security logs to a local Gemma 4 model through Ollama. Gemma 4 reads the full window and returns an incident report.

## Why This Uses Gemma 4 Meaningfully

Gemma 4 is the core reasoning layer.

The model is asked to:

- read a multi-event telemetry window
- correlate events across time
- identify a likely attack chain
- summarize the incident
- produce IOCs
- recommend triage steps

This makes the model central to the product instead of a decorative chatbot.

## Architecture

Local components:

- FastAPI API gateway
- Pydantic schemas for validated output
- Ollama local model runtime
- Gemma 4 E4B Q8_0
- sanitizer script for SOC-shaped logs
- minimal web UI for demo use

Flow:

1. prepare or collect SOC-shaped events
2. sanitize sensitive values
3. submit logs to `/analyze-logs`
4. Gemma 4 analyzes the full event window
5. FastAPI validates the structured JSON
6. user reviews the incident report

## Demo Walkthrough

The demo event window contains:

1. TCP scan
2. SQL injection-style probe
3. SSH brute force attempts
4. successful login
5. privileged payload download
6. script execution
7. outbound shell activity
8. suspicious root-level user creation

Gemma 4 returns a report that ties those events together.

## Privacy And Safety

The project is local-first because security telemetry can be sensitive.

The public demo uses sanitized data. The design preserves useful event structure while removing private values such as internal IPs, usernames, and hostnames.

The model binary is not committed to GitHub.

## What Worked

The strongest result was moving from single-alert analysis to log-window analysis.

Single-alert analysis is useful, but the hackathon-worthy feature is the long-context incident autopsy: giving Gemma 4 a sequence of events and asking it to explain the incident.

## What I Would Improve Next

1. Add a richer NetGuard dashboard panel.
2. Add exportable analyst reports.
3. Add side-by-side raw alert stream versus Gemma incident report.
4. Add confidence notes explaining why Gemma chose each stage.
5. Test larger sanitized event windows.
6. Add support for uploaded local log files through the UI.

## Closing

This project is about giving small SOC workflows a local analyst layer.

The value is not just that Gemma 4 can answer a security question. The value is that it can read a window of evidence, connect related events, and return a structured report without sending sensitive logs to a hosted model.