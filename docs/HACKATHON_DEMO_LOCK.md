# NetGuard Gemma 4 Demo Lock

## Current Stable Demo

The hackathon demo is now centered on Gemma 4 doing real SOC analysis work:

- Endpoint: POST /analyze-logs
- Input: sanitized Suricata/Wazuh-shaped eve.json logs
- Model: local Gemma 4 E4B Q8_0 through Ollama
- Runtime: FastAPI on 127.0.0.1:8000
- Demo result: Gemma correlates a multi-stage attack across log events

## Why This Matters For The Contest

This is not just a prompt wrapper. The model is reading a block of security telemetry and producing an analyst-style incident report with:

- incident summary
- severity
- confidence
- attack chain
- timeline
- IOCs
- triage recommendations

## Confirmed Demo Behaviors

Based on the successful Phase 6 run:

- C2 port 4444 was identified
- DNS query was treated as C2 preparation
- compromised host attribution was handled correctly after payload download
- sanitized usernames were carried consistently through IOCs and triage
- domain IOC was promoted alongside IP indicators
- end-to-end response time was approximately 18 seconds

## Next Step

Do not rebuild Reflex.

Next development phase should be one of:

1. Add a minimal Gemma Analysis panel to the existing NetGuard UI on port 8055.
2. Prepare the Dev.to article and screen recording around the current working API demo.

## Locked On

2026-05-07 20:55:19