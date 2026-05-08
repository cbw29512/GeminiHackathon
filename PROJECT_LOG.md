# Dev.to Gemma 4 Challenge: NetGuard Local Inference

## 1. Objective

Extend the existing NetGuard SOC with a local-first AI analysis layer powered by Gemma 4 E4B. The system reasons over network telemetry on local hardware and produces structured security narratives without sending data to external APIs. Submission target: Dev.to "Build with Gemma 4" prompt, deadline May 24, 2026.

## 2. Constraints

- Extends NetGuard, does not fork it. Final analysis layer folds back into the :8055 UI.
- Hybrid data: real Suricata/Wazuh structure, sanitized content (synthetic IPs, hostnames, usernames).
- Hardware: RTX 5070 Ti, 16GB VRAM. All inference local.
- Network: API binds to 127.0.0.1 only.

## 3. Execution Log

### Phase 1 — Architecture & Schema (complete)
- Pydantic contracts in `services/schemas.py`: `NetworkAnomaly`, `SecurityAlert`.
- Async HTTPX client in `services/llm_analyzer.py` for local Ollama calls.
- Project tree scaffolded: `services/`, `scripts/`, `tests/`.

### Phase 2 — Local Model Deployment (complete)
- Downloaded `bartowski/google_gemma-4-E4B-it-GGUF` Q8_0 (~8GB) to project root.
- Modelfile: `FROM ./gemma-4-e4b.gguf`, `temperature=0.1`, `num_ctx=16384`.
- Registered as `gemma4:latest` via `ollama create`.
- Verified with direct Ollama ping.

### Phase 3 — API Gateway (complete)
- `main.py`: FastAPI on `127.0.0.1:8000`. Routes: GET `/`, POST `/analyze`.
- Pydantic V2 enforces input/output schemas.

### Phase 4 — Validation (complete)
- SQL injection payload returned severity HIGH with correct mechanism description.
- 5-vector concurrent stress test (DDoS, SQLi, XSS, path traversal, SSH brute force) all returned valid structured JSON.
- Sub-3s inference latency on RTX 5070 Ti for short anomalies.

### Phase 5 — Hero Feature: Long-Context Log Autopsy (planned)
- New endpoint POST `/analyze-logs` accepts a sanitized Suricata `eve.json` block.
- Gemma 4 reasons across the 16K context window. Returns: incident timeline, IOC list, suspected attack chain, triage recommendations.
- This is the differentiator. Most hackathon entries will be one-shot prompt wrappers.

### Phase 6 — Sanitization Pipeline (planned)
- `scripts/sanitize_logs.py`: takes real Suricata/Wazuh exports, swaps IPs/hostnames/usernames with consistent synthetic placeholders, preserves structure.

### Phase 7 — NetGuard UI Integration (planned)
- Add a "Gemma analysis" panel to the existing NetGuard UI on port 8055.
- No new frontend stack. Extend what already works.

### Phase 8 — Submission (planned)
- Screen recording demo: autopsy of a sanitized incident.
- Dev.to post: "I gave my home SOC a brain — what Gemma 4 found in a week of my own logs."
- Submit before May 24, 2026.

## 4. Known Issues / Reverted

- Earlier Reflex SOC dashboard attempts failed on `AttributeError: No reflex attribute Base` in Reflex 0.9.x. Reverted. Will reuse existing NetGuard UI.
- Earlier Modelfile self-referenced `FROM gemma4` instead of the GGUF path. Corrected.
- Orphan Reflex scaffold at `C:\Users\divcl\divcl\` was outside the project root. Removed.