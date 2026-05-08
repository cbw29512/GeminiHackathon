# NetGuard SOC â€” Gemma 4 Local Inference

Local-first AI security analysis layer for the NetGuard SOC stack. Submits to the Dev.to Gemma 4 Challenge (Build with Gemma 4 prompt, deadline May 24, 2026).

## What it does

NetGuard already collects network telemetry. This layer adds an inference brain: Gemma 4 E4B (Q8_0) running locally via Ollama, producing structured security narratives over log data without sending a byte to an external API.

The hero feature is **long-context log autopsy**. Drop a sanitized block of Suricata `eve.json` into a single Gemma 4 call and get back an incident timeline, IOC list, suspected attack chain, and triage recommendations. The 16K context window is the point: a regex SIEM misses slow-burn campaigns; reasoning across the full window catches them.

## Why local

- Network telemetry contains internal IPs, usernames, and traffic patterns. Cloud APIs are a non-starter for anything sensitive.
- Sub-3s response on an RTX 5070 Ti for short anomalies. No round-trip to a hosted endpoint.
- Once the GGUF is on disk, inference is electricity.

## Stack

| Layer | Tech |
| --- | --- |
| Model | Gemma 4 E4B Q8_0 (~8GB GGUF) |
| Runtime | Ollama, loopback only |
| Validation | Pydantic V2 |
| API | FastAPI on 127.0.0.1:8000 |
| Hardware | NVIDIA RTX 5070 Ti, 16GB VRAM |

## Run it

Prerequisites: [Ollama](https://ollama.com), Python 3.11, the Q8_0 GGUF placed at `./gemma-4-e4b.gguf`.

```powershell
ollama create gemma4 -f Modelfile
pip install -r requirements.txt
python main.py
```

Health check:

```powershell
Invoke-RestMethod http://127.0.0.1:8000/
```

Analyze a single anomaly:

```powershell
$body = @{
  timestamp = (Get-Date).ToString("o")
  source_ip = "192.0.2.55"
  destination_ip = "10.0.0.5"
  protocol = "HTTP"
  flagged_reason = "SQL injection attempt"
  payload_snippet = "GET /login?user=' OR 1=1 --"
} | ConvertTo-Json
Invoke-RestMethod -Uri "http://127.0.0.1:8000/analyze" -Method Post -Body $body -ContentType "application/json"
```

Run the 5-vector stress test:

```powershell
python scripts/stress_test.py
```

## Status

See `PROJECT_LOG.md` for the live execution log. Phases 1â€“4 complete; long-context log autopsy in progress.