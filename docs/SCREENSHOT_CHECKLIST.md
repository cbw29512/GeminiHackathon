# Screenshot Checklist

## Purpose

Use these screenshots for the Dev.to article and final contest submission.

## Required Screenshots

### 1. GitHub Repository

Capture:

- repo name
- README
- docs folder
- scripts folder
- services folder
- tests folder

Do not show local ignored files.

### 2. API Health Response

Command or browser URL:

`http://127.0.0.1:8000/`

Capture:

- `status`
- `engine`
- `endpoints`
- `max_log_chars`

### 3. Web UI

URL:

`http://127.0.0.1:8000/ui`

Capture:

- title
- log input area
- Load sample logs button
- Analyze logs button
- output area

### 4. Sample Logs Loaded

In the UI, click:

`Load sample logs`

Capture:

- sanitized log content in the text area
- no private values visible

### 5. Gemma 4 Incident Output

After clicking:

`Analyze logs`

Capture:

- incident summary
- severity
- confidence
- attack chain
- timeline
- IOCs
- triage recommendations

### 6. Sanitizer Code

File:

`scripts/sanitize_logs.py`

Capture the sections showing:

- stable mapping
- IP replacement
- username replacement
- structure preservation

### 7. Schema Validation

File:

`services/schemas.py`

Capture:

- `IncidentReport`
- `TimelineEvent`
- severity/confidence validation

### 8. Test Results

Command:

`python -m pytest -q`

Capture:

`11 passed`

### 9. Local Model Runtime

Optional command:

`ollama list | Select-String -Pattern "gemma"`

Capture only the model list. Do not show private paths.

## Local Screenshot Folder

Save screenshots in:

`screenshots/`

This folder is ignored by Git and should not be committed.

## Final Screenshot Rule

Every screenshot should support one of these claims:

1. The project runs locally.
2. Gemma 4 is central to the analysis.
3. The data is sanitized.
4. The output is structured.
5. The project is testable and reproducible.