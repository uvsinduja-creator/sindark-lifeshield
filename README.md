# LifeShield

Privacy-preserving, local-first AI-powered endpoint security agent for Windows.
Research/prototype project — not a replacement for commercial antivirus/EDR.

## The 8-Station Pipeline

```
1. WATCH   -> collectors/ (browser, windows, filesystem, network)
2. CLEAN   -> storage/ (schema + normalizer + SQLite)
3. THINK   -> ml/ (url_model, nlp_model, behavior_model, file_model)
4. CONNECT -> correlation/
5. SCORE   -> risk/
6. DECIDE  -> decision/
7. ACT     -> decision/ (response layer)
8. EXPLAIN -> llm/ (Ollama) + frontend/ (dashboard)
```

Everything above is coordinated by `agent/` (the always-on process) and
exposed via `api/` (FastAPI backend).

## Folder Guide

| Folder | Purpose | Built in |
|---|---|---|
| `agent/` | Always-on background process, wires all stations together | Week 2 |
| `api/` | FastAPI backend, the "post office" between modules | Week 2 |
| `storage/` | Event schema + SQLite access layer | Week 1-2 |
| `collectors/browser/` | Receives events from the browser extension | Week 3 |
| `collectors/windows/` | Windows Event Log / login / process telemetry | Week 6 |
| `collectors/filesystem/` | Downloaded/created file metadata | Week 7 |
| `collectors/network/` | DNS / connection metadata | Week 7 |
| `browser-extension/` | Actual Chrome/Edge Manifest V3 extension code | Week 3 |
| `ml/url_model/` | Phishing URL classifier | Week 4 |
| `ml/nlp_model/` | Scam/phishing message classifier | Week 5 |
| `ml/behavior_model/` | Isolation Forest anomaly detector | Week 8 |
| `ml/file_model/` | File risk scoring (metadata-based) | Week 8 |
| `correlation/` | Links related events into attack chains | Week 9-10 |
| `risk/` | Combines evidence into one overall risk score | Week 11 |
| `decision/` | Thresholds -> ALLOW/WARN/BLOCK + response actions | Week 11-12 |
| `llm/` | Local Ollama integration for plain-English explanations | Week 13 |
| `frontend/` | React dashboard | Week 13 |
| `tests/` | pytest unit + integration tests, mirrors structure above | ongoing |
| `docs/` | Architecture notes, diagrams, decisions | ongoing |
| `configs/` | YAML config, thresholds, ports (no hardcoding allowed) | Week 1 |

## Setup

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

## Week 1 Self-Checks

```bash
python storage/schema.py     # should print a sample LifeShieldEvent as JSON
python configs/loader.py     # should print "Agent will run on 127.0.0.1:8787"
```

## Git Workflow

Branch off `develop`, never `main` directly:

```
main
develop
feature/agent
feature/browser
feature/ml-url
feature/ml-nlp
feature/behavior
feature/correlation
feature/frontend
```

## Core Principle

The ML models alone are not the innovation — the SYSTEM is:
continuous telemetry + lightweight AI detection + behavioral anomaly
detection + cross-source correlation + risk-based decisions + local
AI explanation + privacy-first design + CPU-efficient execution.
