# LifeShield

Privacy-preserving, local-first AI-powered endpoint security agent for Windows.
Research/prototype project — not a replacement for commercial antivirus/EDR.

> 📖 **Handover & Master Architecture Guide**: See [`docs/COLLECTIVE_STATE_AND_ROADMAP.md`](docs/COLLECTIVE_STATE_AND_ROADMAP.md) for the complete multi-week implementation status, metrics, and blueprints for all upcoming weeks.

---

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

---

## Implementation Progress

| Folder | Module | Status | Built in |
|---|---|---|---|
| `agent/` | FastAPI Agent + Async EventBus queue worker | ✅ Completed | Week 2 |
| `api/` | REST Endpoints (`/events`, `/health`, `/stats`, `/detections`, `/ml/*`) | ✅ Completed | Week 2 |
| `storage/` | Pydantic Event schema + SQLite Repository (`events`, `detections`) | ✅ Completed | Week 1-2 |
| `browser-extension/` | Chrome/Edge Manifest V3 collector with privacy toggle & stats | ✅ Completed | Week 3 |
| `ml/url_model/` | Phishing URL Classifier (Random Forest on 40,000 real samples, 97.71% acc) | ✅ Completed | Week 4 |
| `ml/nlp_model/` | Scam Message NLP Model (TF-IDF + Logistic Reg on 6,370 samples, 97.33% acc) | ✅ Completed | Week 5 |
| `collectors/windows/` | Windows Event Log / login / process telemetry | ⏳ Next | Week 6 |
| `collectors/filesystem/` | Downloaded/created file metadata | ⏳ Scheduled | Week 7 |
| `collectors/network/` | DNS / connection metadata | ⏳ Scheduled | Week 7 |
| `ml/behavior_model/` | Isolation Forest anomaly detector | ⏳ Scheduled | Week 8 |
| `ml/file_model/` | File risk scoring (metadata-based) | ⏳ Scheduled | Week 8 |
| `correlation/` | Cross-source attack chain correlation engine | ⏳ Scheduled | Week 9-10 |
| `risk/` | Multi-factor risk scoring engine | ⏳ Scheduled | Week 11 |
| `decision/` | Thresholds -> ALLOW/WARN/BLOCK + response actions & toasts | ⏳ Scheduled | Week 11-12 |
| `llm/` | Local Ollama integration for plain-English explanations | ⏳ Scheduled | Week 13 |
| `frontend/` | React dashboard | ⏳ Scheduled | Week 13 |
| `tests/` | 19 automated pytest unit + integration tests (all passing) | ✅ Active | ongoing |

---

## Setup & Running

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run automated test suite (19 tests)
python -m pytest tests/ -v

# 3. Start the LifeShield Agent
python agent/main.py
# API running at http://127.0.0.1:8787
# Interactive Swagger docs: http://127.0.0.1:8787/docs
```

---

## Git Workflow

Branch off `develop` or use `feature/<module>`:

```
main
develop
feature/agent        (Week 2)
feature/browser      (Week 3)
feature/ml-url       (Week 4)
feature/ml-nlp       (Week 5)
feature/windows      (Week 6)
feature/network-file (Week 7)
feature/behavior     (Week 8)
feature/correlation  (Week 9-10)
feature/risk         (Week 11)
feature/decision     (Week 12)
feature/dashboard    (Week 13)
```

---

## Core Principle

The ML models alone are not the innovation — the **SYSTEM** is:
continuous telemetry + lightweight AI detection + behavioral anomaly
detection + cross-source correlation + risk-based decisions + local
AI explanation + privacy-first design + CPU-efficient execution.
