# LifeShield: Collective Architecture, State & Weekly Roadmap

> **For Any AI Assistant / Developer Reading This Repository:**
> This document is the single source of truth for LifeShield. It records everything that has been implemented, the system architectural contracts, current test status, and the exact step-by-step specifications for all upcoming weeks.
> When switching models or starting a new conversation, refer to this document to know immediately what has been built and what needs to be built next.

---

## 🛡️ 1. Project Overview & Core Philosophy

**LifeShield** is a **local-first, privacy-preserving, AI-powered endpoint security agent for Windows**. It acts as a lightweight telemetry monitor, threat detector, and behavioral correlation engine running entirely on-device (CPU-only, no cloud dependency).

### Non-Negotiable Architectural Rules
1. **Contract-Driven**: Every event flowing through the system MUST strictly follow the canonical `LifeShieldEvent` Pydantic schema in [`storage/schema.py`](../storage/schema.py). Never invent ad-hoc JSON formats.
2. **Repository Decoupling**: All database interactions with SQLite MUST go through [`storage/repository.py`](../storage/repository.py). No module should write raw SQL.
3. **Async Queue Ingestion**: The FastAPI agent receives events via `POST /events`, validates them via `agent.normalizer`, and puts them onto an async queue (`agent.event_bus`). A background worker drains the queue into storage and executes real-time ML inference.
4. **No Hardcoding**: All hostnames, ports, database paths, log paths, and threshold cutoffs live in [`configs/base.yaml`](../configs/base.yaml) and are loaded via [`configs/loader.py`](../configs/loader.py).
5. **CPU-Only Efficiency**: All ML models (Random Forest, TF-IDF + Logistic Regression, Isolation Forest) and NLP pipelines must run efficiently on standard consumer CPU without requiring a GPU.

---

## 🏭 2. The 8-Station Pipeline

Every module belongs to one of these 8 pipeline stations:

```
[Station 1: WATCH]   -> collectors/ (browser, windows, filesystem, network)
         ↓
[Station 2: CLEAN]   -> agent/normalizer.py -> storage/ (schema + repository + SQLite)
         ↓
[Station 3: THINK]   -> ml/ (url_model, nlp_model, behavior_model, file_model)
         ↓
[Station 4: CONNECT] -> correlation/ (attack chain linker across time and entity)
         ↓
[Station 5: SCORE]   -> risk/ (multi-source threat risk scoring engine)
         ↓
[Station 6: DECIDE]  -> decision/ (threshold-based ALLOW / MONITOR / WARN / BLOCK)
         ↓
[Station 7: ACT]     -> decision/response (desktop toast notifications, browser block, quarantine)
         ↓
[Station 8: EXPLAIN] -> llm/ (local Ollama LLM) + frontend/ (React security dashboard)
```

---

## 📊 3. Current Implementation Status (Weeks 1 – 7 Completed)

| Week | Component | Status | Key Deliverables & Benchmark Metrics |
|---|---|---|---|
| **Week 1** | Foundation & Architecture | ✅ Done | Folder hierarchy, `storage/schema.py` (`LifeShieldEvent`), `configs/base.yaml`, `configs/loader.py`. |
| **Week 2** | Agent Backbone & Storage | ✅ Done | `storage/database.py` (SQLite schema), `storage/repository.py`, `agent/normalizer.py`, `agent/event_bus.py`, `api/routes.py`, `agent/main.py`. |
| **Week 3** | Browser Extension | ✅ Done | Chrome/Edge Manifest V3 extension in `browser-extension/` (`manifest.json`, `background.js`, `popup.html`, `popup.js`, icons, Section 6 privacy toggle). Captures `URL_VISIT`, `URL_REDIRECT`, and `BROWSER_DOWNLOAD`. |
| **Week 4** | URL Phishing ML Model | ✅ Done | `ml/url_model/` (`features.py`, `train.py`, `classifier.py`, `collect_dataset.py`, `data/dataset.csv`). **Trained on 40,000 real-world samples** (JPCERT/CC + OpenPhish + Tranco Top 1M). **98.29% Train Accuracy, 97.71% Test Accuracy, 0.9979 ROC-AUC**. Real-time scoring wired into agent. |
| **Week 5** | Scam Message NLP Model | ✅ Done | `ml/nlp_model/` (`features.py`, `train.py`, `classifier.py`, `collect_dataset.py`, `data/dataset.csv`). **Trained on 6,370 real-world samples** (UCI SMS Spam Collection + Fraud Email Phishing dataset + mobile scam patterns) using TF-IDF + Logistic Regression. **98.80% Train Accuracy, 97.33% Test Accuracy, 0.9948 ROC-AUC**. Real-time scoring wired into `MESSAGE_ANALYSIS` events. |
| **Week 6** | Windows Telemetry Collector | ✅ Done | `collectors/windows/` (`login_collector.py`, `process_collector.py`, `watcher.py`). Windows Security Event Log (Event ID 4624 -> `LOGIN_SUCCESS`, Event ID 4625 -> `LOGIN_FAILURE`) via `pywin32` + process creation/termination tracking (`PROCESS_START`, `PROCESS_END`) via `psutil`. Configuration from `configs/base.yaml`. |
| **Week 7** | Network & File Collectors | ✅ Done | `collectors/filesystem/` (`file_watcher.py` using `watchdog`, SHA-256 chunked hashing, Shannon entropy, double-extension detection, browser temp download completion handling for `FILE_CREATE` and `FILE_DOWNLOAD`). `collectors/network/` (`dns_collector.py` with Windows DNS cache inspection and socket connection monitoring for `DNS_QUERY` and `NETWORK_CONNECTION`). Master multi-collector orchestrator `collectors/watcher.py`. |
| **Week 8** | Behavior & File Models | ⏳ Next | Isolation Forest behavioral anomaly detector + file risk model. |
| **Weeks 9–10** | Correlation Engine | ⏳ Pending | Cross-source attack chain reconstruction (`URL -> download -> process -> network`). |
| **Week 11** | Risk Scoring Engine | ⏳ Pending | Weighted evidence scoring combining ML, severity, recency, and chain length. |
| **Week 12** | Decision & Response Layer | ⏳ Pending | Policy rules (ALLOW/WARN/BLOCK) + Windows desktop notifications + safe quarantine. |
| **Week 13** | Local LLM & Dashboard | ⏳ Pending | Ollama local explanation generator + React monitoring dashboard. |
| **Week 14** | Packaging & Evaluation | ⏳ Pending | Windows background service + end-to-end benchmark reporting. |

**Current Test Suite**: 40 automated tests passing in ~7 seconds (`python -m pytest tests/ -v`).

---

## 🗺️ 4. Detailed Blueprints for Upcoming Weeks (Weeks 8 – 14)

### Week 8: Station 3 — Think (Behavior Anomaly & File Risk Models)
* **Goal**: Detect anomalies in user activity baselines and evaluate file risk before execution.
* **Target Files**:
  * `ml/behavior_model/anomaly.py`: `IsolationForest` model over user feature vectors (login hour, process launch rate, DNS resolution frequency, download burst rate).
  * `ml/file_model/scorer.py`: Scores file metadata: double extensions (e.g., `.pdf.exe`), high Shannon entropy (packed/encrypted binaries), untrusted source directory, anomalous file size.
* **Deliverable**: Unusual activity patterns (e.g. 3 AM login spike or high-entropy executable download) produce anomaly scores.

### Weeks 9 – 10: Station 4 — Connect (Attack Chain Correlation Engine)
* **Goal**: Connect separate events across time, domain, process, and user into unified attack chains.
* **Target Files**:
  * `correlation/engine.py`: In-memory and SQLite-backed correlation engine.
  * `correlation/graph.py`: Entity-relationship attack graph representation.
  * Links: `URL_VISIT (phishing)` -> `BROWSER_DOWNLOAD` -> `FILE_CREATE` -> `PROCESS_START` -> `NETWORK_CONNECTION`.
* **Deliverable**: A multi-step simulated attack generates ONE correlated incident with a shared `correlation_id`, rather than 5 isolated noise alerts.

### Week 11: Station 5 — Score (Risk Scoring Engine)
* **Goal**: Aggregate evidence from all indicators in a correlated attack chain into a composite risk score (0.00 – 1.00).
* **Target Files**:
  * `risk/engine.py`: Combines base event severity, ML confidence scores, graph chain depth, and temporal decay into a single normalized risk score.
* **Deliverable**: Risk score evaluated and tagged on each correlated detection.

### Week 12: Stations 6 & 7 — Decide & Act (Response Layer)
* **Goal**: Turn risk scores into enforcement decisions and user-visible desktop actions.
* **Target Files**:
  * `decision/policy.py`: Maps risk scores to actions (`ALLOW`, `MONITOR`, `WARN`, `BLOCK`) according to `configs/base.yaml`.
  * `decision/response/toast.py`: Native Windows toast notifications using `plyer` or PowerShell BurntToast.
  * `decision/response/quarantine.py`: Moves suspicious downloaded files into a secure, encrypted or locked quarantine directory.
* **Deliverable**: High-risk threat triggers a desktop alert and isolates the offending file safely.

### Week 13: Station 8 — Explain (Local LLM & Dashboard)
* **Goal**: Explain why an alert was triggered in plain English and provide a security analyst UI.
* **Target Files**:
  * `llm/ollama_client.py`: Calls local Ollama (e.g. `llama3` or `mistral`) with attack chain context, asking it to explain in 2-3 sentences what happened and what action the user should take.
  * `frontend/`: Lightweight React/Vite dashboard showing event streams, active attack graphs, threat breakdown, and one-click mitigation.
* **Deliverable**: User opens browser dashboard to see live threat map and plain-English incident summaries.

### Week 14: Packaging, Hardening & Evaluation
* **Goal**: Package LifeShield as a reliable Windows background service with end-to-end test benchmarks.
* **Target Files**:
  * `service.py`: Windows Service wrapper via `win32serviceutil`.
  * `scripts/benchmark.py`: Evaluates latency (event post to alert), memory footprint, CPU consumption, and detection accuracy under stress.
* **Deliverable**: LifeShield installs, auto-starts on Windows boot, stays under 150MB RAM, and handles 100+ events/sec cleanly.
