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

## 📊 3. Current Implementation Status (Weeks 1 – 5 Completed)

| Week | Component | Status | Key Deliverables & Benchmark Metrics |
|---|---|---|---|
| **Week 1** | Foundation & Architecture | ✅ Done | Folder hierarchy, `storage/schema.py` (`LifeShieldEvent`), `configs/base.yaml`, `configs/loader.py`. |
| **Week 2** | Agent Backbone & Storage | ✅ Done | `storage/database.py` (SQLite schema), `storage/repository.py`, `agent/normalizer.py`, `agent/event_bus.py`, `api/routes.py`, `agent/main.py`. |
| **Week 3** | Browser Extension | ✅ Done | Chrome/Edge Manifest V3 extension in `browser-extension/` (`manifest.json`, `background.js`, `popup.html`, `popup.js`, icons, Section 6 privacy toggle). Captures `URL_VISIT`, `URL_REDIRECT`, and `BROWSER_DOWNLOAD`. |
| **Week 4** | URL Phishing ML Model | ✅ Done | `ml/url_model/` (`features.py`, `train.py`, `classifier.py`, `collect_dataset.py`, `data/dataset.csv`). **Trained on 40,000 real-world samples** (JPCERT/CC + OpenPhish + Tranco Top 1M). **98.29% Train Accuracy, 97.71% Test Accuracy, 0.9979 ROC-AUC**. Real-time scoring wired into agent. |
| **Week 5** | Scam Message NLP Model | ✅ Done | `ml/nlp_model/` (`features.py`, `train.py`, `classifier.py`, `collect_dataset.py`, `data/dataset.csv`). **Trained on 6,370 real-world samples** (UCI SMS Spam Collection + Fraud Email Phishing dataset + mobile scam patterns) using TF-IDF + Logistic Regression. **98.80% Train Accuracy, 97.33% Test Accuracy, 0.9948 ROC-AUC**. Real-time scoring wired into `MESSAGE_ANALYSIS` events. |
| **Week 6** | Windows Telemetry Collector | ⏳ Next | Windows Event Log collector (login events, process start/stop). |
| **Week 7** | Network & File Collectors | ⏳ Pending | DNS query metadata + file creation/download watcher. |
| **Week 8** | Behavior & File Models | ⏳ Pending | Isolation Forest behavioral anomaly detector + file risk model. |
| **Weeks 9–10** | Correlation Engine | ⏳ Pending | Cross-source attack chain reconstruction (`URL -> download -> process -> network`). |
| **Week 11** | Risk Scoring Engine | ⏳ Pending | Weighted evidence scoring combining ML, severity, recency, and chain length. |
| **Week 12** | Decision & Response Layer | ⏳ Pending | Policy rules (ALLOW/WARN/BLOCK) + Windows desktop notifications + safe quarantine. |
| **Week 13** | Local LLM & Dashboard | ⏳ Pending | Ollama local explanation generator + React monitoring dashboard. |
| **Week 14** | Packaging & Evaluation | ⏳ Pending | Windows background service + end-to-end benchmark reporting. |

**Current Test Suite**: 19 automated tests passing in ~5 seconds (`python -m pytest tests/ -v`).

---

## 🗺️ 4. Detailed Blueprints for Upcoming Weeks (Weeks 6 – 14)

### Week 6: Station 1 — Watch (Windows Telemetry Collector)
* **Goal**: Capture Windows login events and process creation events without heavy ETW drivers.
* **Target Files**:
  * `collectors/windows/login_collector.py`: Polls/subscribes to Windows Security Event Log (Event ID 4624 for `LOGIN_SUCCESS`, Event ID 4625 for `LOGIN_FAILURE`).
  * `collectors/windows/process_collector.py`: Monitors process creations (e.g. via `psutil` or WMI / Win32 process events) and normalizes into `PROCESS_START` / `PROCESS_END`.
  * `collectors/windows/watcher.py`: Background runner service that pushes events to `http://127.0.0.1:8787/events`.
* **Deliverable**: Failed Windows login or new process creation automatically lands as a normalized event in `lifeshield.db`.

### Week 7: Station 1 — Watch (Network & Filesystem Collectors)
* **Goal**: Observe DNS lookups and downloaded/created file filesystem changes.
* **Target Files**:
  * `collectors/filesystem/file_watcher.py`: Uses `watchdog` to monitor user Downloads/Desktop directories, extracts SHA-256 hash, size, extension, and parent process, emitting `FILE_CREATE` and `FILE_DOWNLOAD`.
  * `collectors/network/dns_collector.py`: Lightweight DNS query monitor (via ETW Microsoft-Windows-DNS-Client or packet sniffing / netstat polling) emitting `DNS_QUERY` and `NETWORK_CONNECTION`.
* **Deliverable**: Downloading a test executable and having it query an external domain creates two corresponding events in the pipeline.

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
* **Goal**: Synthesize model probabilities, correlation evidence, asset criticality, and time decay into one transparent score ($0.0 - 1.0$).
* **Target Files**:
  * `risk/engine.py`: Formula-based scoring engine:
    $$\text{Risk} = w_{\text{model}} \cdot S_{\text{model}} + w_{\text{corr}} \cdot S_{\text{chain}} + w_{\text{anomaly}} \cdot S_{\text{anomaly}}$$
  * Configurable weights in `configs/base.yaml`.
* **Deliverable**: Testable, transparent scoring breakdown explaining how the number was calculated.

### Week 12: Station 6 & 7 — Decide & Act (Decision Engine & Response Layer)
* **Goal**: Map risk scores to actionable security decisions and execute automated responses.
* **Target Files**:
  * `decision/engine.py`: Evaluates thresholds:
    * `0.00 – 0.30`: `ALLOW`
    * `0.31 – 0.60`: `MONITOR`
    * `0.61 – 0.80`: `WARN` (triggers native Windows desktop toast notification)
    * `0.81 – 0.95`: `STRONG_WARNING`
    * `> 0.95`: `BLOCK` (safe file quarantine to `.quarantine/` in sandbox)
  * `decision/notifier.py`: Windows native desktop toast notifications via `win10toast` or `windows-toasts`.
* **Deliverable**: Visiting a malicious URL or creating a dangerous test file pops up a real Windows notification and records the decision.

### Week 13: Station 8 — Explain (Local LLM Explainer & React Dashboard)
* **Goal**: Explain why an alert fired in plain English using a local model, and present a visual SOC interface.
* **Target Files**:
  * `llm/explainer.py`: Local Ollama integration (`llama3.2:1b` or `qwen2.5:1.5b` CPU-quantized), receives the attack graph and risk factors and generates an explainable summary.
  * `frontend/`: Lightweight React/Vite dashboard displaying protection status, recent events, threat graph, and AI explanations.
* **Deliverable**: Dashboard displaying live attack chain diagram with plain-English explanation generated on-device.

### Week 14: Station Packaging & Evaluation
* **Goal**: Package the agent as a background Windows service and generate the final benchmark report.
* **Target Files**:
  * `agent/service.py`: Windows service wrapper (`pywin32`) for automatic background startup.
  * `tests/evaluation_benchmark.py`: Measures CPU/RAM consumption, event processing latency (ms), and Precision/Recall/F1 table.
* **Deliverable**: Complete capstone project report and reproducible end-to-end demo.

---

## 📋 5. Prompt Template to Give to Any New AI Model

When switching to another model or starting a fresh chat session, copy and paste this exact prompt:

```text
I am continuing the LifeShield project in this workspace.
Please inspect docs/COLLECTIVE_STATE_AND_ROADMAP.md to understand the project architecture, the 8-station pipeline, and the work completed so far (Weeks 1 to 5 are finished and passing 19 pytest tests).

We are currently on: Week [INSERT WEEK NUMBER HERE, e.g. Week 6 - Windows Telemetry Collector].

Strict Rules to Follow:
1. Adhere to the canonical LifeShieldEvent schema in storage/schema.py.
2. Direct all SQLite operations through storage/repository.py.
3. Keep all execution CPU-only (no GPU dependencies).
4. Do not hardcode ports or paths; use configs/loader.py and configs/base.yaml.
5. Create a dedicated git branch 'feature/<module>' and write comprehensive pytest tests.

Please review the codebase and implement Week [N].
```
