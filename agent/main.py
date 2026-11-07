"""
LifeShield Agent Main Application.
Starts the FastAPI application, initializes database, configures CORS middleware,
and runs the background consumer task to drain the EventBus into SQLite storage.
In Week 4: Real-time ML Phishing URL scoring for URL_VISIT and URL_REDIRECT events.
In Week 5: Real-time ML Scam/Phishing NLP text classification for MESSAGE_ANALYSIS events.
In Week 8: Real-time Static File Risk scoring for FILE_CREATE/FILE_DOWNLOAD and
           Behavioral Anomaly scoring for telemetry events.
"""
import sys
import traceback
import asyncio
from pathlib import Path
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.database import init_db
from storage import repository
from storage.schema import EventType
from agent.event_bus import event_bus
from api.routes import router
from ml.url_model.classifier import url_classifier
from ml.nlp_model.classifier import scam_classifier
from ml.file_model.scorer import file_scorer
from ml.behavior_model.anomaly import behavior_detector


async def background_queue_worker():
    """
    Background worker that continuously consumes events from the EventBus,
    runs lightweight ML model inference on applicable events,
    and persists them to SQLite storage and detections table.
    """
    while True:
        try:
            event = await event_bus.get()

            # Week 4: Real-time ML URL Scoring for navigation events
            if event.event_type in (EventType.URL_VISIT, EventType.URL_REDIRECT):
                url = event.data.get("url") or event.data.get("to_url")
                if url and isinstance(url, str):
                    classification = url_classifier.classify(url)
                    event.data["risk_score"] = classification["risk_score"]
                    event.data["severity"] = classification["severity"]
                    event.data["is_phishing"] = classification["is_phishing"]
                    event.data["indicators"] = classification["indicators"]

                    repository.save_detection(
                        event_id=event.event_id,
                        model_name="url_phishing_rf",
                        risk_score=classification["risk_score"],
                        severity=classification["severity"],
                        is_threat=classification["is_phishing"],
                        details=classification,
                    )

            # Week 5: Real-time ML Scam Message NLP Classification
            elif event.event_type == EventType.MESSAGE_ANALYSIS:
                msg_text = event.data.get("text") or event.data.get("message")
                if msg_text and isinstance(msg_text, str):
                    classification = scam_classifier.classify(msg_text)
                    event.data["risk_score"] = classification["risk_score"]
                    event.data["severity"] = classification["severity"]
                    event.data["is_scam"] = classification["is_scam"]
                    event.data["indicators"] = classification["indicators"]

                    repository.save_detection(
                        event_id=event.event_id,
                        model_name="scam_nlp_tfidf",
                        risk_score=classification["risk_score"],
                        severity=classification["severity"],
                        is_threat=classification["is_scam"],
                        details=classification,
                    )

            # Week 8: Real-time Static File Risk Scoring
            elif event.event_type in (EventType.FILE_CREATE, EventType.FILE_DOWNLOAD):
                if event.data and isinstance(event.data, dict) and event.data.get("filename"):
                    file_eval = file_scorer.score(event.data)
                    event.data["file_risk_score"] = file_eval["risk_score"]
                    event.data["file_severity"] = file_eval["severity"]
                    event.data["is_file_threat"] = file_eval["is_threat"]
                    event.data["file_indicators"] = file_eval["indicators"]

                    if file_eval["risk_score"] > 0.30:
                        repository.save_detection(
                            event_id=event.event_id,
                            model_name="file_risk_heuristic",
                            risk_score=file_eval["risk_score"],
                            severity=file_eval["severity"],
                            is_threat=file_eval["is_threat"],
                            details=file_eval,
                        )

            # Week 8: Real-time Behavioral Anomaly Detection for login failures / telemetry
            if event.event_type == EventType.LOGIN_FAILURE:
                failed_count = int(event.data.get("failed_attempts") or event.data.get("attempts") or 1)
                hour = event.timestamp.hour if hasattr(event, "timestamp") and event.timestamp else 12
                b_eval = behavior_detector.score({
                    "hour_of_day": hour,
                    "failed_login_count": failed_count,
                    "event_rate_per_min": 10.0,
                })
                if b_eval["anomaly_score"] > 0.30:
                    repository.save_detection(
                        event_id=event.event_id,
                        model_name="behavior_isolation_forest",
                        risk_score=b_eval["anomaly_score"],
                        severity=b_eval["severity"],
                        is_threat=b_eval["is_anomaly"],
                        details=b_eval,
                    )
            elif event.data and isinstance(event.data, dict) and "behavioral_metrics" in event.data:
                b_eval = behavior_detector.score(event.data["behavioral_metrics"])
                if b_eval["anomaly_score"] > 0.30:
                    repository.save_detection(
                        event_id=event.event_id,
                        model_name="behavior_isolation_forest",
                        risk_score=b_eval["anomaly_score"],
                        severity=b_eval["severity"],
                        is_threat=b_eval["is_anomaly"],
                        details=b_eval,
                    )

            # Persist event into SQLite
            repository.save_event(event)
            event_bus.task_done()
        except asyncio.CancelledError:
            break
        except Exception as e:
            print(f"[Error] Exception in background worker: {e}", file=sys.stderr)
            traceback.print_exc()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan manager: initializes DB and starts/stops background worker.
    """
    init_db()
    worker_task = asyncio.create_task(background_queue_worker())

    yield

    worker_task.cancel()
    try:
        await worker_task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="LifeShield Agent",
    description="Privacy-preserving local endpoint security agent API with AI telemetry",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS Middleware: allow localhost dashboard AND chrome-extension:// origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)

app.include_router(router)

if __name__ == "__main__":
    import uvicorn
    from configs.loader import get_config
    cfg = get_config()
    uvicorn.run("agent.main:app", host=cfg["agent"]["host"], port=cfg["agent"]["port"], reload=False)
