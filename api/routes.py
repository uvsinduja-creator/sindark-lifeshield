"""
FastAPI Routes module for LifeShield API.
Defines endpoints for posting events, fetching events, health check, stats, detections, and ML scoring.
"""
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.normalizer import normalize_event
from agent.event_bus import event_bus
from storage import repository
from storage.schema import LifeShieldEvent
from ml.url_model.classifier import url_classifier

router = APIRouter()


class URLScoreRequest(BaseModel):
    url: str


@router.post("/events", status_code=status.HTTP_202_ACCEPTED)
async def post_event(raw_payload: Dict[str, Any]):
    """
    Receives raw event payload, validates/normalizes it,
    and enqueues it into the async EventBus queue.
    """
    try:
        event = normalize_event(raw_payload)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    await event_bus.put(event)
    return {
        "status": "queued",
        "event_id": event.event_id,
        "event_type": event.event_type,
    }


@router.get("/events", response_model=List[LifeShieldEvent])
async def list_events(limit: int = Query(default=100, ge=1, le=1000)):
    """Retrieves recent events stored in the SQLite database."""
    return repository.get_events(limit=limit)


@router.get("/events/{event_id}", response_model=LifeShieldEvent)
async def get_event(event_id: str):
    """Retrieves a single event by event_id."""
    event = repository.get_event_by_id(event_id)
    if not event:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Event with id '{event_id}' not found",
        )
    return event


@router.get("/detections")
async def list_detections(
    limit: int = Query(default=100, ge=1, le=1000),
    threats_only: bool = Query(default=False)
):
    """Retrieves security threat detections recorded by ML models."""
    return repository.get_detections(limit=limit, threats_only=threats_only)


@router.get("/detections/{event_id}")
async def get_event_detections(event_id: str):
    """Retrieves detections associated with a specific event."""
    return repository.get_detections_by_event_id(event_id)


@router.post("/ml/url/score")
async def score_url_endpoint(req: URLScoreRequest):
    """Direct inference endpoint to evaluate and score any URL for phishing risk."""
    if not req.url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")
    return url_classifier.classify(req.url)


@router.get("/health")
async def health_check():
    """Agent health check endpoint."""
    stats = repository.get_stats()
    return {
        "status": "healthy",
        "queue_size": event_bus.qsize,
        "stored_events": stats["total_events"],
        "total_detections": stats.get("total_detections", 0),
        "total_threats": stats.get("total_threats", 0),
    }


@router.get("/stats")
async def get_stats():
    """Returns database statistics."""
    return repository.get_stats()
