"""
Repository module for LifeShield storage layer.
Provides functions to save and retrieve events and threat detections from SQLite database.
"""
import sys
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.database import get_connection, init_db
from storage.schema import LifeShieldEvent, EventType, EventSource


def save_event(event: LifeShieldEvent) -> None:
    """Saves a LifeShieldEvent object into SQLite database."""
    init_db()
    
    # Extract timestamp string
    ts = event.timestamp.isoformat() if isinstance(event.timestamp, datetime) else str(event.timestamp)

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO events (
                event_id, correlation_id, timestamp, event_type, source,
                user, device, process, data, metadata
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.event_id,
                event.correlation_id,
                ts,
                str(event.event_type),
                str(event.source),
                event.user,
                event.device,
                event.process,
                json.dumps(event.data),
                json.dumps(event.metadata),
            ),
        )
        conn.commit()


def get_events(limit: int = 100) -> List[LifeShieldEvent]:
    """Retrieves recent events from SQLite database sorted by timestamp descending."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = cursor.fetchall()

    events = []
    for row in rows:
        events.append(
            LifeShieldEvent(
                event_id=row["event_id"],
                correlation_id=row["correlation_id"],
                timestamp=row["timestamp"],
                event_type=row["event_type"],
                source=row["source"],
                user=row["user"],
                device=row["device"],
                process=row["process"],
                data=json.loads(row["data"]) if row["data"] else {},
                metadata=json.loads(row["metadata"]) if row["metadata"] else {},
            )
        )
    return events


def get_event_by_id(event_id: str) -> Optional[LifeShieldEvent]:
    """Retrieves a single event by event_id."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM events WHERE event_id = ?", (event_id,))
        row = cursor.fetchone()

    if not row:
        return None

    return LifeShieldEvent(
        event_id=row["event_id"],
        correlation_id=row["correlation_id"],
        timestamp=row["timestamp"],
        event_type=row["event_type"],
        source=row["source"],
        user=row["user"],
        device=row["device"],
        process=row["process"],
        data=json.loads(row["data"]) if row["data"] else {},
        metadata=json.loads(row["metadata"]) if row["metadata"] else {},
    )


# --- Detections Layer (Module 7 & 10) -----------------------------------

def save_detection(
    event_id: str,
    model_name: str,
    risk_score: float,
    severity: str,
    is_threat: bool,
    details: Dict[str, Any],
    detection_id: Optional[str] = None,
    timestamp: Optional[str] = None,
) -> str:
    """Saves an ML model detection record linked to an event."""
    init_db()
    det_id = detection_id or str(uuid4())
    ts = timestamp or datetime.now(timezone.utc).isoformat()

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT OR REPLACE INTO detections (
                detection_id, event_id, model_name, risk_score,
                severity, is_threat, timestamp, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                det_id,
                event_id,
                model_name,
                float(risk_score),
                severity,
                1 if is_threat else 0,
                ts,
                json.dumps(details),
            ),
        )
        conn.commit()
    return det_id


def get_detections(limit: int = 100, threats_only: bool = False) -> List[Dict[str, Any]]:
    """Retrieves recent detections sorted by timestamp descending."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        if threats_only:
            cursor.execute(
                "SELECT * FROM detections WHERE is_threat = 1 ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        else:
            cursor.execute(
                "SELECT * FROM detections ORDER BY timestamp DESC LIMIT ?", (limit,)
            )
        rows = cursor.fetchall()

    detections = []
    for r in rows:
        detections.append({
            "detection_id": r["detection_id"],
            "event_id": r["event_id"],
            "model_name": r["model_name"],
            "risk_score": r["risk_score"],
            "severity": r["severity"],
            "is_threat": bool(r["is_threat"]),
            "timestamp": r["timestamp"],
            "details": json.loads(r["details"]) if r["details"] else {},
        })
    return detections


def get_detections_by_event_id(event_id: str) -> List[Dict[str, Any]]:
    """Retrieves all detections associated with an event."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT * FROM detections WHERE event_id = ? ORDER BY timestamp DESC",
            (event_id,),
        )
        rows = cursor.fetchall()

    return [{
        "detection_id": r["detection_id"],
        "event_id": r["event_id"],
        "model_name": r["model_name"],
        "risk_score": r["risk_score"],
        "severity": r["severity"],
        "is_threat": bool(r["is_threat"]),
        "timestamp": r["timestamp"],
        "details": json.loads(r["details"]) if r["details"] else {},
    } for r in rows]


def get_stats() -> Dict[str, Any]:
    """Returns database statistics including events and detections."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM events")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type")
        by_type = {row["event_type"]: row["count"] for row in cursor.fetchall()}

        cursor.execute("SELECT source, COUNT(*) as count FROM events GROUP BY source")
        by_source = {row["source"]: row["count"] for row in cursor.fetchall()}

        cursor.execute("SELECT COUNT(*) as total FROM detections")
        total_detections = cursor.fetchone()["total"]

        cursor.execute("SELECT COUNT(*) as count FROM detections WHERE is_threat = 1")
        total_threats = cursor.fetchone()["count"]

    return {
        "total_events": total,
        "by_type": by_type,
        "by_source": by_source,
        "total_detections": total_detections,
        "total_threats": total_threats,
    }
