"""
Repository module for LifeShield storage layer.
Provides functions to save and retrieve events from SQLite database.
"""
import sys
import json
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

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


def get_stats() -> Dict[str, Any]:
    """Returns basic event statistics."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as total FROM events")
        total = cursor.fetchone()["total"]

        cursor.execute("SELECT event_type, COUNT(*) as count FROM events GROUP BY event_type")
        by_type = {row["event_type"]: row["count"] for row in cursor.fetchall()}

        cursor.execute("SELECT source, COUNT(*) as count FROM events GROUP BY source")
        by_source = {row["source"]: row["count"] for row in cursor.fetchall()}

    return {
        "total_events": total,
        "by_type": by_type,
        "by_source": by_source,
    }


if __name__ == "__main__":
    test_evt = LifeShieldEvent(
        event_type=EventType.URL_VISIT,
        source=EventSource.MANUAL,
        user="test_repo_user",
        data={"url": "http://test-repo.com"},
    )
    save_event(test_evt)
    retrieved = get_event_by_id(test_evt.event_id)
    print(f"Saved & Retrieved Event: {retrieved.event_id} ({retrieved.event_type})")
    print(f"Stats: {get_stats()}")
