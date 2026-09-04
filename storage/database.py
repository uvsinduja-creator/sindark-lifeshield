"""
SQLite Database Initialization and Connection Management for LifeShield.
"""
import sys
import sqlite3
import json
from pathlib import Path

# Ensure project root is in sys.path when script is executed directly
sys.path.insert(0, str(Path(__file__).parent.parent))

from configs.loader import get_config


def get_db_path() -> Path:
    cfg = get_config()
    db_path = Path(cfg["storage"]["db_path"])
    db_path.parent.mkdir(parents=True, exist_ok=True)
    return db_path


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(str(get_db_path()))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Creates the events table if it does not exist."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                correlation_id TEXT,
                timestamp TEXT NOT NULL,
                event_type TEXT NOT NULL,
                source TEXT NOT NULL,
                user TEXT,
                device TEXT,
                process TEXT,
                data TEXT NOT NULL,
                metadata TEXT NOT NULL
            )
        """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_correlation_id ON events(correlation_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_type ON events(event_type)")
        conn.commit()


if __name__ == "__main__":
    init_db()
    print(f"Database initialized at {get_db_path()}")
