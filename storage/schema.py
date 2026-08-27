"""
LifeShield core event schema.
Every collector MUST produce events in this shape.
This is the contract between all modules — do not modify casually
after Week 1; changing it later breaks every downstream module.
"""

from __future__ import annotations
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4
from pydantic import BaseModel, ConfigDict, Field


class EventType(str, Enum):
    """
    Every kind of thing LifeShield can observe.
    Add new types here ONLY — never invent ad-hoc strings elsewhere,
    or the correlation engine (Week 9-10) won't recognize them.
    """
    URL_VISIT = "URL_VISIT"
    URL_REDIRECT = "URL_REDIRECT"
    FILE_CREATE = "FILE_CREATE"
    FILE_DOWNLOAD = "FILE_DOWNLOAD"
    PROCESS_START = "PROCESS_START"
    PROCESS_END = "PROCESS_END"
    DNS_QUERY = "DNS_QUERY"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    BROWSER_DOWNLOAD = "BROWSER_DOWNLOAD"
    MESSAGE_ANALYSIS = "MESSAGE_ANALYSIS"
    USER_FEEDBACK = "USER_FEEDBACK"


class EventSource(str, Enum):
    """Which collector produced this event."""
    BROWSER_EXTENSION = "browser_extension"
    WINDOWS_COLLECTOR = "windows_collector"
    FILE_COLLECTOR = "file_collector"
    NETWORK_COLLECTOR = "network_collector"
    MANUAL = "manual"          # for testing / manual injection


class LifeShieldEvent(BaseModel):
    """
    The canonical event object. Every collector normalizes into this
    before it enters the pipeline (see Normalizer, Week 2).
    """

    # --- identity ---
    event_id: str = Field(default_factory=lambda: str(uuid4()))
    correlation_id: Optional[str] = None
    # ^ Left empty by collectors. The Correlation Engine (Week 9-10)
    #   fills this in when it links related events together.
    #   All events from the same "attack chain" will share one correlation_id.

    # --- when / what / where ---
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: EventType
    source: EventSource

    # --- who / what machine ---
    user: Optional[str] = None
    device: Optional[str] = None
    process: Optional[str] = None
    # ^ e.g. process name that triggered this event, when known

    # --- the actual payload, e.g. {"url": "http://bad.com"} ---
    data: dict[str, Any] = Field(default_factory=dict)

    # --- anything extra collectors want to attach, non-critical ---
    metadata: dict[str, Any] = Field(default_factory=dict)

    model_config = ConfigDict(use_enum_values=True)


# --- quick self-test you can run directly: python storage/schema.py ---
if __name__ == "__main__":
    test_event = LifeShieldEvent(
        event_type=EventType.URL_VISIT,
        source=EventSource.MANUAL,
        user="test_user",
        device="test_device",
        data={"url": "http://example-test-phishing.com"},
    )
    print(test_event.model_dump_json(indent=2))
