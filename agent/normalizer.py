"""
Normalizer module for LifeShield Agent.
Validates and coerces raw collector payloads into canonical LifeShieldEvent instances.
"""
import sys
from pathlib import Path
from typing import Dict, Any
from pydantic import ValidationError

sys.path.insert(0, str(Path(__file__).parent.parent))

from storage.schema import LifeShieldEvent, EventType, EventSource


def normalize_event(raw_data: Dict[str, Any]) -> LifeShieldEvent:
    """
    Takes a raw dict payload from any collector or API endpoint
    and validates/coerces it into a LifeShieldEvent object.
    Raises ValueError if malformed.
    """
    if not isinstance(raw_data, dict):
        raise ValueError("Payload must be a JSON object / dict")

    try:
        event = LifeShieldEvent(**raw_data)
        return event
    except ValidationError as e:
        raise ValueError(f"Invalid event schema: {e}") from e
    except Exception as e:
        raise ValueError(f"Failed to normalize event: {e}") from e


if __name__ == "__main__":
    raw_valid = {
        "event_type": "URL_VISIT",
        "source": "browser_extension",
        "user": "alice",
        "data": {"url": "https://example.com"}
    }
    normalized = normalize_event(raw_valid)
    print(f"Normalized Valid Event: {normalized.event_id} ({normalized.event_type})")

    try:
        normalize_event({"event_type": "INVALID_TYPE", "source": "unknown"})
    except ValueError as err:
        print(f"Caught expected normalization error: {err}")
