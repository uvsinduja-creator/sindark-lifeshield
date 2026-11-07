"""
ml/behavior_model/features.py
==============================
Feature extraction for behavioral anomaly detection.
Constructs numerical feature vectors from telemetry window statistics
(temporal patterns, process spawn bursts, failed logins, network rates).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# Ordered list of feature names used by Isolation Forest
BEHAVIOR_FEATURE_NAMES = [
    "hour_of_day",
    "is_off_hours",
    "is_weekend",
    "event_rate_per_min",
    "process_start_rate_per_min",
    "failed_login_count",
    "network_conn_rate_per_min",
    "dns_query_rate_per_min",
    "file_download_rate_per_min",
]


def extract_behavior_features(data: dict[str, Any]) -> dict[str, Any]:
    """
    Extract a normalized dictionary of behavioral telemetry features.
    Accepts keys directly or infers current time if omitted.
    """
    now = datetime.now(timezone.utc)
    hour = int(data.get("hour_of_day", now.hour))
    is_off_hours = int(data.get("is_off_hours", 1 if (hour < 7 or hour >= 21) else 0))
    is_weekend = int(data.get("is_weekend", 1 if now.weekday() >= 5 else 0))

    event_rate = float(data.get("event_rate_per_min", 0.0))
    process_rate = float(data.get("process_start_rate_per_min", 0.0))
    failed_logins = int(data.get("failed_login_count", 0))
    network_rate = float(data.get("network_conn_rate_per_min", 0.0))
    dns_rate = float(data.get("dns_query_rate_per_min", 0.0))
    download_rate = float(data.get("file_download_rate_per_min", 0.0))

    return {
        "hour_of_day": hour,
        "is_off_hours": is_off_hours,
        "is_weekend": is_weekend,
        "event_rate_per_min": max(0.0, event_rate),
        "process_start_rate_per_min": max(0.0, process_rate),
        "failed_login_count": max(0, failed_logins),
        "network_conn_rate_per_min": max(0.0, network_rate),
        "dns_query_rate_per_min": max(0.0, dns_rate),
        "file_download_rate_per_min": max(0.0, download_rate),
    }


def to_feature_vector(features: dict[str, Any]) -> list[float]:
    """Convert feature dictionary to ordered float list matching BEHAVIOR_FEATURE_NAMES."""
    return [float(features[name]) for name in BEHAVIOR_FEATURE_NAMES]
