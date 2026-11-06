"""
collectors/windows/login_collector.py
======================================
Polls the Windows Security Event Log for logon events and
posts them to the LifeShield agent API as normalised
LOGIN_SUCCESS / LOGIN_FAILURE events.

Event IDs monitored
-------------------
  4624 -> Logon Success  -> EventType.LOGIN_SUCCESS
  4625 -> Logon Failure  -> EventType.LOGIN_FAILURE

Design decisions
----------------
* Uses pywin32 (win32evtlog) which is the officially supported
  Windows API for reading the Security Event Log.
* Runs in a background *daemon* thread – the caller (watcher.py)
  is responsible for starting it; this module only exposes the
  core polling function and a thin thread-factory helper.
* All configuration (poll interval, look-back window, agent URL)
  comes from configs/loader.py – no hardcoding.
* On machines where the Security Log is inaccessible (non-admin,
  CI runners) the collector logs a warning and exits cleanly
  without crashing the agent process.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Generator

import requests

from configs.loader import get_config
from storage.schema import EventSource, EventType

logger = logging.getLogger(__name__)

# Windows Security Event Log name
_SECURITY_LOG = "Security"

# Map Win32 Event IDs -> LifeShield EventType
_EVENT_ID_MAP: dict[int, EventType] = {
    4624: EventType.LOGIN_SUCCESS,
    4625: EventType.LOGIN_FAILURE,
}

# Logon type descriptions (from Microsoft docs)
_LOGON_TYPES: dict[str, str] = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}


def _get_agent_url(cfg: dict) -> str:
    host = cfg["agent"]["host"]
    port = cfg["agent"]["port"]
    return f"http://{host}:{port}/events"


def _extract_string_inserts(event) -> list[str]:
    """
    Safely extract the StringInserts list from a win32evtlog event record.
    Returns an empty list when the attribute is absent or None.
    """
    try:
        inserts = event.StringInserts
        return list(inserts) if inserts else []
    except Exception:
        return []


def _parse_logon_event(event, event_id: int) -> dict:
    """
    Parse StringInserts from a Security Log logon event.

    Field positions differ between 4624 and 4625 – documented at:
    https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/
    """
    inserts = _extract_string_inserts(event)

    def _si(idx: int, default: str = "") -> str:
        try:
            return str(inserts[idx]) if inserts[idx] else default
        except IndexError:
            return default

    if event_id == 4624:
        # Subject / target account / logon information
        return {
            "subject_user": _si(1),
            "subject_domain": _si(2),
            "target_user": _si(5),
            "target_domain": _si(6),
            "logon_id": _si(7),
            "logon_type": _LOGON_TYPES.get(_si(8), _si(8)),
            "logon_type_raw": _si(8),
            "process_name": _si(17),
            "source_ip": _si(18),
            "source_port": _si(19),
            "workstation": _si(11),
        }
    elif event_id == 4625:
        return {
            "subject_user": _si(1),
            "subject_domain": _si(2),
            "target_user": _si(5),
            "target_domain": _si(6),
            "failure_reason": _si(8),
            "sub_status": _si(9),
            "logon_type": _LOGON_TYPES.get(_si(10), _si(10)),
            "logon_type_raw": _si(10),
            "process_name": _si(11),
            "workstation": _si(13),
            "source_ip": _si(19),
            "source_port": _si(20),
        }
    return {}


def _build_payload(event, event_id: int, event_type: EventType) -> dict:
    """Construct the POST body for the LifeShield events endpoint."""
    parsed = _parse_logon_event(event, event_id)
    target_user = parsed.get("target_user") or parsed.get("subject_user") or ""
    return {
        "event_type": event_type.value,
        "source": EventSource.WINDOWS_COLLECTOR.value,
        "user": target_user,
        "device": socket.gethostname(),
        "data": parsed,
        "metadata": {
            "event_id": event_id,
            "record_number": getattr(event, "RecordNumber", None),
            "collector": "login_collector",
        },
    }


def poll_login_events(
    stop_event: threading.Event,
    lookback_seconds: int | None = None,
    poll_interval: float | None = None,
    agent_url: str | None = None,
) -> None:
    """
    Main loop: poll the Windows Security Event Log and POST matching
    events to the LifeShield agent.

    Parameters
    ----------
    stop_event       : set() this to request a graceful shutdown.
    lookback_seconds : how far back (in seconds) to fetch events on
                       the first poll.  Subsequent polls only fetch
                       new records.  Defaults to config value.
    poll_interval    : seconds between polls.  Defaults to config value.
    agent_url        : override the agent endpoint URL (useful in tests).
    """
    # Import pywin32 lazily so the module can be imported on any platform
    # (tests mock this out when not running on Windows with an open log).
    try:
        import win32evtlog
        import win32evtlogutil
        import winerror
    except ImportError:
        logger.error(
            "pywin32 is not installed – Windows login collector cannot run. "
            "Install it with: pip install pywin32"
        )
        return

    cfg = get_config()
    win_cfg = cfg.get("collectors", {}).get("windows", {})
    _lookback = lookback_seconds if lookback_seconds is not None else win_cfg.get("login_lookback_seconds", 30)
    _interval = poll_interval if poll_interval is not None else win_cfg.get("poll_interval_seconds", 5)
    _url = agent_url or _get_agent_url(cfg)

    logger.info("Login collector starting – polling every %ss, look-back %ss", _interval, _lookback)

    # We track the last seen record number so we don't re-process events.
    last_record: int = -1

    while not stop_event.is_set():
        try:
            handle = win32evtlog.OpenEventLog(None, _SECURITY_LOG)
            flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events_found = 0

            while True:
                raw_events = win32evtlog.ReadEventLog(handle, flags, 0)
                if not raw_events:
                    break
                for ev in raw_events:
                    record_num = getattr(ev, "RecordNumber", 0)
                    ev_id = ev.EventID & 0xFFFF  # strip facility/severity bits
                    if ev_id not in _EVENT_ID_MAP:
                        continue
                    if record_num <= last_record:
                        continue
                    last_record = max(last_record, record_num)
                    event_type = _EVENT_ID_MAP[ev_id]
                    payload = _build_payload(ev, ev_id, event_type)
                    try:
                        resp = requests.post(_url, json=payload, timeout=5)
                        if resp.status_code not in (200, 201):
                            logger.warning("Agent rejected event: %s", resp.text[:200])
                        else:
                            events_found += 1
                            logger.debug("Sent %s event (record %s)", event_type.value, record_num)
                    except requests.RequestException as exc:
                        logger.warning("Could not reach agent at %s: %s", _url, exc)

            win32evtlog.CloseEventLog(handle)
            if events_found:
                logger.info("Login collector: sent %d events this cycle", events_found)

        except Exception as exc:
            logger.warning("Login collector error: %s", exc)

        stop_event.wait(timeout=_interval)

    logger.info("Login collector stopped.")


def make_login_collector_thread(
    stop_event: threading.Event,
    **kwargs,
) -> threading.Thread:
    """Return a configured daemon thread for poll_login_events."""
    t = threading.Thread(
        target=poll_login_events,
        args=(stop_event,),
        kwargs=kwargs,
        name="login-collector",
        daemon=True,
    )
    return t
