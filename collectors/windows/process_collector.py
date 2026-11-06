"""
collectors/windows/process_collector.py
========================================
Monitors Windows process creation and exit using psutil and
posts events to the LifeShield agent API as PROCESS_START /
PROCESS_END events.

Strategy
--------
* Maintains a dict of {pid -> process_start_info} built from
  psutil.process_iter() snapshots taken every poll_interval seconds.
* New PIDs   -> emit PROCESS_START
* Gone PIDs  -> emit PROCESS_END (with estimated exit code where
                 available via psutil.Process.returncode())
* psutil is cross-platform, but this collector is designed for
  Windows and is wired in by watcher.py on Windows only.

All configuration comes from configs/loader.py – no hardcoding.
"""

from __future__ import annotations

import logging
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any

import psutil
import requests

from configs.loader import get_config
from storage.schema import EventSource, EventType

logger = logging.getLogger(__name__)


def _get_agent_url(cfg: dict) -> str:
    host = cfg["agent"]["host"]
    port = cfg["agent"]["port"]
    return f"http://{host}:{port}/events"


def _safe_proc_info(proc: psutil.Process) -> dict[str, Any] | None:
    """
    Collect process attributes that are available without admin rights.
    Returns None when the process has already exited.
    """
    try:
        with proc.oneshot():
            return {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe() if proc.is_running() else "",
                "cmdline": " ".join(proc.cmdline()),
                "username": proc.username(),
                "ppid": proc.ppid(),
                "create_time": proc.create_time(),
            }
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def _parent_name(ppid: int) -> str:
    """Resolve parent PID -> process name safely."""
    try:
        return psutil.Process(ppid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return ""


def _build_start_payload(info: dict) -> dict:
    return {
        "event_type": EventType.PROCESS_START.value,
        "source": EventSource.WINDOWS_COLLECTOR.value,
        "user": info.get("username", ""),
        "device": socket.gethostname(),
        "process": info.get("name", ""),
        "data": {
            "pid": info["pid"],
            "name": info.get("name", ""),
            "exe": info.get("exe", ""),
            "cmdline": info.get("cmdline", ""),
            "username": info.get("username", ""),
            "parent_pid": info.get("ppid", 0),
            "parent_name": _parent_name(info.get("ppid", 0)),
            "create_time_utc": datetime.fromtimestamp(
                info.get("create_time", 0), tz=timezone.utc
            ).isoformat(),
        },
        "metadata": {"collector": "process_collector"},
    }


def _build_end_payload(pid: int, info: dict, exit_code: int | None, now_ts: float) -> dict:
    runtime = max(0.0, now_ts - info.get("create_time", now_ts))
    return {
        "event_type": EventType.PROCESS_END.value,
        "source": EventSource.WINDOWS_COLLECTOR.value,
        "user": info.get("username", ""),
        "device": socket.gethostname(),
        "process": info.get("name", ""),
        "data": {
            "pid": pid,
            "name": info.get("name", ""),
            "exit_code": exit_code,
            "runtime_seconds": round(runtime, 3),
        },
        "metadata": {"collector": "process_collector"},
    }


def _post_event(url: str, payload: dict) -> None:
    """Fire-and-forget POST; logs warnings on failure, never raises."""
    try:
        resp = requests.post(url, json=payload, timeout=5)
        if resp.status_code not in (200, 201):
            logger.warning("Agent rejected process event: %s", resp.text[:200])
    except requests.RequestException as exc:
        logger.warning("Could not reach agent at %s: %s", url, exc)


def poll_process_events(
    stop_event: threading.Event,
    poll_interval: float | None = None,
    agent_url: str | None = None,
) -> None:
    """
    Main loop: diff psutil.process_iter() snapshots and POST
    PROCESS_START / PROCESS_END events to the LifeShield agent.

    Parameters
    ----------
    stop_event    : set() this to request a graceful shutdown.
    poll_interval : seconds between snapshots.  Defaults to config value.
    agent_url     : override the agent endpoint URL (useful in tests).
    """
    cfg = get_config()
    win_cfg = cfg.get("collectors", {}).get("windows", {})
    _interval = poll_interval if poll_interval is not None else win_cfg.get("poll_interval_seconds", 5)
    _url = agent_url or _get_agent_url(cfg)

    logger.info("Process collector starting – polling every %ss", _interval)

    # Seed the initial snapshot so we don't flood START events for every
    # process already running when the collector first starts.
    known: dict[int, dict] = {}
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "ppid", "create_time"]):
        info = _safe_proc_info(proc)
        if info:
            known[info["pid"]] = info

    logger.info("Process collector: seeded with %d running processes", len(known))

    while not stop_event.is_set():
        try:
            current: dict[int, dict] = {}
            for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "username", "ppid", "create_time"]):
                info = _safe_proc_info(proc)
                if info:
                    current[info["pid"]] = info

            now_ts = time.time()
            new_pids = set(current) - set(known)
            gone_pids = set(known) - set(current)

            for pid in new_pids:
                payload = _build_start_payload(current[pid])
                _post_event(_url, payload)
                logger.debug("PROCESS_START pid=%d name=%s", pid, current[pid].get("name"))

            for pid in gone_pids:
                # Try to get exit code – may not be available
                exit_code: int | None = None
                try:
                    p = psutil.Process(pid)
                    exit_code = p.returncode() if hasattr(p, "returncode") else None
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    pass
                payload = _build_end_payload(pid, known[pid], exit_code, now_ts)
                _post_event(_url, payload)
                logger.debug("PROCESS_END pid=%d name=%s", pid, known[pid].get("name"))

            known = current

        except Exception as exc:
            logger.warning("Process collector error: %s", exc)

        stop_event.wait(timeout=_interval)

    logger.info("Process collector stopped.")


def make_process_collector_thread(
    stop_event: threading.Event,
    **kwargs,
) -> threading.Thread:
    """Return a configured daemon thread for poll_process_events."""
    t = threading.Thread(
        target=poll_process_events,
        args=(stop_event,),
        kwargs=kwargs,
        name="process-collector",
        daemon=True,
    )
    return t
