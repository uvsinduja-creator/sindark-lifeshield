"""
collectors/windows/watcher.py
==============================
Orchestrates all Windows telemetry collectors.

Usage (run directly on a Windows machine with the agent running):
    python -m collectors.windows.watcher

It starts:
  * login_collector  – Windows Security Event Log polling
  * process_collector – psutil process diff polling

Both collectors run as daemon threads.  The watcher blocks
on a threading.Event and handles Ctrl-C / SIGTERM for
graceful shutdown.

Configuration is loaded from configs/base.yaml via configs/loader.py.
No hardcoding.
"""

from __future__ import annotations

import logging
import signal
import sys
import threading
import time

from configs.loader import get_config
from collectors.windows.login_collector import make_login_collector_thread
from collectors.windows.process_collector import make_process_collector_thread

logger = logging.getLogger(__name__)


def _configure_logging(cfg: dict) -> None:
    level_name = cfg.get("logging", {}).get("level", "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def run_watcher() -> None:
    """Start all Windows collectors and block until interrupted."""
    cfg = get_config()
    _configure_logging(cfg)

    logger.info("LifeShield Windows Telemetry Watcher starting …")

    stop_event = threading.Event()

    # --- register graceful shutdown for Ctrl-C and SIGTERM ---
    def _shutdown(signum, frame):
        logger.info("Shutdown signal received (%s) – stopping collectors …", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown)

    # --- build and start collector threads ---
    threads: list[threading.Thread] = [
        make_login_collector_thread(stop_event),
        make_process_collector_thread(stop_event),
    ]

    for t in threads:
        logger.info("Starting thread: %s", t.name)
        t.start()

    logger.info(
        "Windows Telemetry Watcher running – %d collector threads active. "
        "Press Ctrl-C to stop.",
        len(threads),
    )

    # Block main thread until stop requested
    while not stop_event.is_set():
        time.sleep(1)

    logger.info("Waiting for collector threads to finish …")
    for t in threads:
        t.join(timeout=10)

    logger.info("LifeShield Windows Telemetry Watcher stopped cleanly.")


if __name__ == "__main__":
    run_watcher()
