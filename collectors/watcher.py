"""
collectors/watcher.py
======================
Master Orchestrator for all LifeShield Station 1 Telemetry Collectors.

Launches and supervises background collectors:
  1. Windows Login Events (Security Event Log 4624/4625)
  2. Windows Process Events (Process creation/termination diff)
  3. Filesystem Watcher (File creations & downloads via watchdog)
  4. DNS Query & Network Connection Monitor

All collectors execute as daemon threads with coordinated graceful
shutdown on SIGINT / SIGTERM.
Configuration is loaded dynamically from configs/base.yaml via configs/loader.py.
"""

from __future__ import annotations

import logging
import signal
import threading
import time

from configs.loader import get_config
from collectors.windows.login_collector import make_login_collector_thread
from collectors.windows.process_collector import make_process_collector_thread
from collectors.filesystem.file_watcher import make_file_watcher_thread
from collectors.network.dns_collector import (
    make_dns_collector_thread,
    make_network_collector_thread,
)

logger = logging.getLogger(__name__)


def _configure_logging(cfg: dict) -> None:
    level_name = cfg.get("logging", {}).get("level", "INFO")
    level = getattr(logging, level_name.upper(), logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


def run_master_watcher() -> None:
    """Start all LifeShield collectors and block until interrupted."""
    cfg = get_config()
    _configure_logging(cfg)

    logger.info("Starting LifeShield Master Telemetry Collector Service...")

    stop_event = threading.Event()

    def _shutdown(signum, frame):
        logger.info("Shutdown signal received (%s) – stopping all collectors...", signum)
        stop_event.set()

    signal.signal(signal.SIGINT, _shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown)

    threads: list[threading.Thread] = [
        make_login_collector_thread(stop_event),
        make_process_collector_thread(stop_event),
        make_file_watcher_thread(stop_event),
        make_dns_collector_thread(stop_event),
        make_network_collector_thread(stop_event),
    ]

    for t in threads:
        logger.info("Starting collector: %s", t.name)
        t.start()

    logger.info(
        "LifeShield Master Collector running with %d active telemetry threads. Press Ctrl-C to stop.",
        len(threads),
    )

    while not stop_event.is_set():
        time.sleep(1)

    logger.info("Waiting for telemetry threads to terminate...")
    for t in threads:
        t.join(timeout=10)

    logger.info("LifeShield Master Collector terminated cleanly.")


if __name__ == "__main__":
    run_master_watcher()
