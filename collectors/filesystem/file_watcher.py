"""
collectors/filesystem/file_watcher.py
=======================================
Monitors local filesystem directories (Downloads, Desktop, etc.)
using watchdog and posts normalized FILE_CREATE / FILE_DOWNLOAD
events to the LifeShield agent API.

Metadata Extracted
------------------
* File path, filename, extension
* File size in bytes
* SHA-256 hash (streamed safely to handle large files)
* Shannon entropy (sampled to detect packed/encrypted executables)
* Suspicious flags: is_double_extension, is_executable, is_script, is_archive
* Creation and modification timestamps

Design Decisions
----------------
* Uses watchdog for cross-platform, low-overhead filesystem notification.
* Handles temporary browser download renames (.crdownload, .tmp, .part)
  by emitting a FILE_DOWNLOAD event upon download completion.
* Graceful retry logic for locked files that are still being written.
* All configuration loaded via configs/loader.py – no hardcoding.
"""

from __future__ import annotations

import getpass
import hashlib
import logging
import math
import os
import socket
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests
from watchdog.events import FileSystemEventHandler, FileCreatedEvent, FileMovedEvent
from watchdog.observers import Observer

from configs.loader import get_config
from storage.schema import EventSource, EventType

logger = logging.getLogger(__name__)

# High-risk executable and script extensions
EXECUTABLE_EXTENSIONS = {
    ".exe", ".dll", ".sys", ".scr", ".com", ".cpl", ".msi", ".pif",
}
SCRIPT_EXTENSIONS = {
    ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
}
ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".iso", ".img", ".cab",
}
TEMP_DOWNLOAD_EXTENSIONS = {
    ".crdownload", ".tmp", ".part", ".download",
}


def _get_agent_url(cfg: dict) -> str:
    host = cfg["agent"]["host"]
    port = cfg["agent"]["port"]
    return f"http://{host}:{port}/events"


def compute_shannon_entropy(filepath: str | Path, max_sample_bytes: int = 1048576) -> float:
    """
    Compute Shannon entropy (0.0 to 8.0) of a file's bytes.
    Values above ~7.2 generally indicate compression, encryption, or packing.
    """
    try:
        with open(filepath, "rb") as f:
            data = f.read(max_sample_bytes)
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        counts = [0] * 256
        for byte in data:
            counts[byte] += 1
        for count in counts:
            if count > 0:
                p = count / length
                entropy -= p * math.log2(p)
        return round(entropy, 4)
    except Exception as exc:
        logger.debug("Could not compute entropy for %s: %s", filepath, exc)
        return 0.0


def compute_file_hash(
    filepath: str | Path,
    max_bytes: int = 52428800,
    retries: int = 3,
    retry_delay: float = 0.1,
) -> tuple[Optional[str], int]:
    """
    Compute the SHA-256 hash of a file streamed in 64KB blocks.
    Retries in case the file is briefly locked by the creator.
    Returns (sha256_hex, file_size_bytes).
    """
    p = Path(filepath)
    for attempt in range(retries):
        try:
            if not p.is_file():
                return None, 0
            size = p.stat().st_size
            if size > max_bytes:
                # File too large to hash without latency impact
                return None, size

            hasher = hashlib.sha256()
            with open(p, "rb") as f:
                while chunk := f.read(65536):
                    hasher.update(chunk)
            return hasher.hexdigest(), size
        except (PermissionError, OSError) as exc:
            if attempt < retries - 1:
                time.sleep(retry_delay)
            else:
                logger.debug("Could not read file %s after %d attempts: %s", filepath, retries, exc)
                try:
                    return None, p.stat().st_size
                except Exception:
                    return None, 0
    return None, 0


def detect_double_extension(filename: str) -> bool:
    """
    Detects masquerading double extensions like 'invoice.pdf.exe' or 'photo.jpg.scr'.
    Returns True if the file has multiple extensions and the last extension is executable/script.
    """
    parts = filename.split(".")
    if len(parts) >= 3:
        last_ext = f".{parts[-1].lower()}"
        if last_ext in (EXECUTABLE_EXTENSIONS | SCRIPT_EXTENSIONS):
            return True
    return False


def extract_file_metadata(filepath: str | Path, max_hash_bytes: int = 52428800) -> dict[str, Any]:
    """Extract comprehensive metadata for a created or downloaded file."""
    p = Path(filepath)
    ext = p.suffix.lower()
    filename = p.name

    sha256_hash, file_size = compute_file_hash(p, max_bytes=max_hash_bytes)
    entropy = compute_shannon_entropy(p) if file_size > 0 else 0.0

    is_exec = ext in EXECUTABLE_EXTENSIONS
    is_script = ext in SCRIPT_EXTENSIONS
    is_archive = ext in ARCHIVE_EXTENSIONS
    is_double_ext = detect_double_extension(filename)

    # Check for hidden attribute
    is_hidden = False
    try:
        if filename.startswith("."):
            is_hidden = True
        elif os.name == "nt":
            import stat
            attrs = p.stat().st_file_attributes
            is_hidden = bool(attrs & stat.FILE_ATTRIBUTE_HIDDEN)
    except Exception:
        pass

    try:
        st = p.stat()
        created_time = datetime.fromtimestamp(st.st_ctime, tz=timezone.utc).isoformat()
        modified_time = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat()
    except Exception:
        now_iso = datetime.now(timezone.utc).isoformat()
        created_time = now_iso
        modified_time = now_iso

    return {
        "path": str(p.resolve()),
        "filename": filename,
        "extension": ext,
        "size_bytes": file_size,
        "sha256": sha256_hash,
        "entropy": entropy,
        "is_executable": is_exec,
        "is_script": is_script,
        "is_archive": is_archive,
        "is_double_extension": is_double_ext,
        "is_hidden": is_hidden,
        "created_time_utc": created_time,
        "modified_time_utc": modified_time,
    }


def is_download_location_or_temp(filepath: str | Path, src_path: Optional[str | Path] = None) -> bool:
    """Determine whether an event corresponds to a file download."""
    p_str = str(filepath).lower()
    if "download" in p_str:
        return True
    if src_path:
        src_ext = Path(src_path).suffix.lower()
        if src_ext in TEMP_DOWNLOAD_EXTENSIONS:
            return True
    return False


def build_filesystem_event_payload(
    filepath: str | Path,
    event_type: EventType,
    max_hash_bytes: int = 52428800,
    metadata_extra: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Construct a LifeShieldEvent-compliant dictionary for the file event."""
    file_meta = extract_file_metadata(filepath, max_hash_bytes=max_hash_bytes)
    user = getpass.getuser()
    device = socket.gethostname()

    extra = metadata_extra or {}
    meta = {"collector": "file_watcher", **extra}

    return {
        "event_type": event_type.value,
        "source": EventSource.FILE_COLLECTOR.value,
        "user": user,
        "device": device,
        "data": file_meta,
        "metadata": meta,
    }


class LifeShieldFileEventHandler(FileSystemEventHandler):
    """Watchdog event handler that emits LifeShield file events."""

    def __init__(self, agent_url: str, max_hash_bytes: int = 52428800):
        super().__init__()
        self.agent_url = agent_url
        self.max_hash_bytes = max_hash_bytes
        self._recently_emitted: dict[str, float] = {}

    def _should_debounce(self, path: str, cooldown: float = 1.0) -> bool:
        now = time.time()
        last = self._recently_emitted.get(path, 0)
        if now - last < cooldown:
            return True
        self._recently_emitted[path] = now
        # Clean up old keys
        if len(self._recently_emitted) > 1000:
            self._recently_emitted = {
                k: v for k, v in self._recently_emitted.items() if now - v < 60
            }
        return False

    def _post(self, payload: dict[str, Any]) -> None:
        try:
            resp = requests.post(self.agent_url, json=payload, timeout=5)
            if resp.status_code not in (200, 201, 202):
                logger.warning("Agent rejected file event: %s", resp.text[:200])
            else:
                logger.debug("Sent %s event for %s", payload["event_type"], payload["data"].get("filename"))
        except requests.RequestException as exc:
            logger.warning("Could not reach agent at %s: %s", self.agent_url, exc)

    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory:
            return
        dest = event.src_path
        ext = Path(dest).suffix.lower()
        # Don't emit for incomplete browser download temp files
        if ext in TEMP_DOWNLOAD_EXTENSIONS:
            return
        if self._should_debounce(dest):
            return

        ev_type = EventType.FILE_DOWNLOAD if is_download_location_or_temp(dest) else EventType.FILE_CREATE
        payload = build_filesystem_event_payload(dest, ev_type, self.max_hash_bytes)
        self._post(payload)

    def on_moved(self, event: FileMovedEvent) -> None:
        if event.is_directory:
            return
        dest = event.dest_path
        src = event.src_path
        ext = Path(dest).suffix.lower()
        if ext in TEMP_DOWNLOAD_EXTENSIONS:
            return
        if self._should_debounce(dest):
            return

        # Often downloaded files are moved from a .crdownload or .tmp path to target name
        ev_type = EventType.FILE_DOWNLOAD if is_download_location_or_temp(dest, src_path=src) else EventType.FILE_CREATE
        payload = build_filesystem_event_payload(
            dest,
            ev_type,
            self.max_hash_bytes,
            metadata_extra={"renamed_from": str(src)},
        )
        self._post(payload)


def start_file_watcher(
    stop_event: threading.Event,
    watch_dirs: Optional[list[str]] = None,
    agent_url: Optional[str] = None,
    max_hash_bytes: Optional[int] = None,
) -> None:
    """
    Main watcher loop: attaches Watchdog observer to configured directories
    and processes file creations and downloads.
    """
    cfg = get_config()
    fs_cfg = cfg.get("collectors", {}).get("filesystem", {})
    _url = agent_url or _get_agent_url(cfg)
    _max_hash = max_hash_bytes if max_hash_bytes is not None else fs_cfg.get("max_hash_bytes", 52428800)

    target_dirs = watch_dirs or fs_cfg.get("watch_dirs", ["~/Downloads", "~/Desktop"])
    resolved_dirs = [Path(os.path.expanduser(d)).resolve() for d in target_dirs]

    handler = LifeShieldFileEventHandler(_url, max_hash_bytes=_max_hash)
    observer = Observer()

    active_paths = []
    for p in resolved_dirs:
        try:
            p.mkdir(parents=True, exist_ok=True)
            observer.schedule(handler, str(p), recursive=False)
            active_paths.append(str(p))
        except Exception as exc:
            logger.warning("Could not watch directory %s: %s", p, exc)

    if not active_paths:
        logger.error("No valid directories configured for file watcher.")
        return

    logger.info("File watcher starting on directories: %s", active_paths)
    observer.start()

    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=1.0)
    finally:
        observer.stop()
        observer.join()
        logger.info("File watcher stopped.")


def make_file_watcher_thread(
    stop_event: threading.Event,
    **kwargs,
) -> threading.Thread:
    """Return a configured daemon thread for start_file_watcher."""
    t = threading.Thread(
        target=start_file_watcher,
        args=(stop_event,),
        kwargs=kwargs,
        name="file-watcher",
        daemon=True,
    )
    return t
