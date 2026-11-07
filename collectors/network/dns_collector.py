"""
collectors/network/dns_collector.py
=====================================
Monitors DNS resolution queries and active network connections,
normalizing them into DNS_QUERY and NETWORK_CONNECTION events
for the LifeShield agent.

Capabilities
------------
1. DNS Resolution Inspection:
   * Polls the Windows DNS Client Cache via `ipconfig /displaydns` or
     `Get-DnsClientCache`.
   * Extracts query domain, record type, answer data (resolved IPs), and TTL.
   * Tracks differential snapshots so each newly resolved hostname is emitted once.

2. Network Connection Tracking:
   * Polls active IPv4/IPv6 connections via `psutil.net_connections(kind='inet')`.
   * Maps remote IP/port to local process PID, process name, and executable.
   * Emits NETWORK_CONNECTION events when new connections are established.

Configuration is loaded from configs/loader.py – no hardcoded ports or intervals.
"""

from __future__ import annotations

import getpass
import logging
import re
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from typing import Any, Optional

import psutil
import requests

from configs.loader import get_config
from storage.schema import EventSource, EventType

logger = logging.getLogger(__name__)

# Map numerical DNS record types to friendly names
DNS_TYPE_MAP: dict[str, str] = {
    "1": "A",
    "2": "NS",
    "5": "CNAME",
    "6": "SOA",
    "12": "PTR",
    "15": "MX",
    "16": "TXT",
    "28": "AAAA",
    "33": "SRV",
}


def _get_agent_url(cfg: dict) -> str:
    host = cfg["agent"]["host"]
    port = cfg["agent"]["port"]
    return f"http://{host}:{port}/events"


def _safe_process_info(pid: Optional[int]) -> tuple[str, str]:
    """Return (process_name, process_exe) safely for a PID."""
    if not pid:
        return "", ""
    try:
        p = psutil.Process(pid)
        return p.name(), (p.exe() if p.is_running() else "")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "", ""


def parse_displaydns_output(raw_text: str) -> list[dict[str, Any]]:
    """
    Parse the plain-text output of `ipconfig /displaydns` into structured records.
    Works across all Windows versions.
    """
    records: list[dict[str, Any]] = []
    # Split records by looking ahead to each "Record Name" line
    blocks = re.split(r"(?=Record Name[\s\.]*:)", raw_text, flags=re.IGNORECASE)

    for block in blocks:
        if not block.strip():
            continue

        name_match = re.search(r"Record Name[\s\.]*:\s*([^\r\n]+)", block, re.IGNORECASE)
        type_match = re.search(r"Record Type[\s\.]*:\s*(\d+)", block, re.IGNORECASE)
        ttl_match = re.search(r"Time To Live[\s\.]*:\s*(\d+)", block, re.IGNORECASE)

        # Look for A Record, AAAA Record, PTR Record, or CNAME Record lines
        data_matches = re.findall(
            r"(?:A \(Host\) Record|AAAA Record|CNAME Record|PTR Record|Data)[\s\.]*:\s*([^\r\n]+)",
            block,
            re.IGNORECASE,
        )

        if name_match:
            record_name = name_match.group(1).strip().rstrip(".")
            type_num = type_match.group(1).strip() if type_match else "1"
            type_name = DNS_TYPE_MAP.get(type_num, f"TYPE_{type_num}")
            ttl = int(ttl_match.group(1).strip()) if ttl_match else 0
            resolved_data = [d.strip().rstrip(".") for d in data_matches if d.strip()]

            records.append({
                "domain": record_name,
                "record_type_id": type_num,
                "record_type": type_name,
                "resolved_data": resolved_data,
                "ttl": ttl,
            })

    return records


def fetch_windows_dns_cache() -> list[dict[str, Any]]:
    """Fetch current DNS cache entries from Windows via ipconfig /displaydns."""
    try:
        proc = subprocess.run(
            ["ipconfig", "/displaydns"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        if proc.returncode == 0 and proc.stdout:
            return parse_displaydns_output(proc.stdout)
    except Exception as exc:
        logger.debug("Failed to fetch DNS cache via ipconfig: %s", exc)
    return []


def build_dns_event_payload(dns_entry: dict[str, Any]) -> dict[str, Any]:
    """Format a DNS cache item into a canonical LifeShieldEvent payload."""
    domain = dns_entry.get("domain", "")
    data = {
        "domain": domain,
        "query": domain,
        "record_type": dns_entry.get("record_type", "A"),
        "record_type_id": dns_entry.get("record_type_id", "1"),
        "resolved_data": dns_entry.get("resolved_data", []),
        "ttl": dns_entry.get("ttl", 0),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }

    return {
        "event_type": EventType.DNS_QUERY.value,
        "source": EventSource.NETWORK_COLLECTOR.value,
        "user": getpass.getuser(),
        "device": socket.gethostname(),
        "data": data,
        "metadata": {"collector": "dns_collector"},
    }


def build_network_connection_payload(conn: Any) -> dict[str, Any]:
    """Format a psutil connection object into a canonical LifeShieldEvent payload."""
    l_ip = conn.laddr.ip if conn.laddr else ""
    l_port = conn.laddr.port if conn.laddr else 0
    r_ip = conn.raddr.ip if conn.raddr else ""
    r_port = conn.raddr.port if conn.raddr else 0
    pid = getattr(conn, "pid", None)
    proc_name, proc_exe = _safe_process_info(pid)

    # Determine rough directionality
    direction = "outbound"
    if r_port in (80, 443, 8080, 8443, 53) or l_port > 1024:
        direction = "outbound"
    elif l_port in (80, 443, 8080, 8787):
        direction = "inbound"

    data = {
        "local_ip": l_ip,
        "local_port": l_port,
        "remote_ip": r_ip,
        "remote_port": r_port,
        "status": getattr(conn, "status", "UNKNOWN"),
        "protocol": "tcp" if getattr(conn, "type", None) == socket.SOCK_STREAM else "udp",
        "direction": direction,
        "pid": pid or 0,
        "process_name": proc_name,
        "process_exe": proc_exe,
    }

    return {
        "event_type": EventType.NETWORK_CONNECTION.value,
        "source": EventSource.NETWORK_COLLECTOR.value,
        "user": getpass.getuser(),
        "device": socket.gethostname(),
        "process": proc_name,
        "data": data,
        "metadata": {"collector": "network_collector"},
    }


def _post_event(url: str, payload: dict[str, Any]) -> None:
    """Send normalized event to agent API."""
    try:
        resp = requests.post(url, json=payload, timeout=5)
        if resp.status_code not in (200, 201, 202):
            logger.warning("Agent rejected network event: %s", resp.text[:200])
    except requests.RequestException as exc:
        logger.warning("Could not reach agent at %s: %s", url, exc)


def poll_dns_queries(
    stop_event: threading.Event,
    poll_interval: Optional[float] = None,
    agent_url: Optional[str] = None,
) -> None:
    """Poll DNS client cache and emit new queries."""
    cfg = get_config()
    net_cfg = cfg.get("collectors", {}).get("network", {})
    _interval = poll_interval if poll_interval is not None else net_cfg.get("dns_poll_interval_seconds", 5)
    _url = agent_url or _get_agent_url(cfg)

    seen_records: set[tuple[str, str, str]] = set()

    # Seed initial cache so we don't spam historical entries on startup
    initial_entries = fetch_windows_dns_cache()
    for entry in initial_entries:
        resolved_str = ",".join(sorted(entry.get("resolved_data", [])))
        key = (entry.get("domain", ""), entry.get("record_type", ""), resolved_str)
        seen_records.add(key)

    logger.info("DNS collector seeded with %d existing DNS cache entries", len(seen_records))

    while not stop_event.is_set():
        try:
            current_entries = fetch_windows_dns_cache()
            for entry in current_entries:
                resolved_str = ",".join(sorted(entry.get("resolved_data", [])))
                key = (entry.get("domain", ""), entry.get("record_type", ""), resolved_str)
                if key not in seen_records:
                    seen_records.add(key)
                    # Skip localhost / internal loopback artifacts
                    domain = entry.get("domain", "").lower()
                    if domain and not domain.endswith(".local") and domain != "localhost":
                        payload = build_dns_event_payload(entry)
                        _post_event(_url, payload)
        except Exception as exc:
            logger.warning("Error in DNS collector poll: %s", exc)

        stop_event.wait(timeout=_interval)

    logger.info("DNS collector stopped.")


def poll_network_connections(
    stop_event: threading.Event,
    poll_interval: Optional[float] = None,
    agent_url: Optional[str] = None,
) -> None:
    """Poll active network connections and emit new remote sockets."""
    cfg = get_config()
    net_cfg = cfg.get("collectors", {}).get("network", {})
    _interval = poll_interval if poll_interval is not None else net_cfg.get("poll_interval_seconds", 5)
    _url = agent_url or _get_agent_url(cfg)

    # Key: (local_ip, local_port, remote_ip, remote_port, pid)
    seen_conns: set[tuple[str, int, str, int, Optional[int]]] = set()

    # Seed current connections
    try:
        for c in psutil.net_connections(kind="inet"):
            if c.raddr:
                key = (c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, c.pid)
                seen_conns.add(key)
    except Exception as exc:
        logger.debug("Initial net_connections seed notice: %s", exc)

    logger.info("Network connection collector seeded with %d connections", len(seen_conns))

    while not stop_event.is_set():
        try:
            current_conns: set[tuple[str, int, str, int, Optional[int]]] = set()
            active_list = []
            for c in psutil.net_connections(kind="inet"):
                if c.raddr:
                    key = (c.laddr.ip, c.laddr.port, c.raddr.ip, c.raddr.port, c.pid)
                    current_conns.add(key)
                    active_list.append((key, c))

            # New connections
            new_keys = current_conns - seen_conns
            for key, conn in active_list:
                if key in new_keys:
                    # Ignore loopback connections (e.g. 127.0.0.1 -> 127.0.0.1)
                    if conn.raddr and conn.raddr.ip != "127.0.0.1" and conn.raddr.ip != "::1":
                        payload = build_network_connection_payload(conn)
                        _post_event(_url, payload)

            seen_conns = current_conns

        except Exception as exc:
            logger.warning("Error in network connections poll: %s", exc)

        stop_event.wait(timeout=_interval)

    logger.info("Network connection collector stopped.")


def make_dns_collector_thread(stop_event: threading.Event, **kwargs) -> threading.Thread:
    """Return a configured daemon thread for poll_dns_queries."""
    return threading.Thread(
        target=poll_dns_queries,
        args=(stop_event,),
        kwargs=kwargs,
        name="dns-collector",
        daemon=True,
    )


def make_network_collector_thread(stop_event: threading.Event, **kwargs) -> threading.Thread:
    """Return a configured daemon thread for poll_network_connections."""
    return threading.Thread(
        target=poll_network_connections,
        args=(stop_event,),
        kwargs=kwargs,
        name="network-collector",
        daemon=True,
    )
