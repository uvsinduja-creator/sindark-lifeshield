"""
Pytest test suite for Week 7: Filesystem and Network Telemetry Collectors.
Tests file_watcher, dns_collector, and integration with the LifeShield Agent API.
"""

import asyncio
import hashlib
import os
import socket
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from httpx import ASGITransport, AsyncClient
from watchdog.events import FileCreatedEvent, FileMovedEvent

sys.path.insert(0, str(Path(__file__).parent.parent))

from agent.main import app
from agent.normalizer import normalize_event
from collectors.filesystem.file_watcher import (
    LifeShieldFileEventHandler,
    build_filesystem_event_payload,
    compute_file_hash,
    compute_shannon_entropy,
    detect_double_extension,
    extract_file_metadata,
    make_file_watcher_thread,
)
from collectors.network.dns_collector import (
    build_dns_event_payload,
    build_network_connection_payload,
    make_dns_collector_thread,
    make_network_collector_thread,
    parse_displaydns_output,
    poll_dns_queries,
    poll_network_connections,
)
from storage.schema import EventSource, EventType, LifeShieldEvent


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
async def client():
    """AsyncClient fixture with app lifespan context."""
    async with app.router.lifespan_context(app):
        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as ac:
            yield ac


# =========================================================================
# Filesystem Collector Tests
# =========================================================================

def test_compute_file_hash():
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        content = b"LifeShield test payload for sha256 hashing."
        f.write(content)
        temp_path = f.name

    try:
        expected_sha = hashlib.sha256(content).hexdigest()
        computed_sha, size = compute_file_hash(temp_path)
        assert computed_sha == expected_sha
        assert size == len(content)
    finally:
        os.remove(temp_path)


def test_compute_shannon_entropy():
    # Low entropy file (repeated characters)
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(b"A" * 1000)
        low_ent_path = f.name

    # High entropy file (pseudo-random bytes)
    with tempfile.NamedTemporaryFile("wb", delete=False) as f:
        f.write(os.urandom(10000))
        high_ent_path = f.name

    try:
        low_ent = compute_shannon_entropy(low_ent_path)
        high_ent = compute_shannon_entropy(high_ent_path)
        assert low_ent == 0.0  # single character has zero entropy
        assert high_ent > 7.0  # random bytes have entropy near 8.0
    finally:
        os.remove(low_ent_path)
        os.remove(high_ent_path)


def test_detect_double_extension():
    assert detect_double_extension("invoice.pdf.exe") is True
    assert detect_double_extension("resume.docx.vbs") is True
    assert detect_double_extension("photo.jpg.scr") is True
    assert detect_double_extension("script.ps1") is False
    assert detect_double_extension("document.pdf") is False
    assert detect_double_extension("archive.tar.gz") is False


def test_extract_file_metadata():
    with tempfile.NamedTemporaryFile("wb", suffix=".exe", delete=False) as f:
        f.write(b"MZ\x90\x00\x03\x00\x00\x00\x04\x00\x00\x00")
        f_path = f.name

    try:
        meta = extract_file_metadata(f_path)
        assert meta["filename"] == Path(f_path).name
        assert meta["extension"] == ".exe"
        assert meta["is_executable"] is True
        assert meta["is_script"] is False
        assert meta["sha256"] is not None
        assert meta["size_bytes"] == 12
    finally:
        os.remove(f_path)


def test_build_filesystem_event_payload():
    with tempfile.NamedTemporaryFile("wb", suffix=".bat", delete=False) as f:
        f.write(b"@echo off\r\necho Suspicious Batch Execution")
        f_path = f.name

    try:
        payload = build_filesystem_event_payload(f_path, EventType.FILE_CREATE)
        assert payload["event_type"] == "FILE_CREATE"
        assert payload["source"] == "file_collector"
        assert payload["data"]["extension"] == ".bat"
        assert payload["data"]["is_script"] is True

        # Ensure schema validates it
        normalized = normalize_event(payload)
        assert isinstance(normalized, LifeShieldEvent)
        assert normalized.event_type == EventType.FILE_CREATE
        assert normalized.source == EventSource.FILE_COLLECTOR
    finally:
        os.remove(f_path)


def test_file_watcher_handler_created_and_moved():
    handler = LifeShieldFileEventHandler(agent_url="http://test/events")
    posted = []

    def mock_post(url, json=None, timeout=None):
        posted.append(json)
        resp = MagicMock()
        resp.status_code = 202
        return resp

    with tempfile.NamedTemporaryFile("wb", suffix=".exe", delete=False) as f:
        f.write(b"test binary content")
        file_path = f.name

    with tempfile.NamedTemporaryFile("wb", suffix=".download", delete=False) as f_temp:
        f_temp.write(b"partial download")
        temp_download = f_temp.name

    try:
        with patch("requests.post", side_effect=mock_post):
            # 1. Direct file create
            handler.on_created(FileCreatedEvent(file_path))
            assert len(posted) == 1
            assert posted[0]["event_type"] in ("FILE_CREATE", "FILE_DOWNLOAD")

            # 2. Incomplete temp file should be ignored
            handler.on_created(FileCreatedEvent(temp_download))
            assert len(posted) == 1  # no new post

            # 3. FileMovedEvent from .download to final .exe in Downloads
            dest_download = os.path.join(tempfile.gettempdir(), "downloads", "payload.exe")
            os.makedirs(os.path.dirname(dest_download), exist_ok=True)
            with open(dest_download, "wb") as f_dest:
                f_dest.write(b"completed download")

            try:
                handler.on_moved(FileMovedEvent(temp_download, dest_download))
                assert len(posted) == 2
                assert posted[1]["event_type"] == "FILE_DOWNLOAD"
                assert posted[1]["data"]["filename"] == "payload.exe"
            finally:
                if os.path.exists(dest_download):
                    os.remove(dest_download)
    finally:
        os.remove(file_path)
        os.remove(temp_download)


# =========================================================================
# Network Collector Tests
# =========================================================================

def test_parse_displaydns_output():
    sample_output = """
Windows IP Configuration

    api.badphish.com
    ----------------------------------------
    Record Name . . . . . : api.badphish.com
    Record Type . . . . . : 1
    Time To Live  . . . . : 120
    Data Length . . . . . : 4
    Section . . . . . . . : Answer
    A (Host) Record . . . : 185.199.108.153


    login.secure-bank.top
    ----------------------------------------
    Record Name . . . . . : login.secure-bank.top
    Record Type . . . . . : 28
    Time To Live  . . . . : 300
    Data Length . . . . . : 16
    Section . . . . . . . : Answer
    AAAA Record . . . . . : 2606:4700:3037::6815:4602
    """
    records = parse_displaydns_output(sample_output)
    assert len(records) == 2

    r0 = records[0]
    assert r0["domain"] == "api.badphish.com"
    assert r0["record_type"] == "A"
    assert "185.199.108.153" in r0["resolved_data"]
    assert r0["ttl"] == 120

    r1 = records[1]
    assert r1["domain"] == "login.secure-bank.top"
    assert r1["record_type"] == "AAAA"
    assert "2606:4700:3037::6815:4602" in r1["resolved_data"]


def test_build_dns_event_payload():
    dns_item = {
        "domain": "phish-test-portal.org",
        "record_type": "A",
        "record_type_id": "1",
        "resolved_data": ["198.51.100.25"],
        "ttl": 60,
    }
    payload = build_dns_event_payload(dns_item)
    assert payload["event_type"] == "DNS_QUERY"
    assert payload["source"] == "network_collector"
    assert payload["data"]["domain"] == "phish-test-portal.org"
    assert payload["data"]["resolved_data"] == ["198.51.100.25"]

    normalized = normalize_event(payload)
    assert isinstance(normalized, LifeShieldEvent)
    assert normalized.event_type == EventType.DNS_QUERY
    assert normalized.source == EventSource.NETWORK_COLLECTOR


def test_build_network_connection_payload():
    class MockAddr:
        def __init__(self, ip, port):
            self.ip = ip
            self.port = port

    class MockConn:
        def __init__(self):
            self.laddr = MockAddr("192.168.1.10", 54321)
            self.raddr = MockAddr("203.0.113.88", 443)
            self.status = "ESTABLISHED"
            self.type = socket.SOCK_STREAM
            self.pid = 4321

    mock_conn = MockConn()
    with patch("collectors.network.dns_collector._safe_process_info", return_value=("curl.exe", "C:\\Windows\\curl.exe")):
        payload = build_network_connection_payload(mock_conn)

    assert payload["event_type"] == "NETWORK_CONNECTION"
    assert payload["source"] == "network_collector"
    assert payload["process"] == "curl.exe"
    assert payload["data"]["local_ip"] == "192.168.1.10"
    assert payload["data"]["remote_ip"] == "203.0.113.88"
    assert payload["data"]["remote_port"] == 443
    assert payload["data"]["direction"] == "outbound"

    normalized = normalize_event(payload)
    assert isinstance(normalized, LifeShieldEvent)
    assert normalized.event_type == EventType.NETWORK_CONNECTION


def test_network_and_fs_thread_factories():
    stop_event = threading.Event()
    t_fs = make_file_watcher_thread(stop_event)
    assert t_fs.daemon is True
    assert t_fs.name == "file-watcher"

    t_dns = make_dns_collector_thread(stop_event)
    assert t_dns.daemon is True
    assert t_dns.name == "dns-collector"

    t_net = make_network_collector_thread(stop_event)
    assert t_net.daemon is True
    assert t_net.name == "network-collector"


def test_poll_dns_queries_mock():
    stop_event = threading.Event()
    mock_entries_seed = [{"domain": "existing.com", "record_type": "A", "resolved_data": ["1.1.1.1"]}]
    mock_entries_new = [
        {"domain": "existing.com", "record_type": "A", "resolved_data": ["1.1.1.1"]},
        {"domain": "newmalware.cc", "record_type": "A", "resolved_data": ["203.0.113.50"]},
    ]

    posted = []
    def mock_post(url, json=None, timeout=None):
        posted.append(json)
        resp = MagicMock()
        resp.status_code = 202
        return resp

    def set_stop(*args, **kwargs):
        stop_event.set()

    with patch("collectors.network.dns_collector.fetch_windows_dns_cache", side_effect=[mock_entries_seed, mock_entries_new]), \
         patch("requests.post", side_effect=mock_post), \
         patch.object(stop_event, "wait", side_effect=set_stop):
        poll_dns_queries(stop_event, poll_interval=0.1, agent_url="http://test/events")

    assert len(posted) == 1
    assert posted[0]["event_type"] == "DNS_QUERY"
    assert posted[0]["data"]["domain"] == "newmalware.cc"


# =========================================================================
# Integration with Agent API
# =========================================================================

@pytest.mark.anyio
async def test_api_accepts_file_and_network_events(client: AsyncClient):
    events = [
        {
            "event_type": "FILE_DOWNLOAD",
            "source": "file_collector",
            "user": "victim_user",
            "device": "WIN-ENDPOINT-01",
            "data": {
                "filename": "invoice_update.pdf.exe",
                "size_bytes": 1048576,
                "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                "is_executable": True,
                "is_double_extension": True,
            },
            "metadata": {"collector": "file_watcher"},
        },
        {
            "event_type": "DNS_QUERY",
            "source": "network_collector",
            "user": "victim_user",
            "device": "WIN-ENDPOINT-01",
            "data": {
                "domain": "c2-command-node.biz",
                "record_type": "A",
                "resolved_data": ["198.51.100.99"],
            },
            "metadata": {"collector": "dns_collector"},
        },
        {
            "event_type": "NETWORK_CONNECTION",
            "source": "network_collector",
            "user": "victim_user",
            "device": "WIN-ENDPOINT-01",
            "process": "invoice_update.pdf.exe",
            "data": {
                "local_ip": "192.168.1.15",
                "local_port": 49872,
                "remote_ip": "198.51.100.99",
                "remote_port": 443,
                "direction": "outbound",
            },
            "metadata": {"collector": "network_collector"},
        },
    ]

    for ev in events:
        post_resp = await client.post("/events", json=ev)
        assert post_resp.status_code == 202
        event_id = post_resp.json()["event_id"]

        await asyncio.sleep(0.3)

        get_resp = await client.get(f"/events/{event_id}")
        assert get_resp.status_code == 200
        saved = get_resp.json()
        assert saved["event_id"] == event_id
        assert saved["event_type"] == ev["event_type"]
        assert saved["source"] == ev["source"]
